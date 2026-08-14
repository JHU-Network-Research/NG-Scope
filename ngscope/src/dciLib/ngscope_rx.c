#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <execinfo.h>

#include "srsran/srsran.h"

#include "ngscope/hdr/dciLib/ngscope_rx.h"
#include "ngscope/hdr/dciLib/load_config.h"
#include "ngscope/hdr/dciLib/record_ring_buffer.h"

const uint64_t RECORD_BUF_CAP = 1024*1024*80;
// const uint64_t flush_thresh = 1024*1024*8;
// static uint8_t record_buf[RECORD_BUF_CAP];
// static uint64_t rb_in_pos = 0;
// static uint64_t rb_out_pos = 0;
// pthread_mutex_t rb_mutex = PTHREAD_MUTEX_INITIALIZER;
// pthread_cond_t rb_cond = PTHREAD_COND_INITIALIZER;

record_ring_buffer_t record_buf;
static uint8_t replay_buf[51200*8];

pthread_t flush_thread;

const char *record_path;
const char *replay_path;

ngscope_mode_t  mode       = NORMAL;
// static uint64_t total_bytes_fetched = 0;
// static struct timespec last_rx_time  = {0, 0};
static FILE*    replay_fh  = NULL;  // used only for REPLAY
// static FILE*    outfp = NULL;

static uint64_t         last_replay_ts_full = 0;
static double           last_replay_ts_frac = 0.0;
static struct timespec  last_replay_return  = {0, 0};
static uint64_t frame_count = 0;
static uint64_t nreplayed = 0;
static uint64_t nrecorded = 0;

bool __attribute__((weak)) go_exit = false;
bool __attribute__((weak)) debug = false;


bool init_record(const char* path, uint32_t buf_size_gb)
{
  record_path = path;
  mode = RECORD;
  uint64_t buf_size = (uint64_t) ONE_GB*buf_size_gb;
  if (debug)
    printf("FLUSH: ONE_GB: %d, requested capacity GB: %d, TOTAL SIZE: %ld\n", ONE_GB, buf_size_gb, buf_size);

  record_ring_buffer_init(&record_buf, buf_size, path);

//   outfp = fopen(path, "wb");

  pthread_create(&flush_thread, NULL, (void*)flush_record, &record_buf);

  return true;
}

bool init_replay(const char* path)
{
    replay_path = path;
    mode = REPLAY;
    replay_fh = fopen(path, "rb");
    return true;
}

// int srsran_rf_recv_wrapper(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t)
int ngscope_recv_samples_wrapper(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t){

    // int nof_channels = 1;
    if (debug)
        printf("DEBUG: ngscope_rx receive %d samples\n", nsamples);
    if (!t){
        if(debug)
            printf("DEBUG: Error, timestamp passed to recv samples is NULL\n");
        return 0;
    }
    
    // fprintf(stdout, "[AGC] retrieving normal sample\n");
    
    DEBUG(" ----  Receive %d samples  ----", nsamples);
    void* ptr[SRSRAN_MAX_PORTS];
    for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
        ptr[i] = data_[i];
    }
    int n = 0;
    if (mode == NORMAL || mode == RECORD){
        if (debug)
            printf("DEBUG: MODE is normal or record\n");
        n = srsran_rf_recv_with_time_multi(h, ptr, nsamples, true, &t->full_secs, &t->frac_secs);
        // return n;
        if (debug)
            printf("DEBUG: got %d samples\n", n);
        if (n != nsamples){
            if (debug)
                printf("DEBUG: Got mismatch in number of samples: actual=%d, expected=%d\n", n, nsamples);
        }

        if (n < 0) {
            // if (debug)
            fprintf(stderr, "Error retrieving samples: recv returned %d\n", n);
            return n;
        }
        if (mode == RECORD){
            if (debug)
                printf("DEBUG: Recording %d samples\n", n);

            rx_frame_header_t hdr;
            memset(&hdr,0,sizeof(rx_frame_header_t));
            hdr.nof_samples         = nsamples;
            hdr.timestamp_full_secs = (uint64_t) t->full_secs;
            hdr.timestamp_frac_secs = t->frac_secs;
            if (debug)
                printf("DEBUG: size of hdr: %ld, size of uint32_t: %ld, size of uint64_t: %ld, size of double: %ld\n", sizeof(rx_frame_header_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(double));
            // uint64_t frame_size = sizeof(hdr) + hdr.nof_samples * sizeof(cf_t);


            record_ring_buffer_insert(&record_buf, &hdr, sizeof(hdr));
            record_ring_buffer_insert(&record_buf, ptr[0], sizeof(cf_t)*n);
            nrecorded += (sizeof(hdr));
            nrecorded += (sizeof(cf_t)*n);
            if (debug)
                printf("RECORD: Written %ld bytes to the buffer\n", nrecorded);

            if (debug)
                printf("Done recording %d samples\n", n);
        }
    }else if (mode == REPLAY){

        if (!replay_fh){
            fprintf(stderr, "ERROR: replay file is not open. Please ensure the file exists and is readable\n");
        }

        if (feof(replay_fh)){
            if (debug)
                printf("REPLAY: reached end of replay file\n");
            sleep(1); // let decoding finish
            raise(SIGINT);
            return 0;
        }

        if (debug)
            printf("REPLAY: Replaying samples\n");
        rx_frame_header_t hdr;
        n = fread(&hdr, sizeof(rx_frame_header_t), 1, replay_fh);
        if (n != 1){
            if (debug)
                printf("REPLAY: error: short read loading header, read %d items instead of 1\n", n);
        }
        if (n <= 0){
            if (debug)
                printf("REPLAY: replay returned %d when reading header\n", n);
            if (feof(replay_fh)){
                if (debug)
                    printf("REPLAY: reached end of replay file\n");
                sleep(1); // let decoding finish
                raise(SIGINT);
                return 0;
            }
        }
        nreplayed += (n*sizeof(rx_frame_header_t));

        srsran_timestamp_init(t, hdr.timestamp_full_secs, hdr.timestamp_frac_secs);


        if (debug)
            printf("REPLAY: read header: nof_samples=%ld, sec=%ld, nsec=%f\n", hdr.nof_samples, hdr.timestamp_full_secs, hdr.timestamp_frac_secs);
        
        if (hdr.nof_samples != nsamples){
            if (debug)
                printf("REPLAY: ERROR: mismatch in number of samples, requested %d but file has %ld\n", nsamples, hdr.nof_samples);
            return 0;
        }
        
        if (last_replay_return.tv_sec == 0){
            struct timespec current;
            clock_gettime(CLOCK_MONOTONIC, &current);
            last_replay_return.tv_sec = current.tv_sec;
            last_replay_return.tv_nsec = current.tv_nsec;
        }

        double recorded_delta = (double)(hdr.timestamp_full_secs - last_replay_ts_full)+ (hdr.timestamp_frac_secs - last_replay_ts_frac);
        struct timespec spin_now;
        double system_elapsed;

        if (debug)
            printf("REPLAY: last_replay_return: %ld.%ld, delta: %.3f\n", last_replay_return.tv_sec, last_replay_return.tv_nsec, recorded_delta);

        // printf("DEBUG: last_replay_return: %ld.%ld\n", last_replay_return.tv_sec, last_replay_return.tv_nsec);
        do {
          clock_gettime(CLOCK_MONOTONIC, &spin_now);
          system_elapsed = (spin_now.tv_sec  - last_replay_return.tv_sec)
                         + (spin_now.tv_nsec - last_replay_return.tv_nsec) * 1e-9;
        //   printf("DEBUG: last_replay_return: %ld.%ld, system elapsed: %ld.%ld, elapsed: %.3f, delta: %.3f\n", last_replay_return.tv_sec, last_replay_return.tv_nsec, spin_now.tv_sec, spin_now.tv_nsec, system_elapsed, recorded_delta);
        } while (system_elapsed < recorded_delta);

        if (debug)
            printf("REPLAY: Done waiting\n");


        last_replay_ts_full  = hdr.timestamp_full_secs;
        last_replay_ts_frac  = hdr.timestamp_frac_secs;


        t->full_secs = hdr.timestamp_full_secs;
        t->frac_secs = hdr.timestamp_frac_secs;

        if (debug)
            printf("REPLAY: Reading %ld samples from file\n", hdr.nof_samples);


        size_t replay_buf_cap = sizeof(replay_buf) / sizeof(cf_t); // 23040
        if (hdr.nof_samples > replay_buf_cap) {
            fprintf(stderr, "REPLAY: ERROR: frame has %ld samples, exceeds replay_buf capacity %zu\n",
                    hdr.nof_samples, replay_buf_cap);
            return 0; // or abort — silently overflowing is worse than refusing
        }

        n = fread(replay_buf, sizeof(cf_t), hdr.nof_samples, replay_fh);
        nreplayed += (n*sizeof(cf_t));
        if (debug)
            printf("Read %ld bytes from file!\n", nreplayed);
        if (n <= 0){
            if (debug)
                printf("REPLAY: replay returned %d when reading header, EOF=%d\n", n, feof(replay_fh));
            if (feof(replay_fh)){
                if (debug)
                    printf("REPLAY: reached end of replay file\n");
                sleep(1); // let decoding finish
                raise(SIGINT);
                return 0;
            }
        }

        if (n != hdr.nof_samples) 
            printf("REPLAY: ERROR: Read %d samples but expected %ld\n", n, hdr.nof_samples);
        else
            if (debug)
                printf("REPLAY: read %d samples (expected %ld)\n", n, hdr.nof_samples);
        memcpy(ptr[0], replay_buf, n*sizeof(cf_t));
        if (debug)
            printf("REPLAY: Copied %d samples to ptr\n", n);
        memset(replay_buf, 0, sizeof(replay_buf));
        clock_gettime(CLOCK_MONOTONIC, &last_replay_return);
    }
    if (debug)
        printf("DEBUG: returning %d samples\n", n);
    if (debug)
    
        printf("FRAME %lu: mode=%d nsamples=%d n=%d\n", frame_count, mode, nsamples, n);
    frame_count++;
    return n;
}

int ngscope_recv_samples_wrapper_agc(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t, srsran_agc_t *agc){

    // int nof_channels = 1;
    if (debug)
        printf("DEBUG: ngscope_rx receive %d samples\n", nsamples);
    if (!t){
        if(debug)
            printf("DEBUG: Error, timestamp passed to recv samples is NULL\n");
        return 0;
    }

    // fprintf(stdout, "[AGC] retrieving AGC sample\n");
    
    
    DEBUG(" ----  Receive %d samples  ----", nsamples);
    void* ptr[SRSRAN_MAX_PORTS];
    for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
        ptr[i] = data_[i];
    }
    int n = 0;
    if (mode == NORMAL || mode == RECORD){
        if (debug)
            printf("DEBUG: MODE is normal or record\n");
        n = srsran_rf_recv_with_time_multi(h, ptr, nsamples, true, &t->full_secs, &t->frac_secs);
        // return n;
        if (debug)
            printf("DEBUG: got %d samples\n", n);
        if (n != nsamples){
            if (debug)
                printf("DEBUG: Got mismatch in number of samples: actual=%d, expected=%d\n", n, nsamples);
        }

        if (n < 0) {
            // if (debug)
            fprintf(stderr, "Error retrieving samples: recv returned %d\n", n);
            return n;
        }
        if (mode == RECORD){
            if (debug)
                printf("DEBUG: Recording %d samples\n", n);

            rx_frame_header_t hdr;
            memset(&hdr,0,sizeof(rx_frame_header_t));
            hdr.nof_samples         = nsamples;
            hdr.timestamp_full_secs = (uint64_t) t->full_secs;
            hdr.timestamp_frac_secs = t->frac_secs;
            if (debug)
                printf("DEBUG: size of hdr: %ld, size of uint32_t: %ld, size of uint64_t: %ld, size of double: %ld\n", sizeof(rx_frame_header_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(double));
            // uint64_t frame_size = sizeof(hdr) + hdr.nof_samples * sizeof(cf_t);


            cf_t *agc_buf = (cf_t*) malloc(sizeof(cf_t)*n);
            if (agc){
                // fprintf(stdout, "[AGC] Applying agc to samples at TTI=%d%d, current_gain=%.02f!\n", q->frame_number, q->sf_idx, q->agc.gain_db);
                // fprintf(stdout, "[AGC 3] applying agc to recorded sample\n");
                srsran_agc_process(agc, agc_buf, n);
                // fprintf(stdout, "[AGC] Done applying agc to recorded sample\n");
            }


            record_ring_buffer_insert(&record_buf, &hdr, sizeof(hdr));
            record_ring_buffer_insert(&record_buf, agc_buf, sizeof(cf_t)*n);
            free(agc_buf);
            nrecorded += (sizeof(hdr));
            nrecorded += (sizeof(cf_t)*n);
            if (debug)
                printf("RECORD: Written %ld bytes to the buffer\n", nrecorded);

            if (debug)
                printf("Done recording %d samples\n", n);
        }
    }else if (mode == REPLAY){

        if (!replay_fh){
            fprintf(stderr, "ERROR: replay file is not open. Please ensure the file exists and is readable\n");
        }

        if (feof(replay_fh)){
            if (debug)
                printf("REPLAY: reached end of replay file\n");
            sleep(1); // let decoding finish
            raise(SIGINT);
            return 0;
        }

        if (debug)
            printf("REPLAY: Replaying samples\n");
        rx_frame_header_t hdr;
        n = fread(&hdr, sizeof(rx_frame_header_t), 1, replay_fh);
        if (n != 1){
            if (debug)
                printf("REPLAY: error: short read loading header, read %d items instead of 1\n", n);
        }
        if (n <= 0){
            if (debug)
                printf("REPLAY: replay returned %d when reading header\n", n);
            if (feof(replay_fh)){
                // if (debug)
                printf("REPLAY: reached end of replay file\n");
                sleep(1); // let decoding finish
                raise(SIGINT);
                return 0;
            }
        }
        nreplayed += (n*sizeof(rx_frame_header_t));

        srsran_timestamp_init(t, hdr.timestamp_full_secs, hdr.timestamp_frac_secs);


        if (debug)
            printf("REPLAY: read header: nof_samples=%ld, sec=%ld, nsec=%f\n", hdr.nof_samples, hdr.timestamp_full_secs, hdr.timestamp_frac_secs);
        
        if (hdr.nof_samples != nsamples){
            if (debug)
                printf("REPLAY: ERROR: mismatch in number of samples, requested %d but file has %ld\n", nsamples, hdr.nof_samples);
            return 0;
        }
        
        if (last_replay_return.tv_sec == 0){
            struct timespec current;
            clock_gettime(CLOCK_MONOTONIC, &current);
            last_replay_return.tv_sec = current.tv_sec;
            last_replay_return.tv_nsec = current.tv_nsec;
        }

        double recorded_delta = (double)(hdr.timestamp_full_secs - last_replay_ts_full)+ (hdr.timestamp_frac_secs - last_replay_ts_frac);
        struct timespec spin_now;
        double system_elapsed;

        if (debug)
            printf("REPLAY: last_replay_return: %ld.%ld, delta: %.3f\n", last_replay_return.tv_sec, last_replay_return.tv_nsec, recorded_delta);

        // printf("DEBUG: last_replay_return: %ld.%ld\n", last_replay_return.tv_sec, last_replay_return.tv_nsec);
        do {
          clock_gettime(CLOCK_MONOTONIC, &spin_now);
          system_elapsed = (spin_now.tv_sec  - last_replay_return.tv_sec)
                         + (spin_now.tv_nsec - last_replay_return.tv_nsec) * 1e-9;
        //   printf("DEBUG: last_replay_return: %ld.%ld, system elapsed: %ld.%ld, elapsed: %.3f, delta: %.3f\n", last_replay_return.tv_sec, last_replay_return.tv_nsec, spin_now.tv_sec, spin_now.tv_nsec, system_elapsed, recorded_delta);
        } while (system_elapsed < recorded_delta);

        if (debug)
            printf("REPLAY: Done waiting\n");


        last_replay_ts_full  = hdr.timestamp_full_secs;
        last_replay_ts_frac  = hdr.timestamp_frac_secs;


        t->full_secs = hdr.timestamp_full_secs;
        t->frac_secs = hdr.timestamp_frac_secs;

        if (debug)
            printf("REPLAY: Reading %ld samples from file\n", hdr.nof_samples);
        n = fread(replay_buf, sizeof(cf_t), hdr.nof_samples, replay_fh);
        nreplayed += (n*sizeof(cf_t));
        if (debug)
            printf("Read %ld bytes from file!\n", nreplayed);
        if (n <= 0){
            if (debug)
                printf("REPLAY: replay returned %d when reading header, EOF=%d\n", n, feof(replay_fh));
            if (feof(replay_fh)){
                if (debug)
                    printf("REPLAY: reached end of replay file\n");
                sleep(1); // let decoding finish
                raise(SIGINT);
                return 0;
            }
        }

        if (n != hdr.nof_samples) 
            printf("REPLAY: ERROR: Read %d samples but expected %ld\n", n, hdr.nof_samples);
        else
            if (debug)
                printf("REPLAY: read %d samples (expected %ld)\n", n, hdr.nof_samples);
        memcpy(ptr[0], replay_buf, n*sizeof(cf_t));
        if (debug)
            printf("REPLAY: Copied %d samples to ptr\n", n);
        memset(replay_buf, 0, sizeof(replay_buf));
        clock_gettime(CLOCK_MONOTONIC, &last_replay_return);
    }
    if (debug)
        printf("DEBUG: returning %d samples\n", n);
    if (debug)
    
        printf("FRAME %lu: mode=%d nsamples=%d n=%d\n", frame_count, mode, nsamples, n);
    frame_count++;
    return n;
}

int stop_record(){

    if (debug)
        printf("DEBUG: closing record files\n");

    // pthread_cancel(flush_thread);

    // pthread_join(flush_thread, NULL);

    // record_ring_buffer_destroy(&record_buf);
    pthread_mutex_lock(&record_buf.mutex);
    pthread_cond_signal(&record_buf.cond);
    pthread_mutex_unlock(&record_buf.mutex);
    pthread_join(flush_thread, NULL);  // no cancel needed
    if (debug)
        printf("DEBUG: final flush done\n");
    record_ring_buffer_destroy(&record_buf);

    return 0;
}

int stop_replay(){

    if (debug)
        printf("DEBUG: closing replay files\n");

    if (replay_fh){
        if (fclose(replay_fh) < 0)
            return -1;
    }
    printf("DEBUG: file read %ld times\n", frame_count);
    fflush(stdout);
    return 0;
}


void flush_record(void *arg){
    record_ring_buffer_t *buf = (record_ring_buffer_t *) arg;

    pthread_cleanup_push(flush_thread_cleanup, (void*)buf);

    while(!go_exit){

        pthread_mutex_lock(&buf->mutex);

        while (!buf->flush && !go_exit){
            pthread_cond_wait(&buf->cond,&buf->mutex);
        }
        // printf("[FLUSH] out of wait\n");
        record_ring_buffer_flush(buf);

        pthread_mutex_unlock(&buf->mutex);

    }
    pthread_cleanup_pop((void*)buf);

}

void flush_thread_cleanup(void *arg){

    if (debug)
        printf("RECORD: flushing the buffer for cleanup\n");

    record_ring_buffer_t *buf = (record_ring_buffer_t *) arg;

    pthread_mutex_lock(&buf->mutex);
    record_ring_buffer_flush(buf);
    pthread_mutex_unlock(&buf->mutex);
    // pthread_mutex_unlock(&buf->mutex);

}
