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
// #include "ngscope/hdr/dciLib/record_ring_buffer.h"

const uint64_t RECORD_BUF_CAP = 1024*1024*80;
// const uint64_t flush_thresh = 1024*1024*8;
// static uint8_t record_buf[RECORD_BUF_CAP];
// static uint64_t rb_in_pos = 0;
// static uint64_t rb_out_pos = 0;
// pthread_mutex_t rb_mutex = PTHREAD_MUTEX_INITIALIZER;
// pthread_cond_t rb_cond = PTHREAD_COND_INITIALIZER;

record_ring_buffer_t record_buf;
static uint8_t replay_buf[23040*8];

pthread_t flush_thread;

const char *record_path;
const char *replay_path;

static ngscope_mode_t  mode       = NORMAL;
// static uint64_t total_bytes_fetched = 0;
// static struct timespec last_rx_time  = {0, 0};
static FILE*    replay_fh  = NULL;  // used only for REPLAY
// static FILE*    outfp = NULL;

static uint64_t         last_replay_ts_full = 0;
static double           last_replay_ts_frac = 0.0;
static struct timespec  last_replay_return  = {0, 0};

extern bool go_exit;

extern bool debug;


bool init_record(const char* path, uint32_t buf_size_gb)
{
  record_path = path;
  mode = RECORD;

  record_ring_buffer_init(&record_buf, buf_size_gb, path);

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
    // if (debug)
    printf("DEBUG: ngscope_rx receive %d samples\n", nsamples);
    DEBUG(" ----  Receive %d samples  ----", nsamples);
    void* ptr[SRSRAN_MAX_PORTS];
    for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
        ptr[i] = data_[i];
    }
    int n;
    if (mode == NORMAL || mode == RECORD){
        if (debug)
            printf("DEBUG: MODE is normal or record\n");
    //return srsran_rf_recv_with_time_multi(h, ptr, nsamples, true, NULL, NULL);
        n = srsran_rf_recv_with_time_multi(h, ptr, nsamples, true, &t->full_secs, &t->frac_secs);
        // return n;
        // if (debug)
        printf("DEBUG: got %d samples\n", n);
        if (n != 11520){
            // if (debug)
            printf("DEBUG: got invalid number of samples, skipping");
            int nptrs;
            void *buffer[4096];
            char **strings;
            nptrs = backtrace(buffer, 4096);
            printf("backtrace() returned %d addresses\n", nptrs);
            
            strings = backtrace_symbols(buffer, nptrs);
            if (strings == NULL){
                perror("backtrace_symbols");
            }else{
                for (size_t j = 0; j < nptrs; j++){
                    printf("%s\n", strings[j]);
                }
                free(strings);
            }
            return n;
        }

        if (n < 0) {
            if (debug)
                fprintf(stderr, "Error retrieving samples: recv returned %d\n", n);
            return n;
        }
        if (mode == RECORD){

            rx_frame_header_t hdr;
            memset(&hdr,0,sizeof(rx_frame_header_t));
            hdr.nof_samples         = nsamples;
            hdr.timestamp_full_secs = (uint64_t) t->full_secs;
            hdr.timestamp_frac_secs = t->frac_secs;
            printf("DEBUG: size of hdr: %ld, size of uint32_t: %ld, size of uint64_t: %ld, size of double: %ld\n", sizeof(rx_frame_header_t), sizeof(uint32_t), sizeof(uint64_t), sizeof(double));
            // uint64_t frame_size = sizeof(hdr) + hdr.nof_samples * sizeof(cf_t);


            record_ring_buffer_insert(&record_buf, &hdr, sizeof(hdr));
            record_ring_buffer_insert(&record_buf, ptr[0], sizeof(cf_t)*n);

            // pthread_mutex_lock(&rb_mutex);

            // memcpy(record_buf + rb_in_pos, &hdr, sizeof(rx_frame_header_t));
            // rb_in_pos += sizeof(rx_frame_header_t);
            // memcpy(record_buf + rb_in_pos, ptr[ch], sizeof(cf_t) * n);
            // rb_in_pos += sizeof(cf_t) * n;
            // // pthread_cond_signal();

            // rb_in_pos %= RECORD_BUF_CAP;
            // pthread_mutex_unlock(&rb_mutex);

            // size_t written = fwrite(&hdr,sizeof(rx_frame_header_t),1,outfp);
            // if (written != 1){
            //     printf("DEBUG: error: short write for header\n");
            //     return -1;
            // }

            // for (int ch = 0; ch < nof_channels; ch++) {
            //     // printf("DEBUG: Got %d samples on channel %d\n", n, ch);
            //     // printf("DEBUG: file pointer is null: %d\n", outfp == NULL);
            //     size_t written = fwrite(ptr[ch],
            //                             sizeof(cf_t),
            //                             n,   /* use actual returned count */
            //                             outfp);
            //     if ((int)written != n) {
            //         fprintf(stderr, "DEBUG: Error: short write on ch %d\n", ch);
            //         break;
            //     }
            // }
            // printf("DEBUG: wrote %ld bytes\n", written);
        }
    }else if (mode == REPLAY){

        if (feof(replay_fh)){
            printf("DEBUG: reached end of replay file\n");
            sleep(1); // let decoding finish
            raise(SIGINT);
            return 0;
        }

        if (nsamples != 11520){
            // if (debug)
            printf("DEBUG: replay got invalid number of samples, skipping\n");
            int nptrs;
            void *buffer[4096];
            char **strings;
            nptrs = backtrace(buffer, 4096);
            printf("backtrace() returned %d addresses\n", nptrs);
            
            strings = backtrace_symbols(buffer, nptrs);
            if (strings == NULL){
                perror("backtrace_symbols");
            }else{
                for (size_t j = 0; j < nptrs; j++){
                    printf("%s\n", strings[j]);
                }
                free(strings);
            }
            return 0;
        }

        if (debug)
            printf("DEBUG: Replaying samples\n");
        rx_frame_header_t hdr;
        n = fread(&hdr, sizeof(rx_frame_header_t), 1, replay_fh);
        if (n != 1){
            printf("DEBUG: error: short read loading header, got %ld bytes instead of 24\n", n*sizeof(rx_frame_header_t));
        }
        if (n <= 0){
            printf("DEBUG: replay returned %d when reading header\n", n);
            if (feof(replay_fh)){
                printf("DEBUG: reached end of replay file\n");
                sleep(1); // let decoding finish
                raise(SIGINT);
                return 0;
            }
        }


        if (debug)
            printf("DEBUG: read header: nof_samples=%ld, sec=%ld, nsec=%f\n", hdr.nof_samples, hdr.timestamp_full_secs, hdr.timestamp_frac_secs);
        
        if (hdr.nof_samples != nsamples){
            if (debug)
                printf("DEBUG: ERROR: mismatch in number of samples, requested %d but file has %ld\n", nsamples, hdr.nof_samples);
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
            printf("DEBUG: last_replay_return: %ld.%ld, delta: %.3f\n", last_replay_return.tv_sec, last_replay_return.tv_nsec, recorded_delta);

        // printf("DEBUG: last_replay_return: %ld.%ld\n", last_replay_return.tv_sec, last_replay_return.tv_nsec);
        do {
          clock_gettime(CLOCK_MONOTONIC, &spin_now);
          system_elapsed = (spin_now.tv_sec  - last_replay_return.tv_sec)
                         + (spin_now.tv_nsec - last_replay_return.tv_nsec) * 1e-9;
        //   printf("DEBUG: last_replay_return: %ld.%ld, system elapsed: %ld.%ld, elapsed: %.3f, delta: %.3f\n", last_replay_return.tv_sec, last_replay_return.tv_nsec, spin_now.tv_sec, spin_now.tv_nsec, system_elapsed, recorded_delta);
        } while (system_elapsed < recorded_delta);

        if (debug)
            printf("DEBUG: Done waiting\n");


        last_replay_ts_full  = hdr.timestamp_full_secs;
        last_replay_ts_frac  = hdr.timestamp_frac_secs;


        t->full_secs = hdr.timestamp_full_secs;
        t->frac_secs = hdr.timestamp_frac_secs;


        n = fread(replay_buf, sizeof(cf_t), hdr.nof_samples, replay_fh);
        if (n <= 0){
            printf("DEBUG: replay returned %d when reading header, EOF=%d\n", n, feof(replay_fh));
            if (feof(replay_fh)){
                printf("DEBUG: reached end of replay file\n");
                sleep(1); // let decoding finish
                raise(SIGINT);
                return 0;
            }
        }

        if (debug)
            printf("DEBUG: read %d samples (expected %ld)\n", n, hdr.nof_samples);
        memcpy(ptr[0], replay_buf, n*sizeof(cf_t));
        if (debug)
            printf("DEBUG: Copied %d samples to ptr\n", n);
        memset(replay_buf, 0, sizeof(replay_buf));
        clock_gettime(CLOCK_MONOTONIC, &last_replay_return);
    }
    // printf("DEBUG: returning samples\n");
    return n;
}

int stop_record(){

    if (debug)
        printf("DEBUG: closing record files\n");

    pthread_cancel(flush_thread);

    pthread_join(flush_thread, NULL);

    record_ring_buffer_destroy(&record_buf);

    // if (outfp){
    //     if (fflush(outfp) < 0 )
    //         return -1;
    //     if (fclose(outfp) < 0)
    //         return -1;
    // }
    return 0;
}

int stop_replay(){

    if (debug)
        printf("DEBUG: closing replay files\n");

    if (replay_fh){
        if (fclose(replay_fh) < 0)
            return -1;
    }
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

        record_ring_buffer_flush(buf);

        pthread_mutex_unlock(&buf->mutex);

    }
    pthread_cleanup_pop((void*)buf);

}

void flush_thread_cleanup(void *arg){

    record_ring_buffer_t *buf = (record_ring_buffer_t *) arg;

    record_ring_buffer_flush(buf);
    // pthread_mutex_unlock(&buf->mutex);

}
