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
#include <errno.h>

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

/* ue_sync does not always ask for exactly one subframe: while re-acquiring PSS or applying a
 * timing correction it requests a longer block, and the recorder faithfully stores frames of
 * that size. The buffer therefore has to cover the largest read the task scheduler can ask
 * for, which is 3 * SRSRAN_SF_LEN_PRB(cell.nof_prb) (see task_scheduler.c:506). Sizing this
 * for a single 100-PRB subframe used to overflow it on the first oversized frame. */
#define REPLAY_BUF_NOF_SAMPLES (3 * SRSRAN_SF_LEN_MAX)
static uint8_t replay_buf[REPLAY_BUF_NOF_SAMPLES * sizeof(cf_t)];

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

/* ------------------------------------------------------------ compressed replay
 *
 * A recording may be handed over compressed. The replay reads strictly forward -- a header,
 * then its payload, and the only seek is a forward skip over a payload it has decided not
 * to use -- so a decompression stream serves it as well as a file, provided the skip is
 * implemented by reading and discarding rather than by fseek().
 *
 * Decompression runs in a subprocess rather than in-process, and that is a throughput
 * decision, not a convenience one. Measured on this machine over 300 MB of IQ:
 *
 *     bzip2  -dc   34 MB/s     (single-threaded; what linking libbz2 would give)
 *     lbzip2 -dc  400 MB/s     (16 threads)
 *     replay consumes ~97 MB/s
 *
 * So the obvious implementation -- link libbz2 and decode inline -- would have made every
 * replay about three times slower, while a parallel decompressor leaves fourfold headroom.
 * A slow source cannot corrupt a measurement, because the replay scheduler blocks on a busy
 * decoder rather than discarding subframes, but it does cost wall time on every run.
 *
 * The parallel tool is preferred and the serial one is the fallback, so this works on a host
 * that has only the latter -- just slower, and it says so. gzip and xz are listed too: the
 * mechanism is identical and leaving them out would be an arbitrary limitation.
 *
 * IQ compresses poorly -- bzip2 gets a recording to about 46% of its original size -- so
 * this trades a lot of CPU for a moderate saving. Worth it for archived captures, rarely
 * worth it for one being iterated on. */

static bool     replay_is_pipe   = false;
/* Time spent blocked reading the recording, against wall time. The question "is the
 * decompressor the bottleneck?" has no general answer -- it depends on the cell's sample
 * rate and on how much work the decode settings ask for -- so it is measured rather than
 * predicted. Single-threaded and per device, like replay_fh itself. */
static uint64_t replay_read_ns   = 0;
static uint64_t replay_bytes     = 0;
static uint64_t replay_start_ns  = 0;

static uint64_t replay_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* fread() on the recording, timed. */
static size_t replay_fread(void* dst, size_t size, size_t nmemb)
{
    const uint64_t t0 = replay_now_ns();
    const size_t   n  = fread(dst, size, nmemb, replay_fh);
    replay_read_ns += replay_now_ns() - t0;
    replay_bytes   += n * size;
    return n;
}

static const struct {
    const char* ext;
    const char* cmds[3]; /* preferred first; NULL-terminated */
} REPLAY_CODECS[] = {
    {".bz2", {"lbzip2", "bzip2", NULL}},
    {".gz",  {"pigz",   "gzip",  NULL}},
    {".xz",  {"xz",     NULL,    NULL}},
};

/* PATH lookup without spawning anything: popen() would report a missing decompressor only
 * as an empty stream, which is indistinguishable here from an empty recording. */
static bool replay_have_cmd(const char* cmd)
{
    const char* path = getenv("PATH");
    if (path == NULL) {
        return false;
    }
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char* dir = strtok(buf, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        char full[4352];
        snprintf(full, sizeof(full), "%s/%s", dir, cmd);
        if (access(full, X_OK) == 0) {
            return true;
        }
    }
    return false;
}

static bool replay_ends_with(const char* s, const char* suffix)
{
    const size_t ls = strlen(s), lx = strlen(suffix);
    return ls >= lx && strcasecmp(s + ls - lx, suffix) == 0;
}

bool init_replay(const char* path)
{
    replay_path     = path;
    mode            = REPLAY;
    replay_is_pipe  = false;
    replay_fh       = NULL;
    replay_read_ns  = 0;
    replay_bytes    = 0;
    replay_start_ns = replay_now_ns();

    const char* cmd = NULL;
    for (size_t i = 0; i < sizeof(REPLAY_CODECS) / sizeof(REPLAY_CODECS[0]); i++) {
        if (!replay_ends_with(path, REPLAY_CODECS[i].ext)) {
            continue;
        }
        for (int c = 0; REPLAY_CODECS[i].cmds[c] != NULL; c++) {
            if (replay_have_cmd(REPLAY_CODECS[i].cmds[c])) {
                cmd = REPLAY_CODECS[i].cmds[c];
                if (c > 0) {
                    /* Whether single-threaded decompression actually limits the run depends
                     * on the cell's sample rate and how hard the decoder is working, which
                     * this cannot know in advance. So say what was picked and let the
                     * teardown report which side was the limiter. */
                    printf("REPLAY: %s not found; using %s (single-threaded). The teardown "
                           "reports whether it limited the run.\n",
                           REPLAY_CODECS[i].cmds[0], cmd);
                }
                break;
            }
        }
        if (cmd == NULL) {
            fprintf(stderr, "REPLAY: ERROR: %s is compressed but no decompressor for '%s' "
                            "is on PATH (looked for %s)\n",
                    path, REPLAY_CODECS[i].ext, REPLAY_CODECS[i].cmds[0]);
            return false;
        }
        break;
    }

    if (cmd == NULL) {
        replay_fh = fopen(path, "rb");
        if (replay_fh == NULL) {
            fprintf(stderr, "REPLAY: ERROR: cannot open %s: %s\n", path, strerror(errno));
            return false;
        }
        return true;
    }

    /* Single-quote the path and escape any embedded quote, so a filename with a space or a
     * shell metacharacter cannot turn into a command. */
    char quoted[2048];
    size_t q = 0;
    quoted[q++] = '\'';
    for (const char* c = path; *c != '\0' && q + 4 < sizeof(quoted); c++) {
        if (*c == '\'') {
            q += (size_t)snprintf(quoted + q, sizeof(quoted) - q, "'\\''");
        } else {
            quoted[q++] = *c;
        }
    }
    quoted[q++] = '\'';
    quoted[q]   = '\0';

    char argv[2304];
    snprintf(argv, sizeof(argv), "%s -dc -- %s", cmd, quoted);
    replay_fh = popen(argv, "r");
    if (replay_fh == NULL) {
        fprintf(stderr, "REPLAY: ERROR: cannot start '%s': %s\n", argv, strerror(errno));
        return false;
    }
    replay_is_pipe = true;
    printf("REPLAY: decompressing %s through %s\n", path, cmd);
    return true;
}

/* Forward skip over a payload the caller has decided not to use. fseek() cannot do this on
 * a pipe, and silently doing nothing there would leave the next header read landing inside
 * the IQ samples, from which the stream never recovers. */
static void replay_skip(long nbytes)
{
    if (nbytes <= 0 || replay_fh == NULL) {
        return;
    }
    if (!replay_is_pipe) {
        fseek(replay_fh, nbytes, SEEK_CUR);
        return;
    }
    char   scratch[64 * 1024];
    size_t left = (size_t)nbytes;
    while (left > 0) {
        const size_t want = left < sizeof(scratch) ? left : sizeof(scratch);
        const size_t got  = fread(scratch, 1, want, replay_fh);
        if (got == 0) {
            return; /* EOF or error; the caller's next read reports it */
        }
        left -= got;
    }
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
        
        /* Both bail-outs below have already consumed the frame header, so the payload has to
         * be skipped as well -- otherwise the next header read lands in the middle of the IQ
         * samples and the stream never recovers. */
        if (hdr.nof_samples != nsamples){
            if (debug)
                printf("REPLAY: ERROR: mismatch in number of samples, requested %d but file has %ld\n", nsamples, hdr.nof_samples);
            replay_skip((long)(hdr.nof_samples * sizeof(cf_t)));
            return 0;
        }

        if (hdr.nof_samples > REPLAY_BUF_NOF_SAMPLES){
            fprintf(stderr, "REPLAY: ERROR: frame of %ld samples exceeds the %d sample replay buffer, skipping\n",
                    hdr.nof_samples, REPLAY_BUF_NOF_SAMPLES);
            replay_skip((long)(hdr.nof_samples * sizeof(cf_t)));
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
        n = replay_fread(replay_buf, sizeof(cf_t), hdr.nof_samples);
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
        
        /* Both bail-outs below have already consumed the frame header, so the payload has to
         * be skipped as well -- otherwise the next header read lands in the middle of the IQ
         * samples and the stream never recovers. */
        if (hdr.nof_samples != nsamples){
            if (debug)
                printf("REPLAY: ERROR: mismatch in number of samples, requested %d but file has %ld\n", nsamples, hdr.nof_samples);
            replay_skip((long)(hdr.nof_samples * sizeof(cf_t)));
            return 0;
        }

        if (hdr.nof_samples > REPLAY_BUF_NOF_SAMPLES){
            fprintf(stderr, "REPLAY: ERROR: frame of %ld samples exceeds the %d sample replay buffer, skipping\n",
                    hdr.nof_samples, REPLAY_BUF_NOF_SAMPLES);
            replay_skip((long)(hdr.nof_samples * sizeof(cf_t)));
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
        n = replay_fread(replay_buf, sizeof(cf_t), hdr.nof_samples);
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
        /* pclose() on a popen() stream: fclose() would leak the decompressor as a zombie. */
        const int rc = replay_is_pipe ? pclose(replay_fh) : fclose(replay_fh);
        replay_fh = NULL;
        if (rc < 0)
            return -1;
    }
    if (replay_start_ns != 0 && replay_bytes > 0) {
        const double wall    = (double)(replay_now_ns() - replay_start_ns) / 1e9;
        const double blocked = (double)replay_read_ns / 1e9;
        const double gb      = (double)replay_bytes / 1e9;
        printf("\nREPLAY SOURCE: %.2f GB in %.1f s wall; %.1f s (%.0f%%) blocked reading the\n",
               gb, wall, blocked, wall > 0 ? 100.0 * blocked / wall : 0.0);
        printf("               recording, i.e. %.0f MB/s from the source.\n",
               blocked > 0 ? gb * 1000.0 / blocked : 0.0);
        if (replay_is_pipe) {
            /* The decompressor runs concurrently with the decoder, so it only costs wall
             * time when the decoder is left waiting on it. That is what this fraction is. */
            printf("               %s\n",
                   (wall > 0 && blocked / wall > 0.25)
                       ? "The decompressor was the limiter -- a parallel one (lbzip2) would be faster."
                       : "Decompression kept up: the decoder, not the source, set the pace.");
        }
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
