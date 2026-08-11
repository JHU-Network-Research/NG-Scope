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

#include "srsran/srsran.h"
// #include "record_ring_buffer.h"

#define ONE_GB 1024*1024*1024


typedef struct {
  uint64_t nof_samples;
  uint64_t timestamp_full_secs;
  double   timestamp_frac_secs;
}rx_frame_header_t;

bool init_record(const char* path, uint32_t buf_size_gb);
bool init_replay(const char* path);
int ngscope_recv_samples_wrapper(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t);
int ngscope_recv_samples_wrapper_agc(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t, srsran_agc_t* agc, srsran_ue_sync_state_t state);

// #define ngscope_recv_samples_wrapper(h, data_, nsamples, t) _ngscope_recv_samples_wrapper(__func__, h, data_, nsamples, t)

int stop_record();
int stop_replay();
void flush_record(void *buf);
void flush_thread_cleanup(void *arg);
