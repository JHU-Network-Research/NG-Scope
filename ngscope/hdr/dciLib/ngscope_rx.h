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

typedef struct {
    // written before recording starts, gathered from config
    uint32_t nof_rx_antenna;
    double rf_freq;
    uint64_t record_start_ns;

    //populated after the recording is done
    char location[1024];
    char comment[1024];
    uint64_t record_duration_ns;

    uint32_t pci;
    uint32_t prb;
    uint32_t nof_cell_ports;

    srsran_cp_t           cp;
    srsran_phich_length_t phich_length;
    srsran_phich_r_t      phich_resources;
    srsran_frame_type_t   frame_type;

    uint32_t decoded_frames;
    uint32_t desynced_frames;
    uint32_t skipped_frames;
    uint32_t first_sync_frame;

}rx_record_header_t;

bool init_record(const char* path, uint32_t buf_size_gb, uint32_t nof_ports, double rf_freq);
bool init_replay(const char* path, rx_record_header_t*, uint32_t nof_ports);

/* How many receive channels the decoder has buffers for. Must be set before the first
 * receive in EVERY mode -- live capture has no init of its own -- because it bounds every
 * write through the caller's channel array. */
void ngscope_rx_set_nof_rx_ant(uint32_t n);
// int replay_get_nof_antenna();
int ngscope_recv_samples_wrapper(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t);
int ngscope_recv_samples_wrapper_agc(void* h, cf_t* data_[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t, srsran_agc_t* agc);

// #define ngscope_recv_samples_wrapper(h, data_, nsamples, t) _ngscope_recv_samples_wrapper(__func__, h, data_, nsamples, t)

int stop_record();
int stop_replay();
void flush_record(void *buf);
void flush_thread_cleanup(void *arg);

void update_record_header(rx_record_header_t *hdr);

uint32_t get_rx_read_ctr();
