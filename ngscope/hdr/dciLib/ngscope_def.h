#ifndef NGSCOPE_DEF_H
#define NGSCOPE_DEF_H

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

#ifdef __cplusplus
extern "C" {
#endif

#include "srsran/srsran.h"

#define MAX_NOF_DCI_DECODER 8
#define MAX_NOF_RF_DEV 4

/* tracked_search: how ngscope_sec_scan_subframe() finds each tracked UE's DCIs (replay only;
 * live and record always use PER_RNTI). All three return identical DCIs -- see
 * docs/configuration.md. */
#define NGSCOPE_TRACKED_SEARCH_PER_RNTI    0 /* srsRAN's per-RNTI search, every decode fresh  */
#define NGSCOPE_TRACKED_SEARCH_CACHE       1 /* same search, candidate decodes memoized       */
#define NGSCOPE_TRACKED_SEARCH_SOLVE_FIRST 2 /* decode all candidates once, search only RNTIs
                                                that came out; implies CACHE                  */
/* rx_combine: how the decoder combines receive antennas (srsran_ue_dl_set_rx_irc / _noise_weighting).
 * Any mode; inert with one antenna. */
#define NGSCOPE_RX_COMBINE_OFF    0 /* srsRAN's gain-only combining, unchanged          */
#define NGSCOPE_RX_COMBINE_WEIGHT 1 /* per-antenna noise weighting (MRC)                */
#define NGSCOPE_RX_COMBINE_IRC    2 /* interference-rejection combining, 2 antennas;
                                       noise weighting where it does not apply          */
#define NOF_LOG_SF 32

//#define NOF_LOG_SUBF (NOF_LOG_SF * 10)

// the buffer size of the cell status tracker 32-SFN 
#define CELL_STATUS_RING_BUF_SIZE 320 

// the buffer size of the DCI-logger 32-SFN 
#define DCI_LOGGER_RING_BUF_SIZE 320 

#define MAX_MSG_PER_SUBF 10

#define MAX_DCI_BUFFER 30

#define PLOT_SF 10

#define MAX_TTI 10240

//#define TTI_TO_IDX(i) (i%NOF_LOG_SUBF)

#define DCI_DECODE_TIMEOUT 30

/*     LOGGING Related  */
#define LOG_DCI_RING_BUFFER
#define LOG_DCI_LOGGER

typedef struct{
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    int             nof_dci;
    int             header;
}dci_ready_t;

/* Wait, with q->mutex held, until q has DCIs or *exit_flag is set. True when there are DCIs to
 * take; false means shutting down with nothing pending, and the caller should unlock and leave.
 *
 * The status tracker, cell status and DCI logger threads used to wait on the bare condition,
 * which only a decoder producing a DCI ever signals. A run that never decoded a subframe -- a
 * replay whose cell cannot synchronise, say -- left all three asleep after go_exit, and main's
 * join on the tracker kept the process alive forever. The timed wait polls the flag instead
 * of signalling from the SIGINT handler, where pthread calls are not async-signal-safe. */
static inline bool ngscope_dci_ready_wait(dci_ready_t* q, const bool* exit_flag)
{
    while (q->nof_dci <= 0) {
        if (*exit_flag) {
            return false;
        }
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_nsec += 100 * 1000 * 1000;
        if (until.tv_nsec >= 1000000000L) {
            until.tv_sec++;
            until.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&q->cond, &q->mutex, &until);
    }
    return true;
}

typedef struct {
    ngscope_dci_per_sub_t   dci_per_sub;
    //float                   csi_amp[100 * 12];
    uint32_t                tti;
    uint16_t                cell_idx;
}ngscope_status_buffer_t;

#ifdef __cplusplus
}
#endif
#endif
