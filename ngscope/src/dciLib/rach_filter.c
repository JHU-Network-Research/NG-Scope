#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "ngscope/hdr/dciLib/rach_filter.h"
#include "ngscope/hdr/dciLib/ngscope_def.h"

extern bool debug;

typedef struct {
    bool     seen[65536];
    uint32_t first_tti[65536];
    uint8_t  anchor[65536];   /* ngscope_rach_anchor_t: how this RNTI was admitted */
    int      nof_rnti;
    int      nof_rnti_crc;    /* of those, admitted by a DL-SCH CRC rather than a RAR */

    // statistics, only meaningful when the filter is actually applied
    uint64_t nof_passed;
    uint64_t nof_dropped;
} rach_filter_t;

static rach_filter_t   rach_filter[MAX_NOF_RF_DEV];
static pthread_mutex_t rach_filter_mutex[MAX_NOF_RF_DEV] = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
};

static inline bool rf_idx_valid(int rf_idx)
{
    return rf_idx >= 0 && rf_idx < MAX_NOF_RF_DEV;
}

/* Which device the calling thread decodes for, and whether that device asked for filtering.
 *
 * srsran_ngscope_search_in_space_yx() consults the filter per PDCCH candidate, deep inside
 * libsrsran_phy, where there is no rf_idx and no config in scope -- so the call site used to
 * hardcode rf_idx 0 and apply the filter unconditionally. That was wrong twice over: cells
 * 1..3 were filtered against cell 0's RNTI set, and with rach_filter_only off the search
 * still dropped every unicast DCI whose RNTI had not been seen in a RAR (with decode_RAR off
 * the set is empty, so that meant essentially all of them).
 *
 * A decoder thread serves exactly one RF device for its whole life, so binding the device to
 * the thread carries the missing context at the cost of one TLS load per candidate. Unbound
 * (-1) means "do not filter", which is what cellscanner, cellinspector and the tests want --
 * srsran_phy links this object unconditionally, so they resolve the symbol too. */
static __thread int  bound_rf_idx = -1;
static bool          filter_active[MAX_NOF_RF_DEV];

/* Let the PDCCH search report RNTIs the filter has not admitted yet, while the filter still
 * applies to everything downstream.
 *
 * The filter has two jobs that used to be one. Downstream, ngscope_rach_filter_apply() keeps
 * manufactured RNTIs out of the reported DCIs -- 6,369 of them in 60 s against 188 real, so
 * that job is not optional. Inside the search it also suppresses the candidate entirely,
 * which is cheaper but means an RNTI the filter does not know can never be *examined*, and a
 * UE that handed in to this cell has no RAR here by construction.
 *
 * The blind-DCI probe exists to adjudicate exactly those: it decodes the transport block and
 * uses the DL-SCH CRC24A, which is not RNTI-seeded while PDSCH descrambling is, so a pass
 * proves the (RNTI, grant) pair real. It cannot adjudicate what it never sees. Bypassing the
 * search-level suppression when the probe is on hands it the population it was written to
 * measure; the downstream filter is untouched, so nothing unproven reaches the output. */
static bool          search_bypass[MAX_NOF_RF_DEV];

void ngscope_rach_filter_set_search_bypass(int rf_idx, bool bypass)
{
    if (rf_idx_valid(rf_idx)) {
        search_bypass[rf_idx] = bypass;
    }
}

void ngscope_rach_filter_bind_thread(int rf_idx)
{
    bound_rf_idx = rf_idx_valid(rf_idx) ? rf_idx : -1;
}

void ngscope_rach_filter_set_active(int rf_idx, bool active)
{
    if (rf_idx_valid(rf_idx)) {
        filter_active[rf_idx] = active;
    }
}

bool ngscope_rach_filter_pass_bound(uint16_t rnti)
{
    const int rf = bound_rf_idx;
    if (rf < 0) {
        return true; /* unbound thread: no filtering */
    }
    if (!filter_active[rf]) {
        return true; /* this device did not ask for it */
    }
    if (search_bypass[rf]) {
        return true; /* the probe adjudicates; ngscope_rach_filter_apply() still filters */
    }
    return ngscope_rach_filter_pass(rf, rnti);
}

/* SI-RNTI, P-RNTI and RA-RNTI are not UE identities and never appear in a RAR body, so they
 * are exempt rather than dropped. */
static inline bool is_broadcast_rnti(uint16_t rnti)
{
    return rnti == SRSRAN_SIRNTI || rnti == SRSRAN_PRNTI || SRSRAN_RNTI_ISRAR(rnti);
}

void ngscope_rach_filter_add(int rf_idx, uint16_t rnti, uint32_t tti, int anchor)
{
    if (!rf_idx_valid(rf_idx) || rnti == 0) {
        return;
    }
    rach_filter_t* q = &rach_filter[rf_idx]; // JH Does this need to be per rf device?

    pthread_mutex_lock(&rach_filter_mutex[rf_idx]);
    if (!q->seen[rnti]) {
        q->seen[rnti]      = true;
        q->first_tti[rnti] = tti;
        q->anchor[rnti]    = (uint8_t)anchor;
        q->nof_rnti++;
        if (anchor == NGSCOPE_RACH_ANCHOR_CRC) {
            q->nof_rnti_crc++;
        }
        if (debug) {
            printf("DEBUG: TTI=%d RACH filter admits rnti=%d anchor=%d (%d known)\n",
                   tti, rnti, anchor, q->nof_rnti);
        }
    } else if (anchor == NGSCOPE_RACH_ANCHOR_RAR &&
               q->anchor[rnti] != NGSCOPE_RACH_ANCHOR_RAR) {
        /* Upgrade only. A UE confirmed by its traffic and then seen RACHing is a UE that
         * started here; the reverse is not an event, so a CRC never overwrites a RAR. */
        q->anchor[rnti] = NGSCOPE_RACH_ANCHOR_RAR;
        if (q->nof_rnti_crc > 0) {
            q->nof_rnti_crc--;
        }
    }
    pthread_mutex_unlock(&rach_filter_mutex[rf_idx]);
}

int ngscope_rach_filter_anchor(int rf_idx, uint16_t rnti)
{
    if (!rf_idx_valid(rf_idx) || rnti == 0) {
        return NGSCOPE_RACH_ANCHOR_NONE;
    }
    return (int)rach_filter[rf_idx].anchor[rnti];
}

/* ------------------------------------------------------------------ PDCCH order */

static FILE*           pdcch_order_fd[MAX_NOF_RF_DEV];
static pthread_mutex_t pdcch_order_mtx[MAX_NOF_RF_DEV] = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
};
static uint64_t        pdcch_order_count[MAX_NOF_RF_DEV];
static uint64_t        pdcch_order_known[MAX_NOF_RF_DEV];

int ngscope_pdcch_order_init(const char* out_path, int rf_idx)
{
    if (!rf_idx_valid(rf_idx)) {
        return -1;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%spdcch_order-%d.csv", out_path ? out_path : "", rf_idx);
    pdcch_order_fd[rf_idx] = fopen(path, "w");
    if (pdcch_order_fd[rf_idx] == NULL) {
        printf("PDCCH ORDER: could not open %s\n", path);
        return -1;
    }
    /* Header written up front, so a file with only a header means "looked, found none" --
     * the same convention security_scan.py uses, and the distinction matters here: zero
     * ordered RACHes and never having looked imply opposite things about a contention-free
     * RAR. */
    fprintf(pdcch_order_fd[rf_idx], "tti,rnti,preamble_idx,prach_mask_idx,rnti_known\n");
    fflush(pdcch_order_fd[rf_idx]);
    printf("PDCCH ORDER: writing %s\n", path);
    return 0;
}

void ngscope_pdcch_order_note_bound(uint16_t rnti, uint32_t tti, uint32_t preamble_idx,
                                    uint32_t prach_mask_idx)
{
    const int rf = bound_rf_idx;
    if (!rf_idx_valid(rf) || pdcch_order_fd[rf] == NULL) {
        return;
    }
    /* Whether this RNTI is one the cell is known to be serving.
     *
     * The PDCCH-order pattern -- an all-ones RBA field with all remaining bits zero -- is
     * only 1A-shaped, so a false-alarm DCI can match it, and a false alarm carries a
     * manufactured RNTI. A genuine order goes to a UE the cell is actively serving, which is
     * exactly what admission to the filter means. Measured on att_850_office: all 9 orders
     * found went to RNTIs no other path had ever seen, so all 9 were false alarms. Recording
     * the column rather than dropping the row keeps that measurable instead of asserted. */
    const int known = ngscope_rach_filter_pass(rf, rnti) ? 1 : 0;

    pthread_mutex_lock(&pdcch_order_mtx[rf]);
    fprintf(pdcch_order_fd[rf], "%u,%u,%u,%u,%d\n", tti, rnti, preamble_idx, prach_mask_idx,
            known);
    pdcch_order_count[rf]++;
    if (known) {
        pdcch_order_known[rf]++;
    }
    pthread_mutex_unlock(&pdcch_order_mtx[rf]);
}

void ngscope_pdcch_order_report(int rf_idx)
{
    if (!rf_idx_valid(rf_idx) || pdcch_order_fd[rf_idx] == NULL) {
        return;
    }
    printf("PDCCH ORDER (cell %d): %llu random-access orders seen, %llu of them to an RNTI "
           "this cell is known to serve. A contention-free RAR matching one of those was "
           "ordered by the network, not a handover.\n",
           rf_idx,
           (unsigned long long)pdcch_order_count[rf_idx],
           (unsigned long long)pdcch_order_known[rf_idx]);
    if (pdcch_order_count[rf_idx] > 0 && pdcch_order_known[rf_idx] == 0) {
        printf("PDCCH ORDER (cell %d): none went to a known RNTI, so on this run they are "
               "false alarms, not orders\n", rf_idx);
    }
}

void ngscope_pdcch_order_close(int rf_idx)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    pthread_mutex_lock(&pdcch_order_mtx[rf_idx]);
    if (pdcch_order_fd[rf_idx] != NULL) {
        fclose(pdcch_order_fd[rf_idx]);
        pdcch_order_fd[rf_idx] = NULL;
    }
    pthread_mutex_unlock(&pdcch_order_mtx[rf_idx]);
}

// Has the given rnti been seen by the specified rf device?
bool ngscope_rach_filter_pass(int rf_idx, uint16_t rnti)
{
    if (rnti == 0) {
        return false;
    }
    if (is_broadcast_rnti(rnti)) {
        return true;
    }
    if (!rf_idx_valid(rf_idx)) {
        return false;
    }

    pthread_mutex_lock(&rach_filter_mutex[rf_idx]);
    bool pass = rach_filter[rf_idx].seen[rnti];
    pthread_mutex_unlock(&rach_filter_mutex[rf_idx]);
    return pass;
}

// prune DCIs from the given dci_per_sub struct according to the filter for the rf device
int ngscope_rach_filter_apply(int rf_idx, ngscope_dci_per_sub_t* q)
{
    if (q == NULL || !rf_idx_valid(rf_idx)) {
        return 0;
    }
    int dropped = 0;
    int kept    = 0;

    uint32_t n = 0;
    for (uint32_t i = 0; i < q->nof_dl_dci; i++) {
        if (ngscope_rach_filter_pass(rf_idx, q->dl_msg[i].rnti)) {
            if (n != i) {
                q->dl_msg[n] = q->dl_msg[i];
            }
            /* Stamp how this RNTI earned admission, here rather than at the decoder: this is
             * the only place that knows, and it is the last hop before the .dciLog. */
            q->dl_msg[n].anchor = (uint8_t)ngscope_rach_filter_anchor(rf_idx, q->dl_msg[i].rnti);
            n++;
        } else {
            dropped++;
        }
    }
    kept += n;
    q->nof_dl_dci = n;

    n = 0;
    for (uint32_t i = 0; i < q->nof_ul_dci; i++) {
        if (ngscope_rach_filter_pass(rf_idx, q->ul_msg[i].rnti)) {
            if (n != i) {
                q->ul_msg[n] = q->ul_msg[i];
            }
            /* Stamp how this RNTI earned admission, here rather than at the decoder: this is
             * the only place that knows, and it is the last hop before the .dciLog. */
            q->ul_msg[n].anchor = (uint8_t)ngscope_rach_filter_anchor(rf_idx, q->ul_msg[i].rnti);
            n++;
        } else {
            dropped++;
        }
    }
    kept += n;
    q->nof_ul_dci = n;

    pthread_mutex_lock(&rach_filter_mutex[rf_idx]);
    rach_filter[rf_idx].nof_passed += (uint64_t)kept;
    rach_filter[rf_idx].nof_dropped += (uint64_t)dropped;
    pthread_mutex_unlock(&rach_filter_mutex[rf_idx]);

    return dropped;
}

int ngscope_rach_filter_nof_rnti(int rf_idx)
{
    if (!rf_idx_valid(rf_idx)) {
        return 0;
    }
    pthread_mutex_lock(&rach_filter_mutex[rf_idx]);
    int n = rach_filter[rf_idx].nof_rnti;
    pthread_mutex_unlock(&rach_filter_mutex[rf_idx]);
    return n;
}

void ngscope_rach_filter_report(int rf_idx)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    pthread_mutex_lock(&rach_filter_mutex[rf_idx]);
    rach_filter_t* q     = &rach_filter[rf_idx];
    uint64_t       total = q->nof_passed + q->nof_dropped;
    printf("RACH filter (cell %d): %d RNTIs admitted (%d by a RAR, %d by a DL-SCH CRC), "
           "%lu DCIs kept, %lu dropped (%.1f%%)\n",
           rf_idx,
           q->nof_rnti,
           q->nof_rnti - q->nof_rnti_crc,
           q->nof_rnti_crc,
           q->nof_passed,
           q->nof_dropped,
           total ? 100.0 * (double)q->nof_dropped / (double)total : 0.0);
    if (q->nof_rnti_crc > 0) {
        /* These have no RAR on this cell, which is what a UE that handed in -- or was
         * already connected when the capture began -- looks like from the target side. The
         * CRC is what makes them evidence rather than noise. */
        printf("RACH filter (cell %d): the %d CRC-confirmed RNTIs never RACHed here; they "
               "handed in, or were already connected when the capture began\n",
               rf_idx, q->nof_rnti_crc);
    }
    pthread_mutex_unlock(&rach_filter_mutex[rf_idx]);
}
