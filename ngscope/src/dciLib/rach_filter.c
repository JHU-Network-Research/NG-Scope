#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "ngscope/hdr/dciLib/rach_filter.h"
#include "ngscope/hdr/dciLib/ngscope_def.h"

extern bool debug;

typedef struct {
    bool     seen[65536];
    uint32_t first_tti[65536];
    int      nof_rnti;

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
    return ngscope_rach_filter_pass(rf, rnti);
}

/* SI-RNTI, P-RNTI and RA-RNTI are not UE identities and never appear in a RAR body, so they
 * are exempt rather than dropped. */
static inline bool is_broadcast_rnti(uint16_t rnti)
{
    return rnti == SRSRAN_SIRNTI || rnti == SRSRAN_PRNTI || SRSRAN_RNTI_ISRAR(rnti);
}

void ngscope_rach_filter_add(int rf_idx, uint16_t rnti, uint32_t tti)
{
    if (!rf_idx_valid(rf_idx) || rnti == 0) {
        return;
    }
    rach_filter_t* q = &rach_filter[rf_idx]; // JH Does this need to be per rf device?

    pthread_mutex_lock(&rach_filter_mutex[rf_idx]);
    if (!q->seen[rnti]) {
        q->seen[rnti]      = true;
        q->first_tti[rnti] = tti;
        q->nof_rnti++;
        if (debug) {
            printf("DEBUG: TTI=%d RACH filter admits rnti=%d (%d known)\n", tti, rnti, q->nof_rnti);
        }
    }
    pthread_mutex_unlock(&rach_filter_mutex[rf_idx]);
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
    printf("RACH filter (cell %d): %d RNTIs admitted, %lu DCIs kept, %lu dropped (%.1f%%)\n",
           rf_idx,
           q->nof_rnti,
           q->nof_passed,
           q->nof_dropped,
           total ? 100.0 * (double)q->nof_dropped / (double)total : 0.0);
    pthread_mutex_unlock(&rach_filter_mutex[rf_idx]);
}
