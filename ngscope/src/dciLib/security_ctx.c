#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "ngscope/hdr/dciLib/security_ctx.h"
#include "ngscope/hdr/dciLib/mac_pcap.h"
#include "ngscope/hdr/dciLib/ngscope_def.h"
#include "srsran/srsran.h"
#include <inttypes.h>

extern bool debug;

/* How long after its RAR an RNTI stays worth attempting an RRC decode for.
 *
 * This bounds *work*, not semantics: expiring an RNTI stops the decode attempts, it never
 * turns an UNKNOWN into a PRE or a POST. RRC setup plus security activation is a couple of
 * round trips to the core, so ten seconds is generous. */
#define SEC_TRACK_WINDOW_US (10 * 1000000ULL)

typedef struct {
    bool     anchored;      /* a RAR was seen for this RNTI */
    uint64_t rar_us;
    uint32_t rar_tti;
    /* Radio-domain time of the same instant. ts_us is host wall-clock taken when a decoder
     * thread picked the subframe up, so in replay it advances at decode speed, not capture
     * speed -- bucketing a run by it silently distorts any rate over time. */
    uint64_t rar_ct;
} sec_rnti_t;

/* Cap on UEs tracked concurrently. Only a backstop against a pathological cell, so it must
 * sit well above real load: at 64 it was not a backstop but a binding limit. Measured on a
 * 300 s band 12 capture, RACH arrivals averaged 3.9/s, which over the 10 s tracking window
 * is ~39 concurrent -- but the busiest 10 s window held 107, so bursts were evicting UEs
 * mid-setup and they could never yield a SecurityModeCommand.
 *
 * Costs 2 bytes per slot per device and nothing per subframe: ngscope_sec_tracked() already
 * walks the whole list to prune it, and how many are actually scanned is capped separately
 * by the caller. Evictions are counted, so a cell that outgrows even this says so. */
#define SEC_MAX_ACTIVE 512

typedef struct {
    sec_rnti_t rnti[65536];

    /* Explicit list of who is currently in setup. The per-RNTI state above is a flat array
     * for O(1) lookup, but it must never be *scanned*: ngscope_sec_tracked() runs on every
     * subframe of every decoder thread, and walking 65536 entries there under a mutex is
     * enough to push replay several times slower than real time. */
    uint16_t   active[SEC_MAX_ACTIVE];
    int        nof_active;
    uint64_t   nof_rar;
    uint64_t   nof_attempt;
    uint64_t   nof_pdsch_ok;

    /* Silent losses. Both drop a UE that was mid-setup, which is indistinguishable in the
     * output from a UE that genuinely never reached security -- so they have to be counted,
     * or the detection rate cannot be read as a property of the cell. */
    uint64_t   nof_evicted;      /* dropped from active[] because it was full */
    uint64_t   nof_not_scanned;  /* tracked, but past the caller's per-subframe scan cap */
    uint64_t   nof_tracked_calls;
    int        max_active_seen;  /* high-water mark of concurrent tracked UEs */

    /* Why entries left active[]. have_smc is the successful exit; window is the honest
     * timeout. backwards is neither: it means a decoder thread working on an older subframe
     * than the one that anchored the RAR dropped a UE that had only just arrived. */
    uint64_t   nof_exp_window;
    uint64_t   nof_exp_backwards;

    /* Which MCS->TBS table the cell's transport blocks actually needed. nof_tb_retried is the
     * measurement: blocks that only passed CRC on the table enable_256qam did not select. */
    uint64_t   nof_tb_decoded;
    uint64_t   nof_tb_retried;
    uint64_t   nof_tb_retry_tried;

} sec_ctx_t;

static sec_ctx_t       sec_ctx[MAX_NOF_RF_DEV];
static pthread_mutex_t sec_mutex[MAX_NOF_RF_DEV] = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
};

static inline bool rf_idx_valid(int rf_idx)
{
    return rf_idx >= 0 && rf_idx < MAX_NOF_RF_DEV;
}

bool ngscope_sec_is_unicast(uint16_t rnti)
{
    if (rnti == 0 || rnti == SRSRAN_SIRNTI || rnti == SRSRAN_PRNTI) {
        return false;
    }
    return !SRSRAN_RNTI_ISRAR(rnti);
}

void ngscope_sec_note_rar(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
                          uint64_t collection_time)
{
    if (!rf_idx_valid(rf_idx) || !ngscope_sec_is_unicast(rnti)) {
        return;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];

    pthread_mutex_lock(&sec_mutex[rf_idx]);
    /* Deliberately unconditional: a RAR re-arms the identity. The RACH filter keeps only
     * the first sighting, which is right for a membership test but wrong here -- an RNTI
     * handed out again later belongs to a different UE with a different boundary. */
    memset(&q->rnti[rnti], 0, sizeof(sec_rnti_t));
    q->rnti[rnti].anchored = true;
    q->rnti[rnti].rar_us   = ts_us;
    q->rnti[rnti].rar_tti  = tti;
    q->rnti[rnti].rar_ct   = collection_time;
    q->nof_rar++;

    bool listed = false;
    for (int i = 0; i < q->nof_active; i++) {
        if (q->active[i] == rnti) {
            listed = true;
            break;
        }
    }
    if (!listed) {
        if (q->nof_active < SEC_MAX_ACTIVE) {
            q->active[q->nof_active++] = rnti;
        } else {
            /* Full: drop whoever has been in setup longest, since they are the least
             * likely to still yield a SecurityModeCommand. Counted, because the dropped UE
             * then looks exactly like one that never reached security. */
            int oldest = 0;
            for (int i = 1; i < SEC_MAX_ACTIVE; i++) {
                if (q->rnti[q->active[i]].rar_us < q->rnti[q->active[oldest]].rar_us) {
                    oldest = i;
                }
            }
            q->active[oldest] = rnti;
            q->nof_evicted++;
        }
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}

int ngscope_sec_tracked(int rf_idx, uint64_t now_us, uint16_t* out, int max_out)
{
    if (!rf_idx_valid(rf_idx) || out == NULL || max_out <= 0) {
        return 0;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];
    int        n = 0;

    pthread_mutex_lock(&sec_mutex[rf_idx]);
    for (int i = 0; i < q->nof_active;) {
        const uint16_t    rnti = q->active[i];
        const sec_rnti_t* r    = &q->rnti[rnti];

        /* The window is now the only exit. There used to be a second one -- a UE left as
         * soon as its SecurityModeCommand was decoded -- but nothing in this process reads
         * the payload any more, so every anchored UE is scanned for its full window. That
         * costs decode time, not slots: the window already dominated the tracked-set size
         * (high-water 64 of 512 on the busiest capture, against ~61 predicted by RAR
         * arrival rate x window alone), and the SMC exit was taken via note_smc rather than
         * here, so nof_exp_smc always read 0.
         *
         * now_us is the timestamp of the subframe the calling decoder thread happens to be
         * working on, and threads run subframes out of order -- so it can sit behind a RAR
         * anchored moments ago by a thread that was ahead. That must not expire anything: an
         * entry newer than the current subframe cannot have exceeded the window. It used to,
         * because the guard against unsigned underflow in the subtraction below was written
         * as an expiry condition, and removal from active[] is permanent until the next RAR.
         * Measured over 60 s: 117 of 221 tracking exits were this, against 104 real timeouts. */
        const bool behind     = now_us < r->rar_us;
        const bool exp_window = !behind && r->anchored &&
                                (now_us - r->rar_us) > SEC_TRACK_WINDOW_US;
        bool expired = !r->anchored || exp_window;
        if (behind && !expired) {
            q->nof_exp_backwards++;   /* counted as an averted drop, not an exit */
        }
        if (expired) {
            if (exp_window) q->nof_exp_window++;
            q->active[i] = q->active[--q->nof_active];
            continue;
        }
        if (n < max_out) {
            out[n++] = rnti;
        } else {
            /* Tracked but not scanned this subframe. ngscope_sec_tracked() emits in array
             * order, so with more tracked UEs than the caller's cap it is the same ones
             * that miss out every subframe, not a rotating sample. */
            q->nof_not_scanned++;
        }
        i++;
    }
    if (q->nof_active > q->max_active_seen) {
        q->max_active_seen = q->nof_active;
    }
    q->nof_tracked_calls++;
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
    return n;
}

void ngscope_sec_count_attempt(int rf_idx, bool pdsch_ok)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];
    pthread_mutex_lock(&sec_mutex[rf_idx]);
    q->nof_attempt++;
    if (pdsch_ok) {
        q->nof_pdsch_ok++;
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}

void ngscope_sec_count_tb_table(int rf_idx, bool retried)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    pthread_mutex_lock(&sec_mutex[rf_idx]);
    sec_ctx[rf_idx].nof_tb_decoded++;
    if (retried) {
        sec_ctx[rf_idx].nof_tb_retried++;
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}

void ngscope_sec_count_tb_retry(int rf_idx)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    pthread_mutex_lock(&sec_mutex[rf_idx]);
    sec_ctx[rf_idx].nof_tb_retry_tried++;
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}

/* Coverage, not conclusions.
 *
 * Everything here is a property of the decoder, and every line is a validity condition for
 * whatever tools/security_scan.py concludes from the pcap: a UE dropped by a cap or a busy
 * decoder is indistinguishable in that capture from a UE that never reached security. The
 * detection rate itself is printed by the offline tool, which is the only thing that reads
 * the payloads. */
void ngscope_sec_report(int rf_idx)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];

    pthread_mutex_lock(&sec_mutex[rf_idx]);
    int anchored = 0;
    for (int rnti = 1; rnti < 65536; rnti++) {
        if (q->rnti[rnti].anchored) {
            anchored++;
        }
    }

    printf("SECURITY (cell %d): %d RNTIs anchored by a RAR. PDSCH attempts %llu, decoded "
           "%llu (%.1f%%) -- written to the MAC pcap; run tools/security_scan.py over it "
           "for the detection rate.\n",
           rf_idx,
           anchored,
           (unsigned long long)q->nof_attempt,
           (unsigned long long)q->nof_pdsch_ok,
           q->nof_attempt ? 100.0 * q->nof_pdsch_ok / q->nof_attempt : 0.0);

    /* A UE dropped by either of these is indistinguishable in the pcap from one that
     * genuinely never reached security, so the offline rate can only be read as a property
     * of the cell to the extent that both are zero. */
    printf("SECURITY (cell %d): tracking high-water %d of %d slots", rf_idx, q->max_active_seen,
           SEC_MAX_ACTIVE);
    if (q->nof_evicted > 0) {
        printf(", %llu EVICTED mid-setup (raise SEC_MAX_ACTIVE)", (unsigned long long)q->nof_evicted);
    }
    if (q->nof_not_scanned > 0 && q->nof_tracked_calls > 0) {
        printf(", %llu tracked-but-unscanned over %llu subframes (%.1f per subframe -- raise the "
               "caller's scan cap)",
               (unsigned long long)q->nof_not_scanned,
               (unsigned long long)q->nof_tracked_calls,
               (double)q->nof_not_scanned / (double)q->nof_tracked_calls);
    }
    if (q->nof_evicted == 0 && q->nof_not_scanned == 0) {
        printf(", no UE dropped for want of a slot");
    }
    printf("\n");
    printf("SECURITY (cell %d): tracking exits -- %llu on the %d s window; %llu drops averted "
           "where a decoder thread was behind the RAR\n",
           rf_idx,
           (unsigned long long)q->nof_exp_window,
           (int)(SEC_TRACK_WINDOW_US / 1000000ULL),
           (unsigned long long)q->nof_exp_backwards);

    /* Which MCS->TBS table the traffic actually used -- a decode measurement, so it stays
     * here rather than moving offline. A block either passes its CRC on a table or it does
     * not. */
    if (q->nof_tb_decoded > 0) {
        printf("SECURITY (cell %d): MCS->TBS table -- %llu transport blocks decoded, %llu of them "
               "(%.1f%%) only after falling back to the other table",
               rf_idx,
               (unsigned long long)q->nof_tb_decoded,
               (unsigned long long)q->nof_tb_retried,
               100.0 * (double)q->nof_tb_retried / (double)q->nof_tb_decoded);
        if (q->nof_tb_retried == 0 && q->nof_tb_retry_tried > 0) {
            printf(" -- %llu failures were retried and none were rescued, so the configured "
                   "enable_256qam fits this cell",
                   (unsigned long long)q->nof_tb_retry_tried);
        } else if (q->nof_tb_retry_tried == 0) {
            printf(" -- no retry ran (qam_retry off, or live capture), so the table is untested");
        }
        printf("\n");
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}
