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

    bool     have_smc;      /* SecurityModeCommand seen: the boundary */
    uint64_t smc_us;
    uint32_t smc_tti;

    /* Latest successfully decoded unciphered RRC message. Anything up to here is provably
     * pre-security even when the SMC itself is never decoded. */
    uint64_t last_clear_us;
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
    uint64_t   nof_smc;
    uint64_t   nof_clear_rrc;
    uint64_t   nof_attempt;
    uint64_t   nof_pdsch_ok;
    uint64_t   nof_rrc_ok;

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
    uint64_t   nof_exp_smc;
    uint64_t   nof_exp_window;
    uint64_t   nof_exp_backwards;
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

const char* ngscope_sec_phase_str(ngscope_sec_phase_t phase)
{
    switch (phase) {
        case NGSCOPE_SEC_PRE:
            return "pre";
        case NGSCOPE_SEC_POST:
            return "post";
        default:
            return "unknown";
    }
}

bool ngscope_sec_is_unicast(uint16_t rnti)
{
    if (rnti == 0 || rnti == SRSRAN_SIRNTI || rnti == SRSRAN_PRNTI) {
        return false;
    }
    return !SRSRAN_RNTI_ISRAR(rnti);
}

void ngscope_sec_note_rar(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us)
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

void ngscope_sec_note_unciphered_rrc(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us)
{
    if (!rf_idx_valid(rf_idx) || !ngscope_sec_is_unicast(rnti)) {
        return;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];

    pthread_mutex_lock(&sec_mutex[rf_idx]);
    if (q->rnti[rnti].anchored && ts_us > q->rnti[rnti].last_clear_us) {
        q->rnti[rnti].last_clear_us = ts_us;
        q->nof_clear_rrc++;
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
    if (debug) {
        printf("DEBUG: TTI=%d rnti=%d unciphered RRC decoded\n", tti, rnti);
    }
}

/* <out_path>/security_log-<rf_idx>.csv -- the boundary per RNTI, joinable to the DCI logs.
 *
 * The .dciLog label can only ever be best-effort for "pre": labels are stamped as each
 * subframe is decoded, but the boundary is not known until the SecurityModeCommand arrives
 * later, so a DCI that precedes it cannot be recognised at the time it is written. This
 * file closes that gap -- join it on rnti and compare timestamps to place every DCI
 * exactly, including the ones written before their boundary was known. */
static void sec_log_write(const char* out_path,
                          int         rf_idx,
                          uint16_t    rnti,
                          uint32_t    rar_tti,
                          uint64_t    rar_us,
                          uint32_t    smc_tti,
                          uint64_t    smc_us)
{
    if (out_path == NULL) {
        return;
    }
    char path[1024];
    snprintf(path, sizeof(path), "%ssecurity_log-%d.csv", out_path, rf_idx);

    /* Header on creation only, so appending across a rotation stays valid CSV. */
    bool  fresh = access(path, F_OK) != 0;
    FILE* f     = fopen(path, "a");
    if (f == NULL) {
        return;
    }
    if (fresh) {
        fprintf(f, "rnti,rar_tti,rar_timestamp,smc_tti,smc_timestamp,rar_to_smc_ms\n");
    }
    fprintf(f,
            "%u,%u,%" PRIu64 ",%u,%" PRIu64 ",%.1f\n",
            rnti,
            rar_tti,
            rar_us,
            smc_tti,
            smc_us,
            (double)(smc_us - rar_us) / 1000.0);
    fclose(f);
}

void ngscope_sec_note_smc(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
                          const char* out_path)
{
    if (!rf_idx_valid(rf_idx) || !ngscope_sec_is_unicast(rnti)) {
        return;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];

    bool     log_it      = false;
    uint32_t log_rar_tti = 0;
    uint64_t log_rar_us  = 0;

    pthread_mutex_lock(&sec_mutex[rf_idx]);
    if (q->rnti[rnti].anchored && !q->rnti[rnti].have_smc) {
        q->rnti[rnti].have_smc = true;
        q->rnti[rnti].smc_us   = ts_us;
        q->rnti[rnti].smc_tti  = tti;
        q->nof_smc++;
        for (int i = 0; i < q->nof_active; i++) {
            if (q->active[i] == rnti) {
                q->active[i] = q->active[--q->nof_active];
                break;
            }
        }
        printf("SECURITY: TTI=%d rnti=%d SecurityModeCommand (RAR was TTI=%d, %.0f ms earlier)\n",
               tti,
               rnti,
               q->rnti[rnti].rar_tti,
               (double)(ts_us - q->rnti[rnti].rar_us) / 1000.0);
        log_rar_tti = q->rnti[rnti].rar_tti;
        log_rar_us  = q->rnti[rnti].rar_us;
        log_it      = true;
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);

    /* Outside the lock: this opens a file. */
    if (log_it) {
        sec_log_write(out_path, rf_idx, rnti, log_rar_tti, log_rar_us, tti, ts_us);
    }
}

/* Strong override of the weak default in mac_pcap.c, so a capture written while the tracker
 * is running carries the real phase instead of a permanent "unknown". Deliberately still
 * answers "unknown" for anything unplaced: the boundary is only ever set by an observed
 * SecurityModeCommand, and most packets are written before theirs arrives. The authoritative
 * labelling comes from joining security_log-<rf_idx>.csv afterwards. */
const char* ngscope_mac_pcap_sec_phase(int rf_idx, uint16_t rnti, uint64_t ts_us)
{
    return ngscope_sec_phase_str(ngscope_sec_phase(rf_idx, rnti, ts_us));
}

ngscope_sec_phase_t ngscope_sec_phase(int rf_idx, uint16_t rnti, uint64_t ts_us)
{
    if (!rf_idx_valid(rf_idx) || !ngscope_sec_is_unicast(rnti)) {
        return NGSCOPE_SEC_UNKNOWN;
    }
    sec_ctx_t*          q     = &sec_ctx[rf_idx];
    ngscope_sec_phase_t phase = NGSCOPE_SEC_UNKNOWN;

    pthread_mutex_lock(&sec_mutex[rf_idx]);
    const sec_rnti_t* r = &q->rnti[rnti];
    if (r->anchored) {
        if (r->have_smc) {
            /* The boundary is known, so every DCI for this identity can be placed.
             *
             * Strictly greater, not >=: the SecurityModeCommand is the last unciphered
             * downlink message, so the DCI carrying it is itself pre-security. Security
             * does not activate until the UE answers with SecurityModeComplete. */
            phase = (ts_us > r->smc_us) ? NGSCOPE_SEC_POST : NGSCOPE_SEC_PRE;
        }
        /* Deliberately no "before the last cleartext RRC we saw" fallback here.
         *
         * It looks sound and it is not, because decoder threads process subframes in
         * parallel and out of order: a clear-RRC sighting from a later subframe can land
         * before an earlier subframe is stamped, and the earlier DCI then gets called pre
         * on evidence that post-dates it. Observed exactly that -- rnti 26131 TTI 1098
         * labelled pre against a boundary at TTI 1094.
         *
         * With the fallback gone the in-stream label is derived only from a fixed smc_us,
         * so it can be incomplete but never wrong. The join against security_log-<n>.csv
         * is what recovers the rest, and it places the full pre population (1196 records
         * against the 138 this path could prove in real time). */
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
    return phase;
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

        /* Expiry stops the decode attempts only. It never converts an UNKNOWN into a
         * label -- the phase still comes from what was actually observed. */
        /* now_us is the timestamp of the subframe the calling decoder thread happens to be
         * working on, and threads run subframes out of order -- so it can sit behind a RAR
         * anchored moments ago by a thread that was ahead. That must not expire anything: an
         * entry newer than the current subframe cannot have exceeded the window. It used to,
         * because the guard against unsigned underflow in the subtraction below was written
         * as an expiry condition, and removal from active[] is permanent until the next RAR.
         * Measured over 60 s: 117 of 221 tracking exits were this, against 104 real timeouts. */
        const bool exp_smc      = r->have_smc;
        const bool behind       = now_us < r->rar_us;
        const bool exp_window   = !exp_smc && !behind && r->anchored &&
                                  (now_us - r->rar_us) > SEC_TRACK_WINDOW_US;
        bool expired = !r->anchored || exp_smc || exp_window;
        if (behind && !expired) {
            q->nof_exp_backwards++;   /* counted as an averted drop, not an exit */
        }
        if (expired) {
            if (exp_smc)         q->nof_exp_smc++;
            else if (exp_window) q->nof_exp_window++;
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

void ngscope_sec_count_attempt(int rf_idx, bool pdsch_ok, bool rrc_ok)
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
    if (rrc_ok) {
        q->nof_rrc_ok++;
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}

void ngscope_sec_report(int rf_idx)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];

    pthread_mutex_lock(&sec_mutex[rf_idx]);
    int anchored = 0, bounded = 0;
    for (int rnti = 1; rnti < 65536; rnti++) {
        if (q->rnti[rnti].anchored) {
            anchored++;
            if (q->rnti[rnti].have_smc) {
                bounded++;
            }
        }
    }
    printf("SECURITY (cell %d): %d RNTIs anchored by a RAR, %d with a SecurityModeCommand "
           "(%.1f%%). PDSCH attempts %llu, decoded %llu (%.1f%%), RRC unpacked %llu (%.1f%%).\n",
           rf_idx,
           anchored,
           bounded,
           anchored ? 100.0 * bounded / anchored : 0.0,
           (unsigned long long)q->nof_attempt,
           (unsigned long long)q->nof_pdsch_ok,
           q->nof_attempt ? 100.0 * q->nof_pdsch_ok / q->nof_attempt : 0.0,
           (unsigned long long)q->nof_rrc_ok,
           q->nof_attempt ? 100.0 * q->nof_rrc_ok / q->nof_attempt : 0.0);

    /* Coverage. A UE dropped by either of these is indistinguishable in the output from one
     * that genuinely never reached security, so the detection rate above can only be read as
     * a property of the cell to the extent that both are zero. */
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
    printf("SECURITY (cell %d): tracking exits -- %llu on SecurityModeCommand, %llu on the %d s "
           "window; %llu drops averted where a decoder thread was behind the RAR\n",
           rf_idx,
           (unsigned long long)q->nof_exp_smc,
           (unsigned long long)q->nof_exp_window,
           (int)(SEC_TRACK_WINDOW_US / 1000000ULL),
           (unsigned long long)q->nof_exp_backwards);
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}
