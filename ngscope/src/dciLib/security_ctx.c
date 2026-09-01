#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "ngscope/hdr/dciLib/security_ctx.h"
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

/* Cap on UEs tracked concurrently. RACH arrivals are a few per second and setup lasts
 * well under a second, so a handful are in flight at once; this only stops a pathological
 * cell from growing the per-subframe work without bound. */
#define SEC_MAX_ACTIVE 64

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
             * likely to still yield a SecurityModeCommand. */
            int oldest = 0;
            for (int i = 1; i < SEC_MAX_ACTIVE; i++) {
                if (q->rnti[q->active[i]].rar_us < q->rnti[q->active[oldest]].rar_us) {
                    oldest = i;
                }
            }
            q->active[oldest] = rnti;
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
        bool expired = !r->anchored || r->have_smc || now_us < r->rar_us ||
                       (now_us - r->rar_us) > SEC_TRACK_WINDOW_US;
        if (expired) {
            q->active[i] = q->active[--q->nof_active];
            continue;
        }
        if (n < max_out) {
            out[n++] = rnti;
        }
        i++;
    }
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
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}
