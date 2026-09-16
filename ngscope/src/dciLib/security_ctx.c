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
    /* Anchored by a passing DL-SCH CRC rather than by a RAR on this cell: a UE that handed
     * in, or one already connected when the capture began. */
    bool     crc_only;
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

#define SEC_NOF_FORMATS NGSCOPE_SEC_NOF_FORMATS
#define SEC_NOF_SCHEMES NGSCOPE_SEC_NOF_SCHEMES

typedef struct {
    sec_rnti_t rnti[65536];

    /* Explicit list of who is currently in setup. The per-RNTI state above is a flat array
     * for O(1) lookup, but it must never be *scanned*: ngscope_sec_tracked() runs on every
     * subframe of every decoder thread, and walking 65536 entries there under a mutex is
     * enough to push replay several times slower than real time. */
    uint16_t   active[SEC_MAX_ACTIVE];
    int        nof_active;
    uint64_t   nof_rar;
    uint64_t   nof_crc_confirmed;  /* tracked without a RAR, on a passing DL-SCH CRC */
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

    /* What the targeted search actually looked at. nof_scan_no_dci was a bare `continue`
     * before there was anywhere to count it. */
    uint64_t   nof_scan_rnti;
    uint64_t   nof_scan_no_dci;

    /* Per DCI format, so a coverage claim can be checked rather than asserted -- in
     * particular whether widening the search past {1A, 2} finds anything. Indexed by
     * srsran_dci_format_t; SEC_NOF_FORMATS is SRSRAN_DCI_NOF_FORMATS, restated here because
     * this file must not include srsran.h (see security_ctx.h). */
    uint64_t   nof_dci_fmt[SEC_NOF_FORMATS];
    uint64_t   nof_attempt_fmt[SEC_NOF_FORMATS];
    uint64_t   nof_crc_pass_fmt[SEC_NOF_FORMATS];

    /* Per transmission scheme, and why a decode did not land. A grant srsRAN has no
     * predecoder for on this cell is not the same observation as one the channel beat. */
    uint64_t   nof_scheme[SEC_NOF_SCHEMES];
    uint64_t   nof_scheme_unsupported;
    uint64_t   nof_predecode_err;
    uint64_t   nof_crc_fail;

    uint32_t   cell_nof_ports;
    uint32_t   cell_nof_rxant;

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

/* See the header. Same tracked-set insertion as a RAR, with a weaker claim attached. */
void ngscope_sec_note_crc_confirmed(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
                                    uint64_t collection_time)
{
    if (!rf_idx_valid(rf_idx) || !ngscope_sec_is_unicast(rnti)) {
        return;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];

    pthread_mutex_lock(&sec_mutex[rf_idx]);
    if (q->rnti[rnti].anchored) {
        /* Already anchored -- by a RAR, or by an earlier confirmation. Leave it: a RAR is the
         * stronger claim and carries the TTI the offline tool joins sessions on, and
         * re-arming on every decoded block would reset the tracking window forever. */
        pthread_mutex_unlock(&sec_mutex[rf_idx]);
        return;
    }

    memset(&q->rnti[rnti], 0, sizeof(sec_rnti_t));
    q->rnti[rnti].anchored = true;
    q->rnti[rnti].crc_only = true;
    q->rnti[rnti].rar_us   = ts_us;
    q->rnti[rnti].rar_tti  = tti;
    q->rnti[rnti].rar_ct   = collection_time;
    q->nof_crc_confirmed++;

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

void ngscope_sec_set_cell(int rf_idx, uint32_t nof_ports, uint32_t nof_rxant)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    pthread_mutex_lock(&sec_mutex[rf_idx]);
    sec_ctx[rf_idx].cell_nof_ports = nof_ports;
    sec_ctx[rf_idx].cell_nof_rxant = nof_rxant;
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}

void ngscope_sec_count_scan(int rf_idx, int nof_searched, int nof_without_dci)
{
    if (!rf_idx_valid(rf_idx) || nof_searched <= 0) {
        return;
    }
    pthread_mutex_lock(&sec_mutex[rf_idx]);
    sec_ctx[rf_idx].nof_scan_rnti   += (uint64_t)nof_searched;
    sec_ctx[rf_idx].nof_scan_no_dci += (uint64_t)(nof_without_dci > 0 ? nof_without_dci : 0);
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}

void ngscope_sec_count_dci(int rf_idx, int fmt)
{
    if (!rf_idx_valid(rf_idx) || fmt < 0 || fmt >= SEC_NOF_FORMATS) {
        return;
    }
    pthread_mutex_lock(&sec_mutex[rf_idx]);
    sec_ctx[rf_idx].nof_dci_fmt[fmt]++;
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}

void ngscope_sec_count_grant(int rf_idx, int fmt, int scheme, int outcome)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    sec_ctx_t* q = &sec_ctx[rf_idx];
    pthread_mutex_lock(&sec_mutex[rf_idx]);
    if (fmt >= 0 && fmt < SEC_NOF_FORMATS) {
        q->nof_attempt_fmt[fmt]++;
        if (outcome == NGSCOPE_SEC_GRANT_CRC_PASS) {
            q->nof_crc_pass_fmt[fmt]++;
        }
    }
    if (scheme >= 0 && scheme < SEC_NOF_SCHEMES) {
        q->nof_scheme[scheme]++;
    }
    switch (outcome) {
        case NGSCOPE_SEC_GRANT_CRC_FAIL:      q->nof_crc_fail++;           break;
        case NGSCOPE_SEC_GRANT_PREDECODE_ERR: q->nof_predecode_err++;      break;
        case NGSCOPE_SEC_GRANT_UNSUPPORTED:   q->nof_scheme_unsupported++; break;
        default: break;
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

/* Names for the srsran_dci_format_t domain. Restated rather than calling
 * srsran_dci_format_string(), because this file deliberately does not include srsran.h. */
static const char* sec_format_name(int f)
{
    static const char* n[SEC_NOF_FORMATS] = {"0",  "1",  "1A", "1B", "1C", "1D", "2",
                                             "2A", "2B", "N0", "N1", "N2", "RAR"};
    return (f >= 0 && f < SEC_NOF_FORMATS) ? n[f] : "?";
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
    /* Distinct identities, not events: nof_rar counts every RAR including the re-arms of an
     * RNTI handed out twice, so it is the wrong numerator for "how many UEs". */
    int anchored = 0, anchored_crc = 0;
    for (int rnti = 1; rnti < 65536; rnti++) {
        if (q->rnti[rnti].anchored) {
            anchored++;
            if (q->rnti[rnti].crc_only) {
                anchored_crc++;
            }
        }
    }

    printf("SECURITY (cell %d): %d RNTIs tracked (%llu anchored by a RAR, %llu by a passing "
           "DL-SCH CRC with no RAR on this cell -- handed in, or already connected). PDSCH "
           "attempts %llu, decoded %llu (%.1f%%) -- written to the MAC pcap; run "
           "tools/security_scan.py over it for the detection rate.\n",
           rf_idx,
           anchored,
           (unsigned long long)(anchored - anchored_crc),
           (unsigned long long)anchored_crc,
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

    /* How much of the cell the targeted search actually looked at.
     *
     * Read the change between runs, not the level: most tracked UEs have no grant in a given
     * subframe, so a high no-DCI share is normal and this is an upper bound on loss, never a
     * loss figure. What it is good for is telling whether widening the searched format set
     * found anything -- which the per-format table below answers directly. */
    if (q->nof_scan_rnti > 0) {
        printf("SECURITY (cell %d): targeted search -- %llu (rnti, subframe) searched, %llu found "
               "no DCI (%.1f%%). Upper bound on loss, not a loss figure: most tracked UEs simply "
               "have no grant in a given subframe.\n",
               rf_idx,
               (unsigned long long)q->nof_scan_rnti,
               (unsigned long long)q->nof_scan_no_dci,
               100.0 * (double)q->nof_scan_no_dci / (double)q->nof_scan_rnti);
    }

    uint64_t sum_att = 0, sum_pass = 0;
    for (int f = 0; f < SEC_NOF_FORMATS; f++) {
        sum_att  += q->nof_attempt_fmt[f];
        sum_pass += q->nof_crc_pass_fmt[f];
    }
    if (sum_att > 0) {
        printf("SECURITY (cell %d): DCI by format --", rf_idx);
        for (int f = 0; f < SEC_NOF_FORMATS; f++) {
            if (q->nof_dci_fmt[f] == 0 && q->nof_attempt_fmt[f] == 0) {
                continue;
            }
            printf(" %s %llu found/%llu built/%llu CRC (%.1f%%);",
                   sec_format_name(f),
                   (unsigned long long)q->nof_dci_fmt[f],
                   (unsigned long long)q->nof_attempt_fmt[f],
                   (unsigned long long)q->nof_crc_pass_fmt[f],
                   q->nof_attempt_fmt[f]
                       ? 100.0 * (double)q->nof_crc_pass_fmt[f] / (double)q->nof_attempt_fmt[f]
                       : 0.0);
        }
        printf("\n");

        /* A counter that does not reconcile with the totals it is supposed to decompose is
         * the failure this whole family of counters exists to catch, so say so rather than
         * assuming it. */
        if (sum_att != q->nof_attempt || sum_pass != q->nof_pdsch_ok) {
            printf("SECURITY (cell %d): COUNTER MISMATCH -- per-format attempts %llu vs %llu, "
                   "passes %llu vs %llu. One of the two paths is not counting every grant.\n",
                   rf_idx,
                   (unsigned long long)sum_att, (unsigned long long)q->nof_attempt,
                   (unsigned long long)sum_pass, (unsigned long long)q->nof_pdsch_ok);
        }

        /* The decodable share, by the condition that actually decides it -- transmission
         * scheme against the cell's port count and this receiver's antenna count -- rather
         * than by "single transport block", which is neither necessary nor sufficient:
         * config_mimo_type() sends a single-TB TM4 grant with pinfo != 0 to spatial
         * multiplexing, and a 4-port transmit-diversity grant decodes at any antenna count. */
        const uint64_t built = q->nof_scheme[0] + q->nof_scheme[1] + q->nof_scheme[2] + q->nof_scheme[3];
        printf("SECURITY (cell %d): tx scheme on a %u-port cell with %u rx antenna%s -- "
               "PORT0 %llu, DIVERSITY %llu, SPATIALMUX %llu, CDD %llu built; "
               "%llu structurally undecodable here, %llu predecoding errors, %llu CRC failures.",
               rf_idx,
               q->cell_nof_ports,
               q->cell_nof_rxant,
               q->cell_nof_rxant == 1 ? "" : "s",
               (unsigned long long)q->nof_scheme[0],
               (unsigned long long)q->nof_scheme[1],
               (unsigned long long)q->nof_scheme[2],
               (unsigned long long)q->nof_scheme[3],
               (unsigned long long)q->nof_scheme_unsupported,
               (unsigned long long)q->nof_predecode_err,
               (unsigned long long)q->nof_crc_fail);
        if (built > 0) {
            printf(" Decodable share of built grants: %.1f%% (%llu/%llu).",
                   100.0 * (double)(built - q->nof_scheme_unsupported) / (double)built,
                   (unsigned long long)(built - q->nof_scheme_unsupported),
                   (unsigned long long)built);
        }
        printf("\n");
    }
    pthread_mutex_unlock(&sec_mutex[rf_idx]);
}
