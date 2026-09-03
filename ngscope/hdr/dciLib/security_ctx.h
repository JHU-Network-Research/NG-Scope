#ifndef _NGSCOPE_SECURITY_CTX_H_
#define _NGSCOPE_SECURITY_CTX_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Where a unicast DCI sits relative to the UE establishing an AS security context.
 *
 * Decided by observation only. AS security actually activates when the UE sends
 * SecurityModeComplete, which is uplink and therefore invisible here; what a downlink
 * sniffer can see is the SecurityModeCommand a few milliseconds earlier, sent unciphered.
 * That is the boundary used, and it is slightly early by construction.
 *
 * Nothing is inferred from elapsed time or grant counts: a DCI we cannot place is
 * UNKNOWN. In particular, a failure to decode RRC is not evidence of ciphering -- it is
 * equally consistent with a missed subframe -- so it never yields POST. */
typedef enum {
    NGSCOPE_SEC_UNKNOWN = 0,
    NGSCOPE_SEC_PRE,
    NGSCOPE_SEC_POST,
} ngscope_sec_phase_t;

const char* ngscope_sec_phase_str(ngscope_sec_phase_t phase);

/* SI-RNTI, P-RNTI and RA-RNTI are not UE identities and have no security context. */
bool ngscope_sec_is_unicast(uint16_t rnti);

/* Create security_log-<rf_idx>.csv with its header, before any UE is tracked. Call once per
 * device at startup, as with the RAR log: an empty file then means "measured, nobody reached
 * security" -- which for IMSI-catcher detection is the result of interest -- and a missing
 * file means the run never measured it. */
void ngscope_sec_log_init(const char* out_path, int rf_idx);

/* A RAR handed this RNTI out: the anchor. Re-arms the RNTI, so an identity reused later in
 * a long capture is tracked as the new session rather than the old one. */
void ngscope_sec_note_rar(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
                          uint64_t collection_time);

/* A successfully decoded, still-unciphered RRC message. Proves everything up to this point
 * preceded security activation, even if the SecurityModeCommand itself is never seen. */
void ngscope_sec_note_unciphered_rrc(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us);

/* An RRC procedure that resumes an AS security context the UE already held, rather than
 * establishing a new one.
 *
 * Both re-establishment (DL-CCCH, after radio link or handover failure) and resume (DL-DCCH,
 * Rel-13 suspend/resume) restore a stored K_eNB instead of deriving a fresh one, so **no
 * SecurityModeCommand is ever sent**. Such a UE would otherwise sit in the denominator as a
 * failure, when in fact it is the opposite: reaching this point means it presented credentials
 * derived from a real prior context, which a fake base station cannot manufacture.
 *
 * Recorded so the rate can be quoted against the UEs that could have shown a boundary. */
typedef enum {
    NGSCOPE_REUSE_REESTABLISH = 0,   /* RRCConnectionReestablishment */
    NGSCOPE_REUSE_RESUME,            /* RRCConnectionResume-r13 */
    NGSCOPE_REUSE_NOF_KINDS
} ngscope_reuse_kind_t;

void ngscope_sec_note_ctx_reuse(int rf_idx, uint16_t rnti, ngscope_reuse_kind_t kind,
                                uint32_t tti, uint64_t ts_us, uint64_t collection_time,
                                const char* out_path);

/* The SecurityModeCommand: the boundary itself. */
void ngscope_sec_note_smc(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
                          uint64_t collection_time, const char* out_path);

ngscope_sec_phase_t ngscope_sec_phase(int rf_idx, uint16_t rnti, uint64_t ts_us);

/* RNTIs worth attempting an RRC decode for right now: anchored by a RAR, not yet past the
 * boundary. Returns how many were written to out[]. */
int ngscope_sec_tracked(int rf_idx, uint64_t now_us, uint16_t* out, int max_out);

/* What became of a DL-DCCH SDU handed to the RRC unpacker.
 *
 * Counted rather than dropped quietly. A SecurityModeCommand lost anywhere in here is
 * indistinguishable in the output from a UE that never reached security, which is the one
 * confusion this measurement cannot afford -- so every path that discards an SDU lands in
 * exactly one of these buckets and is reported at teardown. */
typedef enum {
    NGSCOPE_DCCH_OK = 0,       /* unpacked from a single PDU */
    NGSCOPE_DCCH_REASSEMBLED,  /* unpacked after rejoining segments */
    NGSCOPE_DCCH_CTRL,         /* RLC control PDU (STATUS): carries no SDU, not a loss */
    NGSCOPE_DCCH_SEGMENTED,    /* part of a split SDU, and reassembly was off */
    NGSCOPE_DCCH_UNSUPPORTED,  /* re-segmented, or carries a length-indicator list */
    NGSCOPE_DCCH_SHORT,        /* too short to hold RLC + PDCP + MAC-I */
    NGSCOPE_DCCH_ASN1,         /* headers stripped, ASN.1 refused it -- normally ciphered */
    NGSCOPE_DCCH_REASM_LOST,   /* a partial SDU dropped before its last segment arrived */
    NGSCOPE_DCCH_NOF_RESULTS
} ngscope_dcch_result_t;

void ngscope_sec_count_dcch(int rf_idx, ngscope_dcch_result_t result);

/* One transport block decoded. `retried` means it only passed CRC after falling back to the
 * other MCS->TBS table, i.e. the configured enable_256qam is wrong for that grant. */
void ngscope_sec_count_tb_table(int rf_idx, bool retried);

/* A retry was actually attempted. Counted separately so the report can tell "tested, and the
 * configured table fits" from "never tested" -- with qam_retry off the two are otherwise
 * indistinguishable, and claiming the former would be a fabricated result. */
void ngscope_sec_count_tb_retry(int rf_idx);

/* Counters, for measuring how often the decode actually lands. */
void ngscope_sec_count_attempt(int rf_idx, bool pdsch_ok, bool rrc_ok);
void ngscope_sec_report(int rf_idx);

#ifdef __cplusplus
}
#endif

#endif
