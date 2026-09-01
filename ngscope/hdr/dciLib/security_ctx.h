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

/* A RAR handed this RNTI out: the anchor. Re-arms the RNTI, so an identity reused later in
 * a long capture is tracked as the new session rather than the old one. */
void ngscope_sec_note_rar(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
                          uint64_t collection_time);

/* A successfully decoded, still-unciphered RRC message. Proves everything up to this point
 * preceded security activation, even if the SecurityModeCommand itself is never seen. */
void ngscope_sec_note_unciphered_rrc(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us);

/* The SecurityModeCommand: the boundary itself. */
void ngscope_sec_note_smc(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
                          uint64_t collection_time, const char* out_path);

ngscope_sec_phase_t ngscope_sec_phase(int rf_idx, uint16_t rnti, uint64_t ts_us);

/* RNTIs worth attempting an RRC decode for right now: anchored by a RAR, not yet past the
 * boundary. Returns how many were written to out[]. */
int ngscope_sec_tracked(int rf_idx, uint64_t now_us, uint16_t* out, int max_out);

/* Counters, for measuring how often the decode actually lands. */
void ngscope_sec_count_attempt(int rf_idx, bool pdsch_ok, bool rrc_ok);
void ngscope_sec_report(int rf_idx);

#ifdef __cplusplus
}
#endif

#endif
