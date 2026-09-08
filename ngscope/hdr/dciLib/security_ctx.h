#ifndef _NGSCOPE_SECURITY_CTX_H_
#define _NGSCOPE_SECURITY_CTX_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Which UEs are worth decoding transport blocks for, and how well that decoding went.
 *
 * This file used to also decide what those transport blocks *meant* -- it tracked each UE's
 * SecurityModeCommand and labelled every DCI pre/post/unknown. It no longer does. ngscope
 * writes the decoded MAC PDUs to mac-<rf_idx>.pcapng and makes no claim about their
 * contents; tools/security_scan.py dissects that capture with Wireshark, which reassembles
 * RLC and understands NAS, and writes security_events / security_sessions / security_summary
 * beside the run.
 *
 * What remains here is the tracked set (a RAR anchors an RNTI; it stays for a bounded
 * window) and the coverage counters. Those counters are the validity conditions for
 * everything the offline tool concludes: a UE dropped by a cap or a busy decoder is
 * indistinguishable in the pcap from a UE that never reached security, so the rate can only
 * be read as a property of the cell while they are zero. */

/* SI-RNTI, P-RNTI and RA-RNTI are not UE identities and are never tracked. */
bool ngscope_sec_is_unicast(uint16_t rnti);

/* A RAR handed this RNTI out: the anchor, and the only way into the tracked set. Re-arms the
 * RNTI, so an identity reused later in a long capture is tracked as the new session rather
 * than the old one. The RAR log this feeds is also the denominator the offline tool seeds
 * its sessions from. */
void ngscope_sec_note_rar(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
                          uint64_t collection_time);

/* RNTIs worth attempting a PDSCH decode for right now: anchored by a RAR and still inside
 * the tracking window. Returns how many were written to out[]. */
int ngscope_sec_tracked(int rf_idx, uint64_t now_us, uint16_t* out, int max_out);

/* One transport block decoded. `retried` means it only passed CRC after falling back to the
 * other MCS->TBS table, i.e. the configured enable_256qam is wrong for that grant. */
void ngscope_sec_count_tb_table(int rf_idx, bool retried);

/* A retry was actually attempted. Counted separately so the report can tell "tested, and the
 * configured table fits" from "never tested" -- with qam_retry off the two are otherwise
 * indistinguishable, and claiming the former would be a fabricated result. */
void ngscope_sec_count_tb_retry(int rf_idx);

/* Counters, for measuring how often the decode actually lands. */
void ngscope_sec_count_attempt(int rf_idx, bool pdsch_ok);
void ngscope_sec_report(int rf_idx);

#ifdef __cplusplus
}
#endif

#endif
