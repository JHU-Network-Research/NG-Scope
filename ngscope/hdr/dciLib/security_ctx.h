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

/* A transport block addressed to this RNTI passed its DL-SCH CRC, but no RAR on this cell
 * ever handed the RNTI out. Track it anyway.
 *
 * The CRC is a stronger test than the RAR anchor, not a weaker one. PDSCH descrambling is
 * seeded with the RNTI and CRC24A is not, so a pass says the (RNTI, grant) pair is real to
 * about 2^-24 -- whereas a RAR only says some UE was handed that identity. What it does not
 * say is where the UE came from, and that is the point: a UE that handed in to this cell has
 * no RAR here by construction, and neither does one that was already connected when the
 * capture began. Both are positive evidence of a UE the cell is really serving, and both
 * were previously dropped by the RACH filter as indistinguishable from the thousands of
 * RNTIs blind search manufactures.
 *
 * Unlike a RAR this does not re-arm an identity: with no RAR there is no boundary to reset,
 * and an RNTI already anchored by a RAR keeps that anchor. */
void ngscope_sec_note_crc_confirmed(int rf_idx, uint16_t rnti, uint32_t tti, uint64_t ts_us,
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

/* The cell's antenna configuration, so the report can say which transmission schemes were
 * decodable at all rather than leaving that to be inferred. Call once per device, after cell
 * search. */
void ngscope_sec_set_cell(int rf_idx, uint32_t nof_ports, uint32_t nof_rxant);

/* One subframe's targeted search: how many tracked RNTIs were searched and how many of those
 * searches found no DCI. The second was a bare `continue` with no counter, which is exactly
 * the silent loss this file exists to rule out -- though note it is an upper bound on loss,
 * since most tracked UEs simply have no grant in a given subframe. */
void ngscope_sec_count_scan(int rf_idx, int nof_searched, int nof_without_dci);

/* One built grant, classified. `fmt` is an srsran_dci_format_t and `scheme` an
 * srsran_tx_scheme_t, both passed as plain int: this header is a leaf that includes only
 * stdbool/stdint, and pulling srsran.h in here would force the C/C++ linkage dance that
 * security_rrc.h documents.
 *
 * `outcome` is NGSCOPE_SEC_GRANT_*. The point of separating UNSUPPORTED and PREDECODE_ERR
 * from CRC_FAIL is that they are not the same claim: a spatial-multiplexing grant on a
 * 4-port cell could never have decoded whatever the signal was like, while a CRC failure
 * means the receiver tried and the channel beat it. Collapsing them is what made the
 * "~91% of grants are decodable" figure unmeasurable. */
/* Sizes of the srsran_dci_format_t and srsran_tx_scheme_t domains, restated because this
 * header is a leaf (stdbool/stdint only). security_rrc.cpp, which does see the real enums,
 * static_asserts these against them, so a drift in srsRAN fails the build rather than
 * silently dropping counts off the end of an array. */
#define NGSCOPE_SEC_NOF_FORMATS 13
#define NGSCOPE_SEC_NOF_SCHEMES 4

#define NGSCOPE_SEC_GRANT_CRC_PASS      0
#define NGSCOPE_SEC_GRANT_CRC_FAIL      1
#define NGSCOPE_SEC_GRANT_PREDECODE_ERR 2
#define NGSCOPE_SEC_GRANT_UNSUPPORTED   3

void ngscope_sec_count_grant(int rf_idx, int fmt, int scheme, int outcome);

/* One DCI found by the targeted search, before any decode is attempted. Separate from
 * count_grant so "found but never buildable" is visible per format. */
void ngscope_sec_count_dci(int rf_idx, int fmt);

void ngscope_sec_report(int rf_idx);

#ifdef __cplusplus
}
#endif

#endif
