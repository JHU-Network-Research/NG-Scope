#ifndef _NGSCOPE_SECURITY_RRC_H_
#define _NGSCOPE_SECURITY_RRC_H_

#include <stdbool.h>
#include <stdint.h>

/* Outside the extern "C" block below: srsran.h reaches C++ standard headers, and templates
   cannot have C linkage. */
#include "srsran/srsran.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Per-subframe scan caps, chosen by mode. Live capture discards a subframe when every
 * decoder is busy, so overspending here loses whole subframes invisibly; replay blocks
 * instead and stays lossless however slow it runs, so it can afford full coverage.
 * The replay value matches SEC_MAX_ACTIVE, so nothing tracked goes unscanned. */
#define NGSCOPE_SEC_SCAN_CAP_LIVE 128
#define NGSCOPE_SEC_SCAN_CAP_REPLAY 512

/* When a transport block fails its CRC, rebuild the grant on the other MCS->TBS table and try
 * once more, keeping whichever passes. Off unless this is called.
 *
 * The CRC is ground truth, so this measures the table rather than guessing it -- and it is the
 * only way to be right per grant. 36.213 permits the 256QAM table only when the cell configures
 * `altCQI-Table-r12`, which is **per-UE** RRC state a downlink sniffer cannot see, so no single
 * `enable_256qam` setting can be correct for every UE on a cell.
 *
 * Both this and the reassembly above are set per device, because `mode` is per device.
 *
 * Replay only, for the same reason as the scan cap: the retry costs a second PDSCH decode on
 * every failure, and replay blocks on a busy decoder rather than discarding the subframe, so
 * spending CPU there is lossless. Set before any decoder thread starts. */
void ngscope_sec_rrc_set_qam_retry(int rf_idx, bool enable);

/* For each RNTI currently anchored by a RAR, decode its downlink transport block in this
 * subframe and write it to the MAC pcapng. Nothing here parses the payload.
 *
 * Everything needed is already known: the DCI search is targeted, so the PDCCH CRC is
 * checked against the RNTI rather than recovered from it, and the transport-block CRC then
 * confirms the grant. A decode that survives both is not a false positive.
 *
 * What the bytes mean is decided offline by tools/security_scan.py, which dissects the
 * pcapng with Wireshark. That is why this function no longer takes an out_path: it writes
 * no logs and reaches no conclusions.
 *
 * scan_cap bounds how many tracked UEs are attempted this subframe; 0 means the built-in
 * maximum. Live capture wants it low, because overspending here makes the scheduler discard
 * whole subframes; replay wants it high, because replay blocks rather than dropping and so
 * stays lossless however slow it runs.
 *
 * Returns the number of transport blocks written to the pcap. */
int ngscope_sec_scan_subframe(srsran_ue_dl_t*     ue_dl,
                              srsran_dl_sf_cfg_t* sf,
                              srsran_ue_dl_cfg_t* cfg,
                              srsran_pdsch_cfg_t* pdsch_cfg,
                              uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                              int                 rf_idx,
                              uint32_t            tti,
                              uint64_t            ts_us,
                              uint64_t            collection_time,
                              int                 scan_cap);

/* ---------------------------------------------------------------- blind-DCI probe
 *
 * Measurement instrument, not part of the security measurement. Answers one question:
 * of the DCIs the blind search reports, how many are real?
 *
 * The oracle is the transport-block CRC, and it is a strong one. PDSCH descrambling is
 * seeded with the RNTI -- (rnti << 14) + (q << 13) + ((nslot/2) << 9) + cell_id, see
 * sequences.c -- while the DL-SCH CRC is an unmasked CRC24A that the RNTI does not touch
 * (sch.c). So a transport block that passes CRC was descrambled with the right RNTI and
 * rate-matched to the right size: the (RNTI, grant) pair is real, with a false-pass
 * probability around 2^-24. That is a far stronger test than asking whether the payload
 * parses, and it is already computed by the decoder.
 *
 * The test is ONE-SIDED and the output keeps that visible. A pass proves the DCI real; a
 * failure proves nothing, because srsRAN cannot predecode spatial multiplexing on a 4-port
 * cell, the MCS->TBS table is a per-UE guess, the signal may simply be weak, and an rv > 0
 * retransmission needs HARQ combining across TTIs that this does not do. Every probe is
 * therefore recorded in one of three buckets -- no DCI found, found but CRC failed, CRC
 * passed -- and never collapsed into "real" versus "spurious".
 *
 * Writes blind_probe-<rf_idx>.csv beside the run, one row per probed RNTI per subframe,
 * carrying rach_ok so the two populations can be compared. Deliberately NOT written to the
 * MAC pcapng: those frames would be attributed to RAR-anchored sessions by
 * tools/security_scan.py and would change n_pdus and possibly an outcome, contaminating the
 * measurement this is meant to inform.
 *
 * Replay only. It costs a targeted PDCCH search plus a PDSCH decode for every distinct RNTI
 * in every subframe, which live capture would pay for in discarded subframes. */
int  ngscope_sec_probe_blind_init(const char* out_path, int rf_idx);
void ngscope_sec_probe_blind_close(int rf_idx);

/* Probe every distinct unicast RNTI in `dci_per_sub`. Call BEFORE the RACH filter, so the
 * population is what the blind search actually produced. Returns rows written. */
int ngscope_sec_probe_blind(srsran_ue_dl_t*        ue_dl,
                            srsran_dl_sf_cfg_t*    sf,
                            srsran_ue_dl_cfg_t*    cfg,
                            srsran_pdsch_cfg_t*    pdsch_cfg,
                            uint8_t*               data[SRSRAN_MAX_CODEWORDS],
                            ngscope_dci_per_sub_t* dci_per_sub,
                            int                    rf_idx,
                            uint32_t               tti,
                            uint64_t               ts_us,
                            uint64_t               collection_time);

/* Teardown summary: the two populations side by side. */
void ngscope_sec_probe_blind_report(int rf_idx);

#ifdef __cplusplus
}
#endif

#endif
