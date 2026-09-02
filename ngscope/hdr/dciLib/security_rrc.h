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

/* Rejoin DL-DCCH SDUs that the eNB split across several RLC PDUs, so a SecurityModeCommand
 * that did not fit one grant is still read. Off unless this is called.
 *
 * Replay only, deliberately. Reassembly means holding a partial SDU until its remaining
 * segments arrive, and that is only sound where nothing goes missing: replay blocks on a
 * busy decoder and therefore sees every subframe, whereas live capture discards them
 * (task_scheduler.c, find_idle_decoder). A discarded middle segment leaves a partial SDU
 * that never completes -- indistinguishable, in the output, from a UE that never reached
 * security, which is exactly the confusion this measurement exists to avoid.
 *
 * Set before any decoder thread starts. */
void ngscope_sec_rrc_set_reassembly(int rf_idx, bool enable);

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

/* Account for partial SDUs still held at teardown. Each one is an RRC message that was
 * observed and never read, so it is counted as lost rather than forgotten. Call once per
 * device, before ngscope_sec_report(). */
void ngscope_sec_rrc_reasm_flush(void);

/* For each RNTI currently anchored by a RAR and not yet past the security boundary, try to
 * decode its downlink transport block in this subframe and unpack the RRC inside it.
 *
 * Everything needed is already known: the DCI search is targeted, so the PDCCH CRC is
 * checked against the RNTI rather than recovered from it, and the transport-block CRC then
 * confirms the grant. A decode that survives both is not a false positive.
 *
 * scan_cap bounds how many tracked UEs are attempted this subframe; 0 means the built-in
 * maximum. Live capture wants it low, because overspending here makes the scheduler discard
 * whole subframes; replay wants it high, because replay blocks rather than dropping and so
 * stays lossless however slow it runs.
 *
 * Returns the number of RNTIs for which RRC was successfully unpacked. */
int ngscope_sec_scan_subframe(srsran_ue_dl_t*     ue_dl,
                              srsran_dl_sf_cfg_t* sf,
                              srsran_ue_dl_cfg_t* cfg,
                              srsran_pdsch_cfg_t* pdsch_cfg,
                              uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                              int                 rf_idx,
                              uint32_t            tti,
                              uint64_t            ts_us,
                              uint64_t            collection_time,
                              const char*         out_path,
                              int                 scan_cap);

#ifdef __cplusplus
}
#endif

#endif
