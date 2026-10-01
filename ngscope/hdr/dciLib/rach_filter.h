#ifndef _RACH_FILTER_H_
#define _RACH_FILTER_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "srsran/srsran.h"
#include "srsran/phy/ue/ngscope_st.h"

/* Set of RNTIs that were observed being handed out in a Random Access Response, kept per RF
 * device. Populated by the RAR decoder; optionally used to restrict what NG-Scope reports.
 *
 * The point is precision. The blind decoder recovers an RNTI from the descrambled PDCCH CRC
 * rather than checking it against a known value, so a false alarm produces a uniformly
 * distributed 16-bit RNTI. Requiring membership in a set of ~100 observed RNTIs therefore
 * rejects roughly 1 - 100/65536 of them. The cost is recall: a UE that completed RACH before
 * the capture started can never enter the set, and everything it does is discarded. */

/* Record an RNTI seen in a RAR. Idempotent. */
/* How an RNTI earned admission. Mirrored into ngscope_dci_msg_t.anchor and written to the
 * .dciLog, so a reader can tell a UE that started on this cell from one that was confirmed
 * only by decoding its traffic. */
typedef enum {
    NGSCOPE_RACH_ANCHOR_NONE = 0,
    NGSCOPE_RACH_ANCHOR_RAR  = 1,
    NGSCOPE_RACH_ANCHOR_CRC  = 2,
} ngscope_rach_anchor_t;

/* A RAR anchor is never downgraded to a CRC one: it is the stronger claim and it carries the
 * RAR TTI the offline tool joins sessions on. */
void ngscope_rach_filter_add(int rf_idx, uint16_t rnti, uint32_t tti, int anchor);

/* NGSCOPE_RACH_ANCHOR_* for an admitted RNTI, NONE if it was never admitted. */
int ngscope_rach_filter_anchor(int rf_idx, uint16_t rnti);

/* ------------------------------------------------------------------ PDCCH order
 *
 * A Format1A DCI with the RBA field all ones and the remaining bits zero is not a grant: it
 * is the eNB ordering a UE to start a random access procedure, and it carries the preamble
 * index it must use (36.212 5.3.3.1.3; srsran_dci_msg_unpack_pdsch sets is_pdcch_order).
 *
 * It lives here because it is a fact about RACH provenance, and that is what this file is
 * for. A contention-free RACH -- one using a preamble the cell reserves rather than one the
 * UE picked -- has exactly two causes: a handover into this cell, and a PDCCH order. Only
 * the first is interesting, and the only way to tell them apart from the downlink is to see
 * the order. Without this, every ordered RACH would read as a handover.
 *
 * Written to pdcch_order-<rf_idx>.csv beside rar_log-<rf_idx>.csv, which is where
 * tools/security_scan.py already looks. */
int  ngscope_pdcch_order_init(const char* out_path, int rf_idx);

/* Uses the calling thread's bound device, like ngscope_rach_filter_pass_bound(): the unpack
 * happens inside libsrsran_phy where there is no rf_idx in scope. A no-op on an unbound
 * thread or before init, so cellsearch and the tests are unaffected. */
void ngscope_pdcch_order_note_bound(uint16_t rnti, uint32_t tti, uint32_t preamble_idx,
                                    uint32_t prach_mask_idx);

void ngscope_pdcch_order_report(int rf_idx);
void ngscope_pdcch_order_close(int rf_idx);

/* Bind the calling thread to an RF device, so the filter can be consulted from inside
 * libsrsran_phy where no rf_idx is in scope. Call once per decoder thread. -1 unbinds.
 * An unbound thread never filters. */
void ngscope_rach_filter_bind_thread(int rf_idx);

/* Whether this device wants the filter applied during the blind search, i.e. rach_filter_only.
 * Call once per RF device before its decoder threads start. Defaults to false. */
void ngscope_rach_filter_set_active(int rf_idx, bool active);

/* Stop the PDCCH search itself from suppressing RNTIs the filter has not admitted, so the
 * blind-DCI probe can adjudicate them against the DL-SCH CRC. ngscope_rach_filter_apply()
 * is unaffected: nothing unproven reaches the reported DCIs either way. See the definition
 * for why the two jobs have to be separable. */
void ngscope_rach_filter_set_search_bypass(int rf_idx, bool bypass);

/* ngscope_rach_filter_pass() for the calling thread's bound device, returning true when the
 * thread is unbound or the device did not enable filtering. This is what the PDCCH candidate
 * loop calls. */
bool ngscope_rach_filter_pass_bound(uint16_t rnti);

/* true if this RNTI may be reported. Broadcast RNTIs (SI-RNTI, P-RNTI, RA-RNTI) always pass:
 * they never RACH by definition, and dropping them would silently discard all system
 * information and paging DCIs. RNTI 0 never passes. */
bool ngscope_rach_filter_pass(int rf_idx, uint16_t rnti);

/* Drop every DL and UL message in q whose RNTI does not pass. Returns the number dropped. */
int ngscope_rach_filter_apply(int rf_idx, ngscope_dci_per_sub_t* q);

/* Number of distinct RNTIs recorded so far. */
int ngscope_rach_filter_nof_rnti(int rf_idx);

/* One-line summary of what the filter kept and dropped, for teardown. */
void ngscope_rach_filter_report(int rf_idx);

#ifdef __cplusplus
}
#endif

#endif
