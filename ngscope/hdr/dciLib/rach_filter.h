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
void ngscope_rach_filter_add(int rf_idx, uint16_t rnti, uint32_t tti);

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
