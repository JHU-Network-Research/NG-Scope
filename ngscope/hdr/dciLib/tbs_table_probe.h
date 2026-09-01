#ifndef _NGSCOPE_TBS_TABLE_PROBE_H_
#define _NGSCOPE_TBS_TABLE_PROBE_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "srsran/srsran.h"

/* Decide which MCS->TBS table the cell is actually using, without decoding anything.
 *
 * 36.213 permits the 256QAM table only when the cell configures altCQI-Table-r12, which is
 * per-UE RRC state a downlink sniffer cannot see -- so ngscope has to guess, and the guess
 * sets the tbs values written to the .dciLog files as well as deciding whether a transport
 * block can ever pass CRC.
 *
 * There is a decisive test that needs no decode and no RRC: an effective code rate above 1 is
 * physically impossible. tbs/nof_bits is the code rate, nof_bits being the REs of the grant
 * times the bits per modulation symbol. Interpreting a grant with the wrong table produces
 * impossible rates for a meaningful fraction of grants; the right table essentially never
 * does, since real schedulers stay under ~0.93.
 *
 * So evaluate every downlink grant both ways and count. Whichever table yields no impossible
 * rates is the one the cell is using. Counting rather than deciding per grant matters: a
 * single grant can be plausible under both tables, and only the population separates them. */

/* Record one downlink grant. Called with the grant as built under the table currently
 * configured, so the probe can recompute the alternative itself. Cheap: two table lookups and
 * two divides, no allocation. */
void ngscope_tbs_probe_add(const srsran_pdsch_grant_t* grant,
                           const srsran_dci_dl_t*      dci,
                           bool                        configured_alt,
                           float                       corr);

/* One-line verdict at teardown, naming the table the evidence supports. */
void ngscope_tbs_probe_report(void);

#ifdef __cplusplus
}
#endif

#endif
