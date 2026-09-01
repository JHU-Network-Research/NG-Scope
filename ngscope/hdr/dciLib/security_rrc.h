#ifndef _NGSCOPE_SECURITY_RRC_H_
#define _NGSCOPE_SECURITY_RRC_H_

#include <stdint.h>

/* Outside the extern "C" block below: srsran.h reaches C++ standard headers, and templates
   cannot have C linkage. */
#include "srsran/srsran.h"

#ifdef __cplusplus
extern "C" {
#endif

/* For each RNTI currently anchored by a RAR and not yet past the security boundary, try to
 * decode its downlink transport block in this subframe and unpack the RRC inside it.
 *
 * Everything needed is already known: the DCI search is targeted, so the PDCCH CRC is
 * checked against the RNTI rather than recovered from it, and the transport-block CRC then
 * confirms the grant. A decode that survives both is not a false positive.
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
                              const char*         out_path);

#ifdef __cplusplus
}
#endif

#endif
