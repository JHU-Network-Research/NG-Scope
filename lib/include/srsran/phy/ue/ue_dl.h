/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

/******************************************************************************
 *  File:         ue_dl.h
 *
 *  Description:  UE downlink object.
 *
 *                This module is a frontend to all the downlink data and control
 *                channel processing modules.
 *
 *  Reference:
 *****************************************************************************/

#ifndef SRSRAN_UE_DL_H
#define SRSRAN_UE_DL_H

#include <stdbool.h>

#include "srsran/phy/ch_estimation/chest_dl.h"
#include "srsran/phy/common/phy_common.h"
#include "srsran/phy/dft/ofdm.h"

#include "srsran/phy/phch/dci.h"
#include "srsran/phy/phch/pcfich.h"
#include "srsran/phy/phch/pdcch.h"
#include "srsran/phy/phch/pdsch.h"
#include "srsran/phy/phch/pdsch_cfg.h"
#include "srsran/phy/phch/phich.h"
#include "srsran/phy/phch/pmch.h"
#include "srsran/phy/phch/ra.h"
#include "srsran/phy/phch/regs.h"

#include "srsran/phy/sync/cfo.h"

#include "srsran/phy/utils/debug.h"
#include "srsran/phy/utils/vector.h"

#include "srsran/phy/ue/ngscope_st.h"

#include "srsran/config.h"

#define SRSRAN_MAX_CANDIDATES_UE 16 // From 36.213 Table 9.1.1-1
#define SRSRAN_MAX_CANDIDATES_COM 6 // From 36.213 Table 9.1.1-1
#define SRSRAN_MAX_CANDIDATES (SRSRAN_MAX_CANDIDATES_UE + SRSRAN_MAX_CANDIDATES_COM)

#define SRSRAN_MAX_FORMATS 8

#define SRSRAN_MI_NOF_REGS ((q->cell.frame_type == SRSRAN_FDD) ? 1 : 6)
#define SRSRAN_MI_MAX_REGS 6

#define SRSRAN_MAX_DCI_MSG SRSRAN_MAX_CARRIERS

typedef struct SRSRAN_API {
  srsran_dci_format_t   formats[SRSRAN_MAX_FORMATS];
  srsran_dci_location_t loc[SRSRAN_MAX_CANDIDATES];
  uint32_t              nof_locations;
  uint32_t              nof_formats;
} dci_blind_search_t;

typedef struct SRSRAN_API {
  // Cell configuration
  srsran_cell_t cell;
  uint32_t      nof_rx_antennas;
  uint16_t      current_mbsfn_area_id;

  // Objects for all DL Physical Channels
  srsran_pcfich_t pcfich;
  srsran_pdcch_t  pdcch;
  srsran_pdsch_t  pdsch;
  srsran_pmch_t   pmch;
  srsran_phich_t  phich;

  // Control region
  srsran_regs_t regs[SRSRAN_MI_MAX_REGS];
  uint32_t      mi_manual_index;
  bool          mi_auto;

  // Channel estimation and OFDM demodulation
  srsran_chest_dl_t     chest;
  srsran_chest_dl_res_t chest_res;
  srsran_ofdm_t         fft[SRSRAN_MAX_PORTS];
  srsran_ofdm_t         fft_mbsfn;

  // Buffers to store channel symbols after demodulation
  cf_t*              sf_symbols[SRSRAN_MAX_PORTS];
  dci_blind_search_t current_ss_common;

  srsran_dci_msg_t pending_ul_dci_msg[SRSRAN_MAX_DCI_MSG];
  uint32_t         pending_ul_dci_count;

  srsran_dci_location_t allocated_locations[SRSRAN_MAX_DCI_MSG];
  uint32_t              nof_allocated_locations;

  /* Solve-first index (srsran_ue_dl_solve_first): every candidate decoded this subframe,
   * chained by the RNTI it decoded to. solved_gen is the PDCCH dec_gen it was built for; the
   * index is only trusted while that still matches, i.e. on the same LLRs. */
  uint32_t                      solved_gen;
  bool                          solved_ok;
  uint32_t                      nof_solved;
  struct srsran_ue_dl_solved_s* solved;
  int16_t*                      solved_head;

  /* FFT + channel-estimation reuse (srsran_ue_dl_set_fft_reuse). srsran_ue_dl_decode_fft_estimate
   * is called several times per subframe by independent steps; a repeat with the same input
   * returns the stored result instead of recomputing it. Keyed on everything that feeds it:
   * the subframe (serial from srsran_ue_dl_new_subframe, plus the sf config minus its output
   * cfi), the PHICH mi setting and the channel-estimation config. */
  bool                  fft_reuse_en;
  bool                  fft_valid;
  uint64_t              fft_serial;
  uint64_t              fft_key_serial;
  srsran_dl_sf_cfg_t    fft_key_sf;
  srsran_chest_dl_cfg_t fft_key_chest;
  bool                  fft_key_mi_auto;
  uint32_t              fft_key_mi_idx;
  uint32_t              fft_cfi;
  uint64_t              fft_computed;
  uint64_t              fft_reused;
  uint64_t              fft_verified;
} srsran_ue_dl_t;

// Downlink config (includes common and dedicated variables)
typedef struct SRSRAN_API {
  srsran_cqi_report_cfg_t cqi_report;
  srsran_pdsch_cfg_t      pdsch;
  srsran_dci_cfg_t        dci;
  srsran_tm_t             tm;
  bool                    dci_common_ss;
} srsran_dl_cfg_t;

typedef struct SRSRAN_API {
  srsran_dl_cfg_t       cfg;
  srsran_chest_dl_cfg_t chest_cfg;
  uint32_t              last_ri;
  float                 snr_to_cqi_offset;
} srsran_ue_dl_cfg_t;

typedef struct {
  uint32_t v_dai_dl;
  uint32_t n_cce;
  uint32_t grant_cc_idx;
  uint32_t tpc_for_pucch;
} srsran_pdsch_ack_resource_t;

typedef struct {
  srsran_pdsch_ack_resource_t resource;
  uint32_t                    k;
  uint8_t                     value[SRSRAN_MAX_CODEWORDS]; // 0/1 or 2 for DTX
  bool                        present;
} srsran_pdsch_ack_m_t;

typedef struct {
  uint32_t             M;
  srsran_pdsch_ack_m_t m[SRSRAN_UCI_MAX_M];
} srsran_pdsch_ack_cc_t;

typedef struct {
  srsran_pdsch_ack_cc_t           cc[SRSRAN_MAX_CARRIERS];
  uint32_t                        nof_cc;
  uint32_t                        V_dai_ul;
  srsran_tm_t                     transmission_mode;
  srsran_ack_nack_feedback_mode_t ack_nack_feedback_mode;
  bool                            is_grant_available;
  bool                            is_pusch_available;
  bool                            tdd_ack_multiplex;
  bool                            simul_cqi_ack;
  bool                            simul_cqi_ack_pucch3;
} srsran_pdsch_ack_t;

SRSRAN_API int
srsran_ue_dl_init(srsran_ue_dl_t* q, cf_t* input[SRSRAN_MAX_PORTS], uint32_t max_prb, uint32_t nof_rx_antennas);

SRSRAN_API void srsran_ue_dl_free(srsran_ue_dl_t* q);

SRSRAN_API int srsran_ue_dl_set_cell(srsran_ue_dl_t* q, srsran_cell_t cell);

SRSRAN_API int srsran_ue_dl_set_mbsfn_area_id(srsran_ue_dl_t* q, uint16_t mbsfn_area_id);

SRSRAN_API void srsran_ue_dl_set_non_mbsfn_region(srsran_ue_dl_t* q, uint8_t non_mbsfn_region_length);

SRSRAN_API void srsran_ue_dl_set_mi_manual(srsran_ue_dl_t* q, uint32_t mi_idx);

SRSRAN_API void srsran_ue_dl_set_mi_auto(srsran_ue_dl_t* q);

/* Perform signal demodulation and channel estimation and store signals in the object */
/* Opt in to reusing a subframe's FFT + channel estimate across repeated
 * srsran_ue_dl_decode_fft_estimate() calls. Exact for every estimator except wiener (which
 * keeps state across calls and therefore always recomputes). */
SRSRAN_API void srsran_ue_dl_set_fft_reuse(srsran_ue_dl_t* q, bool enable);

/* New IQ is in the input buffer: nothing computed so far may be reused. */
SRSRAN_API void srsran_ue_dl_new_subframe(srsran_ue_dl_t* q);

SRSRAN_API int srsran_ue_dl_decode_fft_estimate(srsran_ue_dl_t* q, srsran_dl_sf_cfg_t* sf, srsran_ue_dl_cfg_t* cfg);

SRSRAN_API int srsran_ue_dl_decode_fft_estimate_noguru(srsran_ue_dl_t*     q,
                                                       srsran_dl_sf_cfg_t* sf,
                                                       srsran_ue_dl_cfg_t* cfg,
                                                       cf_t*               input[SRSRAN_MAX_PORTS]);

/* Finds UL/DL DCI in the signal processed in a previous call to decode_fft_estimate() */
SRSRAN_API int srsran_ue_dl_find_ul_dci(srsran_ue_dl_t*     q,
                                        srsran_dl_sf_cfg_t* sf,
                                        srsran_ue_dl_cfg_t* dl_cfg,
                                        uint16_t            rnti,
                                        srsran_dci_ul_t     dci_msg[SRSRAN_MAX_DCI_MSG]);

SRSRAN_API int srsran_ue_dl_find_dl_dci(srsran_ue_dl_t*     q,
                                        srsran_dl_sf_cfg_t* sf,
                                        srsran_ue_dl_cfg_t* dl_cfg,
                                        uint16_t            rnti,
                                        srsran_dci_dl_t     dci_msg[SRSRAN_MAX_DCI_MSG]);

/* Like srsran_ue_dl_find_dl_dci(), but with the UE-specific search-space format set supplied
 * by the caller instead of derived from dl_cfg->cfg.tm, and with the common-SS Format1A pass
 * requested explicitly rather than through dl_cfg->cfg.dci_common_ss. See the definition in
 * ue_dl.c for why a sniffer needs both. */
SRSRAN_API int srsran_ue_dl_find_dl_dci_formats(srsran_ue_dl_t*            q,
                                                srsran_dl_sf_cfg_t*        sf,
                                                srsran_ue_dl_cfg_t*        dl_cfg,
                                                uint16_t                   rnti,
                                                const srsran_dci_format_t* ue_formats,
                                                uint32_t                   nof_ue_formats,
                                                bool                       search_common_1a,
                                                srsran_dci_dl_t            dci_dl[SRSRAN_MAX_DCI_MSG]);

/* Solve-first: decode every aligned PDCCH candidate of this subframe once, at the payload
 * sizes srsran_ue_dl_find_dl_dci_formats() would use for these UE formats plus Format1A in
 * the common search space, and index them by the RNTI each decodes to (its CRC remainder).
 * Call after the LLRs are extracted; best with srsran_pdcch_set_decode_cache() on, so the
 * searches below reuse the decodes. Returns the number of candidates indexed. */
SRSRAN_API int srsran_ue_dl_solve_first(srsran_ue_dl_t*            q,
                                        srsran_dl_sf_cfg_t*        sf,
                                        srsran_ue_dl_cfg_t*        dl_cfg,
                                        const srsran_dci_format_t* ue_formats,
                                        uint32_t                   nof_ue_formats);

/* Did any candidate in the current index decode to this RNTI? true when the index is not
 * valid for the current LLRs, so a caller that skips on false can never skip wrongly. */
SRSRAN_API bool srsran_ue_dl_solved_has(srsran_ue_dl_t* q, uint16_t rnti);

/* Same result as srsran_ue_dl_find_dl_dci_formats(), from the solve-first index: it visits
 * only the candidates that decoded to this RNTI, applying the identical acceptance rules
 * (dci_blind_search_accept) in the identical order. Falls back to the full search when the
 * index is not valid for the current LLRs. */
SRSRAN_API int srsran_ue_dl_find_dl_dci_formats_solved(srsran_ue_dl_t*            q,
                                                       srsran_dl_sf_cfg_t*        sf,
                                                       srsran_ue_dl_cfg_t*        dl_cfg,
                                                       uint16_t                   rnti,
                                                       const srsran_dci_format_t* ue_formats,
                                                       uint32_t                   nof_ue_formats,
                                                       bool                       search_common_1a,
                                                       srsran_dci_dl_t            dci_dl[SRSRAN_MAX_DCI_MSG]);

SRSRAN_API int srsran_ue_dl_dci_to_pdsch_grant(srsran_ue_dl_t*       q,
                                               srsran_dl_sf_cfg_t*   sf,
                                               srsran_ue_dl_cfg_t*   cfg,
                                               srsran_dci_dl_t*      dci,
                                               srsran_pdsch_grant_t* grant);

SRSRAN_API int srsran_ue_dl_dci_to_pdsch_grant_wo_mimo_yx(srsran_ue_dl_t*       q,
                                               srsran_dl_sf_cfg_t*   sf,
                                               srsran_ue_dl_cfg_t*   cfg,
                                               srsran_dci_dl_t*      dci,
                                               srsran_pdsch_grant_t* grant,
                                               uint32_t*             out_L_crb,
                                               uint32_t*             out_RB_start);

/* Decodes PDSCH and PHICH in the signal processed in a previous call to decode_fft_estimate() */
SRSRAN_API int srsran_ue_dl_decode_pdsch(srsran_ue_dl_t*     q,
                                         srsran_dl_sf_cfg_t* sf,
                                         srsran_pdsch_cfg_t* pdsch_cfg,
                                         srsran_pdsch_res_t  data[SRSRAN_MAX_CODEWORDS]);

SRSRAN_API int srsran_ue_dl_decode_pmch(srsran_ue_dl_t*     q,
                                        srsran_dl_sf_cfg_t* sf,
                                        srsran_pmch_cfg_t*  pmch_cfg,
                                        srsran_pdsch_res_t  data[SRSRAN_MAX_CODEWORDS]);

SRSRAN_API int srsran_ue_dl_decode_phich(srsran_ue_dl_t*       q,
                                         srsran_dl_sf_cfg_t*   sf,
                                         srsran_ue_dl_cfg_t*   cfg,
                                         srsran_phich_grant_t* grant,
                                         srsran_phich_res_t*   result);

SRSRAN_API int srsran_ue_dl_select_ri(srsran_ue_dl_t* q, uint32_t* ri, float* cn);

SRSRAN_API void srsran_ue_dl_gen_cqi_periodic(srsran_ue_dl_t*     q,
                                              srsran_ue_dl_cfg_t* cfg,
                                              uint32_t            wideband_value,
                                              uint32_t            tti,
                                              srsran_uci_data_t*  uci_data);

SRSRAN_API void srsran_ue_dl_gen_cqi_aperiodic(srsran_ue_dl_t*     q,
                                               srsran_ue_dl_cfg_t* cfg,
                                               uint32_t            wideband_value,
                                               srsran_uci_data_t*  uci_data);

SRSRAN_API void srsran_ue_dl_gen_ack(const srsran_cell_t*      cell,
                                     const srsran_dl_sf_cfg_t* sf,
                                     const srsran_pdsch_ack_t* ack_info,
                                     srsran_uci_data_t*        uci_data);

/* Functions used for testing purposes */
SRSRAN_API int srsran_ue_dl_find_and_decode(srsran_ue_dl_t*     q,
                                            srsran_dl_sf_cfg_t* sf,
                                            srsran_ue_dl_cfg_t* cfg,
                                            srsran_pdsch_cfg_t* pdsch_cfg,
                                            uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                                            bool                acks[SRSRAN_MAX_CODEWORDS]);

SRSRAN_API int srsran_ngscope_search_in_space_yx(srsran_ue_dl_t*     q,
                            srsran_dl_sf_cfg_t* sf,
                            dci_blind_search_t* search_space,
                            srsran_dci_cfg_t*   dci_cfg,
                            srsran_dci_msg_t    dci_msg[MAX_NOF_FORMAT],
                            srsran_dci_dl_t     dci_dl[MAX_NOF_FORMAT]);

SRSRAN_API bool srsran_ngscope_space_match_yx(uint16_t rnti,
                                    uint32_t nof_cce,
                                    uint32_t sf_idx,
                                    uint32_t ncce,
                                    srsran_dci_format_t format);

SRSRAN_API uint32_t srsran_ngscope_ue_locations_ncce_check_ue_specific(uint32_t nof_cce, uint32_t nsubframe, uint16_t rnti,
                                                                    uint32_t this_ncce);

SRSRAN_API uint32_t srsran_ngscope_ue_locations_ncce_check_common(uint32_t nof_cce, uint32_t nsubframe, uint16_t rnti,
                                                                    uint32_t this_ncce);

/* Functions used for testing purposes */
SRSRAN_API int srsran_ue_decode_dci_yx(srsran_ue_dl_t*     q,
                                 srsran_dl_sf_cfg_t* sf,
                                 srsran_ue_dl_cfg_t* cfg,
                                 srsran_pdsch_cfg_t* pdsch_cfg,
                                 ngscope_dci_per_sub_t* dci_res,
								 uint16_t 				targetRNTI);

SRSRAN_API void srsran_ue_dl_save_signal(srsran_ue_dl_t* q, srsran_dl_sf_cfg_t* sf, srsran_pdsch_cfg_t* pdsch_cfg);

#endif // SRSRAN_UE_DL_H
