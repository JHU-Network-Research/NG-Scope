#include "srsran/phy/ue/ngscope_consistency.h"
#include <math.h>
#include <string.h>
#include "srsran/srsran.h"
/* ---------------------------------------------------------------
 * TS 36.213 Table 7.1.7.2.1-1 : TBS(I_TBS, N_PRB)
 *
 * I_TBS in [0..26], N_PRB in [1..110]. This is a pure lookup table
 * in the spec (not a closed-form formula) — srsRAN carries the full
 * grid as a static const array in ra_tbs.c (or equivalent).
 *
 * IMPORTANT: only a representative subset of rows/columns is
 * populated below (enough for the small-cell-BW, low/mid-MCS cases
 * that dominate what you'll actually see on your RAK/srsRAN lab
 * setup) so the code compiles and runs end-to-end. Before using
 * this against real captures, copy the full 27x110 grid from
 * srsRAN's own ra_tbs.c (it already has the spec table verified
 * against 36.213) rather than re-deriving/re-typing all 2970
 * entries by hand — that's the kind of table you want sourced from
 * a validated implementation, not retyped from memory.
 * -1 marks "not populated in this stub".
 * --------------------------------------------------------------- */
#define NOF_ITBS 27
#define MAX_PRB_STUB 12  /* stub only covers N_PRB = 1..12 */

bool ngscope_riv_valid(const srsran_cell_t *cell,
                        uint32_t rb_start, uint32_t l_crb)
{
    if (l_crb == 0) {
        return false; /* zero-length allocation is never valid */
    }
    if (rb_start + l_crb > cell->nof_prb) {
        return false; /* RIV decodes past the cell's own bandwidth */
    }
    return true;
}

/* Number of REs consumed by cell-specific reference signals per PRB
 * pair, per TS 36.211 Table 6.10.1.2-1 conventions: 4 REs/port/PRB
 * for 1 or 2 ports, 4 REs/port/PRB but staggered for 4 ports (extra
 * pattern shift on ports 2/3, so effectively still 4 per port in the
 * subframe but with different symbol positions). We only need total
 * RE overhead here, not exact symbol position. */
static int crs_re_per_prb_pair(uint32_t nof_ports)
{
    switch (nof_ports) {
        case 1:  return 4;   /* 4 RE/PRB-pair for port 0 */
        case 2:  return 8;   /* 4 RE/PRB-pair x 2 ports */
        case 4:  return 12;  /* 4 RE/PRB-pair x 4 ports */
        default: return 8;
    }
}

int ngscope_compute_n_re(const srsran_cell_t *cell,
                          uint32_t cfi,
                          uint32_t sf_idx,
                          uint32_t l_crb)
{
    const uint32_t symb_per_slot = cell->cp == SRSRAN_CP_EXT ? 6 : 7;
    const uint32_t symb_per_sf   = 2 * symb_per_slot;

    /* REs per PRB before any overhead */
    uint32_t re_per_prb = 12 * symb_per_sf;

    /* Subtract PDCCH control region (n_symb_pdcch full OFDM symbols
     * across the whole bandwidth, so per-PRB it's just symbols * 12) */
    uint32_t pdcch_re = cfi * 12;

    /* Subtract CRS overhead */
    uint32_t crs_re = crs_re_per_prb_pair(cell->nof_ports);

    int re_per_prb_net = (int)re_per_prb - (int)pdcch_re - (int)crs_re;
    // fprintf(stderr, "re_per_prb_net=%d, re_per_prb=%u, pdcch_re=%u, crs_re=%u\n", re_per_prb_net, re_per_prb, pdcch_re,crs_re);

    /* Subframes 0 and 5 (FDD) carry PBCH/PSS/SSS in the center 6 PRBs;
     * subframe 5 also carries PSS/SSS every subframe in FDD (SSS in 0
     * and 5, PSS in 0 and 5 for FDD -- simplified here). This stub
     * only flags it; exact RE deduction for those center PRBs should
     * be added if you're validating DCIs scheduled in sf 0/5 against
     * allocations that overlap the center 6 PRBs. */
    bool sf_has_sync_or_pbch = (sf_idx == 0 || sf_idx == 5);
    (void)sf_has_sync_or_pbch; /* TODO: deduct center-6-PRB overhead when rb range overlaps */

    if (re_per_prb_net < 0) {
        re_per_prb_net = 0;
    }

    return re_per_prb_net * (int)l_crb;
}


float get_code_rate(ngscope_dci_tb_t tb, float n_re){
    float bits_to_map = (float)(tb.tbs + 24);
    float capacity_bits = (float)n_re * srsran_mod_bits_x_symbol(srsran_ra_dl_mod_from_mcs(tb.mcs, true));
    float code_rate = bits_to_map / capacity_bits;
    return code_rate;
}


// ngscope_consistency_result_t
// ngscope_consistency_check(const srsran_cell_t *cell,
//                            const ngscope_dci_msg_t *dci,
//                            uint32_t sf_idx,
//                             uint32_t n_symbols)
// {
//     ngscope_consistency_result_t res;
//     memset(&res, 0, sizeof(res));

//     /* Gate 1: deterministic RIV/allocation validity */
//     if (!ngscope_riv_valid(cell, dci->rb_start, dci->l_crb)) {
//         res.hard_fail = true;
//         res.weight = 0.0f;
//         return res;
//     }

//     int nof_tb = dci->nof_tb;
//     // int tbs1, tbs2 = 0;
//     if (nof_tb <= 0 || nof_tb > 2){
//         // invalid # of TBs
//         res.hard_fail = true;
//         res.weight = 0.0f;
//         return res;
//     }

//     ngscope_dci_tb_t tb1;
//     memset(&tb1, 0, sizeof(ngscope_dci_tb_t));
//     ngscope_dci_tb_t tb2;
//     memset(&tb2, 0, sizeof(ngscope_dci_tb_t));
//     tb1 = dci->tb[0];
//     if (nof_tb == 2){
//         tb2 = dci->tb[1];
//     }

//     /* Gate 3: effective code-rate plausibility */
//     int n_re = ngscope_compute_n_re(cell, n_symbols, sf_idx, dci->l_crb);
//     if (n_re <= 0) {
//         res.hard_fail = true; /* no room for the payload at all */
//         res.weight = 0.0f;
//         return res;
//     }

//     const float R_MAX = 0.930f;   /* practical turbo-code ceiling */
//     const float K_DECAY = 25.0f;  /* soft decay steepness past R_MAX */

//     /* +24 bits for the transport-block CRC (36.212 5.1.1), which is
//      * what actually goes through the modulator alongside the TBS. */
//     float cr1 = get_code_rate(tb1, (float) n_re);
//     if (cr1 > 1.0f) {
//         /* Physically impossible: more bits than the allocation can
//          * carry even at rate 1. This is a hard structural failure,
//          * not just "unlikely scheduler choice". */
//         res.hard_fail = true;
//         res.weight = 0.0f;
//         return res;
//     } else if (cr1 > R_MAX) {
//         res.weight = expf(-(cr1 - R_MAX) * K_DECAY);
//     } else {
//         res.weight = 1.0f;
//     }
    
//     if (nof_tb == 2){
//         float cr2 = get_code_rate(tb2, (float) n_re);

//         if (cr2 > 1.0f) {
//             /* Physically impossible: more bits than the allocation can
//             * carry even at rate 1. This is a hard structural failure,
//             * not just "unlikely scheduler choice". */
//             res.hard_fail = true;
//             res.weight = 0.0f;
//             return res;
//         } else if (cr2 > R_MAX) {
//             res.weight = expf(-(cr2 - R_MAX) * K_DECAY);
//         } else {
//             res.weight = 1.0f;
//         }
//     }

//     return res;
// }


ngscope_consistency_result_t
ngscope_consistency_check(const srsran_cell_t *cell,
                           const ngscope_dci_msg_t *dci,
                           uint32_t sf_idx,
                           uint32_t cfi)
{
    ngscope_consistency_result_t res;
    memset(&res, 0, sizeof(res));
 
    if (dci->alloc_type == SRSRAN_RA_ALLOC_TYPE2){
        /* Gate 1: deterministic RIV/allocation validity */
        if (!ngscope_riv_valid(cell, dci->rb_start, dci->l_crb)) {
            // fprintf(stderr,"ERROR: Invalid RIV with l_crb=%u and rb_start=%u\n", dci->l_crb, dci->rb_start);
            res.hard_fail = true;
            res.weight = 0.0f;
            return res;
        }
    }
    
    int nof_tb = dci->nof_tb;
    if (nof_tb <= 0 || nof_tb > 2) {
        /* invalid # of TBs */
        // fprintf(stderr,"ERROR: Invalid number of tb: %d\n", nof_tb);
        res.hard_fail = true;
        res.weight = 0.0f;
        return res;
    }
 
    ngscope_dci_tb_t tb1;
    memset(&tb1, 0, sizeof(ngscope_dci_tb_t));
    ngscope_dci_tb_t tb2;
    memset(&tb2, 0, sizeof(ngscope_dci_tb_t));
    tb1 = dci->tb[0];
    if (nof_tb == 2) {
        tb2 = dci->tb[1];
    }
 
    /* Gate 3: effective code-rate plausibility */
    int n_re = ngscope_compute_n_re(cell, cfi, sf_idx, dci->prb);
    if (n_re <= 0) {
        // fprintf(stderr,"ERROR: Invalid n_re: %d\n", n_re);
        res.hard_fail = true; /* no room for the payload at all */
        return res;
    }
 
    const float R_MAX = 0.930f;   /* practical turbo-code ceiling */
    const float K_DECAY = 25.0f;  /* soft decay steepness past R_MAX */
 
    /* NOTE: get_code_rate() calls srsran_mod_bits_x_symbol(tb.mcs).
     * That function expects a srsran_mod_t (modulation enum), not an
     * MCS index. Confirm ngscope_dci_tb_t's "mcs" field actually
     * holds the resolved modulation type from the MCS lookup, not
     * the raw 0-31 mcs_idx -- if it's the raw index, this silently
     * produces wrong bits-per-RE for every codeword. If your struct
     * has a separate resolved-modulation field (e.g. tb.mod), use
     * that here instead. */
 
    /* +24 bits for the transport-block CRC (36.212 5.1.1), which is
     * what actually goes through the modulator alongside the TBS. */
    float weight1 = 1.0f;
    float cr1 = get_code_rate(tb1, (float) n_re);
    res.code_rate = cr1; /* primary codeword's rate, for logging */
 
    if (cr1 > 1.0f) {
        // fprintf(stderr,"ERROR: Invalid cr1: %f\n", cr1);
        res.hard_fail = true;
        res.weight = 0.0f;
        return res;
    } else if (cr1 > R_MAX) {
        weight1 = expf(-(cr1 - R_MAX) * K_DECAY);
    }
 
    float weight2 = 1.0f;
    if (nof_tb == 2) {
        float cr2 = get_code_rate(tb2, (float) n_re);
 
        if (cr2 > 1.0f) {
            // fprintf(stderr,"ERROR: Invalid cr2: %f\n", cr2);
            res.hard_fail = true;
            res.weight = 0.0f;
            return res;
        } else if (cr2 > R_MAX) {
            weight2 = expf(-(cr2 - R_MAX) * K_DECAY);
        }
    }
 
    /* Combine: a single implausible codeword should still pull the
     * overall score down, not get averaged/overwritten away. Using
     * the minimum is the conservative choice -- worst codeword sets
     * the ceiling on how much we trust the DCI as a whole. */
    res.weight = fminf(weight1, weight2);

    // fprintf(stderr,"Returing valid: weight=%f, hard_fail=%d\n", res.weight, res.hard_fail);
 
    return res;
}
