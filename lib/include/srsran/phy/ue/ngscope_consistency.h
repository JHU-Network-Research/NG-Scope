// /*
//  * ngscope_consistency.h
//  *
//  * Soft consistency-validation gate for NG-Scope blind-decoded DCI.
//  * Fits between the correlation-scoring stage and the final commit
//  * decision in the tree-prune pipeline (srsran_ngscope_tree_prune_node).
//  *
//  * Conventions follow srsRAN's srsran_ra_dl.h / srsran_ra_dl.c style
//  * (srsran_cell_t, srsran_ra_dl_grant_t) so this drops in without
//  * re-deriving cell config plumbing.
//  */

// #ifndef NGSCOPE_CONSISTENCY_H
// #define NGSCOPE_CONSISTENCY_H

// #include <stdbool.h>
// #include <stdint.h>
// #include "srsran/srsran.h"


// /* ---- Minimal shape of what we need from srsRAN's own types ----
//  * These mirror fields already present in srsran_cell_t / dci_msg
//  * structs; declared narrowly here so this header is self-contained
//  * for review. In the real tree, just use the existing srsran_cell_t
//  * and srsran_ra_dl_dci_t / equivalent instead of redeclaring. */

// // typedef struct {
// //     uint32_t nof_prb;      /* N_RB_DL, e.g. 6,15,25,50,75,100 */
// //     uint32_t cp_is_ext;    /* 0 = normal CP, 1 = extended CP */
// //     uint32_t nof_ports;    /* 1, 2, or 4 antenna ports */
// // } ngscope_cell_ctx_t;

// typedef struct {
//     uint32_t rb_start;
//     uint32_t l_crb;
//     uint32_t itbs;
//     uint32_t mod_order;      /* Qm: 2=QPSK, 4=16QAM, 6=64QAM */
//     uint32_t n_symb_pdcch;   /* PDCCH control region length, 1..3(4) */
//     bool     has_csrs;       /* cell-specific RS present (always true) */
//     bool     tbs_with_crc;   /* whether TBS below already includes CRC bits handled elsewhere */
// } ngscope_dci_fields_t;

// /* Result of the consistency gate: a soft multiplicative weight in [0,1],
//  * plus a hard-fail flag for deterministic structural violations. */
// typedef struct {
//     bool  hard_fail;     /* true => RIV/allocation is structurally impossible */
//     float weight;        /* [0,1], multiply into correlation score */
//     float code_rate;     /* for logging / offline analysis */
//     int   tbs1_bits;      /* looked-up TBS, for logging */
//     int   tbs2_bits;      /* looked-up TBS, for logging */
//     float code_rate1;
//     float code_rate2;
// } ngscope_consistency_result_t;

// /* --- Public API --- */

// float get_code_rate(ngscope_dci_tb_t tb, float n_re);

// /* Validates RB_start + L_RBs against cell bandwidth (RIV consistency).
//  * Deterministic, zero false-positive cost: a legitimate scheduler can
//  * never violate this. */
// bool ngscope_riv_valid(const srsran_cell_t *cell,
//                         uint32_t rb_start, 
//                         uint32_t l_crb);

// /* TS 36.213 Table 7.1.7.2.1-1 lookup: TBS(itbs, n_prb). */
// int ngscope_get_tbs(uint32_t itbs, uint32_t n_prb);

// /* Computes N_RE available for PDSCH given control region size,
//  * CRS overhead (from nof_ports), and PBCH/PSS/SSS/PCFICH/PHICH
//  * collision in the relevant subframes. `sf_idx` and `is_mbsfn`
//  * let the caller flag subframes 0/5 (sync+PBCH) and 6 (SIB1) on
//  * FDD; extend for special subframes if you're also chasing TDD. */
// int ngscope_compute_n_re(const srsran_cell_t *cell,
//                           uint32_t nof_symbols,
//                           uint32_t sf_idx,
//                           uint32_t l_crb);

// /* Top-level gate: run RIV + code-rate checks, return combined result. */
// ngscope_consistency_result_t
// ngscope_consistency_check(const srsran_cell_t *cell,
//                            const ngscope_dci_msg_t *dci,
//                            uint32_t sf_idx,
//                             uint32_t nof_symbols);

// #endif /* NGSCOPE_CONSISTENCY_H */