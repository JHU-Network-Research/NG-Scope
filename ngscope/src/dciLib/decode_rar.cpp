#include "../../hdr/dciLib/decode_rar.h"
#include "ngscope/hdr/dciLib/ngscope_def.h"

#include "ngscope/hdr/dciLib/mac_pcap.h"
#include "srsran/mac/pdu.h"
#include "srsran/srslog/srslog.h"

#include <inttypes.h>
#include <pthread.h>
#include <string.h>

extern bool debug;

/* RA-RNTI = 1 + t_id + 10*f_id (36.321 5.1.4). f_id is always 0 on FDD, and is 0 for TDD
 * cells that configure a single PRACH frequency resource, so the useful range is 1..10.
 *
 * We deliberately do not go beyond 10: srsRAN puts SRSRAN_CRNTI_START at 0x000B, so an
 * RA-RNTI of 11..60 tests true for SRSRAN_RNTI_ISUSER() and dci_format1As_unpack() would
 * read the trailing Format1A bits with the UE-specific layout (NDI/TPC) instead of the
 * broadcast one (n_gap/n_prb1a), yielding a wrong grant and a wrong TBS. */
#define NGSCOPE_RARNTI_START 1
#define NGSCOPE_RARNTI_END 10

/* RAR blocks that matched their CRC but decoded to all zeros, per cell. The CRC starts from
 * zero, so an all-zero decode passes it; an all-zero RAR PDU parses as a lone backoff-indicator
 * subheader, so it never produced an anchor -- but it did reach the pcap as a fabricated
 * Msg2 (ny_87_broadway/buffer/earfcn-650, frame 50: 312 bytes, all zero). Counted, never
 * silent: reported by ngscope_rar_report() at teardown. */
static uint64_t rar_zero_tb[MAX_NOF_RF_DEV];


/* ------------------------------------------------ rar_pdsch-<rf>.csv and the RAR sweep
 *
 * One row per RAR transport block attempted -- i.e. per RA-RNTI DCI found -- whether it
 * passed or not. A RAR whose DCI decoded but whose block failed used to vanish without a
 * trace, and on the 4x2 capture that is 10-14% of them: a UE whose RAR fails is a UE the
 * RACH-anchored rate never sees. The row carries what the receiver knew about the subframe
 * (CFI, channel-estimate SNR, CFO and timing error, EVM) so failures can be told apart.
 *
 * NGSCOPE_RAR_SWEEP=1 (diagnostic, not a config key) additionally re-decodes every failed
 * block -- and the first RAR_SWEEP_PASSES passing ones, for comparison -- under a grid of
 * FFT-window shifts and CFO offsets, and at each CFI with the samples untouched, writing one
 * row per variant to rar_sweep-<rf>.csv. The subframe is restored exactly afterwards (the
 * samples copied back, FFT and channel estimate recomputed), so nothing downstream sees it.
 *
 * rar_sweep rows: shift/cfo_hz are the perturbation; `cfi` is 1-3 for a forced CFI on the
 * original estimate, 1xy for a fresh FFT+estimate on untouched samples (x = decoded CFI,
 * y = pass 1 or 2), 20v for estimator variant v (1 sync-error correction off, 2 average
 * estimator, 3 no smoothing filter, 4 RS CFO estimate toggled). crc: 1 pass, 0 fail,
 * 2 all-zero (not a pass), -1 decode error.
 *
 * Measured on 4x2/tmobile-5035: of 36 failed RAR blocks, 16 are genuine RARs that pass under
 * ~83% of perturbations (one consistent payload each) and 20 never pass (false-positive
 * Format1C RA-RNTI DCIs). Passing RARs pass under ~87%. So every RAR on that cell fails at
 * ~13-17% of sample alignments: marginal, not a reader or estimator-state defect. */

#define RAR_SWEEP_PASSES 30
#define RAR_SWEEP_MAX_SHIFT 10

static FILE*           rar_pdsch_fd[MAX_NOF_RF_DEV];
static FILE*           rar_sweep_fd[MAX_NOF_RF_DEV];
static pthread_mutex_t rar_pdsch_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t        rar_attempts[MAX_NOF_RF_DEV], rar_pass[MAX_NOF_RF_DEV];
static uint64_t        rar_crc_fail[MAX_NOF_RF_DEV], rar_dec_err[MAX_NOF_RF_DEV];
static uint64_t        rar_swept_pass[MAX_NOF_RF_DEV], rar_swept_fail[MAX_NOF_RF_DEV];
static uint64_t        rar_rescued[MAX_NOF_RF_DEV];

static bool rar_sweep_on(void)
{
  static int on = -1;
  if (on < 0) {
    on = getenv("NGSCOPE_RAR_SWEEP") != NULL;
  }
  return on;
}

static void rar_pdsch_row(int rf_idx, uint32_t tti, uint64_t ct, uint16_t ra_rnti, const srsran_dci_dl_t* dci,
                          const srsran_ue_dl_t* q, const srsran_dl_sf_cfg_t* sf,
                          const srsran_pdsch_cfg_t* pdsch_cfg, const srsran_pdsch_res_t* res, int crc,
                          int ladder)
{
  if (rf_idx < 0 || rf_idx >= MAX_NOF_RF_DEV) {
    return;
  }
  pthread_mutex_lock(&rar_pdsch_mutex);
  rar_attempts[rf_idx]++;
  if (crc == 1) {
    rar_pass[rf_idx]++;
  } else if (crc == 0) {
    rar_crc_fail[rf_idx]++;
  } else if (crc < 0) {
    rar_dec_err[rf_idx]++;
  } /* crc == 2, all-zero: counted in rar_zero_tb */
  if (rar_pdsch_fd[rf_idx]) {
    fprintf(rar_pdsch_fd[rf_idx],
            "%u,%" PRIu64 ",%u,%s,%u,%u,%u,%d,%d,%u,%d,%d,%.3f,%.2f,%.1f,%.3f,%.1f,%u,%u\n",
            tti, ct, ra_rnti, srsran_dci_format_string(dci->format), pdsch_cfg->grant.nof_prb,
            pdsch_cfg->grant.tb[0].mcs_idx, (unsigned)pdsch_cfg->grant.tb[0].tbs, pdsch_cfg->grant.tb[0].rv,
            (int)pdsch_cfg->grant.tx_scheme, sf->cfi, crc, ladder, res ? res->evm : -1.0f, q->chest_res.snr_db,
            15000.0f * q->chest_res.cfo, q->chest_res.sync_error, q->chest_res.rsrp_dbm,
            dci->location.ncce, dci->location.L);
  }
  pthread_mutex_unlock(&rar_pdsch_mutex);
}

/* Decode the RAR block of `dci` on the current FFT/estimate. 1 pass, 0 CRC fail, -1 error. */
static int rar_decode_once(srsran_ue_dl_t* q, srsran_dl_sf_cfg_t* sf, srsran_ue_dl_cfg_t* cfg,
                           srsran_pdsch_cfg_t* pdsch_cfg, srsran_dci_dl_t* dci,
                           uint8_t* data[SRSRAN_MAX_CODEWORDS], srsran_pdsch_res_t* res)
{
  if (srsran_ue_dl_dci_to_pdsch_grant(q, sf, cfg, dci, &pdsch_cfg->grant)) {
    return -1;
  }
  for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
    if (pdsch_cfg->grant.tb[i].enabled) {
      if (pdsch_cfg->grant.tb[i].rv < 0) {
        pdsch_cfg->grant.tb[i].rv = 0;
      }
      srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
    }
  }
  memset(res, 0, sizeof(srsran_pdsch_res_t) * SRSRAN_MAX_CODEWORDS);
  for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
    if (pdsch_cfg->grant.tb[tb].enabled) {
      res[tb].payload = data[tb];
    }
  }
  if (srsran_ue_dl_decode_pdsch(q, sf, pdsch_cfg, res)) {
    return -1;
  }
  if (!(res[0].crc && pdsch_cfg->grant.tb[0].tbs > 0)) {
    return 0;
  }
  /* 2 = matched its CRC but all zeros: not a pass (see decode_rar_for_rnti). */
  for (int i = 0; i < pdsch_cfg->grant.tb[0].tbs / 8; i++) {
    if (res[0].payload[i]) {
      return 1;
    }
  }
  return 2;
}

/* Write orig, shifted by `shift` samples (FFT window later for shift > 0, zero-padded at the
 * edge) and rotated by -cfo_hz, into the receive buffers ue_dl's FFT reads. */
void ngscope_sf_perturb(srsran_ue_dl_t* q, cf_t* const orig[SRSRAN_MAX_PORTS], int shift, double cfo_hz)
{
  const uint32_t sf_len = SRSRAN_SF_LEN_PRB(q->cell.nof_prb);
  const double   fs     = (double)srsran_sampling_freq_hz(q->cell.nof_prb);
  for (uint32_t a = 0; a < q->nof_rx_antennas; a++) {
    cf_t* buf = q->fft[a].cfg.in_buffer;
    for (uint32_t n = 0; n < sf_len; n++) {
      const int m = (int)n + shift;
      cf_t      x = (m >= 0 && m < (int)sf_len) ? orig[a][m] : 0;
      if (cfo_hz != 0) {
        const double ph = -2.0 * M_PI * cfo_hz * (double)n / fs;
        cf_t         rot;
        __real__ rot = (float)cos(ph);
        __imag__ rot = (float)sin(ph);
        x *= rot;
      }
      buf[n] = x;
    }
  }
  /* New IQ in the input buffer. Without this the FFT reuse cache (srsran_ue_dl_set_fft_reuse)
   * matched the subframe's key and returned the unperturbed estimate, so every ladder rung and
   * sweep point decoded the original samples again; NGSCOPE_VERIFY_FFT_CACHE=1 aborts on it. */
  srsran_ue_dl_new_subframe(q);
}

void ngscope_sf_snapshot(srsran_ue_dl_t* q, cf_t* orig[SRSRAN_MAX_PORTS])
{
  const uint32_t sf_len = SRSRAN_SF_LEN_PRB(q->cell.nof_prb);
  for (uint32_t a = 0; a < SRSRAN_MAX_PORTS; a++) {
    orig[a] = NULL;
  }
  for (uint32_t a = 0; a < q->nof_rx_antennas; a++) {
    orig[a] = srsran_vec_cf_malloc(sf_len);
    memcpy(orig[a], q->fft[a].cfg.in_buffer, sizeof(cf_t) * sf_len);
  }
}

void ngscope_sf_restore(srsran_ue_dl_t* q, srsran_dl_sf_cfg_t* sf, srsran_ue_dl_cfg_t* cfg,
                        cf_t* orig[SRSRAN_MAX_PORTS], uint32_t cfi0)
{
  const uint32_t sf_len = SRSRAN_SF_LEN_PRB(q->cell.nof_prb);
  for (uint32_t a = 0; a < q->nof_rx_antennas; a++) {
    memcpy(q->fft[a].cfg.in_buffer, orig[a], sizeof(cf_t) * sf_len);
    free(orig[a]);
    orig[a] = NULL;
  }
  srsran_ue_dl_new_subframe(q); /* the buffer changed again: recompute, never reuse */
  srsran_ue_dl_decode_fft_estimate(q, sf, cfg);
  sf->cfi = cfi0;
}

/* ------------------------------------------------------------------------- RAR ladder
 *
 * A RAR block that fails its CRC is re-decoded on slightly perturbed samples before it is
 * given up. Measured (rar_sweep, 4x2/tmobile-5035): every genuine RAR on that cell fails at
 * roughly 1 in 7 sample alignments -- passing RARs survive ~87% of +/-10-sample / +/-1 kHz
 * perturbations, the failed genuine ones pass under ~83% -- so a failure at one alignment is
 * mostly bad luck, and a second look usually lands. Each rung alone rescued 15, 14 and 16 of
 * the 16 genuine failures there. Rungs are deliberately generic small perturbations, not the
 * single best-fitting point on that one capture.
 *
 * Sound because the CRC still decides: a rung is accepted only on a CRC24A pass with a
 * non-zero payload, so three extra tries raise the false-pass odds from ~2^-24 to ~2^-22.4 per
 * DCI. The 20 false-positive RA-RNTI DCIs on that capture never pass under any variant.
 * The subframe is restored exactly afterwards (samples, FFT, channel estimate). Every rescue
 * is counted per rung and marked in rar_pdsch-<rf>.csv (`ladder`). */
static const struct {
  int    shift;
  double cfo_hz;
} RAR_LADDER[] = {{2, 0.0}, {0, 100.0}, {-4, -500.0}};
#define RAR_LADDER_LEN (int)(sizeof(RAR_LADDER) / sizeof(RAR_LADDER[0]))
static uint64_t rar_ladder_tried[MAX_NOF_RF_DEV];
static uint64_t rar_ladder_rescued[MAX_NOF_RF_DEV][4];

/* Returns the 1-based rung that passed, or -1. On success data[0] holds the payload and
 * pdsch_cfg->grant the block's grant; ue_dl state is the original subframe's either way. */
static int rar_ladder(srsran_ue_dl_t* q, srsran_dl_sf_cfg_t* sf, srsran_ue_dl_cfg_t* cfg,
                      srsran_pdsch_cfg_t* pdsch_cfg, srsran_dci_dl_t* dci, uint8_t* data[SRSRAN_MAX_CODEWORDS],
                      srsran_pdsch_res_t* res, int rf_idx)
{
  const uint32_t sf_len = SRSRAN_SF_LEN_PRB(q->cell.nof_prb);
  cf_t*          orig[SRSRAN_MAX_PORTS] = {};
  for (uint32_t a = 0; a < q->nof_rx_antennas; a++) {
    orig[a] = srsran_vec_cf_malloc(sf_len);
    memcpy(orig[a], q->fft[a].cfg.in_buffer, sizeof(cf_t) * sf_len);
  }
  const uint32_t cfi0 = sf->cfi;
  int            won  = -1;
  for (int k = 0; k < RAR_LADDER_LEN && won < 0; k++) {
    ngscope_sf_perturb(q, orig, RAR_LADDER[k].shift, RAR_LADDER[k].cfo_hz);
    srsran_ue_dl_decode_fft_estimate(q, sf, cfg);
    sf->cfi = cfi0; /* the CFI the DCI was found under; the PDSCH region follows it */
    if (rar_decode_once(q, sf, cfg, pdsch_cfg, dci, data, res) == 1) {
      won = k + 1;
    }
  }
  /* Restore the subframe for everything decoded after this. The payload in data[0] is
   * untouched by the FFT/estimate. */
  for (uint32_t a = 0; a < q->nof_rx_antennas; a++) {
    memcpy(q->fft[a].cfg.in_buffer, orig[a], sizeof(cf_t) * sf_len);
    free(orig[a]);
  }
  srsran_ue_dl_new_subframe(q); /* see ngscope_sf_perturb() */
  srsran_ue_dl_decode_fft_estimate(q, sf, cfg);
  sf->cfi = cfi0;
  if (won > 0) {
    /* rar_decode_once rebuilt the grant from the same DCI and CFI; nothing to restore. */
  } else {
    srsran_ue_dl_dci_to_pdsch_grant(q, sf, cfg, dci, &pdsch_cfg->grant);
  }

  if (rf_idx >= 0 && rf_idx < MAX_NOF_RF_DEV) {
    pthread_mutex_lock(&rar_pdsch_mutex);
    rar_ladder_tried[rf_idx]++;
    if (won > 0) {
      rar_ladder_rescued[rf_idx][won]++;
    }
    pthread_mutex_unlock(&rar_pdsch_mutex);
  }
  return won;
}

static void rar_sweep(srsran_ue_dl_t* q, srsran_dl_sf_cfg_t* sf, srsran_ue_dl_cfg_t* cfg,
                      srsran_pdsch_cfg_t* pdsch_cfg, srsran_dci_dl_t* dci, uint8_t* data[SRSRAN_MAX_CODEWORDS],
                      int rf_idx, uint32_t tti, uint64_t ct, int base_crc)
{
  if (rf_idx < 0 || rf_idx >= MAX_NOF_RF_DEV || rar_sweep_fd[rf_idx] == NULL) {
    return;
  }
  pthread_mutex_lock(&rar_pdsch_mutex);
  const bool take = base_crc != 1 || rar_swept_pass[rf_idx] < RAR_SWEEP_PASSES;
  if (take) {
    (base_crc == 1 ? rar_swept_pass : rar_swept_fail)[rf_idx]++;
  }
  pthread_mutex_unlock(&rar_pdsch_mutex);
  if (!take) {
    return;
  }

  const uint32_t nof_rx = q->nof_rx_antennas;
  const uint32_t sf_len = SRSRAN_SF_LEN_PRB(q->cell.nof_prb);
  const double   fs     = (double)srsran_sampling_freq_hz(q->cell.nof_prb);
  cf_t*          buf[SRSRAN_MAX_PORTS] = {};
  cf_t*          orig[SRSRAN_MAX_PORTS] = {};
  for (uint32_t a = 0; a < nof_rx; a++) {
    buf[a]  = q->fft[a].cfg.in_buffer;
    orig[a] = srsran_vec_cf_malloc(sf_len);
    memcpy(orig[a], buf[a], sizeof(cf_t) * sf_len);
  }
  const uint32_t cfi0 = sf->cfi;
  srsran_pdsch_res_t res[SRSRAN_MAX_CODEWORDS];
  static const float CFOS[] = {-1000, -500, -250, -100, 0, 100, 250, 500, 1000};
  bool rescued = false;

  char rows[1 << 16];
  size_t used = 0;
  /* CFI with the samples untouched */
  for (uint32_t cfi = 1; cfi <= 3; cfi++) {
    sf->cfi = cfi;
    int c = rar_decode_once(q, sf, cfg, pdsch_cfg, dci, data, res);
    used += snprintf(rows + used, sizeof(rows) - used, "%u,%" PRIu64 ",%d,0,0,%u,%d,%.3f\n", tti, ct, base_crc,
                     cfi, c, res[0].evm);
  }
  /* Fresh FFT + estimate on the untouched samples, twice: does recomputing alone change the
   * verdict? Marked shift=0 cfo=0 with cfi = 100 + pass number. */
  for (int pass = 1; pass <= 2; pass++) {
    srsran_ue_dl_new_subframe(q); /* a fresh FFT is the point of this pass */
    srsran_ue_dl_decode_fft_estimate(q, sf, cfg);
    const uint32_t cfi_fresh = sf->cfi;
    sf->cfi = cfi0;
    int c = rar_decode_once(q, sf, cfg, pdsch_cfg, dci, data, res);
    rescued |= (c == 1 && base_crc != 1);
    used += snprintf(rows + used, sizeof(rows) - used, "%u,%" PRIu64 ",%d,0,0,%d,%d,%.3f\n", tti, ct, base_crc,
                     100 + pass + 10 * (int)cfi_fresh, c, res[0].evm);
  }
  /* Estimator settings varied one at a time on the untouched samples. Marked shift=0 cfo=0,
   * cfi = 200 + variant: 1 sync-error correction off, 2 average estimator, 3 no smoothing
   * filter, 4 RS-based CFO estimate on. */
  for (int v = 1; v <= 4; v++) {
    const srsran_chest_dl_cfg_t saved = cfg->chest_cfg;
    if (v == 1) cfg->chest_cfg.sync_error_enable = false;
    if (v == 2) cfg->chest_cfg.estimator_alg = SRSRAN_ESTIMATOR_ALG_AVERAGE;
    if (v == 3) cfg->chest_cfg.filter_type = SRSRAN_CHEST_FILTER_NONE;
    if (v == 4) cfg->chest_cfg.cfo_estimate_enable = !cfg->chest_cfg.cfo_estimate_enable;
    srsran_ue_dl_decode_fft_estimate(q, sf, cfg);
    sf->cfi = cfi0;
    int c = rar_decode_once(q, sf, cfg, pdsch_cfg, dci, data, res);
    cfg->chest_cfg = saved;
    used += snprintf(rows + used, sizeof(rows) - used, "%u,%" PRIu64 ",%d,0,0,%d,%d,%.3f,%.3f\n", tti, ct, base_crc,
                     200 + v, c, res[0].evm, q->chest_res.sync_error);
  }
  /* timing x CFO, CFI held at the decoded value */
  for (int shift = -RAR_SWEEP_MAX_SHIFT; shift <= RAR_SWEEP_MAX_SHIFT; shift++) {
    for (size_t k = 0; k < sizeof(CFOS) / sizeof(CFOS[0]); k++) {
      if (shift == 0 && CFOS[k] == 0) {
        continue; /* that is the baseline, already covered by the CFI row */
      }
      ngscope_sf_perturb(q, orig, shift, CFOS[k]);
      srsran_ue_dl_decode_fft_estimate(q, sf, cfg);
      sf->cfi = cfi0;
      int c = rar_decode_once(q, sf, cfg, pdsch_cfg, dci, data, res);
      rescued |= (c == 1 && base_crc != 1);
      if (sizeof(rows) - used > 128) {
        used += snprintf(rows + used, sizeof(rows) - used, "%u,%" PRIu64 ",%d,%d,%.0f,%u,%d,%.3f,%02x%02x%02x%02x\n",
                         tti, ct, base_crc, shift, CFOS[k], cfi0, c, res[0].evm, data[0][0], data[0][1], data[0][2],
                         data[0][3]);
      }
    }
  }

  /* Restore exactly: samples, then the FFT and estimate every later stage reads. */
  for (uint32_t a = 0; a < nof_rx; a++) {
    memcpy(buf[a], orig[a], sizeof(cf_t) * sf_len);
    free(orig[a]);
  }
  srsran_ue_dl_new_subframe(q); /* see ngscope_sf_perturb() */
  srsran_ue_dl_decode_fft_estimate(q, sf, cfg);
  sf->cfi = cfi0;

  pthread_mutex_lock(&rar_pdsch_mutex);
  if (rescued) {
    rar_rescued[rf_idx]++;
  }
  fwrite(rows, 1, used, rar_sweep_fd[rf_idx]);
  pthread_mutex_unlock(&rar_pdsch_mutex);
}

/* Decode every RAR carried by a single RA-RNTI in this subframe.
 * Appends to out[] and returns the number of records added. */
// JH TODO go through args and confirm what is necessary
static int decode_rar_for_rnti(srsran_ue_dl_t*     q,
                               srsran_dl_sf_cfg_t* sf,
                               srsran_ue_dl_cfg_t* cfg,
                               srsran_pdsch_cfg_t* pdsch_cfg,
                               uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                               uint16_t            ra_rnti,
                               ngscope_rar_t       out[NGSCOPE_MAX_RAR_PER_SF],
                               int                 nof_out,
                               int                 rf_idx,
                               uint64_t            ts_us,
                               uint64_t            collection_time)
{
  srsran_dci_dl_t    dci_dl[SRSRAN_MAX_DCI_MSG] = {};
  srsran_pdsch_res_t pdsch_res[SRSRAN_MAX_CODEWORDS];

  /* Targeted search in the common search space. The CRC is checked against ra_rnti and a
   * re-encode correlation of at least 0.5 is required, so a hit here is already strong. */
  int nof_dci = srsran_ue_dl_find_dl_dci_sirnti(q, sf, cfg, ra_rnti, dci_dl);
  if (nof_dci <= 0) {
    return 0;
  }

  int added = 0;

  for (int d = 0; d < nof_dci && (nof_out + added) < NGSCOPE_MAX_RAR_PER_SF; d++) {
    pdsch_cfg->rnti = ra_rnti;

    if (srsran_ue_dl_dci_to_pdsch_grant(q, sf, cfg, &dci_dl[d], &pdsch_cfg->grant)) {
      continue;
    }

    /* Format1A carries an explicit RV; Format1C leaves rv at -1 and
     * srsran_ra_dl_dci_to_grant() has already forced it to 0 for an RA-RNTI. This is only
     * a guard against an unset value -- do not derive an RV from the SFN the way the SIB
     * path does, that rule is specific to SI-RNTI. */
    for (int i = 0; i < SRSRAN_MAX_CODEWORDS; i++) {
      if (pdsch_cfg->grant.tb[i].enabled) {
        if (pdsch_cfg->grant.tb[i].rv < 0) {
          pdsch_cfg->grant.tb[i].rv = 0;
        }
        srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[i], (uint32_t)pdsch_cfg->grant.tb[i].tbs);
      }
    }

    bool decode_enable = false;
    ZERO_OBJECT(pdsch_res);
    for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
      if (pdsch_cfg->grant.tb[tb].enabled) {
        decode_enable         = true;
        pdsch_res[tb].payload = data[tb];
        pdsch_res[tb].crc     = false;
      }
    }
    if (!decode_enable) {
      continue;
    }

    if (srsran_ue_dl_decode_pdsch(q, sf, pdsch_cfg, pdsch_res)) {
      rar_pdsch_row(rf_idx, sf->tti, collection_time, ra_rnti, &dci_dl[d], q, sf, pdsch_cfg, NULL, -1, 0);
      if (rar_sweep_on()) {
        rar_sweep(q, sf, cfg, pdsch_cfg, &dci_dl[d], data, rf_idx, sf->tti, collection_time, -1);
      }
      continue;
    }

    int tbs = pdsch_cfg->grant.tb[0].tbs;
    int crc_ok = (pdsch_res[0].crc && tbs > 0) ? 1 : 0;
    /* An all-zero block matches its zero-initialised CRC without carrying anything, so it is
     * not a pass: logged as crc=2 and counted below. */
    bool all_zero = crc_ok;
    for (int i = 0; all_zero && i < tbs / 8; i++) {
      all_zero = (pdsch_res[0].payload[i] == 0);
    }
    if (all_zero) {
      crc_ok = 0;
      if (rf_idx >= 0 && rf_idx < MAX_NOF_RF_DEV) {
        __atomic_fetch_add(&rar_zero_tb[rf_idx], 1, __ATOMIC_RELAXED);
      }
    }
    /* The sweep (diagnostic) studies the block as first decoded, so it runs before the
     * ladder changes anything; the ladder then decides what the run keeps. */
    const int crc_first = all_zero ? 2 : crc_ok;
    int       ladder    = 0;
    if (rar_sweep_on()) {
      static __thread uint8_t keep[SRSRAN_MAX_BUFFER_SIZE_BYTES];
      if (crc_ok) {
        memcpy(keep, pdsch_res[0].payload, (size_t)tbs / 8);
      }
      rar_sweep(q, sf, cfg, pdsch_cfg, &dci_dl[d], data, rf_idx, sf->tti, collection_time, crc_ok);
      srsran_ue_dl_dci_to_pdsch_grant(q, sf, cfg, &dci_dl[d], &pdsch_cfg->grant);
      if (crc_ok) {
        memcpy(pdsch_res[0].payload, keep, (size_t)tbs / 8);
      }
    }
    if (!crc_ok) {
      ladder = rar_ladder(q, sf, cfg, pdsch_cfg, &dci_dl[d], data, pdsch_res, rf_idx);
      if (ladder > 0) {
        crc_ok = 1;
        tbs    = pdsch_cfg->grant.tb[0].tbs;
      }
    }
    rar_pdsch_row(rf_idx, sf->tti, collection_time, ra_rnti, &dci_dl[d], q, sf, pdsch_cfg, &pdsch_res[0],
                  crc_ok ? 1 : crc_first, crc_first == 1 ? 0 : ladder);
    if (!crc_ok) {
      continue;
    }

    /* Msg2 is a real downlink MAC PDU and it is the moment a UE gets its identity, so it is
     * worth having in the capture. Emitted before the parse below, which consumes nothing. */
    ngscope_mac_tb_t cap;
    memset(&cap, 0, sizeof(cap));
    cap.rf_idx          = rf_idx;
    cap.tti             = sf->tti;
    cap.ts_us           = ts_us;
    cap.collection_time = collection_time;
    cap.rnti            = ra_rnti;
    cap.src             = NGSCOPE_MAC_SRC_RAR;
    cap.rv              = pdsch_cfg->grant.tb[0].rv;
    cap.mcs             = pdsch_cfg->grant.tb[0].mcs_idx;
    cap.tbs             = tbs;
    cap.prb             = pdsch_cfg->grant.nof_prb;
    cap.format          = dci_dl[d].format;
    cap.tx_scheme       = pdsch_cfg->grant.tx_scheme;
    cap.rach_ok         = true; /* RA-RNTI is exempt from the RACH filter by definition */
    cap.evm             = pdsch_res[0].evm;
    cap.payload         = pdsch_res[0].payload;
    cap.len             = (uint32_t)tbs / 8;
    ngscope_mac_pcap_write(&cap);

    /* MAC RAR PDU, 36.321 6.1.5 / 6.2.2 / 6.2.3 */
    srsran::rar_pdu pdu(NGSCOPE_MAX_RAR_PER_SF);
    pdu.init_rx((uint32_t)tbs / 8);
    if (pdu.parse_packet(pdsch_res[0].payload) != SRSRAN_SUCCESS) {
      continue;
    }

    while (pdu.next() && (nof_out + added) < NGSCOPE_MAX_RAR_PER_SF) {
      srsran::rar_subh* subh = pdu.get();
      if (subh == NULL || !subh->has_rapid()) {
        continue; // backoff indicator subheader, no RNTI in it
      }

      ngscope_rar_t* r = &out[nof_out + added];
      memset(r, 0, sizeof(ngscope_rar_t));

      r->ra_rnti    = ra_rnti;
      r->rapid      = subh->get_rapid();
      r->ta_cmd     = subh->get_ta_cmd();
      r->temp_crnti = subh->get_temp_crnti();
      subh->get_sched_grant(r->ul_grant);

      /* rar_subh stores the grant one bit per byte, which is exactly what
       * srsran_dci_rar_unpack() expects -- no repacking needed. */
      srsran_dci_rar_grant_t grant = {};
      srsran_dci_rar_unpack(r->ul_grant, &grant);
      r->grant_rba = grant.rba;
      r->grant_mcs = grant.trunc_mcs;

      r->tbs = tbs;
      r->crc = 1;

      if (debug) {
        printf("RAR: tti=%d ra_rnti=%d rapid=%d temp_crnti=%d ta=%d tbs=%d\n",
               sf->tti,
               r->ra_rnti,
               r->rapid,
               r->temp_crnti,
               r->ta_cmd,
               r->tbs);
      }

      added++;
    }
  }

  return added;
}

// JH TODO go through args and confirm what is necessary
int srsran_ue_dl_find_and_decode_rar(srsran_ue_dl_t*     q,
                                     srsran_dl_sf_cfg_t* sf,
                                     srsran_ue_dl_cfg_t* cfg,
                                     srsran_pdsch_cfg_t* pdsch_cfg,
                                     uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                                     ngscope_rar_t       out[NGSCOPE_MAX_RAR_PER_SF],
                                     int                 rf_idx,
                                     uint64_t            ts_us,
                                     uint64_t            collection_time)
{
  if (q == NULL || sf == NULL || cfg == NULL || pdsch_cfg == NULL || data == NULL || out == NULL) {
    return SRSRAN_ERROR_INVALID_INPUTS;
  }

  /* RARs ride on a normal DL subframe only */
  if (sf->sf_type != SRSRAN_SF_NORM) {
    return 0;
  }
  if (q->cell.frame_type == SRSRAN_TDD && sf->tdd_config.configured &&
      srsran_sfidx_tdd_type(sf->tdd_config, sf->tti % 10) == SRSRAN_TDD_SF_U) {
    return 0;
  }

  /* The RAR grant is a common-search-space Format1A/1C message, decoded like a broadcast
   * one: single-antenna-port TM and the base TBS table. Save what we touch so the caller's
   * configuration is unchanged on return. */
  uint16_t    saved_rnti     = pdsch_cfg->rnti;
  srsran_tm_t saved_tm       = cfg->cfg.tm;
  bool        saved_tbs_alt  = cfg->cfg.pdsch.use_tbs_index_alt;

  cfg->cfg.tm                      = SRSRAN_TM1;
  cfg->cfg.pdsch.use_tbs_index_alt = false;

  uint32_t mi_set_len;
  if (q->cell.frame_type == SRSRAN_TDD && !sf->tdd_config.configured) {
    mi_set_len = 3;
  } else {
    mi_set_len = 1;
  }

  int nof_out = 0;
  int ret     = 0;

  /* Blind search PHICH mi value, as the SIB path does */
  for (uint32_t i = 0; i < mi_set_len && nof_out == 0; i++) {
    if (mi_set_len == 1) {
      srsran_ue_dl_set_mi_auto(q);
    } else {
      srsran_ue_dl_set_mi_manual(q, i);
    }

    if ((ret = srsran_ue_dl_decode_fft_estimate(q, sf, cfg)) < 0) {
      break;
    }

    for (uint16_t ra_rnti = NGSCOPE_RARNTI_START; ra_rnti <= NGSCOPE_RARNTI_END; ra_rnti++) { // JH TODO confirm RA-RNTI range in spec
      nof_out += decode_rar_for_rnti(q, sf, cfg, pdsch_cfg, data, ra_rnti, out, nof_out,
                                     rf_idx, ts_us, collection_time);
      if (nof_out >= NGSCOPE_MAX_RAR_PER_SF) {
        break;
      }
    }
  }

  pdsch_cfg->rnti                  = saved_rnti;
  cfg->cfg.tm                      = saved_tm;
  cfg->cfg.pdsch.use_tbs_index_alt = saved_tbs_alt;

  if (ret < 0 && nof_out == 0) {
    return ret;
  }
  return nof_out;
}

/************************ rar_log-<rf_idx>.csv ************************/

#define RAR_LOG_HEADER                                                                                                 \
  "timestamp,collection_time,tti,rf_idx,ra_rnti,rapid,temp_crnti,ta_cmd,grant_rba,grant_mcs,ul_grant,tbs,crc\n"

/* One file per RF device, appended by that device's decoder threads. */
static pthread_mutex_t rar_log_mutex[MAX_NOF_RF_DEV] = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_MUTEX_INITIALIZER,
};

static void rar_log_path(char* buf, size_t len, const char* out_path, int rf_idx)
{
  /* out_path already carries its trailing '/' -- see main.c */
  snprintf(buf, len, "%srar_log-%d.csv", out_path, rf_idx);
}

static pthread_once_t srslog_once = PTHREAD_ONCE_INIT;

/* srsran::rar_pdu logs through srslog when it meets a malformed PDU. ngscope never starts
 * the srslog backend, so do it here -- otherwise those entries pile up in a queue that
 * nobody drains. */
static void srslog_start(void)
{
  srslog::init();
}

void ngscope_rar_log_init(const char* out_path, int rf_idx)
{
  pthread_once(&srslog_once, srslog_start);

  if (out_path == NULL || rf_idx < 0 || rf_idx >= MAX_NOF_RF_DEV) {
    return;
  }

  char path[1024];
  rar_log_path(path, sizeof(path), out_path, rf_idx);

  pthread_mutex_lock(&rar_log_mutex[rf_idx]);
  FILE* f = fopen(path, "w");
  if (f != NULL) {
    fprintf(f, RAR_LOG_HEADER);
    fclose(f);
  } else {
    printf("ERROR: cannot create RAR log %s\n", path);
  }
  pthread_mutex_unlock(&rar_log_mutex[rf_idx]);

  /* Header first, so an empty file reads as "attempted none", not "never written". */
  snprintf(path, sizeof(path), "%srar_pdsch-%d.csv", out_path, rf_idx);
  rar_pdsch_fd[rf_idx] = fopen(path, "w");
  if (rar_pdsch_fd[rf_idx]) {
    fprintf(rar_pdsch_fd[rf_idx], "tti,ct,ra_rnti,format,nof_prb,mcs,tbs,rv,tx_scheme,cfi,crc,ladder,evm,snr_db,"
                                  "cfo_hz,sync_error,rsrp_dbm,ncce,L\n");
  }
  if (rar_sweep_on()) {
    snprintf(path, sizeof(path), "%srar_sweep-%d.csv", out_path, rf_idx);
    rar_sweep_fd[rf_idx] = fopen(path, "w");
    if (rar_sweep_fd[rf_idx]) {
      fprintf(rar_sweep_fd[rf_idx], "tti,ct,base_crc,shift,cfo_hz,cfi,crc,evm,head\n");
    }
    printf("RAR SWEEP: on -- every failed RAR block and the first %d passing ones are re-decoded "
           "under timing/CFO/CFI variants\n", RAR_SWEEP_PASSES);
  }
}

void ngscope_rar_log_write(const char*          out_path,
                           int                  rf_idx,
                           uint32_t             tti,
                           uint64_t             timestamp,
                           uint64_t             collection_time,
                           const ngscope_rar_t* rar)
{
  if (out_path == NULL || rar == NULL || rf_idx < 0 || rf_idx >= MAX_NOF_RF_DEV) {
    return;
  }

  /* The 20 grant bits, MSB first, as a hex string */
  uint32_t grant_bits = 0;
  for (int i = 0; i < SRSRAN_RAR_GRANT_LEN; i++) {
    grant_bits = (grant_bits << 1) | (rar->ul_grant[i] ? 1u : 0u);
  }

  char path[1024];
  rar_log_path(path, sizeof(path), out_path, rf_idx);

  pthread_mutex_lock(&rar_log_mutex[rf_idx]);
  FILE* f = fopen(path, "a");
  if (f != NULL) {
    fprintf(f,
            "%" PRIu64 ",%" PRIu64 ",%u,%d,%u,%u,%u,%u,%u,%u,0x%05x,%d,%d\n",
            timestamp,
            collection_time,
            tti,
            rf_idx,
            rar->ra_rnti,
            rar->rapid,
            rar->temp_crnti,
            rar->ta_cmd,
            rar->grant_rba,
            rar->grant_mcs,
            grant_bits,
            rar->tbs,
            rar->crc);
    fclose(f);
  }
  pthread_mutex_unlock(&rar_log_mutex[rf_idx]);
}

void ngscope_rar_report(int rf_idx)
{
  if (rf_idx < 0 || rf_idx >= MAX_NOF_RF_DEV) {
    return;
  }
  printf("RAR (cell %d): %" PRIu64 " decoded RAR blocks rejected as all-zero (CRC matched, "
         "never a real MAC PDU)\n",
         rf_idx, __atomic_load_n(&rar_zero_tb[rf_idx], __ATOMIC_RELAXED));
  pthread_mutex_lock(&rar_pdsch_mutex);
  printf("RAR (cell %d): %" PRIu64 " RAR blocks attempted (one per RA-RNTI DCI found): %" PRIu64
         " passed, %" PRIu64 " failed CRC, %" PRIu64 " all-zero, %" PRIu64
         " decode errors -- every one in rar_pdsch-%d.csv\n",
         rf_idx, rar_attempts[rf_idx], rar_pass[rf_idx], rar_crc_fail[rf_idx],
         (uint64_t)__atomic_load_n(&rar_zero_tb[rf_idx], __ATOMIC_RELAXED), rar_dec_err[rf_idx], rf_idx);
  printf("RAR LADDER (cell %d): %" PRIu64 " failed blocks re-decoded; rescued %" PRIu64 " by +2 samples, %" PRIu64
         " by +100 Hz, %" PRIu64 " by -4 samples/-500 Hz (CRC-checked, non-zero)\n",
         rf_idx, rar_ladder_tried[rf_idx], rar_ladder_rescued[rf_idx][1], rar_ladder_rescued[rf_idx][2],
         rar_ladder_rescued[rf_idx][3]);
  if (rar_sweep_fd[rf_idx]) {
    printf("RAR SWEEP (cell %d): %" PRIu64 " failed and %" PRIu64 " passing blocks swept; %" PRIu64
           " failed blocks passed under some variant -- rar_sweep-%d.csv\n",
           rf_idx, rar_swept_fail[rf_idx], rar_swept_pass[rf_idx], rar_rescued[rf_idx], rf_idx);
    fclose(rar_sweep_fd[rf_idx]);
    rar_sweep_fd[rf_idx] = NULL;
  }
  if (rar_pdsch_fd[rf_idx]) {
    fclose(rar_pdsch_fd[rf_idx]);
    rar_pdsch_fd[rf_idx] = NULL;
  }
  pthread_mutex_unlock(&rar_pdsch_mutex);
}
