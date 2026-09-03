#include "ngscope/hdr/dciLib/security_rrc.h"

extern "C" {
#include "ngscope/hdr/dciLib/security_ctx.h"
#include "ngscope/hdr/dciLib/ngscope_def.h"
}

#include "ngscope/hdr/dciLib/mac_pcap.h"

#include <pthread.h>
#include <string.h>

extern bool debug;

/* How many tracked UEs are scanned per subframe.
 *
 * ngscope_sec_tracked() fills its output in array order and stops at this cap, so anything
 * past it is not scanned at all -- and it is the same UEs every subframe, not a rotating
 * sample. Anything missed is a UE that ends up looking like it never reached security.
 *
 * The right cap differs by mode, because the consequence of being too slow differs. In live
 * capture the scheduler discards a subframe when every decoder is busy
 * (task_scheduler.c, find_idle_decoder), so overspending here costs whole subframes and the
 * loss is invisible in the output. In replay it blocks instead, so the run is lossless
 * however slow it gets and the only cost is wall time -- which makes a replay the right
 * place to spend CPU for coverage.
 *
 * 32 was below real concurrency: the tracked set peaks around 57-70 on the band 12 cell
 * measured here, so more than half were never scanned. The live cap is sized above that with
 * headroom; the replay cap matches SEC_MAX_ACTIVE, so in replay nothing tracked goes
 * unscanned. ngscope_sec_report() prints the tracked-but-unscanned count either way. */
#define SEC_MAX_SCAN_RNTI NGSCOPE_SEC_SCAN_CAP_REPLAY

static inline bool sec_rf_idx_ok(int rf_idx)
{
  return rf_idx >= 0 && rf_idx < MAX_NOF_RF_DEV;
}

/* See the header: retry a failed transport block on the other MCS->TBS table. Per device,
 * because mode is a per-rf_config setting -- one device can replay while another is live. */
static bool qam_retry_enabled[MAX_NOF_RF_DEV];

void ngscope_sec_rrc_set_qam_retry(int rf_idx, bool enable)
{
  if (sec_rf_idx_ok(rf_idx)) {
    qam_retry_enabled[rf_idx] = enable;
  }
}

/* Build the grant for one DCI on a given MCS->TBS table and decode its transport block.
 *
 * Returns 1 if the block passed CRC, 0 if it was attempted and failed, and -1 if the grant
 * could not be built or enabled no codeword. That third case is deliberately distinct: it is
 * not an attempt, and counting it as one would understate the decode rate.
 *
 * The grant is rebuilt for each table because the table is precisely what sets the transport
 * block size, and a wrong size cannot be rate-matched -- which is why the CRC can decide. */
static int decode_grant_with_table(srsran_ue_dl_t*     ue_dl,
                                   srsran_dl_sf_cfg_t* sf,
                                   srsran_ue_dl_cfg_t* cfg,
                                   srsran_pdsch_cfg_t* pdsch_cfg,
                                   srsran_dci_dl_t*    dci,
                                   uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                                   srsran_pdsch_res_t* pdsch_res,
                                   bool                use_alt)
{
  cfg->cfg.pdsch.use_tbs_index_alt = use_alt;

  if (srsran_ue_dl_dci_to_pdsch_grant(ue_dl, sf, cfg, dci, &pdsch_cfg->grant)) {
    return -1;
  }

  for (int tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
    if (pdsch_cfg->grant.tb[tb].enabled) {
      if (pdsch_cfg->grant.tb[tb].rv < 0) {
        pdsch_cfg->grant.tb[tb].rv = 0;
      }
      srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[tb],
                                     (uint32_t)pdsch_cfg->grant.tb[tb].tbs);
    }
  }

  memset(pdsch_res, 0, sizeof(srsran_pdsch_res_t) * SRSRAN_MAX_CODEWORDS);
  bool decode_enable = false;
  for (uint32_t tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
    if (pdsch_cfg->grant.tb[tb].enabled) {
      decode_enable         = true;
      pdsch_res[tb].payload = data[tb];
      pdsch_res[tb].crc     = false;
    }
  }
  if (!decode_enable) {
    return -1;
  }
  if (srsran_ue_dl_decode_pdsch(ue_dl, sf, pdsch_cfg, pdsch_res) != SRSRAN_SUCCESS) {
    return 0;
  }
  return (pdsch_res[0].crc && pdsch_cfg->grant.tb[0].tbs > 0) ? 1 : 0;
}

int ngscope_sec_scan_subframe(srsran_ue_dl_t*     ue_dl,
                              srsran_dl_sf_cfg_t* sf,
                              srsran_ue_dl_cfg_t* cfg,
                              srsran_pdsch_cfg_t* pdsch_cfg,
                              uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                              int                 rf_idx,
                              uint32_t            tti,
                              uint64_t            ts_us,
                              uint64_t            collection_time,
                              int                 scan_cap)
{
  uint16_t  rntis[SEC_MAX_SCAN_RNTI];
  const int cap = (scan_cap > 0 && scan_cap < SEC_MAX_SCAN_RNTI) ? scan_cap : SEC_MAX_SCAN_RNTI;
  int       nof_rnti = ngscope_sec_tracked(rf_idx, ts_us, rntis, cap);
  if (nof_rnti <= 0) {
    return 0;
  }

  /* Attempting a UE's PDSCH on a 4-port cell makes srsRAN's PHY complain loudly: grants
   * whose MIMO parameters it cannot build, and multiplex predecoding it has not
   * implemented. Measured over one replay: 5008 stderr lines against 1 for the same run
   * with this feature off. That is not survivable in a console, and with line-buffered
   * output it also cost roughly 5x throughput.
   *
   * Filtering the attempts is not the answer -- every variant tried (skip all Format2,
   * skip only the provably-unbuildable grants) more than halved the SecurityModeCommand
   * detections, from 18.5% of RACHing UEs to ~7%. The failing and succeeding attempts are
   * not separable in advance.
   *
   * So route PHY errors through srslog, where they are dropped absent a sink, instead of
   * stderr. The cost is bounded and measured: the same replay with this feature off
   * produced a single PHY error line, so there is next to nothing here to lose. Announced
   * rather than done silently, and only reached when the feature is switched on. */
  static bool errors_muted = false;
  if (!errors_muted) {
    errors_muted = true;
    set_handler_enabled(true);
    printf("SECURITY: probing UE transport blocks; srsRAN PHY errors are routed to srslog "
           "for the rest of this run (they would otherwise flood stderr)\n");
  }

  const uint16_t saved_rnti = pdsch_cfg->rnti;
  int            nof_written = 0;

  for (int i = 0; i < nof_rnti; i++) {
    const uint16_t rnti = rntis[i];

    /* Targeted search of this UE's search space. The CRC is checked against the RNTI, so
     * unlike the blind path a hit here cannot be a manufactured candidate. */
    srsran_dci_dl_t dci_dl[SRSRAN_MAX_DCI_MSG] = {};
    int             nof_dci = srsran_ue_dl_find_dl_dci(ue_dl, sf, cfg, rnti, dci_dl);
    if (nof_dci <= 0) {
      continue;
    }

    for (int d = 0; d < nof_dci; d++) {
      pdsch_cfg->rnti = rnti;

      /* Deliberately NOT skipping spatial-multiplexing grants. srsRAN has no multiplex
       * predecoder for 4 Tx ports, so on such a cell these attempts emit a pair of errors
       * whenever they fail -- ~3000 over a 150 s replay. But measurement showed the failing
       * and succeeding attempts are the same population: filtering them out took the
       * SecurityModeCommand detections on the mt_airy02 capture from 159 down to 2. The log
       * noise is the cheaper problem, and this whole path is opt-in. */

      srsran_pdsch_res_t pdsch_res[SRSRAN_MAX_CODEWORDS];

      /* Try the configured MCS->TBS table, then the other one if the CRC fails. cfg is this
       * decoder thread's own, but the field is read elsewhere in the thread, so restore it. */
      const bool cfg_alt  = cfg->cfg.pdsch.use_tbs_index_alt;
      bool       used_alt = cfg_alt;

      int r = decode_grant_with_table(ue_dl, sf, cfg, pdsch_cfg, &dci_dl[d], data, pdsch_res,
                                      cfg_alt);
      if (r == 0 && sec_rf_idx_ok(rf_idx) && qam_retry_enabled[rf_idx]) {
        ngscope_sec_count_tb_retry(rf_idx);
        const int r2 = decode_grant_with_table(ue_dl, sf, cfg, pdsch_cfg, &dci_dl[d], data,
                                               pdsch_res, !cfg_alt);
        if (r2 >= 0) {
          r        = r2;
          used_alt = !cfg_alt;
        }
      }
      cfg->cfg.pdsch.use_tbs_index_alt = cfg_alt;

      if (r < 0) {
        continue;   /* no buildable grant: not an attempt */
      }

      bool pdsch_ok = false;

      if (r == 1) {
        const int tbs = pdsch_cfg->grant.tb[0].tbs;
        {
          pdsch_ok = true;
          ngscope_sec_count_tb_table(rf_idx, used_alt != cfg_alt);

          /* This is the interesting traffic -- Msg4, the SecurityModeCommand and the NAS
           * that rides above them all live here, and the search was targeted, so the PDCCH
           * CRC was checked against a known RNTI and the identity is trustworthy.
           *
           * Writing it is now the whole job: nothing here parses the payload or claims
           * anything about it. tools/security_scan.py dissects the resulting pcapng with
           * Wireshark, which reassembles RLC and understands NAS -- neither of which this
           * file ever managed. A no-op unless pcap_mac is set, which
           * ngscope_config_finalize() forces on when mark_security_phase is. */
          ngscope_mac_tb_t cap;
          memset(&cap, 0, sizeof(cap));
          cap.rf_idx    = rf_idx;
          cap.tti       = tti;
          cap.ts_us     = ts_us;
          cap.collection_time = collection_time;
          cap.rnti      = rnti;
          cap.src       = NGSCOPE_MAC_SRC_TARGETED;
          cap.rv        = pdsch_cfg->grant.tb[0].rv;
          cap.mcs       = pdsch_cfg->grant.tb[0].mcs_idx;
          cap.tbs       = tbs;
          cap.prb       = pdsch_cfg->grant.nof_prb;
          cap.harq_pid  = dci_dl[d].pid;
          cap.format    = dci_dl[d].format;
          cap.tx_scheme = pdsch_cfg->grant.tx_scheme;
          cap.rach_ok   = true; /* tracked RNTIs are RAR-anchored by construction */
          cap.evm       = pdsch_res[0].evm;
          cap.payload   = pdsch_res[0].payload;
          cap.len       = (uint32_t)tbs / 8;
          ngscope_mac_pcap_write(&cap);
          nof_written++;
        }
      }

      ngscope_sec_count_attempt(rf_idx, pdsch_ok);
    }
  }

  pdsch_cfg->rnti = saved_rnti;
  return nof_written;
}
