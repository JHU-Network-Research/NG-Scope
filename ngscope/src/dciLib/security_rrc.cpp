#include "ngscope/hdr/dciLib/security_rrc.h"

extern "C" {
#include "ngscope/hdr/dciLib/security_ctx.h"
#include "ngscope/hdr/dciLib/ngscope_def.h"
#include "ngscope/hdr/dciLib/rach_filter.h"
}

#include "ngscope/hdr/dciLib/mac_pcap.h"

#include <pthread.h>
#include <stdio.h>
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


/* ================================================================= blind-DCI probe
 *
 * See security_rrc.h for what this measures and why the transport-block CRC is the right
 * oracle. Deliberately a separate path from ngscope_sec_scan_subframe() above rather than a
 * refactor of it: that function is verified against five reference captures and writes the
 * evidence the whole security measurement rests on, and the two jobs differ -- this one
 * writes no pcap and reaches no conclusion about security.
 */

/* Walk the DL-SCH subheader region and collect its logical channel IDs.
 *
 * Needed because a passing CRC alone does not say what the block carried, and the
 * distinction matters: DRBs are configured by an RRCConnectionReconfiguration that only
 * follows a completed SecurityModeCommand, so DRB traffic is itself proof that AS security
 * was established with this cell. SRB and CCCH traffic proves no such thing.
 *
 * 36.321 6.1.2: every subheader is R/R/E/LCID, plus F/L unless it is the last subheader
 * (E == 0) or a fixed-size MAC control element. All subheaders precede all payloads, so the
 * region can be walked without decoding any payload. Bounded by both the block length and a
 * subheader count so a corrupt block cannot run away -- though a passing CRC means it is not
 * corrupt. */
#define PROBE_MAX_SUBHDR 12

static void probe_walk_lcids(const uint8_t* p, uint32_t len, char* out, size_t outlen,
                             bool* has_drb, bool* has_srb, bool* has_ccch)
{
  *has_drb = *has_srb = *has_ccch = false;
  if (outlen > 0) {
    out[0] = '\0';
  }
  if (p == NULL || len == 0) {
    return;
  }
  size_t   used = 0;
  uint32_t i    = 0;
  for (int n = 0; n < PROBE_MAX_SUBHDR && i < len; n++) {
    const int      e    = (p[i] >> 5) & 1;
    const uint32_t lcid = p[i] & 0x1F;
    i++;

    if (lcid == 0) {
      *has_ccch = true;
    } else if (lcid <= 2) {
      *has_srb = true;
    } else if (lcid <= 10) {
      *has_drb = true;
    }
    if (used + 4 < outlen) {
      used += (size_t)snprintf(out + used, outlen - used, used ? ";%u" : "%u", lcid);
    }

    /* 27..31 are fixed-size control elements and padding: no F/L field. */
    const bool fixed = (lcid >= 27);
    if (e && !fixed) {
      if (i >= len) {
        break;
      }
      i += ((p[i] >> 7) & 1) ? 2 : 1; /* F == 1 selects the 15-bit L field */
    }
    if (!e) {
      break; /* last subheader; payloads follow */
    }
  }
}

typedef struct {
  FILE*           fd;
  pthread_mutex_t mtx;
  uint64_t drb[2];   /* passing blocks carrying a DRB -- proof of established security */
  uint64_t srb[2];
  /* [rach_ok] x bucket. Three buckets, never collapsed: the test is one-sided. */
  uint64_t probed[2];
  uint64_t no_dci[2];   /* targeted search found nothing for this RNTI */
  uint64_t crc_fail[2]; /* DCI found, transport block did not decode */
  uint64_t crc_pass[2]; /* decoded -- the (RNTI, grant) pair is real */
  uint64_t bytes[2];    /* payload bytes recovered, passing blocks only */
} blind_probe_t;

static blind_probe_t blind_probe[MAX_NOF_RF_DEV];

int ngscope_sec_probe_blind_init(const char* out_path, int rf_idx)
{
  if (!sec_rf_idx_ok(rf_idx)) {
    return -1;
  }
  blind_probe_t* q = &blind_probe[rf_idx];
  char           path[1024];
  snprintf(path, sizeof(path), "%sblind_probe-%d.csv", out_path ? out_path : "", rf_idx);
  q->fd = fopen(path, "w");
  if (q->fd == NULL) {
    printf("BLIND PROBE: could not open %s\n", path);
    return -1;
  }
  pthread_mutex_init(&q->mtx, NULL);
  /* Header first, before anything that can fail: a header-only file then reads as "probed,
   * found nothing", which is a measurement, rather than as a run that never probed. */
  fprintf(q->fd, "tti,ct,rnti,rach_ok,outcome,tbs,mcs,prb,rv,fmt,lcids,ch\n");
  fflush(q->fd);
  printf("BLIND PROBE: writing %s\n", path);
  return 0;
}

void ngscope_sec_probe_blind_close(int rf_idx)
{
  if (!sec_rf_idx_ok(rf_idx) || blind_probe[rf_idx].fd == NULL) {
    return;
  }
  fclose(blind_probe[rf_idx].fd);
  blind_probe[rf_idx].fd = NULL;
}

int ngscope_sec_probe_blind(srsran_ue_dl_t*        ue_dl,
                            srsran_dl_sf_cfg_t*    sf,
                            srsran_ue_dl_cfg_t*    cfg,
                            srsran_pdsch_cfg_t*    pdsch_cfg,
                            uint8_t*               data[SRSRAN_MAX_CODEWORDS],
                            ngscope_dci_per_sub_t* dci_per_sub,
                            int                    rf_idx,
                            uint32_t               tti,
                            uint64_t               ts_us,
                            uint64_t               collection_time)
{
  (void)ts_us;
  if (!sec_rf_idx_ok(rf_idx) || dci_per_sub == NULL || blind_probe[rf_idx].fd == NULL) {
    return 0;
  }

  /* One probe per distinct RNTI per subframe. A UE with two DCIs in one subframe is one
   * identity to confirm, and probing it twice would double-count it in the rates. */
  uint16_t seen[MAX_DCI_PER_SUB];
  int      nof_seen = 0;
  for (int i = 0; i < dci_per_sub->nof_dl_dci && nof_seen < MAX_DCI_PER_SUB; i++) {
    const uint16_t rnti = dci_per_sub->dl_msg[i].rnti;
    /* SI-RNTI, P-RNTI and RA-RNTI are not UE identities; they are decoded by their own
     * paths and would not be affected by RACH filtering either way. */
    if (!ngscope_sec_is_unicast(rnti)) {
      continue;
    }
    bool dup = false;
    for (int j = 0; j < nof_seen; j++) {
      if (seen[j] == rnti) {
        dup = true;
        break;
      }
    }
    if (!dup) {
      seen[nof_seen++] = rnti;
    }
  }
  if (nof_seen == 0) {
    return 0;
  }

  blind_probe_t* q          = &blind_probe[rf_idx];
  const uint16_t saved_rnti = pdsch_cfg->rnti;
  const bool     cfg_alt    = cfg->cfg.pdsch.use_tbs_index_alt;
  int            rows       = 0;

  for (int i = 0; i < nof_seen; i++) {
    const uint16_t rnti = seen[i];
    const int      ok   = ngscope_rach_filter_pass(rf_idx, rnti) ? 1 : 0;

    /* Targeted search: the PDCCH CRC is checked against this RNTI instead of being
     * descrambled to produce one, so a hit is already meaningful. Not sufficient on its
     * own, though -- the transport block below is what confirms the grant. */
    srsran_dci_dl_t dci_dl[SRSRAN_MAX_DCI_MSG] = {};
    const int       nof_dci = srsran_ue_dl_find_dl_dci(ue_dl, sf, cfg, rnti, dci_dl);

    const char* outcome = "no_dci";
    const char* ch      = "";
    char        lcids[48] = {0};
    uint32_t    tbs = 0, mcs = 0, prb = 0;
    int         rv = 0, fmt = 0;

    if (nof_dci > 0) {
      pdsch_cfg->rnti = rnti;
      srsran_pdsch_res_t pdsch_res[SRSRAN_MAX_CODEWORDS];

      int r = decode_grant_with_table(ue_dl, sf, cfg, pdsch_cfg, &dci_dl[0], data, pdsch_res,
                                      cfg_alt);
      if (r == 0 && qam_retry_enabled[rf_idx]) {
        /* Same reasoning as the security scan: altCQI-Table-r12 is per-UE state a sniffer
         * cannot see, so a failure on one table is not evidence until the other is tried.
         * Without this the blind population would look worse than it is. */
        r = decode_grant_with_table(ue_dl, sf, cfg, pdsch_cfg, &dci_dl[0], data, pdsch_res,
                                    !cfg_alt);
      }
      cfg->cfg.pdsch.use_tbs_index_alt = cfg_alt;

      tbs     = (uint32_t)(pdsch_cfg->grant.tb[0].tbs > 0 ? pdsch_cfg->grant.tb[0].tbs : 0);
      mcs     = pdsch_cfg->grant.tb[0].mcs_idx;
      prb     = pdsch_cfg->grant.nof_prb;
      rv      = pdsch_cfg->grant.tb[0].rv;
      fmt     = (int)dci_dl[0].format;
      outcome = (r == 1) ? "crc_pass" : "crc_fail";
      if (r == 1) {
        q->bytes[ok] += tbs / 8;
        bool drb = false, srb = false, ccch = false;
        probe_walk_lcids(pdsch_res[0].payload, tbs / 8, lcids, sizeof(lcids), &drb, &srb,
                         &ccch);
        ch = drb ? "drb" : (srb ? "srb" : (ccch ? "ccch" : "other"));
        if (drb) {
          q->drb[ok]++;
        } else if (srb) {
          q->srb[ok]++;
        }
      }
    }

    pthread_mutex_lock(&q->mtx);
    q->probed[ok]++;
    if (nof_dci <= 0) {
      q->no_dci[ok]++;
    } else if (outcome[4] == 'p') { /* crc_pass */
      q->crc_pass[ok]++;
    } else {
      q->crc_fail[ok]++;
    }
    fprintf(q->fd, "%u,%llu,%u,%d,%s,%u,%u,%u,%d,%d,%s,%s\n", tti,
            (unsigned long long)collection_time, rnti, ok, outcome, tbs, mcs, prb, rv, fmt,
            lcids, ch);
    pthread_mutex_unlock(&q->mtx);
    rows++;
  }

  pdsch_cfg->rnti                  = saved_rnti;
  cfg->cfg.pdsch.use_tbs_index_alt = cfg_alt;
  return rows;
}

void ngscope_sec_probe_blind_report(int rf_idx)
{
  if (!sec_rf_idx_ok(rf_idx) || blind_probe[rf_idx].fd == NULL) {
    return;
  }
  blind_probe_t* q = &blind_probe[rf_idx];
  fflush(q->fd);

  printf("\nBLIND DCI PROBE (cell %d): is a reported DCI real?\n", rf_idx);
  printf("  Oracle is the DL-SCH CRC: PDSCH descrambling is seeded with the RNTI and the\n");
  printf("  transport-block CRC24A is not, so a pass means the (RNTI, grant) pair is real.\n");
  printf("  The test is ONE-SIDED -- a failure proves nothing, because 4-port spatial\n");
  printf("  multiplexing, the per-UE MCS->TBS table, weak signal and rv>0 all fail here too.\n");
  printf("  %-22s %14s %14s\n", "", "RACH-confirmed", "not confirmed");
  printf("  %-22s %14llu %14llu\n", "distinct RNTI-probes", (unsigned long long)q->probed[1],
         (unsigned long long)q->probed[0]);
  printf("  %-22s %14llu %14llu\n", "  no DCI found", (unsigned long long)q->no_dci[1],
         (unsigned long long)q->no_dci[0]);
  printf("  %-22s %14llu %14llu\n", "  found, CRC failed", (unsigned long long)q->crc_fail[1],
         (unsigned long long)q->crc_fail[0]);
  printf("  %-22s %14llu %14llu\n", "  CRC PASSED (real)", (unsigned long long)q->crc_pass[1],
         (unsigned long long)q->crc_pass[0]);
  for (int ok = 1; ok >= 0; ok--) {
    const double pct = q->probed[ok] ? 100.0 * (double)q->crc_pass[ok] / (double)q->probed[ok] : 0.0;
    printf("  %-22s %13.2f%%   (%llu bytes recovered)\n",
           ok ? "pass rate, confirmed" : "pass rate, unconfirmed", pct,
           (unsigned long long)q->bytes[ok]);
  }
  printf("  %-22s %14llu %14llu\n", "  of those, on a DRB", (unsigned long long)q->drb[1],
         (unsigned long long)q->drb[0]);
  printf("  %-22s %14llu %14llu\n", "  of those, SRB only", (unsigned long long)q->srb[1],
         (unsigned long long)q->srb[0]);
  printf("  A DRB is configured by an RRCConnectionReconfiguration that only follows a\n");
  printf("  completed SecurityModeCommand, so a passing DRB block is itself proof that this\n");
  printf("  UE established AS security with this cell -- the boundary simply happened before\n");
  printf("  the capture began. Those UEs are evidence FOR the cell, not missing failures.\n");
}
