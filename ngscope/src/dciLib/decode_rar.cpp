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

/* Decode every RAR carried by a single RA-RNTI in this subframe.
 * Appends to out[] and returns the number of records added. */
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
      continue;
    }

    int tbs = pdsch_cfg->grant.tb[0].tbs;
    if (!pdsch_res[0].crc || tbs <= 0) {
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

    for (uint16_t ra_rnti = NGSCOPE_RARNTI_START; ra_rnti <= NGSCOPE_RARNTI_END; ra_rnti++) {
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
