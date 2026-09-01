#include "ngscope/hdr/dciLib/security_rrc.h"

extern "C" {
#include "ngscope/hdr/dciLib/security_ctx.h"
#include "ngscope/hdr/dciLib/ngscope_def.h"
}

#include "srsran/asn1/rrc/dl_ccch_msg.h"
#include "srsran/asn1/rrc/dl_dcch_msg.h"
#include "ngscope/hdr/dciLib/mac_pcap.h"
#include "srsran/mac/pdu.h"
#include "srsran/srslog/srslog.h"

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

/* SRB logical channels on DL-SCH. LCID 0 is CCCH (SRB0), which carries Msg4. */
#define SEC_LCID_CCCH 0
#define SEC_LCID_SRB1 1
#define SEC_LCID_SRB2 2

/* PDCP control-plane PDU for an SRB: 1-byte header holding a 5-bit SN, then the RRC
 * message, then a 4-byte MAC-I. Before integrity is configured the MAC-I is all zeros, but
 * the field is present either way. */
#define SEC_PDCP_SRB_HDR_LEN 1
#define SEC_PDCP_SRB_MAC_I_LEN 4

/* Unpack a DL-CCCH message (SRB0, RLC-TM, no PDCP), i.e. Msg4. Returns true if it decoded.
 *
 * Anything that unpacks here is by definition pre-security: SRB0 is never ciphered, and
 * the connection is not even set up yet. */
static bool unpack_ccch(uint8_t* sdu, uint32_t len, uint16_t rnti, uint32_t tti)
{
  asn1::cbit_ref             bref(sdu, len);
  asn1::rrc::dl_ccch_msg_s   msg;

  if (msg.unpack(bref) != asn1::SRSASN_SUCCESS) {
    return false;
  }
  if (msg.msg.type().value != asn1::rrc::dl_ccch_msg_type_c::types_opts::c1) {
    return false;
  }
  if (debug) {
    printf("DEBUG: TTI=%d rnti=%d DL-CCCH %s\n", tti, rnti, msg.msg.c1().type().to_string());
  }
  return true;
}

/* Unpack a DL-DCCH message (SRB1/SRB2) and report whether it is the SecurityModeCommand.
 *
 * This only works while the DCCH is still in the clear -- which is exactly the window we
 * care about, since SecurityModeCommand is the last unciphered downlink message. Once
 * SecurityModeComplete goes up, the unpack below starts failing, and that failure is
 * deliberately not treated as evidence of anything. */
static bool unpack_dcch(uint8_t* sdu, uint32_t len, uint16_t rnti, uint32_t tti, bool* is_smc)
{
  *is_smc = false;

  /* Strip RLC. These messages are small and arrive as a single unsegmented AM PDU; the
   * header is 2 bytes when there is no length-indicator list. Bail out rather than guess
   * if this one is segmented or carries LIs. */
  if (len < 2) {
    return false;
  }
  const uint8_t* rlc = sdu;
  bool           is_data_pdu = (rlc[0] & 0x80) != 0;   /* D/C: 1 = data */
  bool           resegmented = (rlc[0] & 0x40) != 0;   /* RF */
  bool           has_li      = (rlc[1] & 0x04) != 0;   /* E: extension bit */
  uint8_t        fi          = (rlc[1] >> 3) & 0x03;   /* framing info */
  if (!is_data_pdu || resegmented || has_li || fi != 0) {
    return false;   /* segmented, concatenated or a control PDU: out of scope */
  }
  uint32_t off = 2;

  /* Strip PDCP-C: 1-byte header, and a 4-byte MAC-I trailer. */
  if (len < off + SEC_PDCP_SRB_HDR_LEN + SEC_PDCP_SRB_MAC_I_LEN + 1) {
    return false;
  }
  off += SEC_PDCP_SRB_HDR_LEN;
  uint32_t rrc_len = len - off - SEC_PDCP_SRB_MAC_I_LEN;

  asn1::cbit_ref           bref(sdu + off, rrc_len);
  asn1::rrc::dl_dcch_msg_s msg;
  if (msg.unpack(bref) != asn1::SRSASN_SUCCESS) {
    return false;
  }
  if (msg.msg.type().value != asn1::rrc::dl_dcch_msg_type_c::types_opts::c1) {
    return false;
  }

  using c1_types = asn1::rrc::dl_dcch_msg_type_c::c1_c_::types_opts;
  if (msg.msg.c1().type().value == c1_types::security_mode_cmd) {
    *is_smc = true;
  }
  if (debug) {
    printf("DEBUG: TTI=%d rnti=%d DL-DCCH %s\n", tti, rnti, msg.msg.c1().type().to_string());
  }
  return true;
}

/* Walk the MAC PDU and hand each SRB SDU to the right unpacker. */
static bool scan_mac_pdu(uint8_t* payload, uint32_t tbs_bytes, uint16_t rnti, uint32_t tti, bool* is_smc)
{
  static srslog::basic_logger& logger = srslog::fetch_basic_logger("MAC");

  srsran::sch_pdu pdu(20, logger);
  pdu.init_rx(tbs_bytes, false);
  pdu.parse_packet(payload);

  bool any = false;
  while (pdu.next()) {
    srsran::sch_subh* subh = pdu.get();
    if (subh == NULL || !subh->is_sdu()) {
      continue;   /* MAC control element, not an SDU */
    }
    uint32_t lcid = subh->get_sdu_lcid();
    uint8_t* sdu  = subh->get_sdu_ptr();
    uint32_t len  = subh->get_payload_size();
    if (sdu == NULL || len == 0) {
      continue;
    }

    if (lcid == SEC_LCID_CCCH) {
      any |= unpack_ccch(sdu, len, rnti, tti);
    } else if (lcid == SEC_LCID_SRB1 || lcid == SEC_LCID_SRB2) {
      bool smc = false;
      if (unpack_dcch(sdu, len, rnti, tti, &smc)) {
        any = true;
        if (smc) {
          *is_smc = true;
        }
      }
    }
  }
  return any;
}

int ngscope_sec_scan_subframe(srsran_ue_dl_t*     ue_dl,
                              srsran_dl_sf_cfg_t* sf,
                              srsran_ue_dl_cfg_t* cfg,
                              srsran_pdsch_cfg_t* pdsch_cfg,
                              uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                              int                 rf_idx,
                              uint32_t            tti,
                              uint64_t            ts_us,
                              const char*         out_path,
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
  int            nof_rrc    = 0;

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
      if (srsran_ue_dl_dci_to_pdsch_grant(ue_dl, sf, cfg, &dci_dl[d], &pdsch_cfg->grant)) {
        continue;
      }

      /* Deliberately NOT skipping spatial-multiplexing grants. srsRAN has no multiplex
       * predecoder for 4 Tx ports, so on such a cell these attempts emit a pair of errors
       * whenever they fail -- ~3000 over a 150 s replay. But measurement showed the failing
       * and succeeding attempts are the same population: filtering them out took the
       * SecurityModeCommand detections on the mt_airy02 capture from 159 down to 2. The log
       * noise is the cheaper problem, and this whole path is opt-in. */

      for (int tb = 0; tb < SRSRAN_MAX_CODEWORDS; tb++) {
        if (pdsch_cfg->grant.tb[tb].enabled) {
          if (pdsch_cfg->grant.tb[tb].rv < 0) {
            pdsch_cfg->grant.tb[tb].rv = 0;
          }
          srsran_softbuffer_rx_reset_tbs(pdsch_cfg->softbuffers.rx[tb],
                                         (uint32_t)pdsch_cfg->grant.tb[tb].tbs);
        }
      }

      srsran_pdsch_res_t pdsch_res[SRSRAN_MAX_CODEWORDS];
      ZERO_OBJECT(pdsch_res);
      bool decode_enable = false;
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

      bool pdsch_ok = false;
      bool rrc_ok   = false;
      bool is_smc   = false;

      if (srsran_ue_dl_decode_pdsch(ue_dl, sf, pdsch_cfg, pdsch_res) == SRSRAN_SUCCESS) {
        const int tbs = pdsch_cfg->grant.tb[0].tbs;
        if (pdsch_res[0].crc && tbs > 0) {
          pdsch_ok = true;

          /* This is the interesting traffic -- Msg4 and the SecurityModeCommand live here,
           * and the search was targeted, so the PDCCH CRC was checked against a known RNTI
           * and the identity is trustworthy. Emitted before the RRC scan below, which
           * consumes nothing. A no-op unless pcap_mac is set. */
          ngscope_mac_tb_t cap;
          memset(&cap, 0, sizeof(cap));
          cap.rf_idx    = rf_idx;
          cap.tti       = tti;
          cap.ts_us     = ts_us;
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

          rrc_ok   = scan_mac_pdu(pdsch_res[0].payload, (uint32_t)tbs / 8, rnti, tti, &is_smc);
        }
      }

      ngscope_sec_count_attempt(rf_idx, pdsch_ok, rrc_ok);

      if (rrc_ok) {
        nof_rrc++;
        /* Decoding it in the clear is itself the proof that security was not yet up. */
        ngscope_sec_note_unciphered_rrc(rf_idx, rnti, tti, ts_us);
        if (is_smc) {
          ngscope_sec_note_smc(rf_idx, rnti, tti, ts_us, out_path);
        }
      }
    }
  }

  pdsch_cfg->rnti = saved_rnti;
  return nof_rrc;
}
