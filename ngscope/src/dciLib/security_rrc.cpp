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

/* RLC AM framing info (36.322 6.2.2.6). Two independent bits describing the data field as a
 * whole: whether its first byte begins an SDU, and whether its last byte ends one. */
#define SEC_RLC_FI_BEGINS(fi) (((fi) & 0x2) == 0)
#define SEC_RLC_FI_ENDS(fi)   (((fi) & 0x1) == 0)

/* Rejoining split SDUs. Bounds are generous for SRB traffic, but every overflow is counted, so
 * a cell that outgrows them says so rather than quietly under-reporting. Segmentation varies
 * enormously between cells: 2 of 325 DCCH SDUs needed rejoining on one AT&T capture, 8 of 41 on
 * another. */
#define SEC_REASM_MAX_UE   64    /* partial SDUs held concurrently, across all devices */
#define SEC_REASM_MAX_SEG  8     /* PDUs contributing to one SDU */
#define SEC_REASM_SEG_LEN  256   /* bytes per fragment */
#define SEC_REASM_MAX_LEN  (SEC_REASM_MAX_SEG * SEC_REASM_SEG_LEN)
#define SEC_REASM_SN_MOD   1024  /* the AM sequence number is 10 bits */
#define SEC_REASM_MAX_LI   15    /* length indicators in one PDU */

/* When something happened, in both clocks the rest of the tool carries: the radio-domain
 * collection_time alongside the host wall clock taken at decode. */
typedef struct {
  uint32_t tti;
  uint64_t ts_us;
  uint64_t ct;
} sec_when_t;

/* What one PDU contributes to SDUs that span PDU boundaries.
 *
 * A PDU carrying length indicators holds several SDUs at once: its leading piece may finish an
 * SDU opened at sn-1, its trailing piece may open one that continues at sn+1, and everything
 * between is whole and needs no reassembly at all. So a fragment store keyed only on the
 * sequence number is not enough — a single PDU can be both the end of one SDU and the start of
 * the next, which is exactly the shape that hid a SecurityModeCommand on the mt_airy02 cell. */
typedef struct {
  uint16_t   sn;
  bool       has_head;    /* leading bytes: they finish the SDU left open at sn-1 */
  bool       has_tail;    /* trailing bytes: they open an SDU continuing at sn+1 */
  bool       one_piece;   /* head and tail are the same bytes, i.e. a middle segment */
  uint16_t   head_len;
  uint16_t   tail_len;
  sec_when_t when;        /* the subframe this PDU arrived in */
  uint8_t    head[SEC_REASM_SEG_LEN];
  uint8_t    tail[SEC_REASM_SEG_LEN];
} sec_seg_t;

typedef struct {
  bool      in_use;
  int       rf_idx;
  uint16_t  rnti;
  uint8_t   lcid;
  uint64_t  last_us;
  int       nof_seg;
  sec_seg_t seg[SEC_REASM_MAX_SEG];
} sec_reasm_t;

/* Off unless ngscope_sec_rrc_set_reassembly() says otherwise; see the header for why that
 * is replay-only.
 *
 * Per device, not global: `mode` is a per-rf_config setting, so one device can replay while
 * another captures live. A single flag would let the replaying device switch on behaviour that
 * is unsound for its live neighbour. Written once per device before any decoder thread starts,
 * read from all of them. */
static bool            reasm_enabled[MAX_NOF_RF_DEV];
static sec_reasm_t     reasm[SEC_REASM_MAX_UE];
static pthread_mutex_t reasm_mutex   = PTHREAD_MUTEX_INITIALIZER;

static inline bool sec_rf_idx_ok(int rf_idx)
{
  return rf_idx >= 0 && rf_idx < MAX_NOF_RF_DEV;
}

void ngscope_sec_rrc_set_reassembly(int rf_idx, bool enable)
{
  if (sec_rf_idx_ok(rf_idx)) {
    reasm_enabled[rf_idx] = enable;
  }
}

/* See the header: retry a failed transport block on the other MCS->TBS table. Per device for
 * the same reason as the reassembly flag above. */
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

/* The slot holding this UE's partial SDUs, creating one if needed. Reuses the least recently
 * touched slot when full; whatever was in it was an RRC message we will now never read, so it
 * is counted. Caller holds reasm_mutex. */
static int reasm_slot(int rf_idx, uint16_t rnti, uint8_t lcid, uint64_t ts_us)
{
  int free_slot = -1, oldest = -1;
  for (int i = 0; i < SEC_REASM_MAX_UE; i++) {
    if (reasm[i].in_use) {
      if (reasm[i].rf_idx == rf_idx && reasm[i].rnti == rnti && reasm[i].lcid == lcid) {
        return i;
      }
      if (oldest < 0 || reasm[i].last_us < reasm[oldest].last_us) {
        oldest = i;
      }
    } else if (free_slot < 0) {
      free_slot = i;
    }
  }
  const int idx = (free_slot >= 0) ? free_slot : oldest;
  if (idx < 0) {
    return -1;
  }
  if (reasm[idx].in_use) {
    for (int i = 0; i < reasm[idx].nof_seg; i++) {
      ngscope_sec_count_dcch(reasm[idx].rf_idx, NGSCOPE_DCCH_REASM_LOST);
    }
  }
  memset(&reasm[idx], 0, sizeof(reasm[idx]));
  reasm[idx].in_use  = true;
  reasm[idx].rf_idx  = rf_idx;
  reasm[idx].rnti    = rnti;
  reasm[idx].lcid    = lcid;
  reasm[idx].last_us = ts_us;
  return idx;
}

/* The record for this sequence number, creating one if needed. Caller holds reasm_mutex. */
static int reasm_seg(int idx, uint16_t sn, const sec_when_t* when)
{
  sec_reasm_t* e = &reasm[idx];
  for (int i = 0; i < e->nof_seg; i++) {
    if (e->seg[i].sn == sn) {
      return i;   /* a retransmission: same sequence number, same bytes */
    }
  }
  if (e->nof_seg >= SEC_REASM_MAX_SEG) {
    return -1;
  }
  const int i = e->nof_seg++;
  memset(&e->seg[i], 0, sizeof(e->seg[i]));
  e->seg[i].sn   = sn;
  e->seg[i].when = *when;
  return i;
}

/* Drop the segments a completed SDU consumed, keeping any others this UE still has open.
 * Clearing the whole slot instead would silently discard a second SDU mid-assembly, which is
 * the class of loss this file exists to avoid.
 *
 * Keyed on sequence number rather than array index: removal is a swap with the last element,
 * so indices go stale as soon as the first one is removed. Caller holds reasm_mutex. */
static void reasm_drop(int idx, const uint16_t* consumed, int nof_consumed)
{
  sec_reasm_t* e = &reasm[idx];
  for (int c = 0; c < nof_consumed; c++) {
    for (int i = 0; i < e->nof_seg; i++) {
      if (e->seg[i].sn == consumed[c]) {
        e->seg[i] = e->seg[e->nof_seg - 1];
        e->nof_seg--;
        break;
      }
    }
  }
  if (e->nof_seg <= 0) {
    memset(e, 0, sizeof(*e));
  }
}

/* Look for a complete run: a PDU whose trailing bytes open an SDU, then consecutive sequence
 * numbers, ending at one whose leading bytes close it. Returns the assembled length, or 0 while
 * pieces are still missing.
 *
 * Segments are matched by sequence number rather than arrival order on purpose: decoder threads
 * run in parallel, so a later subframe routinely finishes before an earlier one and the pieces
 * do not arrive in order.
 *
 * *when is set to the subframe carrying the closing PDU, which is when the message finished
 * going out over the air. That is not the subframe that completed the reassembly: out-of-order
 * completion means the closing piece is often already held when the missing middle arrives, and
 * attributing the message to whichever piece happened to land last would put the boundary at an
 * arbitrary TTI. Caller holds reasm_mutex. */
static uint32_t reasm_assemble(int         idx,
                               uint8_t*    out,
                               uint32_t    out_max,
                               sec_when_t* when,
                               uint16_t*   consumed,
                               int*        nof_consumed)
{
  const sec_reasm_t* e = &reasm[idx];

  for (int s = 0; s < e->nof_seg; s++) {
    /* A one-piece middle segment continues an SDU, it does not begin one. */
    if (!e->seg[s].has_tail || e->seg[s].one_piece) {
      continue;
    }
    if (e->seg[s].tail_len > out_max) {
      continue;
    }
    memcpy(out, e->seg[s].tail, e->seg[s].tail_len);
    uint32_t len = e->seg[s].tail_len;
    uint16_t sn  = e->seg[s].sn;
    int      n   = 0;
    consumed[n++] = e->seg[s].sn;

    for (int hop = 0; hop < SEC_REASM_MAX_SEG; hop++) {
      if (n >= SEC_REASM_MAX_SEG) {
        break;   /* the run cannot be longer than the number of segments held */
      }
      sn      = (uint16_t)((sn + 1) % SEC_REASM_SN_MOD);
      int nxt = -1;
      for (int i = 0; i < e->nof_seg; i++) {
        if (e->seg[i].sn == sn) {
          nxt = i;
          break;
        }
      }
      if (nxt < 0 || !e->seg[nxt].has_head) {
        break;   /* gap, or the run does not continue: wait for more */
      }
      if (len + e->seg[nxt].head_len > out_max) {
        break;
      }
      memcpy(out + len, e->seg[nxt].head, e->seg[nxt].head_len);
      len += e->seg[nxt].head_len;
      consumed[n++] = e->seg[nxt].sn;

      if (!e->seg[nxt].one_piece) {
        /* Its leading bytes closed the SDU, so this is the end of the run. */
        *when         = e->seg[nxt].when;
        *nof_consumed = n;
        return len;
      }
    }
  }
  *nof_consumed = 0;
  return 0;
}

void ngscope_sec_rrc_reasm_flush(void)
{
  pthread_mutex_lock(&reasm_mutex);
  for (int i = 0; i < SEC_REASM_MAX_UE; i++) {
    if (reasm[i].in_use) {
      for (int j = 0; j < reasm[i].nof_seg; j++) {
        ngscope_sec_count_dcch(reasm[i].rf_idx, NGSCOPE_DCCH_REASM_LOST);
      }
      memset(&reasm[i], 0, sizeof(reasm[i]));
    }
  }
  pthread_mutex_unlock(&reasm_mutex);
}

/* Unpack the RRC message inside a complete DL-DCCH SDU -- PDCP header, RRC, MAC-I -- and
 * report whether it is the SecurityModeCommand.
 *
 * This only works while the DCCH is still in the clear -- which is exactly the window we
 * care about, since SecurityModeCommand is the last unciphered downlink message. Once
 * SecurityModeComplete goes up, the unpack below starts failing, and that failure is
 * deliberately not treated as evidence of anything. */
static bool unpack_dcch_sdu(const uint8_t* sdu,
                            uint32_t       len,
                            int            rf_idx,
                            uint16_t       rnti,
                            uint32_t       tti,
                            bool*          is_smc,
                            bool           reassembled)
{
  if (len < SEC_PDCP_SRB_HDR_LEN + SEC_PDCP_SRB_MAC_I_LEN + 1) {
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_SHORT);
    return false;
  }
  const uint32_t off     = SEC_PDCP_SRB_HDR_LEN;
  const uint32_t rrc_len = len - off - SEC_PDCP_SRB_MAC_I_LEN;

  asn1::cbit_ref           bref(sdu + off, rrc_len);
  asn1::rrc::dl_dcch_msg_s msg;
  if (msg.unpack(bref) != asn1::SRSASN_SUCCESS ||
      msg.msg.type().value != asn1::rrc::dl_dcch_msg_type_c::types_opts::c1) {
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_ASN1);
    return false;
  }

  using c1_types = asn1::rrc::dl_dcch_msg_type_c::c1_c_::types_opts;
  if (msg.msg.c1().type().value == c1_types::security_mode_cmd) {
    *is_smc = true;
  }
  ngscope_sec_count_dcch(rf_idx, reassembled ? NGSCOPE_DCCH_REASSEMBLED : NGSCOPE_DCCH_OK);
  if (debug) {
    printf("DEBUG: TTI=%d rnti=%d DL-DCCH %s%s\n",
           tti,
           rnti,
           msg.msg.c1().type().to_string(),
           reassembled ? " (reassembled)" : "");
  }
  return true;
}

/* One bit out of a buffer, MSB first, bounds-checked. */
static bool bit_at(const uint8_t* p, uint32_t avail, uint32_t bit, uint32_t* out)
{
  if (bit / 8 >= avail) {
    return false;
  }
  *out = (uint32_t)((p[bit / 8] >> (7 - (bit % 8))) & 1);
  return true;
}

/* The AMD PDU header extension (36.322 6.2.1.4): a run of [E(1 bit), LI(11 bits)] pairs
 * following the two fixed octets, padded with 4 bits when the count is odd so the data field
 * starts on a byte boundary. Returns the number of length indicators, or -1 if the run does not
 * fit or is malformed. Bit-at-a-time on purpose: this is a handful of PDUs per capture, and the
 * packing is easy to get subtly wrong with shifts. */
static int parse_li_chain(const uint8_t* p, uint32_t avail, uint16_t* li, uint32_t* ext_bytes)
{
  int      n   = 0;
  uint32_t bit = 0;

  for (;;) {
    if (n >= SEC_REASM_MAX_LI) {
      return -1;
    }
    uint32_t e = 0;
    if (!bit_at(p, avail, bit++, &e)) {
      return -1;
    }
    uint32_t v = 0;
    for (int k = 0; k < 11; k++) {
      uint32_t b = 0;
      if (!bit_at(p, avail, bit++, &b)) {
        return -1;
      }
      v = (v << 1) | b;
    }
    if (v == 0) {
      return -1;   /* a zero-length SDU is not a thing; treat the header as malformed */
    }
    li[n++] = (uint16_t)v;
    if (e == 0) {
      break;
    }
  }
  *ext_bytes = (uint32_t)((n * 12 + 7) / 8);   /* the odd case pads with 4 bits */
  return n;
}

/* Strip the RLC AM header from one PDU and hand on every SDU it holds: whole ones straight to
 * the unpacker, and the leading and trailing fragments into reassembly. */
static bool unpack_dcch(const uint8_t*    pdu,
                        uint32_t          len,
                        int               rf_idx,
                        uint16_t          rnti,
                        uint8_t           lcid,
                        const sec_when_t* now,
                        bool*             is_smc,
                        sec_when_t*       smc_when)
{
  if (len < 2) {
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_SHORT);
    return false;
  }

  /* AMD PDU fixed header (36.322 6.2.1.4): octet 0 is D/C | RF | P | FI(2) | E | SN(9:8),
   * octet 1 is SN(7:0). FI and E are in octet 0, not octet 1 -- reading them from the
   * sequence-number byte rejects any PDU whose SN happens to have those bits set, which is
   * three quarters of them, and lets a genuinely segmented PDU through as if whole. */
  const uint8_t  h0          = pdu[0];
  const bool     is_data_pdu = (h0 & 0x80) != 0;              /* D/C: 1 = data */
  const bool     resegmented = (h0 & 0x40) != 0;              /* RF */
  const uint8_t  fi          = (uint8_t)((h0 >> 3) & 0x03);   /* framing info */
  const bool     has_li      = (h0 & 0x04) != 0;              /* E: a length-indicator list */
  const uint16_t sn          = (uint16_t)(((h0 & 0x03) << 8) | pdu[1]);

  if (!is_data_pdu) {
    /* An RLC STATUS PDU. It carries no SDU, so it is not a message we failed to read. */
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_CTRL);
    return false;
  }
  if (resegmented) {
    /* An AMD PDU segment, whose header carries a segment offset we do not parse. Rare --
     * zero occurrences across both AT&T captures -- and out of scope. */
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_UNSUPPORTED);
    return false;
  }

  /* Split the data field into the SDUs it holds. Without an LI list there is exactly one. */
  uint16_t li[SEC_REASM_MAX_LI];
  uint32_t ext_bytes = 0;
  int      nof_li    = 0;

  if (has_li) {
    nof_li = parse_li_chain(pdu + 2, len - 2, li, &ext_bytes);
    if (nof_li < 0) {
      ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_UNSUPPORTED);
      return false;
    }
  }

  const uint32_t data_off = 2 + ext_bytes;
  if (data_off >= len) {
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_SHORT);
    return false;
  }
  const uint8_t* data     = pdu + data_off;
  const uint32_t data_len = len - data_off;

  const uint8_t* piece[SEC_REASM_MAX_LI + 1];
  uint32_t       piece_len[SEC_REASM_MAX_LI + 1];
  uint32_t       off = 0;
  for (int i = 0; i < nof_li; i++) {
    if (off + li[i] > data_len) {
      ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_UNSUPPORTED);
      return false;
    }
    piece[i]     = data + off;
    piece_len[i] = li[i];
    off += li[i];
  }
  if (off >= data_len) {
    /* The indicators accounted for the whole data field; there is no trailing SDU. */
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_UNSUPPORTED);
    return false;
  }
  piece[nof_li]     = data + off;
  piece_len[nof_li] = data_len - off;
  const int nof_piece = nof_li + 1;

  /* FI describes the data field as a whole, so it constrains only the outermost pieces. */
  const bool first_begins = SEC_RLC_FI_BEGINS(fi);
  const bool last_ends    = SEC_RLC_FI_ENDS(fi);
  const bool head_frag    = !first_begins;                 /* piece 0 closes an earlier SDU */
  const bool tail_frag    = !last_ends;                    /* the last piece opens a new one */
  const bool one_piece    = (nof_piece == 1) && head_frag && tail_frag;

  bool any = false;

  /* Everything that is neither the leading nor the trailing fragment is a whole SDU. This is
   * where the length-indicator work pays: on the mt_airy02 cell a complete SecurityModeCommand
   * sits here, in front of a fragment that runs on into the next PDU. */
  for (int i = 0; i < nof_piece; i++) {
    if (i == 0 && head_frag) {
      continue;
    }
    if (i == nof_piece - 1 && tail_frag) {
      continue;
    }
    bool smc = false;
    if (unpack_dcch_sdu(piece[i], piece_len[i], rf_idx, rnti, now->tti, &smc, false)) {
      any = true;
      if (smc) {
        *is_smc   = true;
        *smc_when = *now;
      }
    }
  }

  if (!head_frag && !tail_frag) {
    return any;
  }
  if (!sec_rf_idx_ok(rf_idx) || !reasm_enabled[rf_idx]) {
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_SEGMENTED);
    return any;
  }

  uint8_t  full[SEC_REASM_MAX_LEN];
  uint32_t full_len = 0;
  sec_when_t last   = *now;
  uint16_t consumed[SEC_REASM_MAX_SEG];
  int      nof_consumed = 0;
  bool     lost         = false;

  pthread_mutex_lock(&reasm_mutex);
  const int idx = reasm_slot(rf_idx, rnti, lcid, now->ts_us);
  int       si  = (idx >= 0) ? reasm_seg(idx, sn, now) : -1;
  if (si < 0) {
    lost = true;
  } else {
    reasm[idx].last_us = now->ts_us;
    sec_seg_t* g       = &reasm[idx].seg[si];
    g->one_piece       = one_piece;
    if (head_frag && piece_len[0] <= SEC_REASM_SEG_LEN) {
      g->has_head = true;
      g->head_len = (uint16_t)piece_len[0];
      memcpy(g->head, piece[0], piece_len[0]);
    }
    if (tail_frag && piece_len[nof_piece - 1] <= SEC_REASM_SEG_LEN) {
      g->has_tail = true;
      g->tail_len = (uint16_t)piece_len[nof_piece - 1];
      memcpy(g->tail, piece[nof_piece - 1], piece_len[nof_piece - 1]);
    }
    if ((head_frag && !g->has_head) || (tail_frag && !g->has_tail)) {
      lost = true;   /* a fragment too big to hold: the SDU cannot be rebuilt */
    } else {
      full_len = reasm_assemble(idx, full, sizeof(full), &last, consumed, &nof_consumed);
      if (full_len > 0) {
        reasm_drop(idx, consumed, nof_consumed);
      }
    }
  }
  pthread_mutex_unlock(&reasm_mutex);

  if (lost) {
    ngscope_sec_count_dcch(rf_idx, NGSCOPE_DCCH_REASM_LOST);
    return any;
  }
  if (full_len == 0) {
    /* Held, not lost: the remaining pieces may still arrive. Counted when the SDU either
     * completes or is evicted, so each one lands in exactly one bucket. */
    return any;
  }

  bool smc = false;
  if (unpack_dcch_sdu(full, full_len, rf_idx, rnti, last.tti, &smc, true)) {
    any = true;
    if (smc) {
      *is_smc   = true;
      *smc_when = last;
    }
  }
  return any;
}

/* Walk the MAC PDU and hand each SRB SDU to the right unpacker. */
static bool scan_mac_pdu(uint8_t*          payload,
                         uint32_t          tbs_bytes,
                         int               rf_idx,
                         uint16_t          rnti,
                         const sec_when_t* now,
                         bool*             is_smc,
                         sec_when_t*       smc_when)
{
  /* Unless a reassembly says otherwise, the message belongs to the subframe being scanned. */
  *smc_when = *now;

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
      any |= unpack_ccch(sdu, len, rnti, now->tti);
    } else if (lcid == SEC_LCID_SRB1 || lcid == SEC_LCID_SRB2) {
      if (unpack_dcch(sdu, len, rf_idx, rnti, (uint8_t)lcid, now, is_smc, smc_when)) {
        any = true;
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
                              uint64_t            collection_time,
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
      bool rrc_ok   = false;
      bool is_smc   = false;

      /* Where this subframe sits in both clocks, and where the SecurityModeCommand sits if
       * one turns up. They differ only when a reassembly places the message in an earlier
       * subframe than the one that completed it. */
      const sec_when_t now      = {tti, ts_us, collection_time};
      sec_when_t       smc_when = now;

      if (r == 1) {
        const int tbs = pdsch_cfg->grant.tb[0].tbs;
        {
          pdsch_ok = true;
          ngscope_sec_count_tb_table(rf_idx, used_alt != cfg_alt);

          /* This is the interesting traffic -- Msg4 and the SecurityModeCommand live here,
           * and the search was targeted, so the PDCCH CRC was checked against a known RNTI
           * and the identity is trustworthy. Emitted before the RRC scan below, which
           * consumes nothing. A no-op unless pcap_mac is set. */
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

          rrc_ok   = scan_mac_pdu(pdsch_res[0].payload, (uint32_t)tbs / 8, rf_idx, rnti, &now,
                                  &is_smc, &smc_when);
        }
      }

      ngscope_sec_count_attempt(rf_idx, pdsch_ok, rrc_ok);

      if (rrc_ok) {
        nof_rrc++;
        /* Decoding it in the clear is itself the proof that security was not yet up. */
        ngscope_sec_note_unciphered_rrc(rf_idx, rnti, tti, ts_us);
        if (is_smc) {
          ngscope_sec_note_smc(rf_idx, rnti, smc_when.tti, smc_when.ts_us, smc_when.ct, out_path);
        }
      }
    }
  }

  pdsch_cfg->rnti = saved_rnti;
  return nof_rrc;
}
