#include "ngscope/hdr/dciLib/mac_pcap.h"

#include "ngscope/hdr/dciLib/ngscope_def.h"
#include "ngscope/hdr/dciLib/pcapng.h"
#include "srsran/common/pcap.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

extern bool debug;

/* Largest LTE transport block is 75376 bits = 9422 bytes, plus the 22-byte mac-lte context. */
#define MAC_PCAP_MAX_FRAME (PCAP_CONTEXT_HEADER_MAX + 10240)

/* Bounded so one comment can never push a block past NGSCOPE_PCAPNG_MAX_BLOCK. */
#define MAC_PCAP_COMMENT_MAX 256

static ngscope_pcapng_t mac_pcap[MAX_NOF_RF_DEV];
static srsran_cell_t    mac_pcap_cell[MAX_NOF_RF_DEV];

static inline bool rf_idx_valid(int rf_idx)
{
    return rf_idx >= 0 && rf_idx < MAX_NOF_RF_DEV;
}

/* pcap.h rntiType. SRSRAN_RNTI_ISRAR() covers 1..10, which is the whole useful RA-RNTI range
 * on FDD; see the note in decode_rar.h about why we do not go beyond it. */
static uint8_t rnti_type_of(uint16_t rnti)
{
    if (rnti == SRSRAN_SIRNTI) {
        return SI_RNTI;
    }
    if (rnti == SRSRAN_PRNTI) {
        return P_RNTI;
    }
    if (rnti == SRSRAN_MRNTI) {
        return M_RNTI;
    }
    if (SRSRAN_RNTI_ISRAR(rnti)) {
        return RA_RNTI;
    }
    return C_RNTI;
}

static const char* src_str(ngscope_mac_src_t src)
{
    switch (src) {
        case NGSCOPE_MAC_SRC_TARGETED:
            return "targeted";
        case NGSCOPE_MAC_SRC_RAR:
            return "rar";
        case NGSCOPE_MAC_SRC_SIB:
            return "sib";
        case NGSCOPE_MAC_SRC_BLIND:
        default:
            return "blind";
    }
}

/* Weak defaults, and now the only implementations of both.
 *
 * sec_phase used to be overridden by the in-process RRC parser. That parser is gone, so
 * every packet is written "unknown" and tools/security_phase_join.py patches the field
 * afterwards from the offline scan -- which is why mac_pcap.c pads it to a fixed 7
 * characters. Left weak so a future in-process classifier could still override. */

__attribute__((weak)) const char* ngscope_mac_pcap_sec_phase(int rf_idx, uint16_t rnti, uint64_t ts_us)
{
    (void)rf_idx;
    (void)rnti;
    (void)ts_us;
    /* Never guess. Absence of evidence is not evidence of a phase -- that invariant is the
     * whole basis of the detector this feeds. */
    return "unknown";
}

__attribute__((weak)) void ngscope_mac_pcap_classify(const ngscope_mac_tb_t* tb,
                                                     const char**            ch_out,
                                                     bool*                   mixed_out,
                                                     char*                   lcids_out,
                                                     size_t                  lcids_len)
{
    *mixed_out = false;
    if (lcids_len > 0) {
        lcids_out[0] = '\0';
    }
    switch (rnti_type_of(tb->rnti)) {
        case SI_RNTI:
            *ch_out = "bcch";
            break;
        case P_RNTI:
            *ch_out = "pcch";
            break;
        case RA_RNTI:
            *ch_out = "rar";
            break;
        default:
            /* Without a MAC PDU walk the logical channel is unknown; say so rather than
             * claiming a channel we have not looked at. */
            *ch_out = "dlsch";
            break;
    }
}

int ngscope_mac_pcap_init(const char* out_path, int rf_idx, const srsran_cell_t* cell, int max_mb)
{
    if (!rf_idx_valid(rf_idx) || out_path == NULL || cell == NULL) {
        return -1;
    }
    mac_pcap_cell[rf_idx] = *cell;

    char path[1024];
    snprintf(path, sizeof(path), "%smac-%d.pcapng", out_path, rf_idx);

    char desc[256];
    snprintf(desc,
             sizeof(desc),
             "NG-Scope cell %d downlink, %s, %d PRB, %d port%s",
             rf_idx,
             (cell->frame_type == SRSRAN_TDD) ? "TDD" : "FDD",
             cell->nof_prb,
             cell->nof_ports,
             cell->nof_ports == 1 ? "" : "s");

    char name[32];
    snprintf(name, sizeof(name), "cell%d", rf_idx);

    const uint64_t max_bytes = (max_mb > 0) ? ((uint64_t)max_mb * 1024ULL * 1024ULL) : 0;
    if (ngscope_pcapng_open(&mac_pcap[rf_idx], path, MAC_LTE_DLT, name, desc, max_bytes) != 0) {
        return -1;
    }
    printf("pcap: writing downlink MAC PDUs to %s\n", path);
    printf("pcap: Wireshark needs DLT_USER0 (147) mapped to mac-lte-framed -- see docs/pcap.md\n");
    return 0;
}

void ngscope_mac_pcap_write(const ngscope_mac_tb_t* tb)
{
    if (tb == NULL || !rf_idx_valid(tb->rf_idx) || tb->payload == NULL || tb->len == 0) {
        return;
    }
    if (!mac_pcap[tb->rf_idx].is_open) {
        return; /* feature off: callers need no guard */
    }
    if (tb->len > MAC_PCAP_MAX_FRAME - PCAP_CONTEXT_HEADER_MAX) {
        return;
    }

    const srsran_cell_t* cell = &mac_pcap_cell[tb->rf_idx];

    MAC_Context_Info_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.radioType   = (cell->frame_type == SRSRAN_TDD) ? TDD_RADIO : FDD_RADIO;
    ctx.direction   = DIRECTION_DOWNLINK;
    ctx.rntiType    = rnti_type_of(tb->rnti);
    ctx.rnti        = tb->rnti;
    /* Wireshark keys its per-UE MAC/RLC/PDCP state on ueid, and the RNTI is the only UE
     * identity a downlink sniffer has. */
    ctx.ueid        = tb->rnti;
    ctx.isRetx      = (tb->rv != 0);
    ctx.crcStatusOK = 1; /* only CRC-passing transport blocks reach here */
    ctx.cc_idx      = (unsigned char)tb->rf_idx;
    ctx.sysFrameNumber = (unsigned short)(tb->tti / 10);
    ctx.subFrameNumber = (unsigned short)(tb->tti % 10);
    ctx.nbiotMode      = 0;

    uint8_t frame[MAC_PCAP_MAX_FRAME];
    int     off = LTE_PCAP_PACK_MAC_CONTEXT_TO_BUFFER(&ctx, frame, PCAP_CONTEXT_HEADER_MAX);
    if (off <= 0) {
        return;
    }
    memcpy(frame + off, tb->payload, tb->len);

    const char* ch    = "dlsch";
    bool        mixed = false;
    char        lcids[64];
    ngscope_mac_pcap_classify(tb, &ch, &mixed, lcids, sizeof(lcids));

    /* Tag first so `frame.comment contains "sec=post"` works, and sec= padded to a fixed
     * width so a post-pass can rewrite it in place rather than re-serialising the block. */
    char cmt[MAC_PCAP_COMMENT_MAX];
    snprintf(cmt,
             sizeof(cmt),
             "sec=%-7s ch=%s%s src=%s rnti=0x%04x tti=%05u rf=%d "
             "fmt=%s mcs=%d tbs=%d rv=%d prb=%u pid=%u tx=%s evm=%.3f corr=%.3f dp=%.3f rach=%d "
             "ct=%" PRIu64 "%s%s",
             ngscope_mac_pcap_sec_phase(tb->rf_idx, tb->rnti, tb->ts_us),
             ch,
             mixed ? " mix=1" : "",
             src_str(tb->src),
             tb->rnti,
             tb->tti,
             tb->rf_idx,
             srsran_dci_format_string_short(tb->format),
             tb->mcs,
             tb->tbs,
             tb->rv,
             tb->prb,
             tb->harq_pid,
             srsran_mimotype2str(tb->tx_scheme),
             tb->evm,
             tb->corr,
             tb->decode_prob,
             tb->rach_ok ? 1 : 0,
             tb->collection_time,
             lcids[0] ? " lcids=" : "",
             lcids);

    ngscope_pcapng_write(&mac_pcap[tb->rf_idx], 0, tb->ts_us, frame, (uint32_t)off + tb->len, cmt);
}

void ngscope_mac_pcap_close(int rf_idx)
{
    if (!rf_idx_valid(rf_idx)) {
        return;
    }
    ngscope_pcapng_close(&mac_pcap[rf_idx]);
}
