#ifndef _NGSCOPE_MAC_PCAP_H_
#define _NGSCOPE_MAC_PCAP_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "srsran/srsran.h"

/* Write decoded downlink MAC PDUs to a pcapng file, in the MAC-LTE encapsulation Wireshark
 * understands, with a per-packet comment carrying where the PDU sits relative to its UE's AS
 * security context.
 *
 * Framing is srsRAN's own -- LTE_PCAP_PACK_MAC_CONTEXT_TO_BUFFER() builds the pseudo-header,
 * so a capture is byte-compatible with one from srsUE or LTESniffer. The container is pcapng
 * rather than classic pcap because classic pcap has nowhere to put the comment.
 *
 * DLT 147 is DLT_USER0 and has no registered link type, so Wireshark dissects nothing until
 * told to. See docs/pcap.md; the short version is:
 *     tshark -r mac-0.pcapng \
 *       -o 'uat:user_dlts:"User 0 (DLT=147)","mac-lte-framed","0","","0",""'
 */

/* How a transport block came to us, which is how much its RNTI can be trusted.
 *
 * TARGETED, RAR and SIB searched for a known RNTI, so the PDCCH CRC was checked against it
 * and a hit cannot be a manufactured candidate. BLIND recovered the RNTI from the descrambled
 * CRC instead, so the RNTI -- and anything joined onto it later -- may be fictional. The
 * transport-block CRC still makes the bytes themselves trustworthy. */
typedef enum {
    NGSCOPE_MAC_SRC_TARGETED = 0,
    NGSCOPE_MAC_SRC_BLIND,
    NGSCOPE_MAC_SRC_RAR,
    NGSCOPE_MAC_SRC_SIB,
} ngscope_mac_src_t;

/* One decoded, CRC-passing downlink transport block. payload is BORROWED: it points into the
 * decoder thread's scratch buffer and is overwritten by the next decode in the same subframe,
 * so ngscope_mac_pcap_write() copies before returning and callers must not retain it. */
typedef struct {
    int               rf_idx;
    uint32_t          tti;        /* sfn = tti/10, sf_idx = tti%10 */
    uint64_t          ts_us;      /* dci_per_sub->timestamp: microseconds since the epoch */
    uint64_t          collection_time; /* radio-domain clock, device-dependent epoch */
    uint16_t          rnti;
    ngscope_mac_src_t src;
    uint8_t           tb_idx;
    uint8_t           harq_pid;
    int               rv;
    int               mcs;
    int               tbs;        /* bits */
    uint32_t          prb;
    srsran_dci_format_t format;
    srsran_tx_scheme_t  tx_scheme;
    bool              is_tdd;
    bool              rach_ok;    /* would survive the RACH filter */
    float             decode_prob;
    float             corr;
    float             evm;
    const uint8_t*    payload;
    uint32_t          len;        /* bytes, i.e. tbs/8 */
} ngscope_mac_tb_t;

/* Open <out_path>mac-<rf_idx>.pcapng. One file per RF device: RNTIs are unique only within a
 * cell, so merging files would misattribute them. Call once per device, before any decoder
 * thread for it starts. max_mb of 0 means unlimited. Returns 0 on success. */
int ngscope_mac_pcap_init(const char* out_path, int rf_idx, const srsran_cell_t* cell, int max_mb);

/* Append one transport block. No-op when that device's file was never opened, so call sites
 * need no guard of their own. Safe to call from several decoder threads at once. */
void ngscope_mac_pcap_write(const ngscope_mac_tb_t* tb);

/* Flush, close and print a summary. Call after the decoder threads have been joined. */
void ngscope_mac_pcap_close(int rf_idx);

/* Where this RNTI sits relative to its UE establishing AS security: "unknown", "pre" or
 * "post". Weak: the default always answers "unknown", and the security tracker overrides it
 * when that half is present. Kept weak so this file has no dependency on it. */
const char* ngscope_mac_pcap_sec_phase(int rf_idx, uint16_t rnti, uint64_t ts_us);

/* Logical channel class of a MAC PDU: "bcch", "pcch", "rar", "ccch", "srb", "drb", "ce",
 * "pad" or "none". Weak: the default classifies from the RNTI alone and answers "dlsch" for a
 * C-RNTI; the MAC PDU walk overrides it once transport-block parsing is present. lcids_out
 * receives a comma-separated LCID list, or an empty string. */
void ngscope_mac_pcap_classify(const ngscope_mac_tb_t* tb,
                               const char**            ch_out,
                               bool*                   mixed_out,
                               char*                   lcids_out,
                               size_t                  lcids_len);

#ifdef __cplusplus
}
#endif

#endif
