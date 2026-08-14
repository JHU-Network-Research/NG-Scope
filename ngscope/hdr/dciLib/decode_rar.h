#ifndef _DECODE_RAR_H_
#define _DECODE_RAR_H_

#include <stdio.h>
#include <stdlib.h>

#include "srsran/srsran.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Defined in lib/src/phy/ue/ue_dl.c. Despite the name it searches the common search space
 * for whatever RNTI it is given, which is exactly what an RA-RNTI needs. */
int srsran_ue_dl_find_dl_dci_sirnti(srsran_ue_dl_t *q, srsran_dl_sf_cfg_t *sf, srsran_ue_dl_cfg_t *dl_cfg, uint16_t rnti, srsran_dci_dl_t dci_dl[SRSRAN_MAX_DCI_MSG]);

/* Maximum number of RAR records we report for a single subframe. Also used as the
 * max_rars bound of the MAC RAR PDU parser. */
#define NGSCOPE_MAX_RAR_PER_SF 16

/* One MAC RAR (36.321 6.2.3) as recovered from Msg2. */
typedef struct {
    uint16_t ra_rnti;       // RA-RNTI the RAR was addressed to
    uint16_t temp_crnti;    // Temporary C-RNTI assigned to the UE
    uint32_t rapid;         // Random Access Preamble ID
    uint32_t ta_cmd;        // Timing Advance command
    uint8_t  ul_grant[SRSRAN_RAR_GRANT_LEN]; // Msg3 grant, one bit per byte
    uint32_t grant_rba;     // decoded from ul_grant (36.213 6.2)
    uint32_t grant_mcs;
    int      tbs;           // transport block size of the RAR PDSCH, in bits
    int      crc;           // PDSCH CRC result (always 1 for reported records)
} ngscope_rar_t;

/* Look for Random Access Responses in the current subframe.
 *
 * Sweeps the RA-RNTI candidates internally, so srsran_ue_dl_decode_fft_estimate() runs
 * only once. For every RA-RNTI whose PDCCH and PDSCH both pass CRC, the MAC RAR PDU is
 * parsed and one entry per RAR subheader is appended to out[].
 *
 * Returns the number of entries written to out[], or a negative value on error. */
int srsran_ue_dl_find_and_decode_rar(srsran_ue_dl_t*     q,
                                     srsran_dl_sf_cfg_t* sf,
                                     srsran_ue_dl_cfg_t* cfg,
                                     srsran_pdsch_cfg_t* pdsch_cfg,
                                     uint8_t*            data[SRSRAN_MAX_CODEWORDS],
                                     ngscope_rar_t       out[NGSCOPE_MAX_RAR_PER_SF]);

/* Truncate <out_path>rar_log-<rf_idx>.csv and write its header row. Call once per RF
 * device, before any decoder thread for that device starts. */
void ngscope_rar_log_init(const char* out_path, int rf_idx);

/* Append one RAR record. Safe to call from several decoder threads at once. */
void ngscope_rar_log_write(const char*          out_path,
                           int                  rf_idx,
                           uint32_t             tti,
                           uint64_t             timestamp,
                           uint64_t             collection_time,
                           const ngscope_rar_t* rar);

#ifdef __cplusplus
}
#endif

#endif
