/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>

#include <unistd.h>

#include "srsran/srsran.h"

#include "srsran/phy/rf/rf.h"
#include "srsran/phy/rf/rf_utils.h"
#include "srsran/phy/ue/ue_cell_search_nbiot.h"
#include "dciLib/ngscope_rx.h"
#include "dciLib/load_config.h"

extern ngscope_mode_t mode;
static bool celldebug = false;

int rf_rssi_scan(srsran_rf_t* rf, float* freqs, float* rssi, int nof_bands, double fs, int nsamp)
{
  int    i, j;
  int    ret = -1;
  cf_t*  buffer;
  double f;

  buffer = calloc(nsamp, sizeof(cf_t));
  if (!buffer) {
    goto free_and_exit;
  }

  srsran_rf_set_rx_gain(rf, 20.0);
  srsran_rf_set_rx_srate(rf, fs);

  for (i = 0; i < nof_bands; i++) {
    srsran_rf_stop_rx_stream(rf);

    f = (double)freqs[i];
    srsran_rf_set_rx_freq(rf, 0, f);
    usleep(10000);
    srsran_rf_start_rx_stream(rf, false);

    /* discard first samples */
    for (j = 0; j < 2; j++) {
      if (srsran_rf_recv(rf, buffer, nsamp, 1) != nsamp) {
        goto free_and_exit;
      }
    }
    rssi[i] = srsran_vec_avg_power_cf(buffer, nsamp);
    printf("[%3d]: Freq %4.1f Mhz - RSSI: %3.2f dBm\r", i, f / 1000000, srsran_convert_power_to_dBm(rssi[i]));
    fflush(stdout);
    if (SRSRAN_VERBOSE_ISINFO()) {
      printf("\n");
    }
  }
  srsran_rf_stop_rx_stream(rf);

  ret = 0;
free_and_exit:
  free(buffer);
  return ret;
}

int srsran_rf_recv_wrapper_cs(void* h, cf_t* data[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t)
{
  DEBUG(" ----  Receive %d samples  ----", nsamples);
  printf("DEBUG: rf_utils receive %d samples\n",nsamples);
  void* ptr[SRSRAN_MAX_CHANNELS] = {};
  for (int i = 0; i < SRSRAN_MAX_PORTS; i++) {
    ptr[i] = data[i];
  }
  return srsran_rf_recv_with_time_multi(h, ptr, nsamples, 1, NULL, NULL);
}

static SRSRAN_AGC_CALLBACK(srsran_rf_set_rx_gain_wrapper)
{
  srsran_rf_set_rx_gain((srsran_rf_t*)h, gain_db);
}

/* Samples read by this thread's MIB decode, which is what places two decodes in time.
 * Thread-local because each RF device searches for its cell in its own scheduler thread. */
static _Thread_local uint64_t mib_nof_samples = 0;

static int mib_recv_counted(void* h, cf_t* data[SRSRAN_MAX_PORTS], uint32_t nsamples, srsran_timestamp_t* t)
{
  /* In replay, stop where the recorded cell search ends: past it the stream is at the cell's
   * rate, and decoding that as cell-search samples would only eat the start of the capture. */
  if (mode == REPLAY && ngscope_replay_past_cell_search()) {
    return SRSRAN_ERROR;
  }
  int n = ngscope_recv_samples_wrapper(h, data, nsamples, t);
  if (n > 0) {
    mib_nof_samples += (uint64_t)n;
  }
  return n;
}

/* 36.331 MIB dl-Bandwidth: n6..n100. The field is 3 bits, so a corrupted MIB can say 125 or 150,
 * which srsran_pbch_mib_unpack() passes through as a bandwidth. */
static bool mib_prb_valid(uint32_t nof_prb)
{
  return nof_prb == 6 || nof_prb == 15 || nof_prb == 25 || nof_prb == 50 || nof_prb == 75 || nof_prb == 100;
}

/* Two decodes are of the same cell if they agree on everything the MIB configures and the SFN
 * advanced by the frames actually read between them (+-1, for where in a read each was found). */
static bool mib_consistent(const srsran_cell_t* a, uint32_t sfn_a, const srsran_cell_t* b, uint32_t sfn_b, uint64_t frames)
{
  if (a->nof_prb != b->nof_prb || a->nof_ports != b->nof_ports || a->phich_length != b->phich_length ||
      a->phich_resources != b->phich_resources) {
    return false;
  }
  const int32_t d = (int32_t)((sfn_b + 1024 - sfn_a) % 1024) - (int32_t)(frames % 1024);
  const int32_t e = ((d % 1024) + 1024 + 512) % 1024 - 512; /* wrap to [-512, 512) */
  return e >= -1 && e <= 1;
}

/** This function is simply a wrapper to the ue_cell_search module for rf devices
 * Return 1 if the MIB is decoded, 0 if not or -1 on error.
 *
 * A MIB is accepted only once a second decode confirms it. The PBCH CRC is 16 bits and is tried
 * against three port masks on every frame, so noise passes it every few thousand frames, with
 * random fields -- and nothing downstream questions the result: it sets the sample rate a
 * recording is made at and is written to the recording header. Measured on
 * replay-test/vzw-66636-recorded-samples.bin.bz2: a weak antenna kept the true MIB (100 PRB,
 * 4 ports) from decoding for 3.5 s, the search accepted a false pass (15 PRB, 1 port), and the
 * whole capture was recorded at 3.84 Msps instead of 23.04. Over that recording's cell search,
 * 100 such false passes turned up across 504 PCIs x 2 antennas; none would survive this check.
 *
 * The search budget is twice max_frames_pbch, so a cell that used to be found is not lost for
 * want of its confirmation. In replay, a recording made before this check ends its cell search
 * at the first decode; reaching that end with one candidate accepts it, with a warning, which is
 * what the recorder did.
 */
int rf_mib_decoder(srsran_rf_t*       rf,
                   uint32_t           nof_rx_channels,
                   cell_search_cfg_t* config,
                   srsran_cell_t*     cell,
                   float*             cfo)
{
  int                  ret = SRSRAN_ERROR;
  srsran_ue_mib_sync_t ue_mib;
  uint8_t              bch_payload[SRSRAN_BCH_PAYLOAD_LEN] = {};

  if (srsran_ue_mib_sync_init_multi(&ue_mib, mib_recv_counted, nof_rx_channels, (void*)rf)) { // original cb: srsran_rf_recv_wrapper_cs // used for decoding MIB
    fprintf(stderr, "Error initiating srsran_ue_mib_sync\n");
    goto clean_exit;
  }

  if (srsran_ue_mib_sync_set_cell(&ue_mib, *cell)) {
    ERROR("Error initiating srsran_ue_mib_sync");
    goto clean_exit;
  }

  int srate = srsran_sampling_freq_hz(SRSRAN_UE_MIB_NOF_PRB);

  if (mode != REPLAY){
    INFO("Setting sampling frequency %.2f MHz for PSS search", (float)srate / 1000000);
    printf("Setting sampling frequency %.2f MHz for PSS search\n", (float)srate / 1000000);
    double res = srsran_rf_set_rx_srate(rf, (float)srate);
    printf("Set samping frequency to %.2f MHz with result %.2f MHz\n", (float)srate / 1000000, (float)res / 1000000);

    INFO("Starting receiver...");
    printf("DEBUG: Starting receiver\n");
    srsran_rf_start_rx_stream(rf, false);
  }

  // Copy CFO estimate if provided and disable CP estimation during find
  if (cfo) {
    ue_mib.ue_sync.cfo_current_value       = *cfo / 15000;
    ue_mib.ue_sync.cfo_is_copied           = true;
    ue_mib.ue_sync.cfo_correct_enable_find = true;
    srsran_sync_set_cfo_cp_enable(&ue_mib.ue_sync.sfind, false, 0);
  }

  /* Find and decode MIB, then confirm it with a second decode */
  const uint64_t frame_len  = (uint64_t)srate / 100; /* samples per radio frame at the search rate */
  const uint64_t budget     = 2 * (uint64_t)config->max_frames_pbch * frame_len;
  bool           have_cand  = false;
  srsran_cell_t  cand       = *cell;
  uint32_t       cand_sfn   = 0;
  uint64_t       cand_at    = 0;
  uint32_t       nof_reject = 0;
  mib_nof_samples           = 0;
  ret                       = 0;
  while (mib_nof_samples < budget) {
    const uint64_t left_frames = (budget - mib_nof_samples) / frame_len;
    srsran_cell_t  c           = *cell;
    uint32_t       sfn         = 0;
    int            sfn_offset  = 0;
    int            r           = srsran_ue_mib_sync_decode(
        &ue_mib, left_frames > 0 ? (uint32_t)left_frames : 1, bch_payload, &c.nof_ports, &sfn_offset);
    if (r < 0) {
      if (mode == REPLAY && ngscope_replay_past_cell_search()) {
        if (have_cand) {
          fprintf(stderr,
                  "CELL: WARNING: the recording's cell search ends before this MIB could be confirmed "
                  "(%u PRB, %u ports); accepting it unconfirmed, as the recorder did.\n",
                  cand.nof_prb, cand.nof_ports);
          *cell = cand;
          ret   = 1;
        } else {
          fprintf(stderr, "CELL: ERROR: the recording's cell search ends without a decodable MIB.\n");
          ret = 0;
        }
        break;
      }
      ERROR("Error decoding MIB");
      ret = r;
      goto clean_exit;
    }
    if (r != 1) {
      break; /* timed out on the remaining budget */
    }
    srsran_pbch_mib_unpack(bch_payload, &c, &sfn);
    sfn = (sfn + (uint32_t)sfn_offset) % 1024;
    if (celldebug)
      printf("CELL: decoded MIB nof_prb=%d, nof_ports=%d, id=%d, phich_length=%d, phich_resources=%d, sfn=%u\n",
             c.nof_prb, c.nof_ports, c.id, c.phich_length, c.phich_resources, sfn);
    if (!mib_prb_valid(c.nof_prb)) {
      nof_reject++;
      continue;
    }
    const uint64_t at = mib_nof_samples;
    if (have_cand && mib_consistent(&cand, cand_sfn, &c, sfn, (at - cand_at + frame_len / 2) / frame_len)) {
      *cell = c;
      ret   = 1;
      break;
    }
    if (have_cand) {
      nof_reject++;
    }
    cand      = c;
    cand_sfn  = sfn;
    cand_at   = at;
    have_cand = true;
  }
  if (nof_reject > 0) {
    printf("CELL: rejected %u MIB decode%s with an invalid bandwidth or no confirming decode\n", nof_reject,
           nof_reject == 1 ? "" : "s");
  }

  // Save CFO
  if (cfo) {
    *cfo = srsran_ue_sync_get_cfo(&ue_mib.ue_sync);
    if (celldebug)
      printf("CELL: Found CFO=%f\n", *cfo);
  }

clean_exit:

  if (mode != REPLAY)
    srsran_rf_stop_rx_stream(rf);
  srsran_ue_mib_sync_free(&ue_mib);

  return ret;
}

/** This function is simply a wrapper to the ue_cell_search module for rf devices
 */
int rf_cell_search(srsran_rf_t*       rf,
                   uint32_t           nof_rx_channels,
                   cell_search_cfg_t* config,
                   int                force_N_id_2,
                   srsran_cell_t*     cell,
                   float*             cfo)
{
  int                           ret = SRSRAN_ERROR;
  srsran_ue_cellsearch_t        cs;
  srsran_ue_cellsearch_result_t found_cells[3];

  bzero(found_cells, 3 * sizeof(srsran_ue_cellsearch_result_t));

  if (srsran_ue_cellsearch_init_multi(
          &cs, config->max_frames_pss, ngscope_recv_samples_wrapper, nof_rx_channels, (void*)rf)) { // replaced srsran_rf_recv_wrapper_cs // used for finding cells
    fprintf(stderr, "Error initiating UE cell detect\n");
    return SRSRAN_ERROR;
  }
  if (config->nof_valid_pss_frames) {
    srsran_ue_cellsearch_set_nof_valid_frames(&cs, config->nof_valid_pss_frames);
  }

  if (mode != REPLAY){
    INFO("Setting sampling frequency %.2f MHz for PSS search", SRSRAN_CS_SAMP_FREQ / 1000000);
    srsran_rf_set_rx_srate(rf, SRSRAN_CS_SAMP_FREQ);


  INFO("Starting receiver...");
  srsran_rf_start_rx_stream(rf, false);

  }

  if (config->force_tdd) {
    srsran_ue_sync_set_frame_type(&cs.ue_sync, SRSRAN_TDD);
  }

  /* Find a cell in the given N_id_2 or go through the 3 of them to find the strongest */
  uint32_t max_peak_cell = 0;
  if (force_N_id_2 >= 0) {
    ret           = srsran_ue_cellsearch_scan_N_id_2(&cs, force_N_id_2, &found_cells[force_N_id_2]);
    max_peak_cell = force_N_id_2;
  } else {
    ret = srsran_ue_cellsearch_scan(&cs, found_cells, &max_peak_cell);
  }

  if (mode != REPLAY)
    srsran_rf_stop_rx_stream(rf);

  if (ret < 0) {
    ERROR("Error searching cell");
    return SRSRAN_ERROR;
  } else if (ret == 0) {
    ERROR("Could not find any cell in this frequency");
    return SRSRAN_SUCCESS;
  }

  for (int i = 0; i < 3; i++) {
    if (i == max_peak_cell) {
      printf("*");
    } else {
      printf(" ");
    }
    printf("Found Cell_id: %3d %s, CP: %s, DetectRatio=%2.0f%% PSR=%.2f, Power=%.1f dBm\n",
           found_cells[i].cell_id,
           found_cells[i].frame_type == SRSRAN_FDD ? "FDD" : "TDD",
           srsran_cp_string(found_cells[i].cp),
           found_cells[i].mode * 100,
           found_cells[i].psr,
           srsran_convert_amplitude_to_dB(found_cells[i].peak * 1000));
  }

  // Save result
  if (cell) {
    cell->id         = found_cells[max_peak_cell].cell_id;
    cell->cp         = found_cells[max_peak_cell].cp;
    cell->frame_type = found_cells[max_peak_cell].frame_type;
  }

  // Save CFO
  if (cfo) {
    *cfo = found_cells[max_peak_cell].cfo;
  }

  srsran_ue_cellsearch_free(&cs);

  return ret;
}

/* Finds a cell and decodes MIB from the PBCH.
 * Returns 1 if the cell is found and MIB is decoded successfully.
 * 0 if no cell was found or MIB could not be decoded,
 * -1 on error
 */
int rf_search_and_decode_mib(srsran_rf_t*       rf,
                             uint32_t           nof_rx_channels,
                             cell_search_cfg_t* config,
                             int                force_N_id_2,
                             srsran_cell_t*     cell,
                             float*             cfo)
{
  int ret = SRSRAN_ERROR;

  printf("Searching for cell...\n");
  ret = rf_cell_search(rf, nof_rx_channels, config, force_N_id_2, cell, cfo);
  if (ret > 0) {
    printf("Decoding PBCH for cell %d (N_id_2=%d)\n", cell->id, cell->id % 3);
    ret = rf_mib_decoder(rf, nof_rx_channels, config, cell, cfo);
    if (ret < 0) {
      ERROR("Could not decode PBCH from CELL ID %d", cell->id);
      return SRSRAN_ERROR;
    }
  }
  return ret;
}

int rf_cell_search_nbiot(srsran_rf_t* rf, cell_search_cfg_t* config, srsran_nbiot_cell_t* cell, float* cfo)
{
  int                                 ret            = SRSRAN_ERROR;
  srsran_ue_cellsearch_nbiot_t        cs             = {};
  srsran_nbiot_ue_cellsearch_result_t found_cells[3] = {};

  if (srsran_ue_cellsearch_nbiot_init(&cs, config->max_frames_pss, srsran_rf_recv_wrapper_cs, (void*)rf)) {
    fprintf(stderr, "Error initiating UE cell detect\n");
    return SRSRAN_ERROR;
  }

  if (config->nof_valid_pss_frames) {
    srsran_ue_cellsearch_nbiot_set_nof_valid_frames(&cs, config->nof_valid_pss_frames);
  }
  if (config->init_agc > 0) {
    srsran_ue_sync_nbiot_start_agc(&cs.ue_sync, srsran_rf_set_rx_gain_wrapper, config->init_agc);
  }

  DEBUG("Setting sampling frequency %.2f MHz for NPSS search", SRSRAN_CS_SAMP_FREQ / 1000000);
  srsran_rf_set_rx_srate(rf, SRSRAN_CS_SAMP_FREQ);

  INFO("Starting receiver...");
  srsran_rf_start_rx_stream(rf, false);

  ret = srsran_ue_cellsearch_nbiot_scan(&cs);
  if (ret == SRSRAN_ERROR) {
    fprintf(stderr, "Could not find any cell in this frequency\n");
    goto clean_exit;
  }

  INFO("Stopping receiver...");
  srsran_rf_stop_rx_stream(rf);

  // Find a cell
  INFO("Running N_id_ncell detection");

  uint32_t max_peak_cell = 0;
  ret                    = srsran_ue_cellsearch_nbiot_detect(&cs, found_cells);
  if (ret != SRSRAN_SUCCESS) {
    fprintf(stderr, "Could not detect cell ID\n");
    goto clean_exit;
  }

  // Only show first cell
  for (int i = 0; i < 1; i++) {
    if (i == max_peak_cell) {
      printf("*");
    } else {
      printf(" ");
    }
    printf("Found n_id_ncell: %3d DetectRatio=%2.0f%% PSR=%.2f, Power=%.1f dBm\n",
           found_cells[i].n_id_ncell,
           found_cells[i].mode * 100,
           found_cells[i].psr,
           20 * log10(found_cells[i].peak * 1000));
  }

  // Save result
  if (cell) {
    cell->n_id_ncell = found_cells[max_peak_cell].n_id_ncell;
  }

  // Save CFO
  if (cfo) {
    *cfo = found_cells[max_peak_cell].cfo;
  }

  // Save AGC value for MIB decoding
  if (config->init_agc > 0) {
    config->init_agc = srsran_agc_get_gain(&cs.ue_sync.agc);
  }

clean_exit:
  srsran_rf_stop_rx_stream(rf);
  srsran_ue_cellsearch_nbiot_free(&cs);

  return ret;
}
