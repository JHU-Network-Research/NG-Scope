#include <assert.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>

#include "srsran/common/crash_handler.h"
#include "srsran/common/gen_mch_tables.h"
#include "srsran/phy/io/filesink.h"
#include "srsran/srsran.h"

#include "srsran/phy/rf/rf.h"
#include "srsran/phy/ue/ue_cell_search_nbiot.h"

#include "ngscope/hdr/dciLib/radio.h"
#include "ngscope/hdr/dciLib/load_config.h"
// #include "ngscope/hdr/dciLib/resampler.h"


extern bool go_exit;
extern ngscope_mode_t mode;
extern bool debug;

int extract_master_clock_rate(const char *args, int *rate_hz){

    if (!args || !rate_hz){
        return 0;
    }

    const char *key = "master_clock_rate=";
    const char *found = strstr(args,key);

    if (!found){
        return 0;
    }

    const char *value_start = found + strlen(key);

    char *end_ptr;
    double rate = strtod(value_start, &end_ptr);
    if (end_ptr == value_start){
        return 0;
    }

    if (*end_ptr != '\0' && *end_ptr != ',' && *end_ptr != ' '){
        return 0;
    }

    *rate_hz = (int) rate;
    return 1;
}


int radio_init_and_start(srsran_rf_t* rf,
                    srsran_cell_t* cell,
                    prog_args_t prog_args,
                    cell_search_cfg_t* cell_detect_config,
                    float* search_cell_cfo,
                    rf_resampler_t *resampler){
    int ret;

    int mcr = 23040000;
    int mcr_res = extract_master_clock_rate(prog_args.rf_args, &mcr);

    printf("Master clock rate found: %d, using %.02f MHz\n", mcr_res, (float)mcr/1e6);

    if (mode != REPLAY){

      if (debug)
        printf("DEBUG: Opening RF device with %d RX antennas...\n", prog_args.rf_nof_rx_ant);
      if (srsran_rf_open_devname(rf, prog_args.rf_dev, prog_args.rf_args, prog_args.rf_nof_rx_ant)) {
        fprintf(stderr, "Error opening rf\n");
        exit(-1);
      }
      /* Set receiver gain */
      if (prog_args.rf_gain > 0) {
        srsran_rf_set_rx_gain(rf, prog_args.rf_gain);
      } else {
        if (debug)
          printf("DEBUG: Starting AGC thread...\n");
        if (srsran_rf_start_gain_thread(rf, false)) {
          ERROR("Error opening rf");
          exit(-1);
        }
        srsran_rf_set_rx_gain(rf, srsran_rf_get_rx_gain(rf));
        cell_detect_config->init_agc = srsran_rf_get_rx_gain(rf);
      }


    /* set receiver frequency */
      // if (debug)
    printf("DEBUG: Tunning receiver to %.3f MHz\n", (prog_args.rf_freq + prog_args.file_offset_freq) / 1e6);
      srsran_rf_set_rx_freq(rf, prog_args.rf_nof_rx_ant, prog_args.rf_freq + prog_args.file_offset_freq);
    }

    if (debug)
      printf("DEBUG: SEARCHING FOR MIB\n");
    uint32_t ntrial = 0;
    do {
      ret = rf_search_and_decode_mib(
          rf, prog_args.rf_nof_rx_ant, cell_detect_config, prog_args.force_N_id_2, cell, search_cell_cfo);
      if (ret < 0) {
        ERROR("Error searching for cell");
        exit(-1);
      } else if (ret == 0 && !go_exit) {
        printf("Cell not found after %d trials. Trying again (Press Ctrl+C to exit)\n", ntrial++);
      }
    } while (ret == 0 && !go_exit);

    if (go_exit) {
      /* Only close what was opened. In REPLAY the block above never called
       * srsran_rf_open_devname(), and *rf is uninitialised (the task scheduler is
       * malloc'd, not calloc'd), so closing it here dereferences a garbage rf->dev and
       * crashes on every Ctrl-C taken while still searching for a cell. */
      if (mode != REPLAY) {
        srsran_rf_close(rf);
      }
      exit(0);
    }
    if (debug)
      printf("DEBUG: FOUND AND DECODED MIB\n");
    printf("Found cell:\n\tnof_prb:\t%d\n\tnof_ports:\t%d\n\tid:\t%d\n",cell->nof_prb,cell->nof_ports,cell->id);

    if (mode != REPLAY){

      /* set sampling frequency */
      int srate = srsran_sampling_freq_hz(cell->nof_prb);


      if (srate == -1){
          ERROR("Invalid number of PRB %d", cell->nof_prb);
          exit(-1);
      }

      if (mcr % srate != 0){
          printf("Resample needed: master clock rate %.02f MHz not divisible by desired sampling rate %.02f MHz\n", (float) mcr / 1e6, (float) srate / 1e6);
          int resample_rate_hz = find_resample_rate_hz(srate, mcr);
          if (resample_rate_hz == -1){
              ERROR("Could not find suitable resample rate\n");
              exit(-1);
          }
          printf("Found resample rate %.02f MHz for sample rate %.02f MHz and master clock rate %.02f MHz\n", (float) resample_rate_hz/ 1e6, (float) srate/ 1e6, (float) mcr / 1e6);
          rf_resampler_init(resampler, srate, resample_rate_hz, SRSRAN_SF_LEN(srsran_symbol_sz(cell->nof_prb)));
          srate = resample_rate_hz;
        }

        // if (debug)
        // srate = 15000 * 2048;
        printf("DEBUG: Setting sampling rate %.3f MHz\n", (float)srate / 1e6);
        float srate_rf = srsran_rf_set_rx_srate(rf, (double)srate);
        printf("DEBUG: Received srate is %.3f MHz\n", (float)srate_rf / 1e6);
        if (debug)
            printf("DEBUG: srate_rf:%f\n",srate_rf);
        if (srate_rf != srate) {
            ERROR("Could not set sampling rate");
            exit(-1);
        }

      // start rx stream
      srsran_rf_start_rx_stream(rf, false);
    }
    return SRSRAN_SUCCESS;
}

int radio_stop(srsran_rf_t* rf){

    if (mode != REPLAY){
      srsran_rf_stop_rx_stream(rf);
      srsran_rf_close(rf);
    }
    return SRSRAN_SUCCESS;
}
