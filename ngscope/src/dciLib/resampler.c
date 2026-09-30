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
#include <limits.h>

#include "srsran/srsran.h"
#include "ngscope/hdr/dciLib/resampler.h"


static rf_resampler_t g_resampler = {0};

// int find_resample_rate_hz(int srate, int mcr){
//     if (srate > mcr){
//         ERROR("Cannot find a resample rate for target srate %.02f MHz > master clock rate %.02f MHz", (float) srate / 1000000, (float) mcr / 1000000);
//         return -1;
//     }
//     int factor = 1;
//     int resample_rate;
//     while (mcr / factor > srate){
//         resample_rate = mcr / factor;
//         factor*=2;
//     }
//     return resample_rate;
// }

int find_resample_rate_hz(int srate, int mcr)
{
    if (srate <= 0 || mcr <= 0) {
        ERROR("Invalid srate or mcr");
        return -1;
    }
    if (srate > mcr) {
        ERROR("Cannot find resample rate: srate %.02f MHz > mcr %.02f MHz",
              (float)srate / 1e6, (float)mcr / 1e6);
        return -1;
    }

    /* If mcr is already an exact multiple of srate, no resampling needed */
    if (mcr % srate == 0) {
        return srate;
    }

    int best_rate  = -1;
    int best_error = INT_MAX;

    /* Search all integer divisors of mcr that land near srate.
     * Only go up to 2x srate to avoid returning something absurdly large. */
    int max_divisor = mcr / (srate / 2);

    for (int divisor = 1; divisor <= max_divisor; divisor++) {
        int candidate = mcr / divisor;

        /* Must be >= srate so we are downsampling, not upsampling  *
         * (upsampling from RF is unusual and wastes bandwidth)      */
        if (candidate < srate) break;

        int error = candidate - srate;  /* always >= 0 here */
        if (error < best_error) {
            best_error = error;
            best_rate  = candidate;
        }
    }

    if (best_rate == -1) {
        ERROR("Could not find resample rate for srate=%.02f MHz mcr=%.02f MHz",
              (float)srate / 1e6, (float)mcr / 1e6);
        return -1;
    }

    printf("Best RF rate: %.06f MHz (error: %+.02f MHz, ratio: %.8f)\n",
           (float)best_rate / 1e6,
           (float)best_error / 1e6,
           (float)srate / (float)best_rate);

    return best_rate;
}


int rf_resampler_init(rf_resampler_t *r,
                      int base_rate_hz,
                      int rf_rate_hz,
                      uint32_t buf_len)
{
    memset(r, 0, sizeof(*r));

    r->base_rate_hz  = base_rate_hz;
    r->rf_rate_hz    = rf_rate_hz;
    r->resample_ratio = (float)base_rate_hz / (float)rf_rate_hz; /* < 1 = decimate */
    r->enabled       = 1;

    /* liquid msresamp_crcf: arbitrary rate, complex float */
    /* args: rate, stopband attenuation dB                 */
    r->resampler = msresamp_crcf_create(r->resample_ratio, 60.0f);
    if (!r->resampler) {
        fprintf(stderr, "Failed to create liquid resampler\n");
        return -1;
    }

    /* Input buffer holds RF-rate samples.
     * Worst case: rf_rate > base_rate so we need more input samples
     * to produce buf_len output samples.                           */
    r->output_buf_len = buf_len;
    r->input_buf_len  = (uint32_t)ceilf((float)buf_len / r->resample_ratio) + 64;

    r->input_buf  = malloc(r->input_buf_len  * sizeof(cf_t));
    r->output_buf = malloc(r->output_buf_len * sizeof(cf_t));

    if (!r->input_buf || !r->output_buf) {
        fprintf(stderr, "Failed to allocate resampler buffers\n");
        rf_resampler_destroy(r);
        return -1;
    }

    printf("Resampler: %.6f MHz -> %.6f MHz  (ratio=%.8f), buf_len=%d\n",
           (float)rf_rate_hz  / 1e6,
           (float)base_rate_hz / 1e6,
           r->resample_ratio,
           buf_len);

    return 0;
}


void rf_resampler_destroy(rf_resampler_t *r)
{
    if (!r) return;
    if (r->resampler)  msresamp_crcf_destroy(r->resampler);
    if (r->input_buf)  free(r->input_buf);
    if (r->output_buf) free(r->output_buf);
    memset(r, 0, sizeof(*r));
}


/**
 * Resample a block of RF-rate samples down to base rate.
 *
 * @param r             resampler context
 * @param in            input  samples at rf_rate_hz  (length: in_len)
 * @param in_len        number of input samples
 * @param out           output samples at base_rate_hz
 * @param out_len       [out] number of output samples written
 */
void rf_resample_block(rf_resampler_t *r,
                       const cf_t    *in,
                       uint32_t       in_len,
                       cf_t          *out,
                       uint32_t      *out_len)
{
    unsigned int n_written = 0;

    msresamp_crcf_execute(r->resampler,
                          (liquid_float_complex *)in,
                          in_len,
                          (liquid_float_complex *)out,
                          &n_written);
    *out_len = n_written;
}
