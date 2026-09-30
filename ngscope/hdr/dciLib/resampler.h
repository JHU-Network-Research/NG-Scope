#include <liquid/liquid.h>
#include <math.h>

#define DEFAULT_RECV_FRAME_SIZE 8000

typedef struct {
    msresamp_crcf  resampler;       /* liquid DSP rational resampler      */
    float          resample_ratio;  /* rf_rate / srate  e.g. 1.0016...    */
    int            rf_rate_hz;      /* actual rate set on the RF hardware  */
    int            base_rate_hz;    /* rate srsRAN expects (srate)         */
    int            enabled;         /* 0 = pass-through                    */

    cf_t          *input_buf;       /* staging buffer (RF rate)            */
    cf_t          *output_buf;      /* resampled buffer (base rate)        */
    uint32_t       input_buf_len;
    uint32_t       output_buf_len;
} rf_resampler_t;



int find_resample_rate_hz(int srate, int mcr);
int rf_resampler_init(rf_resampler_t *r, int base_rate_hz, int rf_rate_hz, uint32_t buf_len);
void rf_resampler_destroy(rf_resampler_t *r);
void rf_resample_block(rf_resampler_t *r, const cf_t *in, uint32_t in_len,cf_t *out, uint32_t *out_len);
