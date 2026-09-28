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

#include <complex.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "srsran/phy/common/phy_common.h"
#include "srsran/phy/mimo/precoding.h"
#include "srsran/phy/utils/debug.h"
#include "srsran/phy/utils/mat.h"
#include "srsran/phy/utils/simd.h"
#include "srsran/phy/utils/vector.h"

#ifdef LV_HAVE_SSE
#include <immintrin.h>
int srsran_predecoding_single_sse(cf_t* y[SRSRAN_MAX_PORTS],
                                  cf_t* h[SRSRAN_MAX_PORTS],
                                  cf_t* x,
                                  int   nof_rxant,
                                  int   nof_symbols,
                                  float scaling,
                                  float noise_estimate);
int srsran_predecoding_diversity2_sse(cf_t* y[SRSRAN_MAX_PORTS],
                                      cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                      cf_t* x[SRSRAN_MAX_LAYERS],
                                      int   nof_rxant,
                                      int   nof_symbols,
                                      float scaling);
#endif

#ifdef LV_HAVE_AVX
#include <immintrin.h>
int srsran_predecoding_single_avx(cf_t* y[SRSRAN_MAX_PORTS],
                                  cf_t* h[SRSRAN_MAX_PORTS],
                                  cf_t* x,
                                  int   nof_rxant,
                                  int   nof_symbols,
                                  float scaling,
                                  float noise_estimate);
#endif
#include "srsran/phy/utils/mat.h"

static srsran_mimo_decoder_t mimo_decoder = SRSRAN_MIMO_DECODER_MMSE;

/************************************************
 *
 * RECEIVER SIDE FUNCTIONS
 *
 **************************************************/

#ifdef LV_HAVE_SSE

#define PROD(a, b)                                                                                                     \
  _mm_addsub_ps(_mm_mul_ps(a, _mm_moveldup_ps(b)), _mm_mul_ps(_mm_shuffle_ps(a, a, 0xB1), _mm_movehdup_ps(b)))

int srsran_predecoding_single_sse(cf_t* y[SRSRAN_MAX_PORTS],
                                  cf_t* h[SRSRAN_MAX_PORTS],
                                  cf_t* x,
                                  int   nof_rxant,
                                  int   nof_symbols,
                                  float scaling,
                                  float noise_estimate)
{
  float*       xPtr  = (float*)x;
  const float* hPtr1 = (const float*)h[0];
  const float* yPtr1 = (const float*)y[0];
  const float* hPtr2 = (const float*)h[1];
  const float* yPtr2 = (const float*)y[1];

  __m128 conjugator = _mm_setr_ps(0, -0.f, 0, -0.f);

  __m128 noise = _mm_set1_ps(noise_estimate);
  __m128 h1Val1, h2Val1, y1Val1, y2Val1;
  __m128 h1Val2, h2Val2, y1Val2, y2Val2;
  __m128 hsquare, h1square, h2square, h1conj1, h2conj1, x1Val1, x2Val1;
  __m128 hsquare2, h1conj2, h2conj2, x1Val2, x2Val2;

  for (int i = 0; i < nof_symbols / 4; i++) {
    y1Val1 = _mm_load_ps(yPtr1);
    yPtr1 += 4;
    y2Val1 = _mm_load_ps(yPtr1);
    yPtr1 += 4;
    h1Val1 = _mm_load_ps(hPtr1);
    hPtr1 += 4;
    h2Val1 = _mm_load_ps(hPtr1);
    hPtr1 += 4;

    if (nof_rxant == 2) {
      y1Val2 = _mm_load_ps(yPtr2);
      yPtr2 += 4;
      y2Val2 = _mm_load_ps(yPtr2);
      yPtr2 += 4;
      h1Val2 = _mm_load_ps(hPtr2);
      hPtr2 += 4;
      h2Val2 = _mm_load_ps(hPtr2);
      hPtr2 += 4;
    }

    hsquare = _mm_hadd_ps(_mm_mul_ps(h1Val1, h1Val1), _mm_mul_ps(h2Val1, h2Val1));
    if (nof_rxant == 2) {
      hsquare2 = _mm_hadd_ps(_mm_mul_ps(h1Val2, h1Val2), _mm_mul_ps(h2Val2, h2Val2));
      hsquare  = _mm_add_ps(hsquare, hsquare2);
    }
    if (noise_estimate > 0) {
      hsquare = _mm_add_ps(hsquare, noise);
    }

    h1square = _mm_shuffle_ps(hsquare, hsquare, _MM_SHUFFLE(1, 1, 0, 0));
    h2square = _mm_shuffle_ps(hsquare, hsquare, _MM_SHUFFLE(3, 3, 2, 2));

    /* Conjugate channel */
    h1conj1 = _mm_xor_ps(h1Val1, conjugator);
    h2conj1 = _mm_xor_ps(h2Val1, conjugator);

    if (nof_rxant == 2) {
      h1conj2 = _mm_xor_ps(h1Val2, conjugator);
      h2conj2 = _mm_xor_ps(h2Val2, conjugator);
    }

    /* Complex product */
    x1Val1 = PROD(y1Val1, h1conj1);
    x2Val1 = PROD(y2Val1, h2conj1);

    if (nof_rxant == 2) {
      x1Val2 = PROD(y1Val2, h1conj2);
      x2Val2 = PROD(y2Val2, h2conj2);
      x1Val1 = _mm_add_ps(x1Val1, x1Val2);
      x2Val1 = _mm_add_ps(x2Val1, x2Val2);
    }

    x1Val1 = _mm_div_ps(x1Val1, h1square);
    x2Val1 = _mm_div_ps(x2Val1, h2square);

    x1Val1 = _mm_mul_ps(x1Val1, _mm_set1_ps(1 / scaling));
    x2Val1 = _mm_mul_ps(x2Val1, _mm_set1_ps(1 / scaling));

    _mm_store_ps(xPtr, x1Val1);
    xPtr += 4;
    _mm_store_ps(xPtr, x2Val1);
    xPtr += 4;
  }
  for (int i = 8 * (nof_symbols / 8); i < nof_symbols; i++) {
    cf_t r  = 0;
    cf_t hh = 0;
    for (int p = 0; p < nof_rxant; p++) {
      r += y[p][i] * conjf(h[p][i]);
      hh += conjf(h[p][i]) * h[p][i];
    }
    x[i] = scaling * r / (hh + noise_estimate);
  }
  return nof_symbols;
}

#endif

#ifdef LV_HAVE_AVX

#define PROD_AVX(a, b)                                                                                                 \
  _mm256_addsub_ps(_mm256_mul_ps(a, _mm256_moveldup_ps(b)),                                                            \
                   _mm256_mul_ps(_mm256_shuffle_ps(a, a, 0xB1), _mm256_movehdup_ps(b)))

int srsran_predecoding_single_avx(cf_t* y[SRSRAN_MAX_PORTS],
                                  cf_t* h[SRSRAN_MAX_PORTS],
                                  cf_t* x,
                                  int   nof_rxant,
                                  int   nof_symbols,
                                  float scaling,
                                  float noise_estimate)
{
  float*       xPtr  = (float*)x;
  const float* hPtr1 = (const float*)h[0];
  const float* yPtr1 = (const float*)y[0];
  const float* hPtr2 = (const float*)h[1];
  const float* yPtr2 = (const float*)y[1];

  __m256 conjugator = _mm256_setr_ps(0, -0.f, 0, -0.f, 0, -0.f, 0, -0.f);

  __m256 noise = _mm256_set1_ps(noise_estimate);
  __m256 h1Val1, h2Val1, y1Val1, y2Val1, h12square, h1square, h2square, h1_p, h2_p, h1conj1, h2conj1, x1Val, x2Val;
  __m256 h1Val2, h2Val2, y1Val2, y2Val2, h1conj2, h2conj2;
  __m256 avx_scaling = _mm256_set1_ps(1 / scaling);

  for (int i = 0; i < nof_symbols / 8; i++) {
    y1Val1 = _mm256_load_ps(yPtr1);
    yPtr1 += 8;
    y2Val1 = _mm256_load_ps(yPtr1);
    yPtr1 += 8;
    h1Val1 = _mm256_load_ps(hPtr1);
    hPtr1 += 8;
    h2Val1 = _mm256_load_ps(hPtr1);
    hPtr1 += 8;

    if (nof_rxant == 2) {
      y1Val2 = _mm256_load_ps(yPtr2);
      yPtr2 += 8;
      y2Val2 = _mm256_load_ps(yPtr2);
      yPtr2 += 8;
      h1Val2 = _mm256_load_ps(hPtr2);
      hPtr2 += 8;
      h2Val2 = _mm256_load_ps(hPtr2);
      hPtr2 += 8;
    }

    __m256 t1 = _mm256_mul_ps(h1Val1, h1Val1);
    __m256 t2 = _mm256_mul_ps(h2Val1, h2Val1);
    h12square = _mm256_hadd_ps(_mm256_permute2f128_ps(t1, t2, 0x20), _mm256_permute2f128_ps(t1, t2, 0x31));

    if (nof_rxant == 2) {
      t1        = _mm256_mul_ps(h1Val2, h1Val2);
      t2        = _mm256_mul_ps(h2Val2, h2Val2);
      h12square = _mm256_add_ps(
          h12square, _mm256_hadd_ps(_mm256_permute2f128_ps(t1, t2, 0x20), _mm256_permute2f128_ps(t1, t2, 0x31)));
    }

    if (noise_estimate > 0) {
      h12square = _mm256_add_ps(h12square, noise);
    }

    h1_p     = _mm256_permute_ps(h12square, _MM_SHUFFLE(1, 1, 0, 0));
    h2_p     = _mm256_permute_ps(h12square, _MM_SHUFFLE(3, 3, 2, 2));
    h1square = _mm256_permute2f128_ps(h1_p, h2_p, 2 << 4);
    h2square = _mm256_permute2f128_ps(h1_p, h2_p, 3 << 4 | 1);

    /* Conjugate channel */
    h1conj1 = _mm256_xor_ps(h1Val1, conjugator);
    h2conj1 = _mm256_xor_ps(h2Val1, conjugator);

    if (nof_rxant == 2) {
      h1conj2 = _mm256_xor_ps(h1Val2, conjugator);
      h2conj2 = _mm256_xor_ps(h2Val2, conjugator);
    }

    /* Complex product */
    x1Val = PROD_AVX(y1Val1, h1conj1);
    x2Val = PROD_AVX(y2Val1, h2conj1);

    if (nof_rxant == 2) {
      x1Val = _mm256_add_ps(x1Val, PROD_AVX(y1Val2, h1conj2));
      x2Val = _mm256_add_ps(x2Val, PROD_AVX(y2Val2, h2conj2));
    }

    x1Val = _mm256_div_ps(x1Val, h1square);
    x2Val = _mm256_div_ps(x2Val, h2square);

    x1Val = _mm256_mul_ps(x1Val, avx_scaling);
    x2Val = _mm256_mul_ps(x2Val, avx_scaling);

    _mm256_store_ps(xPtr, x1Val);
    xPtr += 8;
    _mm256_store_ps(xPtr, x2Val);
    xPtr += 8;
  }
  for (int i = 8 * (nof_symbols / 8); i < nof_symbols; i++) {
    cf_t r  = 0;
    cf_t hh = 0;
    for (int p = 0; p < nof_rxant; p++) {
      r += y[p][i] * conjf(h[p][i]);
      hh += conjf(h[p][i]) * h[p][i];
    }
    x[i] = r / ((hh + noise_estimate) * scaling);
  }
  return nof_symbols;
}

#endif

int srsran_predecoding_single_gen(cf_t* y[SRSRAN_MAX_PORTS],
                                  cf_t* h[SRSRAN_MAX_PORTS],
                                  cf_t* x,
                                  int   nof_rxant,
                                  int   nof_symbols,
                                  float scaling,
                                  float noise_estimate)
{
  for (int i = 0; i < nof_symbols; i++) {
    cf_t r  = 0;
    cf_t hh = 0;
    for (int p = 0; p < nof_rxant; p++) {
      r += y[p][i] * conjf(h[p][i]);
      hh += conjf(h[p][i]) * h[p][i];
    }
    x[i] = r / ((hh + noise_estimate) * scaling);
  }
  return nof_symbols;
}

int srsran_predecoding_single_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                  cf_t*  h[SRSRAN_MAX_PORTS],
                                  cf_t*  x,
                                  float* csi,
                                  int    nof_rxant,
                                  int    nof_symbols,
                                  float  scaling,
                                  float  noise_estimate)
{
  int i = 0;

#if SRSRAN_SIMD_CF_SIZE
  const simd_f_t _noise   = srsran_simd_f_set1(noise_estimate);
  const simd_f_t _scaling = srsran_simd_f_set1(1.0f / scaling);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t _r  = srsran_simd_cf_zero();
    simd_f_t  _hh = srsran_simd_f_zero();

    for (int p = 0; p < nof_rxant; p++) {
      simd_cf_t _y = srsran_simd_cfi_load(&y[p][i]);
      simd_cf_t _h = srsran_simd_cfi_load(&h[p][i]);

      _r  = srsran_simd_cf_add(_r, srsran_simd_cf_conjprod(_y, _h));
      _hh = srsran_simd_f_add(_hh, srsran_simd_cf_re(srsran_simd_cf_conjprod(_h, _h)));
    }

    simd_f_t  _csi = srsran_simd_f_add(_hh, _noise);
    simd_cf_t _x   = srsran_simd_cf_mul(srsran_simd_cf_mul(_r, _scaling), srsran_simd_f_rcp(_csi));

    srsran_simd_f_store(&csi[i], _csi);
    srsran_simd_cfi_store(&x[i], _x);
  }
#endif

  for (; i < nof_symbols; i++) {
    cf_t  r    = 0;
    float hh   = 0;
    float norm = 1.0f / scaling;
    for (int p = 0; p < nof_rxant; p++) {
      r += y[p][i] * conjf(h[p][i]);
      hh += (__real__ h[p][i] * __real__ h[p][i]) + (__imag__ h[p][i] * __imag__ h[p][i]);
    }
    csi[i] = hh + noise_estimate;
    x[i]   = r * norm / csi[i];
  }
  return nof_symbols;
}

/* ZF/MMSE SISO equalizer x=y(h'h+no)^(-1)h' (ZF if n0=0.0)*/
int srsran_predecoding_single(cf_t*  y_,
                              cf_t*  h_,
                              cf_t*  x,
                              float* csi,
                              int    nof_symbols,
                              float  scaling,
                              float  noise_estimate)
{
  cf_t* y[SRSRAN_MAX_PORTS];
  cf_t* h[SRSRAN_MAX_PORTS];
  y[0]          = y_;
  h[0]          = h_;
  int nof_rxant = 1;

  if (csi) {
    return srsran_predecoding_single_csi(y, h, x, csi, nof_rxant, nof_symbols, scaling, noise_estimate);
  }

#ifdef LV_HAVE_AVX
  if (nof_symbols > 32 && nof_rxant <= 2) {
    return srsran_predecoding_single_avx(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
  } else {
    return srsran_predecoding_single_gen(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
  }
#else
#ifdef LV_HAVE_SSE
  if (nof_symbols > 32 && nof_rxant <= 2) {
    return srsran_predecoding_single_sse(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
  } else {
    return srsran_predecoding_single_gen(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
  }
#else
  return srsran_predecoding_single_gen(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
#endif
#endif
}

/* ZF/MMSE SISO equalizer x=y(h'h+no)^(-1)h' (ZF if n0=0.0)*/
int srsran_predecoding_single_multi(cf_t*  y[SRSRAN_MAX_PORTS],
                                    cf_t*  h[SRSRAN_MAX_PORTS],
                                    cf_t*  x,
                                    float* csi[SRSRAN_MAX_CODEWORDS],
                                    int    nof_rxant,
                                    int    nof_symbols,
                                    float  scaling,
                                    float  noise_estimate)
{
  if (csi && csi[0]) {
    return srsran_predecoding_single_csi(y, h, x, csi[0], nof_rxant, nof_symbols, scaling, noise_estimate);
  }

#ifdef LV_HAVE_AVX
  if (nof_symbols > 32) {
    return srsran_predecoding_single_avx(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
  } else {
    return srsran_predecoding_single_gen(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
  }
#else
#ifdef LV_HAVE_SSE
  if (nof_symbols > 32) {
    return srsran_predecoding_single_sse(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
  } else {
    return srsran_predecoding_single_gen(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
  }
#else
  return srsran_predecoding_single_gen(y, h, x, nof_rxant, nof_symbols, scaling, noise_estimate);
#endif
#endif
}

/* C implementatino of the SFBC equalizer */
int srsran_predecoding_diversity_gen_(cf_t* y[SRSRAN_MAX_PORTS],
                                      cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                      cf_t* x[SRSRAN_MAX_LAYERS],
                                      int   nof_rxant,
                                      int   nof_ports,
                                      int   nof_symbols,
                                      int   symbol_start,
                                      float scaling)
{
  int i;
  if (nof_ports == 2) {
    cf_t h00, h01, h10, h11, r0, r1;

    for (i = symbol_start / 2; i < nof_symbols / 2; i++) {
      float hh = 0;
      cf_t  x0 = 0;
      cf_t  x1 = 0;
      for (int p = 0; p < nof_rxant; p++) {
        h00 = h[0][p][2 * i];
        h01 = h[0][p][2 * i + 1];
        h10 = h[1][p][2 * i];
        h11 = h[1][p][2 * i + 1];
        hh += crealf(h00) * crealf(h00) + cimagf(h00) * cimagf(h00) + crealf(h11) * crealf(h11) +
              cimagf(h11) * cimagf(h11);
        r0 = y[p][2 * i];
        r1 = y[p][2 * i + 1];
        if (hh == 0) {
          hh = 1e-4;
        }
        x0 += (conjf(h00) * r0 + h11 * conjf(r1));
        x1 += (-h10 * conjf(r0) + conjf(h01) * r1);
      }
      hh *= scaling;
      x[0][i] = x0 / hh * M_SQRT2;
      x[1][i] = x1 / hh * M_SQRT2;
    }
    return i;
  } else if (nof_ports == 4) {
    cf_t h0, h1, h2, h3, r0, r1, r2, r3;

    int m_ap = (nof_symbols % 4) ? ((nof_symbols - 2) / 4) : nof_symbols / 4;
    for (i = symbol_start; i < m_ap; i++) {
      float hh02 = 0, hh13 = 0;
      cf_t  x0 = 0, x1 = 0, x2 = 0, x3 = 0;
      for (int p = 0; p < nof_rxant; p++) {
        h0 = h[0][p][4 * i];
        h1 = h[1][p][4 * i + 2];
        h2 = h[2][p][4 * i];
        h3 = h[3][p][4 * i + 2];
        hh02 += crealf(h0) * crealf(h0) + cimagf(h0) * cimagf(h0) + crealf(h2) * crealf(h2) + cimagf(h2) * cimagf(h2);
        hh13 += crealf(h1) * crealf(h1) + cimagf(h1) * cimagf(h1) + crealf(h3) * crealf(h3) + cimagf(h3) * cimagf(h3);
        r0 = y[p][4 * i];
        r1 = y[p][4 * i + 1];
        r2 = y[p][4 * i + 2];
        r3 = y[p][4 * i + 3];

        x0 += (conjf(h0) * r0 + h2 * conjf(r1));
        x1 += (-h2 * conjf(r0) + conjf(h0) * r1);
        x2 += (conjf(h1) * r2 + h3 * conjf(r3));
        x3 += (-h3 * conjf(r2) + conjf(h1) * r3);
      }

      hh02 *= scaling;
      hh13 *= scaling;

      x[0][i] = x0 / hh02 * M_SQRT2;
      x[1][i] = x1 / hh02 * M_SQRT2;
      x[2][i] = x2 / hh13 * M_SQRT2;
      x[3][i] = x3 / hh13 * M_SQRT2;
    }
    return i;
  } else {
    ERROR("Number of ports must be 2 or 4 for transmit diversity (nof_ports=%d)", nof_ports);
    return -1;
  }
}

int srsran_predecoding_diversity_gen(cf_t* y[SRSRAN_MAX_PORTS],
                                     cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                     cf_t* x[SRSRAN_MAX_LAYERS],
                                     int   nof_rxant,
                                     int   nof_ports,
                                     int   nof_symbols,
                                     float scaling)
{
  return srsran_predecoding_diversity_gen_(y, h, x, nof_rxant, nof_ports, nof_symbols, 0, scaling);
}

/* SSE implementation of the 2-port SFBC equalizer */
#ifdef LV_HAVE_SSE
int srsran_predecoding_diversity2_sse(cf_t* y[SRSRAN_MAX_PORTS],
                                      cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                      cf_t* x[SRSRAN_MAX_LAYERS],
                                      int   nof_rxant,
                                      int   nof_symbols,
                                      float scaling)
{
  float*       x0Ptr  = (float*)x[0];
  float*       x1Ptr  = (float*)x[1];
  const float* h0Ptr0 = (const float*)h[0][0];
  const float* h1Ptr0 = (const float*)h[1][0];
  const float* h0Ptr1 = (const float*)h[0][1];
  const float* h1Ptr1 = (const float*)h[1][1];
  const float* yPtr0  = (const float*)y[0];
  const float* yPtr1  = (const float*)y[1];

  __m128 conjugator = _mm_setr_ps(0, -0.f, 0, -0.f);
  __m128 sqrt2      = _mm_set1_ps(M_SQRT2 / scaling);

  __m128 h0Val_00, h0Val_10, h1Val_00, h1Val_10, h000, h00conj0, h010, h01conj0, h100, h110;
  __m128 h0Val_01, h0Val_11, h1Val_01, h1Val_11, h001, h00conj1, h011, h01conj1, h101, h111;
  __m128 hh, hhshuf, hhsum, hhadd;
  __m128 r0Val0, r1Val0, r00, r10, r0conj0, r1conj0;
  __m128 r0Val1, r1Val1, r01, r11, r0conj1, r1conj1;
  __m128 x0, x1;

  for (int i = 0; i < nof_symbols / 4; i++) {
    h0Val_00 = _mm_load_ps(h0Ptr0);
    h0Ptr0 += 4;
    h0Val_10 = _mm_load_ps(h0Ptr0);
    h0Ptr0 += 4;
    h1Val_00 = _mm_load_ps(h1Ptr0);
    h1Ptr0 += 4;
    h1Val_10 = _mm_load_ps(h1Ptr0);
    h1Ptr0 += 4;

    if (nof_rxant == 2) {
      h0Val_01 = _mm_load_ps(h0Ptr1);
      h0Ptr1 += 4;
      h0Val_11 = _mm_load_ps(h0Ptr1);
      h0Ptr1 += 4;
      h1Val_01 = _mm_load_ps(h1Ptr1);
      h1Ptr1 += 4;
      h1Val_11 = _mm_load_ps(h1Ptr1);
      h1Ptr1 += 4;
    }

    h000 = _mm_shuffle_ps(h0Val_00, h0Val_10, _MM_SHUFFLE(1, 0, 1, 0));
    h010 = _mm_shuffle_ps(h0Val_00, h0Val_10, _MM_SHUFFLE(3, 2, 3, 2));

    h100 = _mm_shuffle_ps(h1Val_00, h1Val_10, _MM_SHUFFLE(1, 0, 1, 0));
    h110 = _mm_shuffle_ps(h1Val_00, h1Val_10, _MM_SHUFFLE(3, 2, 3, 2));

    if (nof_rxant == 2) {
      h001 = _mm_shuffle_ps(h0Val_01, h0Val_11, _MM_SHUFFLE(1, 0, 1, 0));
      h011 = _mm_shuffle_ps(h0Val_01, h0Val_11, _MM_SHUFFLE(3, 2, 3, 2));

      h101 = _mm_shuffle_ps(h1Val_01, h1Val_11, _MM_SHUFFLE(1, 0, 1, 0));
      h111 = _mm_shuffle_ps(h1Val_01, h1Val_11, _MM_SHUFFLE(3, 2, 3, 2));
    }

    r0Val0 = _mm_load_ps(yPtr0);
    yPtr0 += 4;
    r1Val0 = _mm_load_ps(yPtr0);
    yPtr0 += 4;
    r00 = _mm_shuffle_ps(r0Val0, r1Val0, _MM_SHUFFLE(1, 0, 1, 0));
    r10 = _mm_shuffle_ps(r0Val0, r1Val0, _MM_SHUFFLE(3, 2, 3, 2));

    if (nof_rxant == 2) {
      r0Val1 = _mm_load_ps(yPtr1);
      yPtr1 += 4;
      r1Val1 = _mm_load_ps(yPtr1);
      yPtr1 += 4;
      r01 = _mm_shuffle_ps(r0Val1, r1Val1, _MM_SHUFFLE(1, 0, 1, 0));
      r11 = _mm_shuffle_ps(r0Val1, r1Val1, _MM_SHUFFLE(3, 2, 3, 2));
    }

    /* Compute channel gain */
    hhadd  = _mm_hadd_ps(_mm_mul_ps(h000, h000), _mm_mul_ps(h110, h110));
    hhshuf = _mm_shuffle_ps(hhadd, hhadd, _MM_SHUFFLE(3, 1, 2, 0));
    hhsum  = _mm_hadd_ps(hhshuf, hhshuf);
    hh     = _mm_shuffle_ps(hhsum, hhsum, _MM_SHUFFLE(1, 1, 0, 0)); // h00^2+h11^2

    /* Add channel from 2nd antenna */
    if (nof_rxant == 2) {
      hhadd  = _mm_hadd_ps(_mm_mul_ps(h001, h001), _mm_mul_ps(h111, h111));
      hhshuf = _mm_shuffle_ps(hhadd, hhadd, _MM_SHUFFLE(3, 1, 2, 0));
      hhsum  = _mm_hadd_ps(hhshuf, hhshuf);
      hh     = _mm_add_ps(hh, _mm_shuffle_ps(hhsum, hhsum, _MM_SHUFFLE(1, 1, 0, 0))); // h00^2+h11^2
    }

    // Conjugate value
    h00conj0 = _mm_xor_ps(h000, conjugator);
    h01conj0 = _mm_xor_ps(h010, conjugator);
    r0conj0  = _mm_xor_ps(r00, conjugator);
    r1conj0  = _mm_xor_ps(r10, conjugator);

    if (nof_rxant == 2) {
      h00conj1 = _mm_xor_ps(h001, conjugator);
      h01conj1 = _mm_xor_ps(h011, conjugator);
      r0conj1  = _mm_xor_ps(r01, conjugator);
      r1conj1  = _mm_xor_ps(r11, conjugator);
    }

    // Multiply by channel matrix
    x0 = _mm_add_ps(PROD(h00conj0, r00), PROD(h110, r1conj0));
    x1 = _mm_sub_ps(PROD(h01conj0, r10), PROD(h100, r0conj0));

    // Add received symbol from 2nd antenna
    if (nof_rxant == 2) {
      x0 = _mm_add_ps(x0, _mm_add_ps(PROD(h00conj1, r01), PROD(h111, r1conj1)));
      x1 = _mm_add_ps(x1, _mm_sub_ps(PROD(h01conj1, r11), PROD(h101, r0conj1)));
    }

    x0 = _mm_mul_ps(_mm_div_ps(x0, hh), sqrt2);
    x1 = _mm_mul_ps(_mm_div_ps(x1, hh), sqrt2);

    _mm_store_ps(x0Ptr, x0);
    x0Ptr += 4;
    _mm_store_ps(x1Ptr, x1);
    x1Ptr += 4;
  }
  // Compute remaining symbols using generic implementation
  srsran_predecoding_diversity_gen_(y, h, x, nof_rxant, 2, nof_symbols, 4 * (nof_symbols / 4), scaling);
  return nof_symbols;
}
#endif

int srsran_predecoding_diversity(cf_t* y_,
                                 cf_t* h_[SRSRAN_MAX_PORTS],
                                 cf_t* x[SRSRAN_MAX_LAYERS],
                                 int   nof_ports,
                                 int   nof_symbols,
                                 float scaling)
{
  cf_t*    h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS];
  cf_t*    y[SRSRAN_MAX_PORTS];
  uint32_t nof_rxant = 1;

  for (int i = 0; i < nof_ports; i++) {
    h[i][0] = h_[i];
  }
  y[0] = y_;

#ifdef LV_HAVE_SSE
  if (nof_symbols > 32 && nof_ports == 2) {
    return srsran_predecoding_diversity2_sse(y, h, x, nof_rxant, nof_symbols, scaling);
  } else {
    return srsran_predecoding_diversity_gen(y, h, x, nof_rxant, nof_ports, nof_symbols, scaling);
  }
#else
  return srsran_predecoding_diversity_gen(y, h, x, nof_rxant, nof_ports, nof_symbols, scaling);
#endif
}

int srsran_predecoding_diversity_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                     cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                     cf_t*  x[SRSRAN_MAX_LAYERS],
                                     float* csi[SRSRAN_MAX_CODEWORDS],
                                     int    nof_rxant,
                                     int    nof_ports,
                                     int    nof_symbols,
                                     float  scaling)
{
  int i;
  if (nof_ports == 2) {
    cf_t h00, h01, h10, h11, r0, r1;

    for (i = 0; i < nof_symbols / 2; i++) {
      float hh = 0;
      cf_t  x0 = 0;
      cf_t  x1 = 0;
      for (int p = 0; p < nof_rxant; p++) {
        h00 = h[0][p][2 * i];
        h01 = h[0][p][2 * i + 1];
        h10 = h[1][p][2 * i];
        h11 = h[1][p][2 * i + 1];
        hh += crealf(h00) * crealf(h00) + cimagf(h00) * cimagf(h00) + crealf(h11) * crealf(h11) +
              cimagf(h11) * cimagf(h11);
        r0 = y[p][2 * i];
        r1 = y[p][2 * i + 1];
        if (hh == 0) {
          hh = 1e-4;
        }
        x0 += (conjf(h00) * r0 + h11 * conjf(r1));
        x1 += (-h10 * conjf(r0) + conjf(h01) * r1);
      }

      csi[0][2 * i + 0] = hh;
      csi[0][2 * i + 1] = hh;

      hh *= scaling;
      x[0][i] = x0 / hh * M_SQRT2;
      x[1][i] = x1 / hh * M_SQRT2;
    }
    return i;
  } else if (nof_ports == 4) {
    int m_ap = (nof_symbols % 4) ? ((nof_symbols - 2) / 4) : nof_symbols / 4;
    for (i = 0; i < m_ap; i++) {
      cf_t  x0 = 0, x1 = 0, x2 = 0, x3 = 0;
      float a0 = 0, a1 = 0, a2 = 0, a3 = 0;
      cf_t  r0, r1, r2, r3;
      cf_t  h00, h01, h10, h11;

      for (int p = 0; p < nof_rxant; p++) {
        h00 = h[0][p][4 * i + 0];
        h01 = h[2][p][4 * i + 0];
        h10 = h[0][p][4 * i + 1];
        h11 = h[2][p][4 * i + 1];

        a0 += __real__ h00 * __real__ h00 + __imag__ h00 * __imag__ h00 + __real__ h11 * __real__ h11 +
              __imag__ h11 * __imag__ h11;

        a1 += __real__ h10 * __real__ h10 + __imag__ h10 * __imag__ h10 + __real__ h01 * __real__ h01 +
              __imag__ h01 * __imag__ h01;

        r0 = y[p][4 * i];
        r1 = y[p][4 * i + 1];

        x0 += (conjf(h00) * r0 + h11 * conjf(r1));
        x1 += (-h01 * conjf(r0) + conjf(h10) * r1);

        h00 = h[1][p][4 * i + 2];
        h01 = h[3][p][4 * i + 2];
        h10 = h[1][p][4 * i + 3];
        h11 = h[3][p][4 * i + 3];

        a2 += __real__ h00 * __real__ h00 + __imag__ h00 * __imag__ h00 + __real__ h11 * __real__ h11 +
              __imag__ h11 * __imag__ h11;

        a3 += __real__ h10 * __real__ h10 + __imag__ h10 * __imag__ h10 + __real__ h01 * __real__ h01 +
              __imag__ h01 * __imag__ h01;

        r2 = y[p][4 * i + 2];
        r3 = y[p][4 * i + 3];

        x2 += (conjf(h00) * r2 + h11 * conjf(r3));
        x3 += (-h01 * conjf(r2) + conjf(h10) * r3);
      }

      a0 *= scaling;
      a1 *= scaling;
      a2 *= scaling;
      a3 *= scaling;

      csi[0][4 * i + 0] = a0 / nof_rxant;
      csi[0][4 * i + 1] = a1 / nof_rxant;
      csi[0][4 * i + 2] = a2 / nof_rxant;
      csi[0][4 * i + 3] = a3 / nof_rxant;

      x[0][i] = x0 / a0 * M_SQRT2;
      x[1][i] = x1 / a1 * M_SQRT2;
      x[2][i] = x2 / a2 * M_SQRT2;
      x[3][i] = x3 / a3 * M_SQRT2;
    }
    return i;
  } else {
    ERROR("Number of ports must be 2 or 4 for transmit diversity (nof_ports=%d)", nof_ports);
    return -1;
  }
}

int srsran_predecoding_diversity_multi(cf_t*  y[SRSRAN_MAX_PORTS],
                                       cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                       cf_t*  x[SRSRAN_MAX_LAYERS],
                                       float* csi[SRSRAN_MAX_CODEWORDS],
                                       int    nof_rxant,
                                       int    nof_ports,
                                       int    nof_symbols,
                                       float  scaling)
{
  if (csi && csi[0]) {
    return srsran_predecoding_diversity_csi(y, h, x, csi, nof_rxant, nof_ports, nof_symbols, scaling);
  } else {
#ifdef LV_HAVE_SSE
    if (nof_symbols > 32 && nof_ports == 2) {
      return srsran_predecoding_diversity2_sse(y, h, x, nof_rxant, nof_symbols, scaling);
    } else {
      return srsran_predecoding_diversity_gen(y, h, x, nof_rxant, nof_ports, nof_symbols, scaling);
    }
#else
    return srsran_predecoding_diversity_gen(y, h, x, nof_rxant, nof_ports, nof_symbols, scaling);
#endif
  }
}

int srsran_precoding_mimo_2x2_gen(cf_t  W[2][2],
                                  cf_t* y[SRSRAN_MAX_PORTS],
                                  cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                  cf_t* x[SRSRAN_MAX_LAYERS],
                                  int   nof_symbols,
                                  float scaling,
                                  float noise_estimate)
{
  cf_t G[2][2], Gx[2][2];

  for (int i = 0; i < nof_symbols; i++) {
    // G=H*W
    G[0][0] = h[0][0][i] * W[0][0] + h[0][1][i] * W[1][0];
    G[0][1] = h[0][0][i] * W[1][0] + h[0][1][i] * W[1][1];
    G[1][0] = h[1][0][i] * W[0][0] + h[1][1][i] * W[1][0];
    G[1][1] = h[1][0][i] * W[1][0] + h[1][1][i] * W[1][1];

    if (noise_estimate == 0) {
      // MF equalizer: Gx = G'
      Gx[0][0] = conjf(G[0][0]);
      Gx[0][1] = conjf(G[1][0]);
      Gx[1][0] = conjf(G[0][1]);
      Gx[1][1] = conjf(G[1][1]);
    } else {
      // MMSE equalizer: Gx = (G'G+I)
      ERROR("MMSE MIMO decoder not implemented");
      return -1;
    }

    // x=G*y
    x[0][i] = (Gx[0][0] * y[0][i] + Gx[0][1] * y[1][i]) * scaling;
    x[1][i] = (Gx[1][0] * y[0][i] + Gx[1][1] * y[1][i]) * scaling;
  }

  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_ccd_2x2_zf_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                             cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                             cf_t*  x[SRSRAN_MAX_LAYERS],
                                             float* csi[SRSRAN_MAX_CODEWORDS],
                                             int    nof_symbols,
                                             float  scaling)
{
  uint32_t i    = 0;
  float    norm = 2.0f / scaling;

#if SRSRAN_SIMD_CF_SIZE != 0
#if SRSRAN_SIMD_CF_SIZE == 16
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {
      +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {
      -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f};
#elif SRSRAN_SIMD_CF_SIZE == 8
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {+0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {-0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f};
#elif SRSRAN_SIMD_CF_SIZE == 4
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {+0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {-0.0f, +0.0f, -0.0f, +0.0f};
#endif

  simd_f_t mask1 = srsran_simd_f_loadu(_mask1);
  simd_f_t mask2 = srsran_simd_f_loadu(_mask2);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    /* Load channel */
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);

    /* Apply precoding */
    simd_cf_t h00, h01, h10, h11;
    h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_neg_mask(h10i, mask1));
    h10 = srsran_simd_cf_add(h01i, srsran_simd_cf_neg_mask(h11i, mask1));
    h01 = srsran_simd_cf_add(h00i, srsran_simd_cf_neg_mask(h10i, mask2));
    h11 = srsran_simd_cf_add(h01i, srsran_simd_cf_neg_mask(h11i, mask2));

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t x0, x1;
    simd_f_t  csi0, csi1;

    srsran_mat_2x2_zf_csi_simd(y0, y1, h00, h01, h10, h11, &x0, &x1, &csi0, &csi1, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);

    srsran_simd_f_store(&csi[0][i], csi0);
    srsran_simd_f_store(&csi[1][i], csi1);
  }
#endif /* SRSRAN_SIMD_CF_SIZE != 0 */

  cf_t h00, h01, h10, h11, det;
  for (; i < nof_symbols; i++) {
    // Even precoder
    h00 = +h[0][0][i] + h[1][0][i];
    h10 = +h[0][1][i] + h[1][1][i];
    h01 = +h[0][0][i] - h[1][0][i];
    h11 = +h[0][1][i] - h[1][1][i];
    det = (h00 * h11 - h01 * h10);
    det = conjf(det) * (norm / (crealf(det) * crealf(det) + cimagf(det) * cimagf(det)));

    x[0][i] = (+h11 * y[0][i] - h01 * y[1][i]) * det;
    x[1][i] = (-h10 * y[0][i] + h00 * y[1][i]) * det;

    csi[0][i] = 1.0f;
    csi[1][i] = 1.0f;

    i++;

    // Odd precoder
    h00 = h[0][0][i] - h[1][0][i];
    h10 = h[0][1][i] - h[1][1][i];
    h01 = h[0][0][i] + h[1][0][i];
    h11 = h[0][1][i] + h[1][1][i];
    det = (h00 * h11 - h01 * h10);
    det = conjf(det) * (norm / (crealf(det) * crealf(det) + cimagf(det) * cimagf(det)));

    x[0][i] = (+h11 * y[0][i] - h01 * y[1][i]) * det;
    x[1][i] = (-h10 * y[0][i] + h00 * y[1][i]) * det;

    csi[0][i] = 1.0f;
    csi[1][i] = 1.0f;
  }
  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_ccd_2x2_zf(cf_t* y[SRSRAN_MAX_PORTS],
                                         cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                         cf_t* x[SRSRAN_MAX_LAYERS],
                                         int   nof_symbols,
                                         float scaling)
{
  uint32_t i    = 0;
  float    norm = 2.0f / scaling;

#if SRSRAN_SIMD_CF_SIZE != 0
#if SRSRAN_SIMD_CF_SIZE == 16
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {
      +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {
      -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f};
#elif SRSRAN_SIMD_CF_SIZE == 8
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {+0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {-0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f};
#elif SRSRAN_SIMD_CF_SIZE == 4
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {+0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {-0.0f, +0.0f, -0.0f, +0.0f};
#endif

  simd_f_t mask1 = srsran_simd_f_loadu(_mask1);
  simd_f_t mask2 = srsran_simd_f_loadu(_mask2);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    /* Load channel */
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);

    /* Apply precoding */
    simd_cf_t h00, h01, h10, h11;
    h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_neg_mask(h10i, mask1));
    h10 = srsran_simd_cf_add(h01i, srsran_simd_cf_neg_mask(h11i, mask1));
    h01 = srsran_simd_cf_add(h00i, srsran_simd_cf_neg_mask(h10i, mask2));
    h11 = srsran_simd_cf_add(h01i, srsran_simd_cf_neg_mask(h11i, mask2));

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t x0, x1;

    srsran_mat_2x2_zf_simd(y0, y1, h00, h01, h10, h11, &x0, &x1, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);
  }
#endif /* SRSRAN_SIMD_CF_SIZE != 0 */

  cf_t h00, h01, h10, h11, det;
  for (; i < nof_symbols; i++) {
    // Even precoder
    h00 = +h[0][0][i] + h[1][0][i];
    h10 = +h[0][1][i] + h[1][1][i];
    h01 = +h[0][0][i] - h[1][0][i];
    h11 = +h[0][1][i] - h[1][1][i];
    det = (h00 * h11 - h01 * h10);
    det = conjf(det) * (norm / (crealf(det) * crealf(det) + cimagf(det) * cimagf(det)));

    x[0][i] = (+h11 * y[0][i] - h01 * y[1][i]) * det;
    x[1][i] = (-h10 * y[0][i] + h00 * y[1][i]) * det;

    i++;

    // Odd precoder
    h00 = h[0][0][i] - h[1][0][i];
    h10 = h[0][1][i] - h[1][1][i];
    h01 = h[0][0][i] + h[1][0][i];
    h11 = h[0][1][i] + h[1][1][i];
    det = (h00 * h11 - h01 * h10);
    det = conjf(det) * (norm / (crealf(det) * crealf(det) + cimagf(det) * cimagf(det)));

    x[0][i] = (+h11 * y[0][i] - h01 * y[1][i]) * det;
    x[1][i] = (-h10 * y[0][i] + h00 * y[1][i]) * det;
  }
  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_ccd_zf(cf_t*  y[SRSRAN_MAX_PORTS],
                                     cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                     cf_t*  x[SRSRAN_MAX_LAYERS],
                                     float* csi[SRSRAN_MAX_CODEWORDS],
                                     int    nof_rxant,
                                     int    nof_ports,
                                     int    nof_layers,
                                     int    nof_symbols,
                                     float  scaling)
{
  if (nof_ports == 2 && nof_rxant == 2) {
    if (nof_layers == 2) {
      if (csi && csi[0]) {
        return srsran_predecoding_ccd_2x2_zf_csi(y, h, x, csi, nof_symbols, scaling);
      } else {
        return srsran_predecoding_ccd_2x2_zf(y, h, x, nof_symbols, scaling);
      }
    } else {
      ERROR("Error predecoding CCD: Invalid number of layers %d", nof_layers);
      return -1;
    }
  } else if (nof_ports == 4) {
    ERROR("Error predecoding CCD: Only 2 ports supported");
  } else {
    ERROR("Error predecoding CCD: Invalid combination of ports %d and rx antennax %d", nof_ports, nof_rxant);
  }
  return SRSRAN_ERROR;
}

static int srsran_predecoding_ccd_2x2_mmse_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                               cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                               cf_t*  x[SRSRAN_MAX_LAYERS],
                                               float* csi[SRSRAN_MAX_CODEWORDS],
                                               int    nof_symbols,
                                               float  scaling,
                                               float  noise_estimate)
{
  int   i    = 0;
  float norm = 2.0f / scaling;

#if SRSRAN_SIMD_CF_SIZE != 0
#if SRSRAN_SIMD_CF_SIZE == 16
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {
      +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {
      -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f};
#elif SRSRAN_SIMD_CF_SIZE == 8
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {+0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {-0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f};
#elif SRSRAN_SIMD_CF_SIZE == 4
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {+0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {-0.0f, +0.0f, -0.0f, +0.0f};
#endif

  simd_f_t mask1 = srsran_simd_f_loadu(_mask1);
  simd_f_t mask2 = srsran_simd_f_loadu(_mask2);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    /* Load channel */
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);

    /* Apply precoding */
    simd_cf_t h00, h01, h10, h11;
    h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_neg_mask(h10i, mask1));
    h10 = srsran_simd_cf_add(h01i, srsran_simd_cf_neg_mask(h11i, mask1));
    h01 = srsran_simd_cf_add(h00i, srsran_simd_cf_neg_mask(h10i, mask2));
    h11 = srsran_simd_cf_add(h01i, srsran_simd_cf_neg_mask(h11i, mask2));

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t x0, x1;
    simd_f_t  csi0, csi1;

    srsran_mat_2x2_mmse_csi_simd(y0, y1, h00, h01, h10, h11, &x0, &x1, &csi0, &csi1, noise_estimate, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);

    srsran_simd_f_store(&csi[0][i], csi0);
    srsran_simd_f_store(&csi[1][i], csi1);
  }
#endif /* SRSRAN_SIMD_CF_SIZE != 0 */

  cf_t h00, h01, h10, h11;
  for (; i < nof_symbols; i++) {
    // Even precoder
    h00 = +h[0][0][i] + h[1][0][i];
    h10 = +h[0][1][i] + h[1][1][i];
    h01 = +h[0][0][i] - h[1][0][i];
    h11 = +h[0][1][i] - h[1][1][i];
    srsran_mat_2x2_mmse_csi_gen(
        y[0][i], y[1][i], h00, h01, h10, h11, &x[0][i], &x[1][i], &csi[0][i], &csi[1][i], noise_estimate, norm);
    i++;

    // Odd precoder
    h00 = h[0][0][i] - h[1][0][i];
    h10 = h[0][1][i] - h[1][1][i];
    h01 = h[0][0][i] + h[1][0][i];
    h11 = h[0][1][i] + h[1][1][i];
    srsran_mat_2x2_mmse_csi_gen(
        y[0][i], y[1][i], h00, h01, h10, h11, &x[0][i], &x[1][i], &csi[0][i], &csi[1][i], noise_estimate, norm);
  }
  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_ccd_2x2_mmse(cf_t* y[SRSRAN_MAX_PORTS],
                                           cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                           cf_t* x[SRSRAN_MAX_LAYERS],
                                           int   nof_symbols,
                                           float scaling,
                                           float noise_estimate)
{
  int   i    = 0;
  float norm = 2.0f / scaling;

#if SRSRAN_SIMD_CF_SIZE != 0
#if SRSRAN_SIMD_CF_SIZE == 16
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {
      +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {
      -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f};
#elif SRSRAN_SIMD_CF_SIZE == 8
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {+0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {-0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f, -0.0f, +0.0f};
#elif SRSRAN_SIMD_CF_SIZE == 4
  float _mask1[SRSRAN_SIMD_CF_SIZE] = {+0.0f, -0.0f, +0.0f, -0.0f};
  float _mask2[SRSRAN_SIMD_CF_SIZE] = {-0.0f, +0.0f, -0.0f, +0.0f};
#endif

  simd_f_t mask1 = srsran_simd_f_loadu(_mask1);
  simd_f_t mask2 = srsran_simd_f_loadu(_mask2);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    /* Load channel */
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);

    /* Apply precoding */
    simd_cf_t h00, h01, h10, h11;
    h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_neg_mask(h10i, mask1));
    h10 = srsran_simd_cf_add(h01i, srsran_simd_cf_neg_mask(h11i, mask1));
    h01 = srsran_simd_cf_add(h00i, srsran_simd_cf_neg_mask(h10i, mask2));
    h11 = srsran_simd_cf_add(h01i, srsran_simd_cf_neg_mask(h11i, mask2));

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t x0, x1;
    srsran_mat_2x2_mmse_simd(y0, y1, h00, h01, h10, h11, &x0, &x1, noise_estimate, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);
  }
#endif /* SRSRAN_SIMD_CF_SIZE != 0 */

  cf_t h00, h01, h10, h11;
  for (; i < nof_symbols; i++) {
    // Even precoder
    h00 = +h[0][0][i] + h[1][0][i];
    h10 = +h[0][1][i] + h[1][1][i];
    h01 = +h[0][0][i] - h[1][0][i];
    h11 = +h[0][1][i] - h[1][1][i];
    srsran_mat_2x2_mmse_gen(y[0][i], y[1][i], h00, h01, h10, h11, &x[0][i], &x[1][i], noise_estimate, norm);

    i++;

    // Odd precoder
    h00 = h[0][0][i] - h[1][0][i];
    h10 = h[0][1][i] - h[1][1][i];
    h01 = h[0][0][i] + h[1][0][i];
    h11 = h[0][1][i] + h[1][1][i];
    srsran_mat_2x2_mmse_gen(y[0][i], y[1][i], h00, h01, h10, h11, &x[0][i], &x[1][i], noise_estimate, norm);
  }
  return SRSRAN_SUCCESS;
}
// In lib/src/phy/mimo/precoding.c
//
int srsran_predecoding_ccd_4x2_mmse(cf_t* y[SRSRAN_MAX_PORTS],
                                    cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                    cf_t* x[SRSRAN_MAX_LAYERS],
                                    int    nof_symbols,
                                    float  scaling,
                                    float  noise_estimate)
{
  float norm = 2.0f / scaling;
  const cf_t phase[4] = {1.0f, -_Complex_I, -1.0f, _Complex_I};

  // Debug: print first few channel values
  static int debug_count = 0;
  if (debug_count < 0) {
    printf("4x2 CDD MMSE: nof_symbols=%d, scaling=%.3f, noise=%.6f\n",
           nof_symbols, scaling, noise_estimate);
    printf("  h[0][0][0] = %.4f + %.4fj\n", crealf(h[0][0][0]), cimagf(h[0][0][0]));
    printf("  h[1][0][0] = %.4f + %.4fj\n", crealf(h[1][0][0]), cimagf(h[1][0][0]));
    printf("  h[2][0][0] = %.4f + %.4fj\n", crealf(h[2][0][0]), cimagf(h[2][0][0]));
    printf("  h[3][0][0] = %.4f + %.4fj\n", crealf(h[3][0][0]), cimagf(h[3][0][0]));
    printf("  y[0][0] = %.4f + %.4fj\n", crealf(y[0][0]), cimagf(y[0][0]));
    printf("  y[1][0] = %.4f + %.4fj\n", crealf(y[1][0]), cimagf(y[1][0]));
    debug_count++;
  }

  for (int i = 0; i < nof_symbols; i++) {
    cf_t d = phase[i & 3];

    cf_t v0_rx0 = 0.5f * (h[0][0][i] + h[1][0][i]);
    cf_t v0_rx1 = 0.5f * (h[0][1][i] + h[1][1][i]);
    cf_t v1_rx0 = 0.5f * (h[2][0][i] - h[3][0][i]) * d;
    cf_t v1_rx1 = 0.5f * (h[2][1][i] - h[3][1][i]) * d;

    cf_t h00 = (v0_rx0 + v1_rx0) * (float)M_SQRT1_2;
    cf_t h10 = (v0_rx1 + v1_rx1) * (float)M_SQRT1_2;
    cf_t h01 = (v0_rx0 - v1_rx0) * (float)M_SQRT1_2;
    cf_t h11 = (v0_rx1 - v1_rx1) * (float)M_SQRT1_2;

    srsran_mat_2x2_mmse_gen(y[0][i], y[1][i], h00, h01, h10, h11, &x[0][i], &x[1][i], noise_estimate, norm);
  }

  // Debug: print first output
  if (debug_count < 0) {
    printf("  x[0][0] = %.4f + %.4fj\n", crealf(x[0][0]), cimagf(x[0][0]));
    printf("  x[1][0] = %.4f + %.4fj\n", crealf(x[1][0]), cimagf(x[1][0]));
    debug_count++;
  }

  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_ccd_4x2_mmse_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                               cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                               cf_t*  x[SRSRAN_MAX_LAYERS],
                                               float* csi[SRSRAN_MAX_CODEWORDS],
                                               int    nof_symbols,
                                               float  scaling,
                                               float  noise_estimate)
{
  if (noise_estimate < 0.01f) {
    noise_estimate = 0.01f;
  }

  // printf("[4x2 CDD] nof_symbols=%d, scaling=%.3f\n", nof_symbols, scaling);

  // Check port powers
  float h_pwr[4] = {0};
  for (int i = 0; i < 100 && i < nof_symbols; i++) {
    for (int p = 0; p < 4; p++) {
      h_pwr[p] += cabsf(h[p][0][i])*cabsf(h[p][0][i]) + cabsf(h[p][1][i])*cabsf(h[p][1][i]);
    }
  }
  int check_n = (nof_symbols < 100) ? nof_symbols : 100;
  // for (int p = 0; p < 4; p++) h_pwr[p] /= check_n;
  // printf("[4x2 CDD] Port powers: P0=%.2f P1=%.2f P2=%.2f P3=%.2f\n",
  //        h_pwr[0], h_pwr[1], h_pwr[2], h_pwr[3]);

  // Check received signal power
  float y_pwr[2] = {0};
  for (int i = 0; i < 100 && i < nof_symbols; i++) {
    y_pwr[0] += cabsf(y[0][i]) * cabsf(y[0][i]);
    y_pwr[1] += cabsf(y[1][i]) * cabsf(y[1][i]);
  }
  y_pwr[0] /= check_n;
  y_pwr[1] /= check_n;
  // printf("[4x2 CDD] Received signal power: Y0=%.2f Y1=%.2f\n", y_pwr[0], y_pwr[1]);

  // // Print first few channel estimates for inspection
  // printf("[4x2 CDD] First 5 channel estimates h[port][rx][i]:\n");
  // for (int i = 0; i < 5; i++) {
  //   printf("  i=%d: h00=(%.2f,%.2f) h10=(%.2f,%.2f) h01=(%.2f,%.2f) h11=(%.2f,%.2f)\n",
  //          i,
  //          crealf(h[0][0][i]), cimagf(h[0][0][i]),
  //          crealf(h[1][0][i]), cimagf(h[1][0][i]),
  //          crealf(h[0][1][i]), cimagf(h[0][1][i]),
  //          crealf(h[1][1][i]), cimagf(h[1][1][i]));
  //   printf("       h20=(%.2f,%.2f) h30=(%.2f,%.2f) h21=(%.2f,%.2f) h31=(%.2f,%.2f)\n",
  //          crealf(h[2][0][i]), cimagf(h[2][0][i]),
  //          crealf(h[3][0][i]), cimagf(h[3][0][i]),
  //          crealf(h[2][1][i]), cimagf(h[2][1][i]),
  //          crealf(h[3][1][i]), cimagf(h[3][1][i]));
  // }

  // // Print first few received symbols
  // printf("[4x2 CDD] First 5 received symbols:\n");
  // for (int i = 0; i < 5; i++) {
  //   printf("  i=%d: y0=(%.2f,%.2f) y1=(%.2f,%.2f)\n",
  //          i, crealf(y[0][i]), cimagf(y[0][i]),
  //          crealf(y[1][i]), cimagf(y[1][i]));
  // }

  // Try simple MRC with just the strongest single channel (diagnostic)
  // Find which h[p][r] has most power
  int best_p = 0, best_r = 0;
  float best_pwr = 0;
  for (int p = 0; p < 4; p++) {
    for (int r = 0; r < 2; r++) {
      float pwr = 0;
      for (int i = 0; i < check_n; i++) {
        pwr += cabsf(h[p][r][i]) * cabsf(h[p][r][i]);
      }
      if (pwr > best_pwr) {
        best_pwr = pwr;
        best_p = p;
        best_r = r;
      }
    }
  }
  // printf("[4x2 CDD] Strongest channel: h[%d][%d] with power %.2f\n", best_p, best_r, best_pwr/check_n);

  // // Try single-tap equalization with strongest channel as diagnostic
  // printf("[4x2 CDD] Single-tap equalization test (using h[%d][%d] on y[%d]):\n", best_p, best_r, best_r);
  // for (int i = 0; i < 10; i++) {
  //   cf_t h_best = h[best_p][best_r][i];
  //   cf_t y_best = y[best_r][i];
  //   cf_t eq = y_best * conjf(h_best) / (cabsf(h_best)*cabsf(h_best) + 0.01f);
  //   printf("  i=%d: h=(%.2f,%.2f) y=(%.2f,%.2f) eq=(%.2f,%.2f) |eq|=%.2f\n",
  //          i, crealf(h_best), cimagf(h_best),
  //          crealf(y_best), cimagf(y_best),
  //          crealf(eq), cimagf(eq), cabsf(eq));
  // }

  // // Now try proper 2x2 MIMO with ports 0,1
  // printf("[4x2 CDD] 2x2 MIMO equalization (ports 0,1):\n");

  int good_count = 0;
  for (int i = 0; i < nof_symbols; i++) {
    // No CDD for now - let's see raw equalization
    cf_t H00 = h[0][0][i];
    cf_t H01 = h[1][0][i];
    cf_t H10 = h[0][1][i];
    cf_t H11 = h[1][1][i];

    // ZF equalization: x = H^-1 * y
    cf_t det = H00 * H11 - H01 * H10;
    if (cabsf(det) < 1e-6f) {
      det = 1e-6f;
    }

    cf_t inv_det = 1.0f / det;
    cf_t x0 = (H11 * y[0][i] - H01 * y[1][i]) * inv_det;
    cf_t x1 = (-H10 * y[0][i] + H00 * y[1][i]) * inv_det;

    x[0][i] = x0 * scaling;
    x[1][i] = x1 * scaling;

    float mag0 = cabsf(x0);
    float mag1 = cabsf(x1);
    if (mag0 > 0.5f && mag0 < 1.5f && mag1 > 0.5f && mag1 < 1.5f) {
      good_count++;
    }

    if (csi[0]) csi[0][i] = cabsf(det);
    if (csi[1]) csi[1][i] = cabsf(det);
  }

  // printf("[4x2 CDD] ZF 2x2 (ports 0,1) QPSK-like: %d/%d (%.1f%%)\n",
  //        good_count, nof_symbols, 100.0f*good_count/nof_symbols);

  // Also try with ports 2,3
  good_count = 0;
  for (int i = 0; i < nof_symbols; i++) {
    cf_t H00 = h[2][0][i];
    cf_t H01 = h[3][0][i];
    cf_t H10 = h[2][1][i];
    cf_t H11 = h[3][1][i];

    cf_t det = H00 * H11 - H01 * H10;
    if (cabsf(det) < 1e-6f) det = 1e-6f;

    cf_t inv_det = 1.0f / det;
    cf_t x0 = (H11 * y[0][i] - H01 * y[1][i]) * inv_det;
    cf_t x1 = (-H10 * y[0][i] + H00 * y[1][i]) * inv_det;

    float mag0 = cabsf(x0);
    float mag1 = cabsf(x1);
    if (mag0 > 0.5f && mag0 < 1.5f && mag1 > 0.5f && mag1 < 1.5f) {
      good_count++;
    }
  }
  // printf("[4x2 CDD] ZF 2x2 (ports 2,3) QPSK-like: %d/%d (%.1f%%)\n",
  //        good_count, nof_symbols, 100.0f*good_count/nof_symbols);

  // // Print first 10 equalized for inspection
  // printf("[4x2 CDD] First 10 ZF equalized (ports 0,1):\n");
  // for (int i = 0; i < 10; i++) {
  //   printf("  (%.2f,%.2f) (%.2f,%.2f)\n",
  //          crealf(x[0][i]), cimagf(x[0][i]),
  //          crealf(x[1][i]), cimagf(x[1][i]));
  // }

  return nof_symbols;
}

// int srsran_predecoding_ccd_4x2_mmse(cf_t* y[SRSRAN_MAX_PORTS],
//                                     cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
//                                     cf_t* x[SRSRAN_MAX_LAYERS],
//                                     int    nof_symbols,
//                                     float  scaling,
//                                     float  noise_estimate)
// {
//   // 4-port CDD per TS 36.211 Table 6.3.4.2.3-1
//   // W = (1/2) * [1  0;  1  0;  0  1;  0 -1] * D(i) * U
//   // D(i) = diag([1, e^{-jπi/2}]) cycles {1, -j, -1, j}
//   // U = (1/sqrt(2)) * [1  1;  1 -1]

//   // Pre-compute phase factors
//   const cf_t phase[4] = {1.0f, -_Complex_I, -1.0f, _Complex_I};

//   for (int i = 0; i < nof_symbols; i++) {
//     // Get delay phase for this subcarrier
//     cf_t d = phase[i & 3];  // i mod 4

//     // Effective channel for layer 0 (before U mixing):
//     // h_eff_l0_rx = (h[0][rx] + h[1][rx]) / 2

//     // Effective channel for layer 1 (before U mixing):
//     // h_eff_l1_rx = (h[2][rx] - h[3][rx]) * d / 2

//     // After U matrix multiplication:
//     // h00 = (h_l0 + h_l1) / sqrt(2), h10 = (h_l0 - h_l1) / sqrt(2)

//     cf_t h_l0 = 0.5f * (h[0][0][i] + h[1][0][i]);
//     cf_t h_l1 = 0.5f * (h[2][0][i] - h[3][0][i]) * d;

//     cf_t h00 = (h_l0 + h_l1) * M_SQRT1_2;
//     cf_t h10 = (h_l0 - h_l1) * M_SQRT1_2;

//     h_l0 = 0.5f * (h[0][1][i] + h[1][1][i]);
//     h_l1 = 0.5f * (h[2][1][i] - h[3][1][i]) * d;

//     cf_t h01 = (h_l0 + h_l1) * M_SQRT1_2;
//     cf_t h11 = (h_l0 - h_l1) * M_SQRT1_2;

//     // Standard 2x2 MMSE equalization
//     cf_t h00_conj = conjf(h00);
//     cf_t h01_conj = conjf(h01);
//     cf_t h10_conj = conjf(h10);
//     cf_t h11_conj = conjf(h11);

//     float norm0 = crealf(h00) * crealf(h00) + cimagf(h00) * cimagf(h00) +
//                   crealf(h01) * crealf(h01) + cimagf(h01) * cimagf(h01);
//     float norm1 = crealf(h10) * crealf(h10) + cimagf(h10) * cimagf(h10) +
//                   crealf(h11) * crealf(h11) + cimagf(h11) * cimagf(h11);

//     cf_t cross = h00_conj * h10 + h01_conj * h11;

//     // MMSE: (H^H * H + σ²I)^-1 * H^H
//     float det_re = (norm0 + noise_estimate) * (norm1 + noise_estimate) -
//                    (crealf(cross) * crealf(cross) + cimagf(cross) * cimagf(cross));

//     if (fabsf(det_re) < 1e-10f) {
//       x[0][i] = 0;
//       x[1][i] = 0;
//       continue;
//     }

//     float inv_det = scaling / det_re;

//     cf_t w00 = ((norm1 + noise_estimate) * h00_conj - conjf(cross) * h10_conj) * inv_det;
//     cf_t w01 = ((norm1 + noise_estimate) * h01_conj - conjf(cross) * h11_conj) * inv_det;
//     cf_t w10 = ((norm0 + noise_estimate) * h10_conj - cross * h00_conj) * inv_det;
//     cf_t w11 = ((norm0 + noise_estimate) * h11_conj - cross * h01_conj) * inv_det;

//     x[0][i] = w00 * y[0][i] + w01 * y[1][i];
//     x[1][i] = w10 * y[0][i] + w11 * y[1][i];
//   }

//   return nof_symbols;
// }

// // Simple 4x2 CDD - Direct extension of 2x2 pattern
// int srsran_predecoding_ccd_4x2_mmse_csi(cf_t* y[SRSRAN_MAX_PORTS],
//                                         cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
//                                         cf_t* x[SRSRAN_MAX_LAYERS],
//                                         float* csi[SRSRAN_MAX_CODEWORDS],
//                                         int    nof_symbols,
//                                         float  scaling,
//                                         float  noise_estimate)
// {
//   // 4-port CDD per TS 36.211 Table 6.3.4.2.3-1
//   const cf_t phase[4] = {1.0f, -_Complex_I, -1.0f, _Complex_I};

//   for (int i = 0; i < nof_symbols; i++) {
//     cf_t d = phase[i & 3];

//     cf_t h_l0 = 0.5f * (h[0][0][i] + h[1][0][i]);
//     cf_t h_l1 = 0.5f * (h[2][0][i] - h[3][0][i]) * d;

//     cf_t h00 = (h_l0 + h_l1) * M_SQRT1_2;
//     cf_t h10 = (h_l0 - h_l1) * M_SQRT1_2;

//     h_l0 = 0.5f * (h[0][1][i] + h[1][1][i]);
//     h_l1 = 0.5f * (h[2][1][i] - h[3][1][i]) * d;

//     cf_t h01 = (h_l0 + h_l1) * M_SQRT1_2;
//     cf_t h11 = (h_l0 - h_l1) * M_SQRT1_2;

//     cf_t h00_conj = conjf(h00);
//     cf_t h01_conj = conjf(h01);
//     cf_t h10_conj = conjf(h10);
//     cf_t h11_conj = conjf(h11);

//     float norm0 = crealf(h00) * crealf(h00) + cimagf(h00) * cimagf(h00) +
//                   crealf(h01) * crealf(h01) + cimagf(h01) * cimagf(h01);
//     float norm1 = crealf(h10) * crealf(h10) + cimagf(h10) * cimagf(h10) +
//                   crealf(h11) * crealf(h11) + cimagf(h11) * cimagf(h11);

//     cf_t cross = h00_conj * h10 + h01_conj * h11;

//     float det_re = (norm0 + noise_estimate) * (norm1 + noise_estimate) -
//                    (crealf(cross) * crealf(cross) + cimagf(cross) * cimagf(cross));

//     if (fabsf(det_re) < 1e-10f) {
//       x[0][i] = 0;
//       x[1][i] = 0;
//       csi[0][i] = 0;
//       csi[1][i] = 0;
//       continue;
//     }

//     float inv_det = scaling / det_re;

//     cf_t w00 = ((norm1 + noise_estimate) * h00_conj - conjf(cross) * h10_conj) * inv_det;
//     cf_t w01 = ((norm1 + noise_estimate) * h01_conj - conjf(cross) * h11_conj) * inv_det;
//     cf_t w10 = ((norm0 + noise_estimate) * h10_conj - cross * h00_conj) * inv_det;
//     cf_t w11 = ((norm0 + noise_estimate) * h11_conj - cross * h01_conj) * inv_det;

//     x[0][i] = w00 * y[0][i] + w01 * y[1][i];
//     x[1][i] = w10 * y[0][i] + w11 * y[1][i];

//     csi[0][i] = (norm0 + noise_estimate) * inv_det;
//     csi[1][i] = (norm1 + noise_estimate) * inv_det;
//   }

//   return nof_symbols;
// }



int srsran_predecoding_ccd_mmse(cf_t*  y[SRSRAN_MAX_PORTS],
                                cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                cf_t*  x[SRSRAN_MAX_LAYERS],
                                float* csi[SRSRAN_MAX_CODEWORDS],
                                int    nof_rxant,
                                int    nof_ports,
                                int    nof_layers,
                                int    nof_symbols,
                                float  scaling,
                                float  noise_estimate)
{
  if (nof_ports == 2 && nof_rxant == 2) {
    if (nof_layers == 2) {
      if (csi && csi[0])
        return srsran_predecoding_ccd_2x2_mmse_csi(y, h, x, csi, nof_symbols, scaling, noise_estimate);
      else {
        return srsran_predecoding_ccd_2x2_mmse(y, h, x, nof_symbols, scaling, noise_estimate);
      }
    } else {
      ERROR("Error predecoding CCD: Invalid number of layers %d", nof_layers);
      return -1;
    }
  } else if (nof_ports == 4 && nof_rxant == 2) {
      if (csi && csi[0])
        return srsran_predecoding_ccd_4x2_mmse_csi(y, h, x, csi, nof_symbols, scaling, noise_estimate);
      else {
        return srsran_predecoding_ccd_4x2_mmse(y, h, x, nof_symbols, scaling, noise_estimate);
      }
  } else {
    ERROR("Error predecoding CCD: Invalid combination of ports %d and rx antennax %d", nof_ports, nof_rxant);
  }
  return SRSRAN_ERROR;
}

static int srsran_predecoding_multiplex_2x2_zf_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                                   cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                   cf_t*  x[SRSRAN_MAX_LAYERS],
                                                   float* csi,
                                                   int    codebook_idx,
                                                   int    nof_symbols,
                                                   float  scaling)
{
  float norm = 1.0f;
  int   i    = 0;

  switch (codebook_idx) {
    case 0:
      norm = (float)M_SQRT2 / scaling;
      break;
    case 1:
    case 2:
      norm = 2.0f / scaling;
      break;
    default:
      ERROR("Wrong codebook_idx=%d", codebook_idx);
      return SRSRAN_ERROR;
  }

#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);

    simd_cf_t h00, h01, h10, h11;
    switch (codebook_idx) {
      case 0:
        h00 = h00i;
        h01 = h10i;
        h10 = h01i;
        h11 = h11i;
        break;
      case 1:
        h00 = srsran_simd_cf_add(h00i, h10i);
        h01 = srsran_simd_cf_sub(h00i, h10i);
        h10 = srsran_simd_cf_add(h01i, h11i);
        h11 = srsran_simd_cf_sub(h01i, h11i);
        break;
      case 2:
        h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_mulj(h10i));
        h01 = srsran_simd_cf_sub(h00i, srsran_simd_cf_mulj(h10i));
        h10 = srsran_simd_cf_add(h01i, srsran_simd_cf_mulj(h11i));
        h11 = srsran_simd_cf_sub(h01i, srsran_simd_cf_mulj(h11i));
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t x0, x1;
    simd_f_t  csi0, csi1;
    srsran_mat_2x2_zf_csi_simd(y0, y1, h00, h01, h10, h11, &x0, &x1, &csi0, &csi1, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);

    srsran_simd_f_store(&csi[i], csi0);
    srsran_simd_f_store(&csi[i], csi1);
  }
#endif /* SRSRAN_SIMD_CF_SIZE */

  for (; i < nof_symbols; i++) {
    cf_t h00, h01, h10, h11;

    switch (codebook_idx) {
      case 0:
        h00 = h[0][0][i];
        h01 = h[1][0][i];
        h10 = h[0][1][i];
        h11 = h[1][1][i];
        break;
      case 1:
        h00 = h[0][0][i] + h[1][0][i];
        h01 = h[0][0][i] - h[1][0][i];
        h10 = h[0][1][i] + h[1][1][i];
        h11 = h[0][1][i] - h[1][1][i];
        break;
      case 2:
        h00 = h[0][0][i] + _Complex_I * h[1][0][i];
        h01 = h[0][0][i] - _Complex_I * h[1][0][i];
        h10 = h[0][1][i] + _Complex_I * h[1][1][i];
        h11 = h[0][1][i] - _Complex_I * h[1][1][i];
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    cf_t det = (h00 * h11 - h01 * h10);
    det      = conjf(det) * (norm / (crealf(det) * crealf(det) + cimagf(det) * cimagf(det)));

    x[0][i] = (+h11 * y[0][i] - h01 * y[1][i]) * det;
    x[1][i] = (-h10 * y[0][i] + h00 * y[1][i]) * det;

    csi[i] = 1.0f;
    csi[i] = 1.0f;
  }
  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_multiplex_4x1_zf_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                                    cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                    cf_t*  x[SRSRAN_MAX_LAYERS],
                                                    float* csi,
                                                    int    codebook_idx,
                                                    int    nof_symbols,
                                                    float  scaling)
{
  float norm = 0.5f / scaling;

  int i = 0;

#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00 = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01 = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h02 = srsran_simd_cfi_load(&h[0][2][i]);
    simd_cf_t h03 = srsran_simd_cfi_load(&h[0][3][i]);
    simd_cf_t h10 = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11 = srsran_simd_cfi_load(&h[1][1][i]);
    simd_cf_t h12 = srsran_simd_cfi_load(&h[1][2][i]);
    simd_cf_t h13 = srsran_simd_cfi_load(&h[1][3][i]);

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t h_eff0, h_eff1;

    switch (codebook_idx) {
      case 0:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h01), srsran_simd_cf_add(h02, h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h11), srsran_simd_cf_add(h12, h13));
        break;
      case 1:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_add(h02, h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_add(h12, h13)));
        break;
      case 2:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h01), srsran_simd_cf_add(h02, h03));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h11), srsran_simd_cf_add(h12, h13));
        break;
      case 3:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_add(h02, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_add(h12, h13)));
        break;
      case 4:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_add(h02, srsran_simd_cf_mulj(h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_add(h12, srsran_simd_cf_mulj(h13)));
        break;
      case 5:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_sub(srsran_simd_cf_mulj(h02), h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_sub(srsran_simd_cf_mulj(h12), h13));
        break;
      case 6:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_add(h02, srsran_simd_cf_mulj(h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_add(h12, srsran_simd_cf_mulj(h13)));
        break;
      case 7:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h02)), srsran_simd_cf_add(srsran_simd_cf_mulj(h01), h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h12)), srsran_simd_cf_add(srsran_simd_cf_mulj(h11), h13));
        break;
      case 8:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_sub(h02, h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_sub(h12, h13));
        break;
      case 9:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_sub(h02, h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_sub(h12, h13)));
        break;
      case 10:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_sub(h02, h03));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_sub(h12, h13));
        break;
      case 11:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_sub(h02, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_sub(h12, h13)));
        break;
      case 12:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h02), srsran_simd_cf_mulj(srsran_simd_cf_add(h01, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h12), srsran_simd_cf_mulj(srsran_simd_cf_add(h11, h13)));
        break;
      case 13:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h03), srsran_simd_cf_sub(srsran_simd_cf_mulj(h02), srsran_simd_cf_mulj(h01)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h13), srsran_simd_cf_sub(srsran_simd_cf_mulj(h12), srsran_simd_cf_mulj(h11)));
        break;
      case 14:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h02), srsran_simd_cf_mulj(srsran_simd_cf_sub(h03, h01)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h12), srsran_simd_cf_mulj(srsran_simd_cf_sub(h13, h11)));
        break;
      case 15:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h03), srsran_simd_cf_mulj(srsran_simd_cf_add(h01, h02)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h13), srsran_simd_cf_mulj(srsran_simd_cf_add(h11, h12)));
        break;
      default:
        ERROR("Invalid codebook index %d for single layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t h_eff0_conj = srsran_simd_cf_conj(h_eff0);
    simd_cf_t h_eff1_conj = srsran_simd_cf_conj(h_eff1);

    simd_cf_t numer = srsran_simd_cf_add(srsran_simd_cf_prod(h_eff0_conj, y0),
                                          srsran_simd_cf_prod(h_eff1_conj, y1));

    simd_f_t h_eff0_sq = srsran_simd_cf_re(srsran_simd_cf_prod(h_eff0, h_eff0_conj));
    simd_f_t h_eff1_sq = srsran_simd_cf_re(srsran_simd_cf_prod(h_eff1, h_eff1_conj));
    simd_f_t denom = srsran_simd_f_add(h_eff0_sq, h_eff1_sq);

    simd_f_t csi_scale = srsran_simd_f_set1(norm * norm);
    simd_f_t csi_val = srsran_simd_f_mul(denom, csi_scale);
    srsran_simd_f_store(&csi[i], csi_val);

    simd_f_t inv_denom = srsran_simd_f_rcp(denom);
    simd_f_t inv_denom_norm = srsran_simd_f_mul(inv_denom, srsran_simd_f_set1(norm));
    simd_cf_t x0 = srsran_simd_cf_mul(numer, inv_denom_norm);

    srsran_simd_cfi_store(&x[0][i], x0);
  }
#endif

  for (; i < nof_symbols; i++) {
    cf_t h00 = h[0][0][i], h01 = h[0][1][i], h02 = h[0][2][i], h03 = h[0][3][i];
    cf_t h10 = h[1][0][i], h11 = h[1][1][i], h12 = h[1][2][i], h13 = h[1][3][i];

    cf_t h_eff0, h_eff1;

    switch (codebook_idx) {
      case 0:  h_eff0 = h00 + h01 + h02 + h03;
               h_eff1 = h10 + h11 + h12 + h13; break;
      case 1:  h_eff0 = h00 + h01 + _Complex_I*(h02 + h03);
               h_eff1 = h10 + h11 + _Complex_I*(h12 + h13); break;
      case 2:  h_eff0 = h00 + h01 - h02 - h03;
               h_eff1 = h10 + h11 - h12 - h13; break;
      case 3:  h_eff0 = h00 + h01 - _Complex_I*(h02 + h03);
               h_eff1 = h10 + h11 - _Complex_I*(h12 + h13); break;
      case 4:  h_eff0 = h00 + _Complex_I*h01 + h02 + _Complex_I*h03;
               h_eff1 = h10 + _Complex_I*h11 + h12 + _Complex_I*h13; break;
      case 5:  h_eff0 = h00 + _Complex_I*h01 + _Complex_I*h02 - h03;
               h_eff1 = h10 + _Complex_I*h11 + _Complex_I*h12 - h13; break;
      case 6:  h_eff0 = h00 + _Complex_I*h01 - h02 - _Complex_I*h03;
               h_eff1 = h10 + _Complex_I*h11 - h12 - _Complex_I*h13; break;
      case 7:  h_eff0 = h00 + _Complex_I*h01 - _Complex_I*h02 + h03;
               h_eff1 = h10 + _Complex_I*h11 - _Complex_I*h12 + h13; break;
      case 8:  h_eff0 = h00 - h01 + h02 - h03;
               h_eff1 = h10 - h11 + h12 - h13; break;
      case 9:  h_eff0 = h00 - h01 + _Complex_I*(h02 - h03);
               h_eff1 = h10 - h11 + _Complex_I*(h12 - h13); break;
      case 10: h_eff0 = h00 - h01 - h02 + h03;
               h_eff1 = h10 - h11 - h12 + h13; break;
      case 11: h_eff0 = h00 - h01 - _Complex_I*(h02 - h03);
               h_eff1 = h10 - h11 - _Complex_I*(h12 - h13); break;
      case 12: h_eff0 = h00 - _Complex_I*h01 + h02 - _Complex_I*h03;
               h_eff1 = h10 - _Complex_I*h11 + h12 - _Complex_I*h13; break;
      case 13: h_eff0 = h00 - _Complex_I*h01 + _Complex_I*h02 + h03;
               h_eff1 = h10 - _Complex_I*h11 + _Complex_I*h12 + h13; break;
      case 14: h_eff0 = h00 - _Complex_I*h01 - h02 + _Complex_I*h03;
               h_eff1 = h10 - _Complex_I*h11 - h12 + _Complex_I*h13; break;
      case 15: h_eff0 = h00 - _Complex_I*h01 - _Complex_I*h02 - h03;
               h_eff1 = h10 - _Complex_I*h11 - _Complex_I*h12 - h13; break;
      default:
        ERROR("Invalid codebook index %d for single layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    float denom = crealf(h_eff0 * conjf(h_eff0)) + crealf(h_eff1 * conjf(h_eff1));
    csi[i] = denom * norm * norm;

    cf_t numer = conjf(h_eff0) * y[0][i] + conjf(h_eff1) * y[1][i];
    x[0][i] = numer * norm / denom;
  }

  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_multiplex_4x2_zf_csi(cf_t* y[SRSRAN_MAX_PORTS],
                                                    cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                    cf_t* x[SRSRAN_MAX_LAYERS],
                                                    float* csi[SRSRAN_MAX_CODEWORDS],
                                                    int   codebook_idx,
                                                    int   nof_symbols,
                                                    float scaling)
{
  float norm = 0.5f / scaling;

  for (int i = 0; i < nof_symbols; i++) {
    // Get channel coefficients: h[rx][tx]
    cf_t h00 = h[0][0][i];
    cf_t h01 = h[0][1][i];
    cf_t h02 = h[0][2][i];
    cf_t h03 = h[0][3][i];
    cf_t h10 = h[1][0][i];
    cf_t h11 = h[1][1][i];
    cf_t h12 = h[1][2][i];
    cf_t h13 = h[1][3][i];

    // Compute effective 2x2 channel H_eff = H * W based on codebook index
    cf_t h_eff00, h_eff01, h_eff10, h_eff11;

    switch (codebook_idx) {
      case 0:  // W = [1,0; 0,1; 1,0; 0,-1]/2
        h_eff00 = h00 + h02;
        h_eff01 = h01 - h03;
        h_eff10 = h10 + h12;
        h_eff11 = h11 - h13;
        break;
      case 1:  // W = [1,0; 0,1; 1,0; 0,1]/2
        h_eff00 = h00 + h02;
        h_eff01 = h01 + h03;
        h_eff10 = h10 + h12;
        h_eff11 = h11 + h13;
        break;
      case 2:  // W = [1,0; 0,1; -1,0; 0,1]/2
        h_eff00 = h00 - h02;
        h_eff01 = h01 + h03;
        h_eff10 = h10 - h12;
        h_eff11 = h11 + h13;
        break;
      case 3:  // W = [1,0; 0,1; -1,0; 0,-1]/2
        h_eff00 = h00 - h02;
        h_eff01 = h01 - h03;
        h_eff10 = h10 - h12;
        h_eff11 = h11 - h13;
        break;
      case 4:  // W = [1,0; 0,1; 0,1; 1,0]/2
        h_eff00 = h00 + h03;
        h_eff01 = h01 + h02;
        h_eff10 = h10 + h13;
        h_eff11 = h11 + h12;
        break;
      case 5:  // W = [1,0; 0,1; 0,1; -1,0]/2
        h_eff00 = h00 - h03;
        h_eff01 = h01 + h02;
        h_eff10 = h10 - h13;
        h_eff11 = h11 + h12;
        break;
      case 6:  // W = [1,0; 0,1; 0,-1; 1,0]/2
        h_eff00 = h00 + h03;
        h_eff01 = h01 - h02;
        h_eff10 = h10 + h13;
        h_eff11 = h11 - h12;
        break;
      case 7:  // W = [1,0; 0,1; 0,-1; -1,0]/2
        h_eff00 = h00 - h03;
        h_eff01 = h01 - h02;
        h_eff10 = h10 - h13;
        h_eff11 = h11 - h12;
        break;
      case 8:  // W = [1,0; 0,1; j,0; 0,j]/2
        h_eff00 = h00 + _Complex_I * h02;
        h_eff01 = h01 + _Complex_I * h03;
        h_eff10 = h10 + _Complex_I * h12;
        h_eff11 = h11 + _Complex_I * h13;
        break;
      case 9:  // W = [1,0; 0,1; j,0; 0,-j]/2
        h_eff00 = h00 + _Complex_I * h02;
        h_eff01 = h01 - _Complex_I * h03;
        h_eff10 = h10 + _Complex_I * h12;
        h_eff11 = h11 - _Complex_I * h13;
        break;
      case 10: // W = [1,0; 0,1; -j,0; 0,j]/2
        h_eff00 = h00 - _Complex_I * h02;
        h_eff01 = h01 + _Complex_I * h03;
        h_eff10 = h10 - _Complex_I * h12;
        h_eff11 = h11 + _Complex_I * h13;
        break;
      case 11: // W = [1,0; 0,1; -j,0; 0,-j]/2
        h_eff00 = h00 - _Complex_I * h02;
        h_eff01 = h01 - _Complex_I * h03;
        h_eff10 = h10 - _Complex_I * h12;
        h_eff11 = h11 - _Complex_I * h13;
        break;
      case 12: // W = [1,0; 0,1; 0,j; j,0]/2
        h_eff00 = h00 + _Complex_I * h03;
        h_eff01 = h01 + _Complex_I * h02;
        h_eff10 = h10 + _Complex_I * h13;
        h_eff11 = h11 + _Complex_I * h12;
        break;
      case 13: // W = [1,0; 0,1; 0,j; -j,0]/2
        h_eff00 = h00 - _Complex_I * h03;
        h_eff01 = h01 + _Complex_I * h02;
        h_eff10 = h10 - _Complex_I * h13;
        h_eff11 = h11 + _Complex_I * h12;
        break;
      case 14: // W = [1,0; 0,1; 0,-j; j,0]/2
        h_eff00 = h00 + _Complex_I * h03;
        h_eff01 = h01 - _Complex_I * h02;
        h_eff10 = h10 + _Complex_I * h13;
        h_eff11 = h11 - _Complex_I * h12;
        break;
      case 15: // W = [1,0; 0,1; 0,-j; -j,0]/2
        h_eff00 = h00 - _Complex_I * h03;
        h_eff01 = h01 - _Complex_I * h02;
        h_eff10 = h10 - _Complex_I * h13;
        h_eff11 = h11 - _Complex_I * h12;
        break;
      default:
        ERROR("Invalid codebook index %d for 4x2 transmission", codebook_idx);
        return SRSRAN_ERROR;
    }

    // Compute ZF equalization with CSI inline
    // det = h_eff00*h_eff11 - h_eff01*h_eff10
    cf_t det = h_eff00 * h_eff11 - h_eff01 * h_eff10;
    float det_sqr = __real__(det * conjf(det));

    // Avoid division by zero
    if (det_sqr < 1e-10f) {
      x[0][i] = 0;
      x[1][i] = 0;
      csi[0][i] = 0;
      csi[1][i] = 0;
      continue;
    }

    cf_t det_conj = conjf(det);

    // Inverse matrix elements (scaled by det*)
    // H_inv = [h_eff11, -h_eff01; -h_eff10, h_eff00] / det
    cf_t inv00 = h_eff11 * det_conj / det_sqr;
    cf_t inv01 = -h_eff01 * det_conj / det_sqr;
    cf_t inv10 = -h_eff10 * det_conj / det_sqr;
    cf_t inv11 = h_eff00 * det_conj / det_sqr;

    // Equalize: x = H_inv * y
    cf_t y0 = y[0][i];
    cf_t y1 = y[1][i];

    x[0][i] = norm * (inv00 * y0 + inv01 * y1);
    x[1][i] = norm * (inv10 * y0 + inv11 * y1);

    // CSI = 1 / ||row of H_inv||^2 (noise enhancement factor)
    float csi0_inv = crealf(inv00) * crealf(inv00) + cimagf(inv00) * cimagf(inv00) +
                     crealf(inv01) * crealf(inv01) + cimagf(inv01) * cimagf(inv01);
    float csi1_inv = crealf(inv10) * crealf(inv10) + cimagf(inv10) * cimagf(inv10) +
                     crealf(inv11) * crealf(inv11) + cimagf(inv11) * cimagf(inv11);

    csi[0][i] = (csi0_inv > 1e-10f) ? (1.0f / csi0_inv) : 0.0f;
    csi[1][i] = (csi1_inv > 1e-10f) ? (1.0f / csi1_inv) : 0.0f;
  }

  return SRSRAN_SUCCESS;
}

// Generic implementation of ZF 2x2 Spatial Multiplexity equalizer
static int srsran_predecoding_multiplex_2x2_zf(cf_t* y[SRSRAN_MAX_PORTS],
                                               cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                               cf_t* x[SRSRAN_MAX_LAYERS],
                                               int   codebook_idx,
                                               int   nof_symbols,
                                               float scaling)
{
  float norm = 1.0f;
  int   i    = 0;

  switch (codebook_idx) {
    case 0:
      norm = (float)M_SQRT2 / scaling;
      break;
    case 1:
    case 2:
      norm = 2.0f / scaling;
      break;
    default:
      ERROR("Wrong codebook_idx=%d", codebook_idx);
      return SRSRAN_ERROR;
  }

#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);

    simd_cf_t h00, h01, h10, h11;
    switch (codebook_idx) {
      case 0:
        h00 = h00i;
        h01 = h10i;
        h10 = h01i;
        h11 = h11i;
        break;
      case 1:
        h00 = srsran_simd_cf_add(h00i, h10i);
        h01 = srsran_simd_cf_sub(h00i, h10i);
        h10 = srsran_simd_cf_add(h01i, h11i);
        h11 = srsran_simd_cf_sub(h01i, h11i);
        break;
      case 2:
        h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_mulj(h10i));
        h01 = srsran_simd_cf_sub(h00i, srsran_simd_cf_mulj(h10i));
        h10 = srsran_simd_cf_add(h01i, srsran_simd_cf_mulj(h11i));
        h11 = srsran_simd_cf_sub(h01i, srsran_simd_cf_mulj(h11i));
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t x0, x1;
    simd_f_t  csi0, csi1;
    srsran_mat_2x2_zf_csi_simd(y0, y1, h00, h01, h10, h11, &x0, &x1, &csi0, &csi1, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);
  }
#endif /* SRSRAN_SIMD_CF_SIZE */

  for (; i < nof_symbols; i++) {
    cf_t h00, h01, h10, h11;

    switch (codebook_idx) {
      case 0:
        h00 = h[0][0][i];
        h01 = h[1][0][i];
        h10 = h[0][1][i];
        h11 = h[1][1][i];
        break;
      case 1:
        h00 = h[0][0][i] + h[1][0][i];
        h01 = h[0][0][i] - h[1][0][i];
        h10 = h[0][1][i] + h[1][1][i];
        h11 = h[0][1][i] - h[1][1][i];
        break;
      case 2:
        h00 = h[0][0][i] + _Complex_I * h[1][0][i];
        h01 = h[0][0][i] - _Complex_I * h[1][0][i];
        h10 = h[0][1][i] + _Complex_I * h[1][1][i];
        h11 = h[0][1][i] - _Complex_I * h[1][1][i];
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    srsran_mat_2x2_zf_gen(y[0][i], y[1][i], h00, h01, h10, h11, &x[0][i], &x[1][i], norm);
  }
  return SRSRAN_SUCCESS;
}



static int srsran_predecoding_multiplex_4x1_zf(cf_t*  y[SRSRAN_MAX_PORTS],
                                               cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                               cf_t*  x[SRSRAN_MAX_LAYERS],
                                               int    codebook_idx,
                                               int    nof_symbols,
                                               float  scaling)
{
  float norm = 0.5f / scaling;

  int i = 0;

#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00 = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01 = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h02 = srsran_simd_cfi_load(&h[0][2][i]);
    simd_cf_t h03 = srsran_simd_cfi_load(&h[0][3][i]);
    simd_cf_t h10 = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11 = srsran_simd_cfi_load(&h[1][1][i]);
    simd_cf_t h12 = srsran_simd_cfi_load(&h[1][2][i]);
    simd_cf_t h13 = srsran_simd_cfi_load(&h[1][3][i]);

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t h_eff0, h_eff1;

    // Codebook indices 0-15 for single layer, 4 antennas
    // W vectors from 3GPP 36.211 Table 6.3.4.2.3-2
    // Pattern: W = [1, u, v, uv]^T where u,v ∈ {1, j, -1, -j}
    switch (codebook_idx) {
      case 0:  // [1, 1, 1, 1]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h01), srsran_simd_cf_add(h02, h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h11), srsran_simd_cf_add(h12, h13));
        break;
      case 1:  // [1, 1, j, j]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_add(h02, h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_add(h12, h13)));
        break;
      case 2:  // [1, 1, -1, -1]
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h01), srsran_simd_cf_add(h02, h03));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h11), srsran_simd_cf_add(h12, h13));
        break;
      case 3:  // [1, 1, -j, -j]
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_add(h02, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_add(h12, h13)));
        break;
      case 4:  // [1, j, 1, j]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_add(h02, srsran_simd_cf_mulj(h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_add(h12, srsran_simd_cf_mulj(h13)));
        break;
      case 5:  // [1, j, j, -1]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_sub(srsran_simd_cf_mulj(h02), h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_sub(srsran_simd_cf_mulj(h12), h13));
        break;
      case 6:  // [1, j, -1, -j]
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_add(h02, srsran_simd_cf_mulj(h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_add(h12, srsran_simd_cf_mulj(h13)));
        break;
      case 7:  // [1, j, -j, 1]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h02)), srsran_simd_cf_add(srsran_simd_cf_mulj(h01), h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h12)), srsran_simd_cf_add(srsran_simd_cf_mulj(h11), h13));
        break;
      case 8:  // [1, -1, 1, -1]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_sub(h02, h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_sub(h12, h13));
        break;
      case 9:  // [1, -1, j, -j]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_sub(h02, h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_sub(h12, h13)));
        break;
      case 10: // [1, -1, -1, 1]
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_sub(h02, h03));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_sub(h12, h13));
        break;
      case 11: // [1, -1, -j, j]
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_sub(h02, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_sub(h12, h13)));
        break;
      case 12: // [1, -j, 1, -j]
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h02), srsran_simd_cf_mulj(srsran_simd_cf_add(h01, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h12), srsran_simd_cf_mulj(srsran_simd_cf_add(h11, h13)));
        break;
      case 13: // [1, -j, j, 1]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h03), srsran_simd_cf_sub(srsran_simd_cf_mulj(h02), srsran_simd_cf_mulj(h01)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h13), srsran_simd_cf_sub(srsran_simd_cf_mulj(h12), srsran_simd_cf_mulj(h11)));
        break;
      case 14: // [1, -j, -1, j]
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h02), srsran_simd_cf_mulj(srsran_simd_cf_sub(h03, h01)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h12), srsran_simd_cf_mulj(srsran_simd_cf_sub(h13, h11)));
        break;
      case 15: // [1, -j, -j, -1]
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h03), srsran_simd_cf_mulj(srsran_simd_cf_add(h01, h02)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h13), srsran_simd_cf_mulj(srsran_simd_cf_add(h11, h12)));
        break;
      default:
        ERROR("Invalid codebook index %d for single layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    // MRC: x = (h_eff0* · y0 + h_eff1* · y1) / (|h_eff0|² + |h_eff1|²)
    simd_cf_t h_eff0_conj = srsran_simd_cf_conj(h_eff0);
    simd_cf_t h_eff1_conj = srsran_simd_cf_conj(h_eff1);

    simd_cf_t numer = srsran_simd_cf_add(srsran_simd_cf_prod(h_eff0_conj, y0),
                                          srsran_simd_cf_prod(h_eff1_conj, y1));

    simd_f_t h_eff0_sq = srsran_simd_cf_re(srsran_simd_cf_prod(h_eff0, h_eff0_conj));
    simd_f_t h_eff1_sq = srsran_simd_cf_re(srsran_simd_cf_prod(h_eff1, h_eff1_conj));
    simd_f_t denom = srsran_simd_f_add(h_eff0_sq, h_eff1_sq);

    simd_f_t inv_denom = srsran_simd_f_rcp(denom);
    simd_f_t inv_denom_norm = srsran_simd_f_mul(inv_denom, srsran_simd_f_set1(norm));
    simd_cf_t x0 = srsran_simd_cf_mul(numer, inv_denom_norm);

    srsran_simd_cfi_store(&x[0][i], x0);
  }
#endif

  // Scalar remainder
  for (; i < nof_symbols; i++) {
    cf_t h00 = h[0][0][i], h01 = h[0][1][i], h02 = h[0][2][i], h03 = h[0][3][i];
    cf_t h10 = h[1][0][i], h11 = h[1][1][i], h12 = h[1][2][i], h13 = h[1][3][i];

    cf_t h_eff0, h_eff1;

    switch (codebook_idx) {
      case 0:  h_eff0 = h00 + h01 + h02 + h03;
               h_eff1 = h10 + h11 + h12 + h13; break;
      case 1:  h_eff0 = h00 + h01 + _Complex_I*(h02 + h03);
               h_eff1 = h10 + h11 + _Complex_I*(h12 + h13); break;
      case 2:  h_eff0 = h00 + h01 - h02 - h03;
               h_eff1 = h10 + h11 - h12 - h13; break;
      case 3:  h_eff0 = h00 + h01 - _Complex_I*(h02 + h03);
               h_eff1 = h10 + h11 - _Complex_I*(h12 + h13); break;
      case 4:  h_eff0 = h00 + _Complex_I*h01 + h02 + _Complex_I*h03;
               h_eff1 = h10 + _Complex_I*h11 + h12 + _Complex_I*h13; break;
      case 5:  h_eff0 = h00 + _Complex_I*h01 + _Complex_I*h02 - h03;
               h_eff1 = h10 + _Complex_I*h11 + _Complex_I*h12 - h13; break;
      case 6:  h_eff0 = h00 + _Complex_I*h01 - h02 - _Complex_I*h03;
               h_eff1 = h10 + _Complex_I*h11 - h12 - _Complex_I*h13; break;
      case 7:  h_eff0 = h00 + _Complex_I*h01 - _Complex_I*h02 + h03;
               h_eff1 = h10 + _Complex_I*h11 - _Complex_I*h12 + h13; break;
      case 8:  h_eff0 = h00 - h01 + h02 - h03;
               h_eff1 = h10 - h11 + h12 - h13; break;
      case 9:  h_eff0 = h00 - h01 + _Complex_I*(h02 - h03);
               h_eff1 = h10 - h11 + _Complex_I*(h12 - h13); break;
      case 10: h_eff0 = h00 - h01 - h02 + h03;
               h_eff1 = h10 - h11 - h12 + h13; break;
      case 11: h_eff0 = h00 - h01 - _Complex_I*(h02 - h03);
               h_eff1 = h10 - h11 - _Complex_I*(h12 - h13); break;
      case 12: h_eff0 = h00 - _Complex_I*h01 + h02 - _Complex_I*h03;
               h_eff1 = h10 - _Complex_I*h11 + h12 - _Complex_I*h13; break;
      case 13: h_eff0 = h00 - _Complex_I*h01 + _Complex_I*h02 + h03;
               h_eff1 = h10 - _Complex_I*h11 + _Complex_I*h12 + h13; break;
      case 14: h_eff0 = h00 - _Complex_I*h01 - h02 + _Complex_I*h03;
               h_eff1 = h10 - _Complex_I*h11 - h12 + _Complex_I*h13; break;
      case 15: h_eff0 = h00 - _Complex_I*h01 - _Complex_I*h02 - h03;
               h_eff1 = h10 - _Complex_I*h11 - _Complex_I*h12 - h13; break;
      default:
        ERROR("Invalid codebook index %d for single layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    float denom = crealf(h_eff0 * conjf(h_eff0)) + crealf(h_eff1 * conjf(h_eff1));
    cf_t numer = conjf(h_eff0) * y[0][i] + conjf(h_eff1) * y[1][i];
    x[0][i] = numer * norm / denom;
  }

  return SRSRAN_SUCCESS;
}


static int srsran_predecoding_multiplex_4x2_zf(cf_t*  y[SRSRAN_MAX_PORTS],
                                               cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                               cf_t*  x[SRSRAN_MAX_LAYERS],
                                               int    codebook_idx,
                                               int    nof_symbols,
                                               float  scaling)
{
  float norm = 0.5f / scaling;

  int i = 0;

#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00 = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01 = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h02 = srsran_simd_cfi_load(&h[0][2][i]);
    simd_cf_t h03 = srsran_simd_cfi_load(&h[0][3][i]);
    simd_cf_t h10 = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11 = srsran_simd_cfi_load(&h[1][1][i]);
    simd_cf_t h12 = srsran_simd_cfi_load(&h[1][2][i]);
    simd_cf_t h13 = srsran_simd_cfi_load(&h[1][3][i]);

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    // Compute effective channel H_eff = H * W (2x2 result)
    // H_eff[0][0] = h00*w00 + h01*w10 + h02*w20 + h03*w30  (RX0, Layer0)
    // H_eff[0][1] = h00*w01 + h01*w11 + h02*w21 + h03*w31  (RX0, Layer1)
    // H_eff[1][0] = h10*w00 + h11*w10 + h12*w20 + h13*w30  (RX1, Layer0)
    // H_eff[1][1] = h10*w01 + h11*w11 + h12*w21 + h13*w31  (RX1, Layer1)
    simd_cf_t h_eff00, h_eff01, h_eff10, h_eff11;

    switch (codebook_idx) {
      case 0:  // W = [1,0; 0,1; 1,0; 0,-1]
        h_eff00 = srsran_simd_cf_add(h00, h02);
        h_eff01 = srsran_simd_cf_sub(h01, h03);
        h_eff10 = srsran_simd_cf_add(h10, h12);
        h_eff11 = srsran_simd_cf_sub(h11, h13);
        break;
      case 1:  // W = [1,0; 0,1; 1,0; 0,1]
        h_eff00 = srsran_simd_cf_add(h00, h02);
        h_eff01 = srsran_simd_cf_add(h01, h03);
        h_eff10 = srsran_simd_cf_add(h10, h12);
        h_eff11 = srsran_simd_cf_add(h11, h13);
        break;
      case 2:  // W = [1,0; 0,1; -1,0; 0,1]
        h_eff00 = srsran_simd_cf_sub(h00, h02);
        h_eff01 = srsran_simd_cf_add(h01, h03);
        h_eff10 = srsran_simd_cf_sub(h10, h12);
        h_eff11 = srsran_simd_cf_add(h11, h13);
        break;
      case 3:  // W = [1,0; 0,1; -1,0; 0,-1]
        h_eff00 = srsran_simd_cf_sub(h00, h02);
        h_eff01 = srsran_simd_cf_sub(h01, h03);
        h_eff10 = srsran_simd_cf_sub(h10, h12);
        h_eff11 = srsran_simd_cf_sub(h11, h13);
        break;
      case 4:  // W = [1,0; 0,1; 0,-1; 1,0]
        h_eff00 = srsran_simd_cf_sub(h00, h02);  // h00 + 0 - h02*1 + 0 -> wait, w20=-1 for col0
        // Actually: col0 = [1,0,0,1], col1 = [0,1,-1,0]
        h_eff00 = srsran_simd_cf_add(h00, h03);
        h_eff01 = srsran_simd_cf_sub(h01, h02);
        h_eff10 = srsran_simd_cf_add(h10, h13);
        h_eff11 = srsran_simd_cf_sub(h11, h12);
        break;
      case 5:  // W = [1,0; 0,1; 0,1; 1,0]
        h_eff00 = srsran_simd_cf_add(h00, h03);
        h_eff01 = srsran_simd_cf_add(h01, h02);
        h_eff10 = srsran_simd_cf_add(h10, h13);
        h_eff11 = srsran_simd_cf_add(h11, h12);
        break;
      case 6:  // W = [1,0; 0,1; 0,1; -1,0]
        h_eff00 = srsran_simd_cf_sub(h00, h03);
        h_eff01 = srsran_simd_cf_add(h01, h02);
        h_eff10 = srsran_simd_cf_sub(h10, h13);
        h_eff11 = srsran_simd_cf_add(h11, h12);
        break;
      case 7:  // W = [1,0; 0,1; 0,-1; -1,0]
        h_eff00 = srsran_simd_cf_sub(h00, h03);
        h_eff01 = srsran_simd_cf_sub(h01, h02);
        h_eff10 = srsran_simd_cf_sub(h10, h13);
        h_eff11 = srsran_simd_cf_sub(h11, h12);
        break;
      case 8:  // W = [1,0; 0,1; j,0; 0,j]
        h_eff00 = srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h02));
        h_eff01 = srsran_simd_cf_add(h01, srsran_simd_cf_mulj(h03));
        h_eff10 = srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h12));
        h_eff11 = srsran_simd_cf_add(h11, srsran_simd_cf_mulj(h13));
        break;
      case 9:  // W = [1,0; 0,1; j,0; 0,-j]
        h_eff00 = srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h02));
        h_eff01 = srsran_simd_cf_sub(h01, srsran_simd_cf_mulj(h03));
        h_eff10 = srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h12));
        h_eff11 = srsran_simd_cf_sub(h11, srsran_simd_cf_mulj(h13));
        break;
      case 10: // W = [1,0; 0,1; -j,0; 0,j]
        h_eff00 = srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h02));
        h_eff01 = srsran_simd_cf_add(h01, srsran_simd_cf_mulj(h03));
        h_eff10 = srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h12));
        h_eff11 = srsran_simd_cf_add(h11, srsran_simd_cf_mulj(h13));
        break;
      case 11: // W = [1,0; 0,1; -j,0; 0,-j]
        h_eff00 = srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h02));
        h_eff01 = srsran_simd_cf_sub(h01, srsran_simd_cf_mulj(h03));
        h_eff10 = srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h12));
        h_eff11 = srsran_simd_cf_sub(h11, srsran_simd_cf_mulj(h13));
        break;
      case 12: // W = [1,0; 0,1; 0,j; j,0]
        h_eff00 = srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h03));
        h_eff01 = srsran_simd_cf_add(h01, srsran_simd_cf_mulj(h02));
        h_eff10 = srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h13));
        h_eff11 = srsran_simd_cf_add(h11, srsran_simd_cf_mulj(h12));
        break;
      case 13: // W = [1,0; 0,1; 0,-j; j,0]
        h_eff00 = srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h03));
        h_eff01 = srsran_simd_cf_sub(h01, srsran_simd_cf_mulj(h02));
        h_eff10 = srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h13));
        h_eff11 = srsran_simd_cf_sub(h11, srsran_simd_cf_mulj(h12));
        break;
      case 14: // W = [1,0; 0,1; 0,j; -j,0]
        h_eff00 = srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h03));
        h_eff01 = srsran_simd_cf_add(h01, srsran_simd_cf_mulj(h02));
        h_eff10 = srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h13));
        h_eff11 = srsran_simd_cf_add(h11, srsran_simd_cf_mulj(h12));
        break;
      case 15: // W = [1,0; 0,1; 0,-j; -j,0]
        h_eff00 = srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h03));
        h_eff01 = srsran_simd_cf_sub(h01, srsran_simd_cf_mulj(h02));
        h_eff10 = srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h13));
        h_eff11 = srsran_simd_cf_sub(h11, srsran_simd_cf_mulj(h12));
        break;
      default:
        ERROR("Invalid codebook index %d for dual layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    // Solve 2x2 system using ZF
    simd_cf_t x0, x1;
    srsran_mat_2x2_zf_simd(y0, y1, h_eff00, h_eff01, h_eff10, h_eff11, &x0, &x1, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);
  }
#endif

  // Scalar remainder
  for (; i < nof_symbols; i++) {
    cf_t h00 = h[0][0][i], h01 = h[0][1][i], h02 = h[0][2][i], h03 = h[0][3][i];
    cf_t h10 = h[1][0][i], h11 = h[1][1][i], h12 = h[1][2][i], h13 = h[1][3][i];

    cf_t h_eff00, h_eff01, h_eff10, h_eff11;

    switch (codebook_idx) {
      case 0:
        h_eff00 = h00 + h02;           h_eff01 = h01 - h03;
        h_eff10 = h10 + h12;           h_eff11 = h11 - h13;
        break;
      case 1:
        h_eff00 = h00 + h02;           h_eff01 = h01 + h03;
        h_eff10 = h10 + h12;           h_eff11 = h11 + h13;
        break;
      case 2:
        h_eff00 = h00 - h02;           h_eff01 = h01 + h03;
        h_eff10 = h10 - h12;           h_eff11 = h11 + h13;
        break;
      case 3:
        h_eff00 = h00 - h02;           h_eff01 = h01 - h03;
        h_eff10 = h10 - h12;           h_eff11 = h11 - h13;
        break;
      case 4:
        h_eff00 = h00 + h03;           h_eff01 = h01 - h02;
        h_eff10 = h10 + h13;           h_eff11 = h11 - h12;
        break;
      case 5:
        h_eff00 = h00 + h03;           h_eff01 = h01 + h02;
        h_eff10 = h10 + h13;           h_eff11 = h11 + h12;
        break;
      case 6:
        h_eff00 = h00 - h03;           h_eff01 = h01 + h02;
        h_eff10 = h10 - h13;           h_eff11 = h11 + h12;
        break;
      case 7:
        h_eff00 = h00 - h03;           h_eff01 = h01 - h02;
        h_eff10 = h10 - h13;           h_eff11 = h11 - h12;
        break;
      case 8:
        h_eff00 = h00 + _Complex_I*h02; h_eff01 = h01 + _Complex_I*h03;
        h_eff10 = h10 + _Complex_I*h12; h_eff11 = h11 + _Complex_I*h13;
        break;
      case 9:
        h_eff00 = h00 + _Complex_I*h02; h_eff01 = h01 - _Complex_I*h03;
        h_eff10 = h10 + _Complex_I*h12; h_eff11 = h11 - _Complex_I*h13;
        break;
      case 10:
        h_eff00 = h00 - _Complex_I*h02; h_eff01 = h01 + _Complex_I*h03;
        h_eff10 = h10 - _Complex_I*h12; h_eff11 = h11 + _Complex_I*h13;
        break;
      case 11:
        h_eff00 = h00 - _Complex_I*h02; h_eff01 = h01 - _Complex_I*h03;
        h_eff10 = h10 - _Complex_I*h12; h_eff11 = h11 - _Complex_I*h13;
        break;
      case 12:
        h_eff00 = h00 + _Complex_I*h03; h_eff01 = h01 + _Complex_I*h02;
        h_eff10 = h10 + _Complex_I*h13; h_eff11 = h11 + _Complex_I*h12;
        break;
      case 13:
        h_eff00 = h00 + _Complex_I*h03; h_eff01 = h01 - _Complex_I*h02;
        h_eff10 = h10 + _Complex_I*h13; h_eff11 = h11 - _Complex_I*h12;
        break;
      case 14:
        h_eff00 = h00 - _Complex_I*h03; h_eff01 = h01 + _Complex_I*h02;
        h_eff10 = h10 - _Complex_I*h13; h_eff11 = h11 + _Complex_I*h12;
        break;
      case 15:
        h_eff00 = h00 - _Complex_I*h03; h_eff01 = h01 - _Complex_I*h02;
        h_eff10 = h10 - _Complex_I*h13; h_eff11 = h11 - _Complex_I*h12;
        break;
      default:
        ERROR("Invalid codebook index %d for dual layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    srsran_mat_2x2_zf_gen(y[0][i], y[1][i], h_eff00, h_eff01, h_eff10, h_eff11,
                          &x[0][i], &x[1][i], norm);
  }

  return SRSRAN_SUCCESS;
}

// Generic implementation of ZF 2x2 Spatial Multiplexity equalizer
static int srsran_predecoding_multiplex_2x2_mmse_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                                     cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                     cf_t*  x[SRSRAN_MAX_LAYERS],
                                                     float* csi[SRSRAN_MAX_CODEWORDS],
                                                     int    codebook_idx,
                                                     int    nof_symbols,
                                                     float  scaling,
                                                     float  noise_estimate)
{
  float norm = 1.0f;
  int   i    = 0;

  switch (codebook_idx) {
    case 0:
      norm = (float)M_SQRT2 / scaling;
      break;
    case 1:
    case 2:
      norm = 2.0f / scaling;
      break;
    default:
      ERROR("Wrong codebook_idx=%d", codebook_idx);
      return SRSRAN_ERROR;
  }

#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);

    simd_cf_t h00, h01, h10, h11;
    switch (codebook_idx) {
      case 0:
        h00 = h00i;
        h01 = h10i;
        h10 = h01i;
        h11 = h11i;
        break;
      case 1:
        h00 = srsran_simd_cf_add(h00i, h10i);
        h01 = srsran_simd_cf_sub(h00i, h10i);
        h10 = srsran_simd_cf_add(h01i, h11i);
        h11 = srsran_simd_cf_sub(h01i, h11i);
        break;
      case 2:
        h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_mulj(h10i));
        h01 = srsran_simd_cf_sub(h00i, srsran_simd_cf_mulj(h10i));
        h10 = srsran_simd_cf_add(h01i, srsran_simd_cf_mulj(h11i));
        h11 = srsran_simd_cf_sub(h01i, srsran_simd_cf_mulj(h11i));
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t x0, x1;
    simd_f_t  csi0, csi1;
    srsran_mat_2x2_mmse_csi_simd(y0, y1, h00, h01, h10, h11, &x0, &x1, &csi0, &csi1, noise_estimate, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);

    srsran_simd_f_store(&csi[0][i], csi0);
    srsran_simd_f_store(&csi[1][i], csi1);
  }
#endif /* SRSRAN_SIMD_CF_SIZE */

  for (; i < nof_symbols; i++) {
    cf_t h00, h01, h10, h11;

    switch (codebook_idx) {
      case 0:
        h00 = h[0][0][i];
        h01 = h[1][0][i];
        h10 = h[0][1][i];
        h11 = h[1][1][i];
        break;
      case 1:
        h00 = h[0][0][i] + h[1][0][i];
        h01 = h[0][0][i] - h[1][0][i];
        h10 = h[0][1][i] + h[1][1][i];
        h11 = h[0][1][i] - h[1][1][i];
        break;
      case 2:
        h00 = h[0][0][i] + _Complex_I * h[1][0][i];
        h01 = h[0][0][i] - _Complex_I * h[1][0][i];
        h10 = h[0][1][i] + _Complex_I * h[1][1][i];
        h11 = h[0][1][i] - _Complex_I * h[1][1][i];
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    srsran_mat_2x2_mmse_csi_gen(
        y[0][i], y[1][i], h00, h01, h10, h11, &x[0][i], &x[1][i], &csi[0][i], &csi[1][i], noise_estimate, norm);
  }
  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_multiplex_4x1_mmse_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                                     cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                     cf_t*  x[SRSRAN_MAX_LAYERS],
                                                     float* csi,
                                                     int    codebook_idx,
                                                     int    nof_symbols,
                                                     float  scaling,
                                                     float  noise_estimate)
{
  float norm = 0.5f / scaling;

  int i = 0;

#if SRSRAN_SIMD_CF_SIZE != 0
  simd_f_t noise_simd = srsran_simd_f_set1(noise_estimate);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00 = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01 = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h02 = srsran_simd_cfi_load(&h[0][2][i]);
    simd_cf_t h03 = srsran_simd_cfi_load(&h[0][3][i]);
    simd_cf_t h10 = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11 = srsran_simd_cfi_load(&h[1][1][i]);
    simd_cf_t h12 = srsran_simd_cfi_load(&h[1][2][i]);
    simd_cf_t h13 = srsran_simd_cfi_load(&h[1][3][i]);

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t h_eff0, h_eff1;

    switch (codebook_idx) {
      case 0:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h01), srsran_simd_cf_add(h02, h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h11), srsran_simd_cf_add(h12, h13));
        break;
      case 1:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_add(h02, h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_add(h12, h13)));
        break;
      case 2:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h01), srsran_simd_cf_add(h02, h03));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h11), srsran_simd_cf_add(h12, h13));
        break;
      case 3:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_add(h02, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_add(h12, h13)));
        break;
      case 4:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_add(h02, srsran_simd_cf_mulj(h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_add(h12, srsran_simd_cf_mulj(h13)));
        break;
      case 5:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_sub(srsran_simd_cf_mulj(h02), h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_sub(srsran_simd_cf_mulj(h12), h13));
        break;
      case 6:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_add(h02, srsran_simd_cf_mulj(h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_add(h12, srsran_simd_cf_mulj(h13)));
        break;
      case 7:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h02)), srsran_simd_cf_add(srsran_simd_cf_mulj(h01), h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h12)), srsran_simd_cf_add(srsran_simd_cf_mulj(h11), h13));
        break;
      case 8:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_sub(h02, h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_sub(h12, h13));
        break;
      case 9:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_sub(h02, h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_sub(h12, h13)));
        break;
      case 10:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_sub(h02, h03));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_sub(h12, h13));
        break;
      case 11:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_sub(h02, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_sub(h12, h13)));
        break;
      case 12:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h02), srsran_simd_cf_mulj(srsran_simd_cf_add(h01, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h12), srsran_simd_cf_mulj(srsran_simd_cf_add(h11, h13)));
        break;
      case 13:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h03), srsran_simd_cf_sub(srsran_simd_cf_mulj(h02), srsran_simd_cf_mulj(h01)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h13), srsran_simd_cf_sub(srsran_simd_cf_mulj(h12), srsran_simd_cf_mulj(h11)));
        break;
      case 14:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h02), srsran_simd_cf_mulj(srsran_simd_cf_sub(h03, h01)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h12), srsran_simd_cf_mulj(srsran_simd_cf_sub(h13, h11)));
        break;
      case 15:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h03), srsran_simd_cf_mulj(srsran_simd_cf_add(h01, h02)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h13), srsran_simd_cf_mulj(srsran_simd_cf_add(h11, h12)));
        break;
      default:
        ERROR("Invalid codebook index %d for single layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t h_eff0_conj = srsran_simd_cf_conj(h_eff0);
    simd_cf_t h_eff1_conj = srsran_simd_cf_conj(h_eff1);

    simd_cf_t numer = srsran_simd_cf_add(srsran_simd_cf_prod(h_eff0_conj, y0),
                                          srsran_simd_cf_prod(h_eff1_conj, y1));

    simd_f_t h_eff0_sq = srsran_simd_cf_re(srsran_simd_cf_prod(h_eff0, h_eff0_conj));
    simd_f_t h_eff1_sq = srsran_simd_cf_re(srsran_simd_cf_prod(h_eff1, h_eff1_conj));
    simd_f_t chan_pwr = srsran_simd_f_add(h_eff0_sq, h_eff1_sq);
    simd_f_t denom = srsran_simd_f_add(chan_pwr, noise_simd);

    // CSI = chan_pwr / denom * norm^2
    simd_f_t csi_val = srsran_simd_f_mul(srsran_simd_f_mul(chan_pwr, srsran_simd_f_rcp(denom)),
                                          srsran_simd_f_set1(norm * norm));
    srsran_simd_f_store(&csi[i], csi_val);

    simd_f_t inv_denom = srsran_simd_f_rcp(denom);
    simd_f_t inv_denom_norm = srsran_simd_f_mul(inv_denom, srsran_simd_f_set1(norm));
    simd_cf_t x0 = srsran_simd_cf_mul(numer, inv_denom_norm);

    srsran_simd_cfi_store(&x[0][i], x0);
  }
#endif

  for (; i < nof_symbols; i++) {
    cf_t h00 = h[0][0][i], h01 = h[0][1][i], h02 = h[0][2][i], h03 = h[0][3][i];
    cf_t h10 = h[1][0][i], h11 = h[1][1][i], h12 = h[1][2][i], h13 = h[1][3][i];

    cf_t h_eff0, h_eff1;

    switch (codebook_idx) {
      case 0:  h_eff0 = h00 + h01 + h02 + h03;
               h_eff1 = h10 + h11 + h12 + h13; break;
      case 1:  h_eff0 = h00 + h01 + _Complex_I*(h02 + h03);
               h_eff1 = h10 + h11 + _Complex_I*(h12 + h13); break;
      case 2:  h_eff0 = h00 + h01 - h02 - h03;
               h_eff1 = h10 + h11 - h12 - h13; break;
      case 3:  h_eff0 = h00 + h01 - _Complex_I*(h02 + h03);
               h_eff1 = h10 + h11 - _Complex_I*(h12 + h13); break;
      case 4:  h_eff0 = h00 + _Complex_I*h01 + h02 + _Complex_I*h03;
               h_eff1 = h10 + _Complex_I*h11 + h12 + _Complex_I*h13; break;
      case 5:  h_eff0 = h00 + _Complex_I*h01 + _Complex_I*h02 - h03;
               h_eff1 = h10 + _Complex_I*h11 + _Complex_I*h12 - h13; break;
      case 6:  h_eff0 = h00 + _Complex_I*h01 - h02 - _Complex_I*h03;
               h_eff1 = h10 + _Complex_I*h11 - h12 - _Complex_I*h13; break;
      case 7:  h_eff0 = h00 + _Complex_I*h01 - _Complex_I*h02 + h03;
               h_eff1 = h10 + _Complex_I*h11 - _Complex_I*h12 + h13; break;
      case 8:  h_eff0 = h00 - h01 + h02 - h03;
               h_eff1 = h10 - h11 + h12 - h13; break;
      case 9:  h_eff0 = h00 - h01 + _Complex_I*(h02 - h03);
               h_eff1 = h10 - h11 + _Complex_I*(h12 - h13); break;
      case 10: h_eff0 = h00 - h01 - h02 + h03;
               h_eff1 = h10 - h11 - h12 + h13; break;
      case 11: h_eff0 = h00 - h01 - _Complex_I*(h02 - h03);
               h_eff1 = h10 - h11 - _Complex_I*(h12 - h13); break;
      case 12: h_eff0 = h00 - _Complex_I*h01 + h02 - _Complex_I*h03;
               h_eff1 = h10 - _Complex_I*h11 + h12 - _Complex_I*h13; break;
      case 13: h_eff0 = h00 - _Complex_I*h01 + _Complex_I*h02 + h03;
               h_eff1 = h10 - _Complex_I*h11 + _Complex_I*h12 + h13; break;
      case 14: h_eff0 = h00 - _Complex_I*h01 - h02 + _Complex_I*h03;
               h_eff1 = h10 - _Complex_I*h11 - h12 + _Complex_I*h13; break;
      case 15: h_eff0 = h00 - _Complex_I*h01 - _Complex_I*h02 - h03;
               h_eff1 = h10 - _Complex_I*h11 - _Complex_I*h12 - h13; break;
      default:
        ERROR("Invalid codebook index %d for single layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    float chan_pwr = crealf(h_eff0 * conjf(h_eff0)) + crealf(h_eff1 * conjf(h_eff1));
    float denom = chan_pwr + noise_estimate;

    csi[i] = (chan_pwr / denom) * norm * norm;

    cf_t numer = conjf(h_eff0) * y[0][i] + conjf(h_eff1) * y[1][i];
    x[0][i] = numer * norm / denom;
  }

  return SRSRAN_SUCCESS;
}

// Test: Compute effective 2x2 channel for codebook 15 and solve
// Test: Compute effective 2x2 channel for codebook 15 and solve
static void test_codebook15_effective_channel(cf_t *y[SRSRAN_MAX_PORTS],
                                               cf_t *h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                               cf_t *x[SRSRAN_MAX_LAYERS],
                                               int nof_symbols)
{
    // Codebook 15: W = 1/2 * [1  1; 1 -1; 1  1; 1 -1]
    // Port 0,2 transmit (x0+x1)/2
    // Port 1,3 transmit (x0-x1)/2
    //
    // y_rx0 = h00*(x0+x1)/2 + h10*(x0-x1)/2 + h20*(x0+x1)/2 + h30*(x0-x1)/2
    // y_rx1 = h01*(x0+x1)/2 + h11*(x0-x1)/2 + h21*(x0+x1)/2 + h31*(x0-x1)/2
    //
    // Rearranging:
    // y_rx0 = [(h00+h20+h10+h30)/2]*x0 + [(h00+h20-h10-h30)/2]*x1
    // y_rx1 = [(h01+h21+h11+h31)/2]*x0 + [(h01+h21-h11-h31)/2]*x1

    int qpsk_count = 0;
    int qpsk_count_mmse = 0;

    // First do forward verification for first few symbols
    printf("Forward verification (y_recon should match y_actual):\n");
    for (int i = 0; i < 5 && i < nof_symbols; i++) {
        cf_t h00 = h[0][0][i];
        cf_t h01 = h[0][1][i];
        cf_t h10 = h[1][0][i];
        cf_t h11 = h[1][1][i];
        cf_t h20 = h[2][0][i];
        cf_t h21 = h[2][1][i];
        cf_t h30 = h[3][0][i];
        cf_t h31 = h[3][1][i];

        cf_t h02_sum = h00 + h20;
        cf_t h13_sum = h10 + h30;
        cf_t h02_sum_rx1 = h01 + h21;
        cf_t h13_sum_rx1 = h11 + h31;

        cf_t Heff00 = (h02_sum + h13_sum) * 0.5f;
        cf_t Heff01 = (h02_sum - h13_sum) * 0.5f;
        cf_t Heff10 = (h02_sum_rx1 + h13_sum_rx1) * 0.5f;
        cf_t Heff11 = (h02_sum_rx1 - h13_sum_rx1) * 0.5f;

        // ZF equalization
        cf_t y0 = y[0][i];
        cf_t y1 = y[1][i];
        cf_t det = Heff00 * Heff11 - Heff01 * Heff10;

        cf_t x0_zf, x1_zf;
        if (cabsf(det) > 1e-9f) {
            x0_zf = (Heff11 * y0 - Heff01 * y1) / det;
            x1_zf = (Heff00 * y1 - Heff10 * y0) / det;
        } else {
            x0_zf = 0;
            x1_zf = 0;
        }

        // Reconstruct y from equalized x
        cf_t y0_recon = Heff00 * x0_zf + Heff01 * x1_zf;
        cf_t y1_recon = Heff10 * x0_zf + Heff11 * x1_zf;

        printf("  RE[%d]:\n", i);
        printf("    H_eff = [[%.2f%+.2fj, %.2f%+.2fj], [%.2f%+.2fj, %.2f%+.2fj]]\n",
               crealf(Heff00), cimagf(Heff00), crealf(Heff01), cimagf(Heff01),
               crealf(Heff10), cimagf(Heff10), crealf(Heff11), cimagf(Heff11));
        printf("    det = %.3f%+.3fj (|det|=%.3f)\n", crealf(det), cimagf(det), cabsf(det));
        printf("    y_actual = (%.2f%+.2fj), (%.2f%+.2fj)\n",
               crealf(y0), cimagf(y0), crealf(y1), cimagf(y1));
        printf("    y_recon  = (%.2f%+.2fj), (%.2f%+.2fj)\n",
               crealf(y0_recon), cimagf(y0_recon), crealf(y1_recon), cimagf(y1_recon));
        printf("    x_zf     = (%.2f%+.2fj), (%.2f%+.2fj)\n",
               crealf(x0_zf), cimagf(x0_zf), crealf(x1_zf), cimagf(x1_zf));
    }

    // Now do full equalization with both ZF and MMSE
    float noise_reg = 0.1f;  // MMSE regularization

    for (int i = 0; i < nof_symbols; i++) {
        cf_t h00 = h[0][0][i];
        cf_t h01 = h[0][1][i];
        cf_t h10 = h[1][0][i];
        cf_t h11 = h[1][1][i];
        cf_t h20 = h[2][0][i];
        cf_t h21 = h[2][1][i];
        cf_t h30 = h[3][0][i];
        cf_t h31 = h[3][1][i];

        cf_t h02_sum = h00 + h20;
        cf_t h13_sum = h10 + h30;
        cf_t h02_sum_rx1 = h01 + h21;
        cf_t h13_sum_rx1 = h11 + h31;

        cf_t Heff00 = (h02_sum + h13_sum) * 0.5f;
        cf_t Heff01 = (h02_sum - h13_sum) * 0.5f;
        cf_t Heff10 = (h02_sum_rx1 + h13_sum_rx1) * 0.5f;
        cf_t Heff11 = (h02_sum_rx1 - h13_sum_rx1) * 0.5f;

        cf_t y0 = y[0][i];
        cf_t y1 = y[1][i];

        // === ZF Equalization ===
        cf_t det = Heff00 * Heff11 - Heff01 * Heff10;
        cf_t x0_zf, x1_zf;
        if (cabsf(det) > 1e-9f) {
            x0_zf = (Heff11 * y0 - Heff01 * y1) / det;
            x1_zf = (Heff00 * y1 - Heff10 * y0) / det;
        } else {
            x0_zf = 0;
            x1_zf = 0;
        }

        // === MMSE Equalization ===
        // x = (H^H * H + noise*I)^-1 * H^H * y
        cf_t HtH00 = conjf(Heff00)*Heff00 + conjf(Heff10)*Heff10 + noise_reg;
        cf_t HtH01 = conjf(Heff00)*Heff01 + conjf(Heff10)*Heff11;
        cf_t HtH10 = conjf(Heff01)*Heff00 + conjf(Heff11)*Heff10;
        cf_t HtH11 = conjf(Heff01)*Heff01 + conjf(Heff11)*Heff11 + noise_reg;

        cf_t Hty0 = conjf(Heff00)*y0 + conjf(Heff10)*y1;
        cf_t Hty1 = conjf(Heff01)*y0 + conjf(Heff11)*y1;

        cf_t det_mmse = HtH00*HtH11 - HtH01*HtH10;
        cf_t x0_mmse, x1_mmse;
        if (cabsf(det_mmse) > 1e-9f) {
            x0_mmse = (HtH11*Hty0 - HtH01*Hty1) / det_mmse;
            x1_mmse = (HtH00*Hty1 - HtH10*Hty0) / det_mmse;
        } else {
            x0_mmse = 0;
            x1_mmse = 0;
        }

        // Store ZF result
        x[0][i] = x0_zf;
        x[1][i] = x1_zf;

        // Check QPSK-like for ZF
        float re0 = crealf(x0_zf);
        float im0 = cimagf(x0_zf);
        float re1 = crealf(x1_zf);
        float im1 = cimagf(x1_zf);

        if (fabsf(fabsf(re0) - fabsf(im0)) < 0.3f * (fabsf(re0) + fabsf(im0) + 0.01f) &&
            fabsf(fabsf(re1) - fabsf(im1)) < 0.3f * (fabsf(re1) + fabsf(im1) + 0.01f)) {
            qpsk_count++;
        }

        // Check QPSK-like for MMSE
        re0 = crealf(x0_mmse);
        im0 = cimagf(x0_mmse);
        re1 = crealf(x1_mmse);
        im1 = cimagf(x1_mmse);

        if (fabsf(fabsf(re0) - fabsf(im0)) < 0.3f * (fabsf(re0) + fabsf(im0) + 0.01f) &&
            fabsf(fabsf(re1) - fabsf(im1)) < 0.3f * (fabsf(re1) + fabsf(im1) + 0.01f)) {
            qpsk_count_mmse++;
        }
    }

    printf("\nCodebook15 effective channel results:\n");
    printf("  ZF   QPSK-like = %.1f%%\n", 100.0f * qpsk_count / nof_symbols);
    printf("  MMSE QPSK-like = %.1f%% (noise_reg=%.2f)\n", 100.0f * qpsk_count_mmse / nof_symbols, noise_reg);

    // Print first 5 equalized symbols (ZF)
    printf("First 5 ZF equalized symbols:\n");
    for (int i = 0; i < 5 && i < nof_symbols; i++) {
        printf("  x[0][%d]=(%.3f%+.3fj)  x[1][%d]=(%.3f%+.3fj)\n",
               i, crealf(x[0][i]), cimagf(x[0][i]),
               i, crealf(x[1][i]), cimagf(x[1][i]));
    }
}

// Test with swapped layers
static void test_codebook15_swapped_layers(cf_t *y[SRSRAN_MAX_PORTS],
                                           cf_t *h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                           cf_t *x[SRSRAN_MAX_LAYERS],
                                           int nof_symbols)
{
    int qpsk_count = 0;

    for (int i = 0; i < nof_symbols; i++) {
        cf_t h00 = h[0][0][i];
        cf_t h01 = h[0][1][i];
        cf_t h10 = h[1][0][i];
        cf_t h11 = h[1][1][i];
        cf_t h20 = h[2][0][i];
        cf_t h21 = h[2][1][i];
        cf_t h30 = h[3][0][i];
        cf_t h31 = h[3][1][i];

        cf_t h02_sum = h00 + h20;
        cf_t h13_sum = h10 + h30;
        cf_t h02_sum_rx1 = h01 + h21;
        cf_t h13_sum_rx1 = h11 + h31;

        // SWAP: Try x1 with first column, x0 with second column
        cf_t Heff00 = (h02_sum - h13_sum) * 0.5f;  // was Heff01
        cf_t Heff01 = (h02_sum + h13_sum) * 0.5f;  // was Heff00
        cf_t Heff10 = (h02_sum_rx1 - h13_sum_rx1) * 0.5f;  // was Heff11
        cf_t Heff11 = (h02_sum_rx1 + h13_sum_rx1) * 0.5f;  // was Heff10

        cf_t y0 = y[0][i];
        cf_t y1 = y[1][i];

        cf_t det = Heff00 * Heff11 - Heff01 * Heff10;
        if (cabsf(det) > 1e-9f) {
            x[0][i] = (Heff11 * y0 - Heff01 * y1) / det;
            x[1][i] = (Heff00 * y1 - Heff10 * y0) / det;
        } else {
            x[0][i] = 0;
            x[1][i] = 0;
        }

        float re0 = crealf(x[0][i]);
        float im0 = cimagf(x[0][i]);
        float re1 = crealf(x[1][i]);
        float im1 = cimagf(x[1][i]);

        if (fabsf(fabsf(re0) - fabsf(im0)) < 0.3f * (fabsf(re0) + fabsf(im0) + 0.01f) &&
            fabsf(fabsf(re1) - fabsf(im1)) < 0.3f * (fabsf(re1) + fabsf(im1) + 0.01f)) {
            qpsk_count++;
        }
    }

    printf("Codebook15 SWAPPED layers: QPSK-like = %.1f%%\n",
           100.0f * qpsk_count / nof_symbols);

    printf("First 5 swapped equalized symbols:\n");
    for (int i = 0; i < 5 && i < nof_symbols; i++) {
        printf("  x[0][%d]=(%.3f%+.3fj)  x[1][%d]=(%.3f%+.3fj)\n",
               i, crealf(x[0][i]), cimagf(x[0][i]),
               i, crealf(x[1][i]), cimagf(x[1][i]));
    }
}

static void test_all_codebook_indices(cf_t *y[SRSRAN_MAX_PORTS],
                                      cf_t *h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                      cf_t *x[SRSRAN_MAX_LAYERS],
                                      int nof_symbols)
{
    // 4-port 2-layer codebook from 36.211 Table 6.3.4.2.3-2
    // Each entry is [w00 w01 w10 w11 w20 w21 w30 w31] for W = [w0 w1] where w0=[w00;w10;w20;w30]
    // Normalized by 1/2

    const cf_t j = I;

    // u vectors for codebook (from 36.211)
    cf_t u[16][4] = {
        {1,  1,  1,  1},      // u0
        {1,  1,  1, -1},      // u1  (actually phase varies)
        {1,  1, -1,  1},      // u2
        {1,  1, -1, -1},      // u3
        {1,  1,  j,  j},      // u4
        {1,  1,  j, -j},      // u5
        {1,  1, -j,  j},      // u6
        {1,  1, -j, -j},      // u7
        {1, -1,  1,  1},      // u8
        {1, -1,  1, -1},      // u9
        {1, -1, -1,  1},      // u10
        {1, -1, -1, -1},      // u11
        {1, -1,  j,  j},      // u12
        {1, -1,  j, -j},      // u13
        {1, -1, -j,  j},      // u14
        {1, -1, -j, -j},      // u15
    };

    printf("\nBrute-force testing all 16 codebook indices:\n");

    for (int cb = 0; cb < 16; cb++) {
        // For 2-layer, W = 1/2 * [u_n  u_n_tilde] where columns are paired
        // Actually the pairing depends on the codebook structure
        // For simplicity, test W = 1/2 * [u_cb  u_cb_rotated]

        // Let's use the actual 36.211 structure:
        // W_n = 1/2 * [e1  e2] * [1  1; 1 -1; phi_n  -phi_n; phi_n  phi_n] or similar

        // For now, test identity-like: layer0->port0+port2, layer1->port1+port3
        // with phase from codebook

        cf_t phase = u[cb][2];  // Use 3rd element as phase for ports 2,3

        int qpsk_count = 0;

        for (int i = 0; i < nof_symbols; i++) {
            cf_t h00 = h[0][0][i];
            cf_t h01 = h[0][1][i];
            cf_t h10 = h[1][0][i];
            cf_t h11 = h[1][1][i];
            cf_t h20 = h[2][0][i];
            cf_t h21 = h[2][1][i];
            cf_t h30 = h[3][0][i];
            cf_t h31 = h[3][1][i];

            // Try: W = 1/2 * [1 0; 0 1; phase 0; 0 phase]
            // So port0=x0/2, port1=x1/2, port2=phase*x0/2, port3=phase*x1/2
            cf_t Heff00 = (h00 + phase*h20) * 0.5f;
            cf_t Heff01 = (h10 + phase*h30) * 0.5f;
            cf_t Heff10 = (h01 + phase*h21) * 0.5f;
            cf_t Heff11 = (h11 + phase*h31) * 0.5f;

            cf_t y0 = y[0][i];
            cf_t y1 = y[1][i];

            cf_t det = Heff00 * Heff11 - Heff01 * Heff10;
            cf_t x0, x1;
            if (cabsf(det) > 1e-9f) {
                x0 = (Heff11 * y0 - Heff01 * y1) / det;
                x1 = (Heff00 * y1 - Heff10 * y0) / det;
            } else {
                x0 = 0;
                x1 = 0;
            }

            float re0 = crealf(x0);
            float im0 = cimagf(x0);
            float re1 = crealf(x1);
            float im1 = cimagf(x1);

            if (fabsf(fabsf(re0) - fabsf(im0)) < 0.3f * (fabsf(re0) + fabsf(im0) + 0.01f) &&
                fabsf(fabsf(re1) - fabsf(im1)) < 0.3f * (fabsf(re1) + fabsf(im1) + 0.01f)) {
                qpsk_count++;
            }
        }

        printf("  CB%2d (phase=%.1f%+.1fj): QPSK-like = %.1f%%\n",
               cb, crealf(phase), cimagf(phase), 100.0f * qpsk_count / nof_symbols);
    }
}

static void analyze_channel_structure(cf_t *h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                      cf_t *y[SRSRAN_MAX_PORTS],
                                      int nof_symbols)
{
    printf("\n========== CHANNEL STRUCTURE ANALYSIS ==========\n");

    // Check if channel varies smoothly (real channel) or randomly (wrong CE)
    printf("Channel variation between adjacent REs (should be small for real channel):\n");
    for (int p = 0; p < 4; p++) {
        float total_diff = 0;
        for (int i = 1; i < 100 && i < nof_symbols; i++) {
            cf_t diff = h[p][0][i] - h[p][0][i-1];
            total_diff += cabsf(diff);
        }
        float avg_diff = total_diff / 99.0f;
        float avg_mag = 0;
        for (int i = 0; i < 100 && i < nof_symbols; i++) {
            avg_mag += cabsf(h[p][0][i]);
        }
        avg_mag /= 100.0f;
        printf("  Port %d: avg_diff=%.3f, avg_mag=%.3f, ratio=%.3f\n",
               p, avg_diff, avg_mag, avg_diff/avg_mag);
    }

    // Check if y varies more than H (data should vary, channel should be smooth)
    printf("\nReceived signal y variation:\n");
    float y_diff = 0;
    float y_mag = 0;
    for (int i = 1; i < 100 && i < nof_symbols; i++) {
        y_diff += cabsf(y[0][i] - y[0][i-1]);
        y_mag += cabsf(y[0][i]);
    }
    printf("  y[rx0]: avg_diff=%.3f, avg_mag=%.3f, ratio=%.3f\n",
           y_diff/99.0f, y_mag/100.0f, (y_diff/99.0f)/(y_mag/100.0f));

    // Check phase rotation across subcarriers (timing offset would cause linear phase)
    printf("\nPhase progression check (linear = timing offset):\n");
    for (int p = 0; p < 2; p++) {
        printf("  Port %d phases: ", p);
        for (int i = 0; i < 12 && i < nof_symbols; i++) {
            float phase = cargf(h[p][0][i]) * 180.0f / M_PI;
            printf("%.0f ", phase);
        }
        printf("\n");
    }

    // Try to detect if there's a constant phase offset between CE and data
    // If y = H*W*x, and x is QPSK, then y/H should cluster around W*x values
    printf("\nRaw y/h ratio (should show structure if CE is correct):\n");
    for (int i = 0; i < 10 && i < nof_symbols; i++) {
        cf_t ratio0 = y[0][i] / h[0][0][i];
        cf_t ratio1 = y[0][i] / h[1][0][i];
        printf("  RE[%d]: y/h0=(%.2f,%.2f) y/h1=(%.2f,%.2f)\n",
               i, crealf(ratio0), cimagf(ratio0), crealf(ratio1), cimagf(ratio1));
    }

    printf("================================================\n");
}

// static int srsran_predecoding_multiplex_4x2_mmse_csi(cf_t*  y[SRSRAN_MAX_PORTS],
//                                                      cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
//                                                      cf_t*  x[SRSRAN_MAX_LAYERS],
//                                                      float* csi[SRSRAN_MAX_CODEWORDS],
//                                                      int    codebook_idx,
//                                                      int    nof_symbols,
//                                                      float  scaling,
//                                                      float  noise_estimate)
// {
// printf("Processing 4x2 multiplexing MIMO using CSI with codebook_idx=%d, nof_symbols=%d, scaling=%.02f, noise_estimate=%.02f\n", codebook_idx, nof_symbols, scaling, noise_estimate);
//   static int first_call = 0;
//   if (first_call) {
//     first_call = 0;

//     printf("\n========== CHANNEL ESTIMATE ANALYSIS ==========\n");
//     printf("codebook_idx=%d, nof_symbols=%d\n\n", codebook_idx, nof_symbols);

//     // Check first 10 RE's channel estimates in detail
//     printf("First 10 REs - Channel estimates h[port][rx]:\n");
//     for (int i = 0; i < 10 && i < nof_symbols; i++) {
//       printf("RE[%d]:\n", i);
//       printf("  p0: rx0=(%+6.3f,%+6.3f) rx1=(%+6.3f,%+6.3f)\n",
//              crealf(h[0][0][i]), cimagf(h[0][0][i]),
//              crealf(h[0][1][i]), cimagf(h[0][1][i]));
//       printf("  p1: rx0=(%+6.3f,%+6.3f) rx1=(%+6.3f,%+6.3f)\n",
//              crealf(h[1][0][i]), cimagf(h[1][0][i]),
//              crealf(h[1][1][i]), cimagf(h[1][1][i]));
//       printf("  p2: rx0=(%+6.3f,%+6.3f) rx1=(%+6.3f,%+6.3f)\n",
//              crealf(h[2][0][i]), cimagf(h[2][0][i]),
//              crealf(h[2][1][i]), cimagf(h[2][1][i]));
//       printf("  p3: rx0=(%+6.3f,%+6.3f) rx1=(%+6.3f,%+6.3f)\n",
//              crealf(h[3][0][i]), cimagf(h[3][0][i]),
//              crealf(h[3][1][i]), cimagf(h[3][1][i]));
//       printf("  y:  rx0=(%+6.3f,%+6.3f) rx1=(%+6.3f,%+6.3f)\n",
//              crealf(y[0][i]), cimagf(y[0][i]),
//              crealf(y[1][i]), cimagf(y[1][i]));
//     }

//     // Check for patterns - are ports 2,3 copies of 0,1?
//     printf("\nCorrelation check - are ports 2,3 duplicates of 0,1?\n");
//     cf_t corr_20 = 0, corr_31 = 0;
//     float pwr_0 = 0, pwr_1 = 0, pwr_2 = 0, pwr_3 = 0;
//     int n_check = (nof_symbols < 100) ? nof_symbols : 100;

//     for (int i = 0; i < n_check; i++) {
//       corr_20 += h[2][0][i] * conjf(h[0][0][i]);
//       corr_31 += h[3][0][i] * conjf(h[1][0][i]);
//       pwr_0 += cabsf(h[0][0][i]) * cabsf(h[0][0][i]);
//       pwr_1 += cabsf(h[1][0][i]) * cabsf(h[1][0][i]);
//       pwr_2 += cabsf(h[2][0][i]) * cabsf(h[2][0][i]);
//       pwr_3 += cabsf(h[3][0][i]) * cabsf(h[3][0][i]);
//     }

//     float norm_corr_20 = cabsf(corr_20) / sqrtf(pwr_0 * pwr_2 + 1e-10f);
//     float norm_corr_31 = cabsf(corr_31) / sqrtf(pwr_1 * pwr_3 + 1e-10f);

//     printf("  Correlation p2 vs p0: %.3f (1.0 = identical)\n", norm_corr_20);
//     printf("  Correlation p3 vs p1: %.3f (1.0 = identical)\n", norm_corr_31);

//     // Check if ports 2,3 are all zeros
//     int zero_count_2 = 0, zero_count_3 = 0;
//     for (int i = 0; i < n_check; i++) {
//       if (cabsf(h[2][0][i]) < 1e-6f && cabsf(h[2][1][i]) < 1e-6f) zero_count_2++;
//       if (cabsf(h[3][0][i]) < 1e-6f && cabsf(h[3][1][i]) < 1e-6f) zero_count_3++;
//     }
//     printf("  Port 2 zero count: %d/%d\n", zero_count_2, n_check);
//     printf("  Port 3 zero count: %d/%d\n", zero_count_3, n_check);

//     // Try simple 2x2 with just ports 0,1 to see if that works at all
//     printf("\nTest: Simple 2x2 ZF with ports 0,1 only (no codebook):\n");
//     int qpsk_01 = 0;
//     for (int i = 0; i < n_check; i++) {
//       cf_t H00 = h[0][0][i];
//       cf_t H01 = h[1][0][i];
//       cf_t H10 = h[0][1][i];
//       cf_t H11 = h[1][1][i];

//       cf_t det = H00*H11 - H01*H10;
//       float det_sq = crealf(det)*crealf(det) + cimagf(det)*cimagf(det);
//       if (det_sq < 1e-12f) continue;

//       cf_t inv_det = conjf(det) / det_sq;
//       cf_t x0 = inv_det * (H11*y[0][i] - H01*y[1][i]);
//       cf_t x1 = inv_det * (-H10*y[0][i] + H00*y[1][i]);

//       if (cabsf(x0) > 0.5f && cabsf(x0) < 1.0f) qpsk_01++;
//       if (cabsf(x1) > 0.5f && cabsf(x1) < 1.0f) qpsk_01++;
//     }
//     printf("  QPSK-like with p0,p1 direct: %.1f%%\n", 100.0f*qpsk_01/(2*n_check));

//     // What if this is actually a 2-port transmission being decoded as 4-port?
//     printf("\nTest: What if eNB is actually transmitting 2-port?\n");
//     printf("  Try decoding as 2x2 TM4 codebook 0 (ports 0,1):\n");

//     // 2-port codebook index 0: W = 1/sqrt(2) * [1, 1; 1, -1]
//     int qpsk_2port = 0;
//     for (int i = 0; i < n_check; i++) {
//       // H_eff = H * W for 2-port
//       cf_t H00 = 0.7071f * (h[0][0][i] + h[1][0][i]);
//       cf_t H01 = 0.7071f * (h[0][0][i] - h[1][0][i]);
//       cf_t H10 = 0.7071f * (h[0][1][i] + h[1][1][i]);
//       cf_t H11 = 0.7071f * (h[0][1][i] - h[1][1][i]);

//       cf_t det = H00*H11 - H01*H10;
//       float det_sq = crealf(det)*crealf(det) + cimagf(det)*cimagf(det);
//       if (det_sq < 1e-12f) continue;

//       cf_t inv_det = conjf(det) / det_sq;
//       cf_t x0 = inv_det * (H11*y[0][i] - H01*y[1][i]);
//       cf_t x1 = inv_det * (-H10*y[0][i] + H00*y[1][i]);

//       if (cabsf(x0) > 0.5f && cabsf(x0) < 1.0f) qpsk_2port++;
//       if (cabsf(x1) > 0.5f && cabsf(x1) < 1.0f) qpsk_2port++;
//     }
//     printf("  QPSK-like with 2-port codebook 0: %.1f%%\n", 100.0f*qpsk_2port/(2*n_check));

//     // Try all 2-port codebook indices
//     printf("\nTest all 2-port codebook indices:\n");
//     for (int cb = 0; cb < 4; cb++) {
//       // 2-port rank-2 codebook (36.211 Table 6.3.4.2.3-1)
//       cf_t W00, W01, W10, W11;
//       float n2 = 0.7071f;  // 1/sqrt(2)

//       switch(cb) {
//         case 0: W00=n2; W01=n2;  W10=n2;  W11=-n2; break;  // [1,1;1,-1]/sqrt(2)
//         case 1: W00=n2; W01=n2;  W10=n2*_Complex_I; W11=-n2*_Complex_I; break;
//         case 2: W00=n2; W01=-n2; W10=n2;  W11=n2;  break;
//         case 3: W00=n2; W01=-n2; W10=n2*_Complex_I; W11=n2*_Complex_I; break;
//       }

//       int qpsk_cb = 0;
//       for (int i = 0; i < n_check; i++) {
//         cf_t H00 = h[0][0][i]*W00 + h[1][0][i]*W10;
//         cf_t H01 = h[0][0][i]*W01 + h[1][0][i]*W11;
//         cf_t H10 = h[0][1][i]*W00 + h[1][1][i]*W10;
//         cf_t H11 = h[0][1][i]*W01 + h[1][1][i]*W11;

//         cf_t det = H00*H11 - H01*H10;
//         float det_sq = crealf(det)*crealf(det) + cimagf(det)*cimagf(det);
//         if (det_sq < 1e-12f) continue;

//         cf_t inv_det = conjf(det) / det_sq;
//         cf_t x0 = inv_det * (H11*y[0][i] - H01*y[1][i]);
//         cf_t x1 = inv_det * (-H10*y[0][i] + H00*y[1][i]);

//         if (cabsf(x0) > 0.5f && cabsf(x0) < 1.0f) qpsk_cb++;
//         if (cabsf(x1) > 0.5f && cabsf(x1) < 1.0f) qpsk_cb++;
//       }
//       printf("  2-port CB%d: %.1f%%\n", cb, 100.0f*qpsk_cb/(2*n_check));
//     }

//     printf("==============================================\n\n");
//   }

//   // ... rest of function unchanged
//   static const cf_t W[16][4][2] = {
//     [0]  = {{1, 1}, {-1, 1}, {-1, 1}, {-1, 1}},
//     [1]  = {{1, 1}, {-_Complex_I, _Complex_I}, {-1, 1}, {_Complex_I, -_Complex_I}},
//     [2]  = {{1, 1}, {1, -1}, {-1, 1}, {1, -1}},
//     [3]  = {{1, 1}, {_Complex_I, -_Complex_I}, {-1, 1}, {-_Complex_I, _Complex_I}},
//     [4]  = {{1, 1}, {-1, 1}, {-_Complex_I, _Complex_I}, {-_Complex_I, _Complex_I}},
//     [5]  = {{1, 1}, {-_Complex_I, _Complex_I}, {-_Complex_I, _Complex_I}, {-1, 1}},
//     [6]  = {{1, 1}, {1, -1}, {-_Complex_I, _Complex_I}, {-1, 1}},
//     [7]  = {{1, 1}, {_Complex_I, -_Complex_I}, {-_Complex_I, _Complex_I}, {1, -1}},
//     [8]  = {{1, 1}, {-1, 1}, {1, -1}, {1, -1}},
//     [9]  = {{1, 1}, {-_Complex_I, _Complex_I}, {1, -1}, {-_Complex_I, _Complex_I}},
//     [10] = {{1, 1}, {1, -1}, {1, -1}, {-1, 1}},
//     [11] = {{1, 1}, {_Complex_I, -_Complex_I}, {1, -1}, {_Complex_I, -_Complex_I}},
//     [12] = {{1, 1}, {-1, 1}, {_Complex_I, -_Complex_I}, {_Complex_I, -_Complex_I}},
//     [13] = {{1, 1}, {-_Complex_I, _Complex_I}, {_Complex_I, -_Complex_I}, {1, -1}},
//     [14] = {{1, 1}, {1, -1}, {_Complex_I, -_Complex_I}, {1, -1}},
//     [15] = {{1, 1}, {_Complex_I, -_Complex_I}, {_Complex_I, -_Complex_I}, {-1, 1}},
//   };

//   if (codebook_idx < 0 || codebook_idx > 15) {
//     ERROR("Wrong codebook_idx=%d", codebook_idx);
//     return SRSRAN_ERROR;
//   }

//   if (codebook_idx == 15){
//       // test_codebook15_effective_channel(y,h,x,nof_symbols);
//       // test_codebook15_swapped_layers(y,h,x,nof_symbols);
//       analyze_channel_structure(h,y,nof_symbols);
//       test_all_codebook_indices(y,h,x,nof_symbols);
//       return SRSRAN_SUCCESS;
//   }

//   const cf_t (*Wn)[2] = W[codebook_idx];
//   const float norm = 0.5f;

//   if (noise_estimate < 1e-6f) {
//     noise_estimate = 0.01f;
//   }

//   for (int i = 0; i < nof_symbols; i++) {
//     cf_t hp0r0 = h[0][0][i], hp1r0 = h[1][0][i], hp2r0 = h[2][0][i], hp3r0 = h[3][0][i];
//     cf_t hp0r1 = h[0][1][i], hp1r1 = h[1][1][i], hp2r1 = h[2][1][i], hp3r1 = h[3][1][i];

//     cf_t H00 = norm*(hp0r0*Wn[0][0] + hp1r0*Wn[1][0] + hp2r0*Wn[2][0] + hp3r0*Wn[3][0]);
//     cf_t H01 = norm*(hp0r0*Wn[0][1] + hp1r0*Wn[1][1] + hp2r0*Wn[2][1] + hp3r0*Wn[3][1]);
//     cf_t H10 = norm*(hp0r1*Wn[0][0] + hp1r1*Wn[1][0] + hp2r1*Wn[2][0] + hp3r1*Wn[3][0]);
//     cf_t H11 = norm*(hp0r1*Wn[0][1] + hp1r1*Wn[1][1] + hp2r1*Wn[2][1] + hp3r1*Wn[3][1]);

//     srsran_mat_2x2_mmse_csi_gen(y[0][i], y[1][i], H00, H01, H10, H11,
//                                 &x[0][i], &x[1][i], &csi[0][i], &csi[1][i],
//                                 noise_estimate, 1.0f/scaling);
//   }

//   return SRSRAN_SUCCESS;
// }

static int srsran_predecoding_multiplex_4x2_mmse_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                                     cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                     cf_t*  x[SRSRAN_MAX_LAYERS],
                                                     float* csi[SRSRAN_MAX_CODEWORDS],
                                                     int    codebook_idx,
                                                     int    nof_symbols,
                                                     float  scaling,
                                                     float  noise_estimate)
{
  float norm = (float) 0.5 / scaling;
  int i = 0;
  static int debug_count = 0;
  // printf("Processing 4x2 multiplexing MIMO using CSI with codebook_idx=%d, nof_symbols=%d, scaling=%.02f, noise_estimate=%.02f\n", codebook_idx, nof_symbols, scaling, noise_estimate);

  // switch (codebook_idx) {
  //     case 0:
  //       norm = (float)M_SQRT2 / scaling;
  //       break;
  //       case 1:
  //       case 2:
  //           norm = 2.0f / scaling;
  //           break;
  //       default:
  //           ERROR("Wrong codebook_idx=%d", codebook_idx);
  //           return SRSRAN_ERROR;
  // }

  if (codebook_idx < 0 || codebook_idx > 15){
      ERROR("Wrong codebook_idx=%d", codebook_idx);
      return SRSRAN_ERROR;
  }



//   static const cf_t W[16][4][2] = {
//       // Index 0: [1,1; -1,1; -1,1; -1,1]
//       [0] = {{1, 1}, {-1, 1}, {-1, 1}, {-1, 1}},
//       // Index 1: [1,1; -j,j; -1,1; j,-j]
//       [1] = {{1, 1}, {-_Complex_I, _Complex_I}, {-1, 1}, {_Complex_I, -_Complex_I}},
//       // Index 2: [1,1; 1,-1; -1,1; 1,-1]
//       [2] = {{1, 1}, {1, -1}, {-1, 1}, {1, -1}},
//       // Index 3: [1,1; j,-j; -1,1; -j,j]
//       [3] = {{1, 1}, {_Complex_I, -_Complex_I}, {-1, 1}, {-_Complex_I, _Complex_I}},
//       // Index 4: [1,1; -1,1; -j,j; -j,j]
//       [4] = {{1, 1}, {-1, 1}, {-_Complex_I, _Complex_I}, {-_Complex_I, _Complex_I}},
//       // Index 5: [1,1; -j,j; -j,j; -1,1]
//       [5] = {{1, 1}, {-_Complex_I, _Complex_I}, {-_Complex_I, _Complex_I}, {-1, 1}},
//       // Index 6: [1,1; 1,-1; -j,j; -1,1]
//       [6] = {{1, 1}, {1, -1}, {-_Complex_I, _Complex_I}, {-1, 1}},
//       // Index 7: [1,1; j,-j; -j,j; 1,-1]
//       [7] = {{1, 1}, {_Complex_I, -_Complex_I}, {-_Complex_I, _Complex_I}, {1, -1}},
//       // Index 8: [1,1; -1,1; 1,-1; 1,-1]
//       [8] = {{1, 1}, {-1, 1}, {1, -1}, {1, -1}},
//       // Index 9: [1,1; -j,j; 1,-1; -j,j]
//       [9] = {{1, 1}, {-_Complex_I, _Complex_I}, {1, -1}, {-_Complex_I, _Complex_I}},
//       // Index 10: [1,1; 1,-1; 1,-1; -1,1]
//       [10] = {{1, 1}, {1, -1}, {1, -1}, {-1, 1}},
//       // Index 11: [1,1; j,-j; 1,-1; j,-j]
//       [11] = {{1, 1}, {_Complex_I, -_Complex_I}, {1, -1}, {_Complex_I, -_Complex_I}},
//       // Index 12: [1,1; -1,1; j,-j; j,-j]
//       [12] = {{1, 1}, {-1, 1}, {_Complex_I, -_Complex_I}, {_Complex_I, -_Complex_I}},
//       // Index 13: [1,1; -j,j; j,-j; 1,-1]
//       [13] = {{1, 1}, {-_Complex_I, _Complex_I}, {_Complex_I, -_Complex_I}, {1, -1}},
//       // Index 14: [1,1; 1,-1; j,-j; 1,-1]
//       [14] = {{1, 1}, {1, -1}, {_Complex_I, -_Complex_I}, {1, -1}},
//       // Index 15: [1,1; j,-j; j,-j; -1,1]
//       [15] = {{1, 1}, {_Complex_I, -_Complex_I}, {_Complex_I, -_Complex_I}, {-1, 1}},
// };
#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h02i = srsran_simd_cfi_load(&h[0][2][i]);
    simd_cf_t h03i = srsran_simd_cfi_load(&h[0][3][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);
    simd_cf_t h12i = srsran_simd_cfi_load(&h[1][2][i]);
    simd_cf_t h13i = srsran_simd_cfi_load(&h[1][3][i]);

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t h00, h01, h10, h11;

    switch (codebook_idx) {
      case 0:
        h00 = srsran_simd_cf_add(h00i, h02i);
        h01 = srsran_simd_cf_sub(h01i, h03i);
        h10 = srsran_simd_cf_add(h10i, h12i);
        h11 = srsran_simd_cf_sub(h11i, h13i);
        break;
      case 1:
        h00 = srsran_simd_cf_add(h00i, h02i);
        h01 = srsran_simd_cf_add(h01i, h03i);
        h10 = srsran_simd_cf_add(h10i, h12i);
        h11 = srsran_simd_cf_add(h11i, h13i);
        break;
      case 2:
        h00 = srsran_simd_cf_sub(h00i, h02i);
        h01 = srsran_simd_cf_add(h01i, h03i);
        h10 = srsran_simd_cf_sub(h10i, h12i);
        h11 = srsran_simd_cf_add(h11i, h13i);
        break;
      case 3:
        h00 = srsran_simd_cf_sub(h00i, h02i);
        h01 = srsran_simd_cf_sub(h01i, h03i);
        h10 = srsran_simd_cf_sub(h10i, h12i);
        h11 = srsran_simd_cf_sub(h11i, h13i);
        break;
      case 4:
        h00 = srsran_simd_cf_add(h00i, h03i);
        h01 = srsran_simd_cf_sub(h01i, h02i);
        h10 = srsran_simd_cf_add(h10i, h13i);
        h11 = srsran_simd_cf_sub(h11i, h12i);
        break;
      case 5:
        h00 = srsran_simd_cf_add(h00i, h03i);
        h01 = srsran_simd_cf_add(h01i, h02i);
        h10 = srsran_simd_cf_add(h10i, h13i);
        h11 = srsran_simd_cf_add(h11i, h12i);
        break;
      case 6:
        h00 = srsran_simd_cf_sub(h00i, h03i);
        h01 = srsran_simd_cf_add(h01i, h02i);
        h10 = srsran_simd_cf_sub(h10i, h13i);
        h11 = srsran_simd_cf_add(h11i, h12i);
        break;
      case 7:
        h00 = srsran_simd_cf_sub(h00i, h03i);
        h01 = srsran_simd_cf_sub(h01i, h02i);
        h10 = srsran_simd_cf_sub(h10i, h13i);
        h11 = srsran_simd_cf_sub(h11i, h12i);
        break;
      case 8:
        h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_mulj(h02i));
        h01 = srsran_simd_cf_add(h01i, srsran_simd_cf_mulj(h03i));
        h10 = srsran_simd_cf_add(h10i, srsran_simd_cf_mulj(h12i));
        h11 = srsran_simd_cf_add(h11i, srsran_simd_cf_mulj(h13i));
        break;
      case 9:
        h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_mulj(h02i));
        h01 = srsran_simd_cf_sub(h01i, srsran_simd_cf_mulj(h03i));
        h10 = srsran_simd_cf_add(h10i, srsran_simd_cf_mulj(h12i));
        h11 = srsran_simd_cf_sub(h11i, srsran_simd_cf_mulj(h13i));
        break;
      case 10:
        h00 = srsran_simd_cf_sub(h00i, srsran_simd_cf_mulj(h02i));
        h01 = srsran_simd_cf_add(h01i, srsran_simd_cf_mulj(h03i));
        h10 = srsran_simd_cf_sub(h10i, srsran_simd_cf_mulj(h12i));
        h11 = srsran_simd_cf_add(h11i, srsran_simd_cf_mulj(h13i));
        break;
      case 11:
        h00 = srsran_simd_cf_sub(h00i, srsran_simd_cf_mulj(h02i));
        h01 = srsran_simd_cf_sub(h01i, srsran_simd_cf_mulj(h03i));
        h10 = srsran_simd_cf_sub(h10i, srsran_simd_cf_mulj(h12i));
        h11 = srsran_simd_cf_sub(h11i, srsran_simd_cf_mulj(h13i));
        break;
      case 12:
        h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_mulj(h03i));
        h01 = srsran_simd_cf_add(h01i, srsran_simd_cf_mulj(h02i));
        h10 = srsran_simd_cf_add(h10i, srsran_simd_cf_mulj(h13i));
        h11 = srsran_simd_cf_add(h11i, srsran_simd_cf_mulj(h12i));
        break;
      case 13:
        h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_mulj(h03i));
        h01 = srsran_simd_cf_sub(h01i, srsran_simd_cf_mulj(h02i));
        h10 = srsran_simd_cf_add(h10i, srsran_simd_cf_mulj(h13i));
        h11 = srsran_simd_cf_sub(h11i, srsran_simd_cf_mulj(h12i));
        break;
      case 14:
        h00 = srsran_simd_cf_sub(h00i, srsran_simd_cf_mulj(h03i));
        h01 = srsran_simd_cf_add(h01i, srsran_simd_cf_mulj(h02i));
        h10 = srsran_simd_cf_sub(h10i, srsran_simd_cf_mulj(h13i));
        h11 = srsran_simd_cf_add(h11i, srsran_simd_cf_mulj(h12i));
        break;
      case 15:
        h00 = srsran_simd_cf_sub(h00i, srsran_simd_cf_mulj(h03i));
        h01 = srsran_simd_cf_sub(h01i, srsran_simd_cf_mulj(h02i));
        h10 = srsran_simd_cf_sub(h10i, srsran_simd_cf_mulj(h13i));
        h11 = srsran_simd_cf_sub(h11i, srsran_simd_cf_mulj(h12i));
        break;
      default:
        ERROR("Invalid codebook index %d for dual layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t x0, x1;
    simd_f_t csi0, csi1;
    srsran_mat_2x2_mmse_csi_simd(y0, y1, h00, h01, h10, h11,
                                 &x0, &x1, &csi0, &csi1, noise_estimate, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);
    srsran_simd_f_store(&csi[0][i], csi0);
    srsran_simd_f_store(&csi[1][i], csi1);
  }
#endif


// Debug: Check input signal power
  // if (debug_count < 5) {
  //   float y0_pwr = 0, y1_pwr = 0;
  //   float h_pwr[4][2] = {{0}};

  //   for (int i = 0; i < nof_symbols && i < 100; i++) {
  //     y0_pwr += crealf(y[0][i]) * crealf(y[0][i]) + cimagf(y[0][i]) * cimagf(y[0][i]);
  //     y1_pwr += crealf(y[1][i]) * crealf(y[1][i]) + cimagf(y[1][i]) * cimagf(y[1][i]);

  //     for (int p = 0; p < 4; p++) {
  //       for (int r = 0; r < 2; r++) {
  //         h_pwr[p][r] += crealf(h[p][r][i]) * crealf(h[p][r][i]) +
  //                        cimagf(h[p][r][i]) * cimagf(h[p][r][i]);
  //       }
  //     }
  //   }

  //   int n = (nof_symbols < 100) ? nof_symbols : 100;
  //   printf("\n=== 4x2 TM4 Debug (codebook=%d, nsym=%d, scale=%.3f, noise=%.6f) ===\n",
  //          codebook_idx, nof_symbols, scaling, noise_estimate);
  //   printf("Y power: y0=%.2f, y1=%.2f\n", y0_pwr/n, y1_pwr/n);
  //   printf("H power [port][rx]:\n");
  //   printf("  Port0: rx0=%.3f rx1=%.3f\n", h_pwr[0][0]/n, h_pwr[0][1]/n);
  //   printf("  Port1: rx0=%.3f rx1=%.3f\n", h_pwr[1][0]/n, h_pwr[1][1]/n);
  //   printf("  Port2: rx0=%.3f rx1=%.3f\n", h_pwr[2][0]/n, h_pwr[2][1]/n);
  //   printf("  Port3: rx0=%.3f rx1=%.3f\n", h_pwr[3][0]/n, h_pwr[3][1]/n);

  //   // Check if ports 2,3 have valid data (non-zero)
  //   if (h_pwr[2][0]/n < 0.001 && h_pwr[2][1]/n < 0.001) {
  //     printf("WARNING: Port 2 has no power - CE may not be extracted!\n");
  //   }
  //   if (h_pwr[3][0]/n < 0.001 && h_pwr[3][1]/n < 0.001) {
  //     printf("WARNING: Port 3 has no power - CE may not be extracted!\n");
  //   }
  // }

  // 4-port rank-2 codebook from 36.211 Table 6.3.4.2.3-2
  static const cf_t W[16][4][2] = {
    [0]  = {{1, 1}, {-1, 1}, {-1, 1}, {-1, 1}},
    [1]  = {{1, 1}, {-_Complex_I, _Complex_I}, {-1, 1}, {_Complex_I, -_Complex_I}},
    [2]  = {{1, 1}, {1, -1}, {-1, 1}, {1, -1}},
    [3]  = {{1, 1}, {_Complex_I, -_Complex_I}, {-1, 1}, {-_Complex_I, _Complex_I}},
    [4]  = {{1, 1}, {-1, 1}, {-_Complex_I, _Complex_I}, {-_Complex_I, _Complex_I}},
    [5]  = {{1, 1}, {-_Complex_I, _Complex_I}, {-_Complex_I, _Complex_I}, {-1, 1}},
    [6]  = {{1, 1}, {1, -1}, {-_Complex_I, _Complex_I}, {-1, 1}},
    [7]  = {{1, 1}, {_Complex_I, -_Complex_I}, {-_Complex_I, _Complex_I}, {1, -1}},
    [8]  = {{1, 1}, {-1, 1}, {1, -1}, {1, -1}},
    [9]  = {{1, 1}, {-_Complex_I, _Complex_I}, {1, -1}, {-_Complex_I, _Complex_I}},
    [10] = {{1, 1}, {1, -1}, {1, -1}, {-1, 1}},
    [11] = {{1, 1}, {_Complex_I, -_Complex_I}, {1, -1}, {_Complex_I, -_Complex_I}},
    [12] = {{1, 1}, {-1, 1}, {_Complex_I, -_Complex_I}, {_Complex_I, -_Complex_I}},
    [13] = {{1, 1}, {-_Complex_I, _Complex_I}, {_Complex_I, -_Complex_I}, {1, -1}},
    [14] = {{1, 1}, {1, -1}, {_Complex_I, -_Complex_I}, {1, -1}},
    [15] = {{1, 1}, {_Complex_I, -_Complex_I}, {_Complex_I, -_Complex_I}, {-1, 1}},
  };

  const cf_t (*Wn)[2] = W[codebook_idx];
  // float norm = 0.5f / scaling;

  // Statistics for output
  float x0_pwr = 0, x1_pwr = 0;
  float x0_mag_sum = 0, x1_mag_sum = 0;
  int qpsk_like_0 = 0, qpsk_like_1 = 0;

  for (int i = 0; i < nof_symbols; i++) {
    // Channel: h[port][rx][i]
    cf_t h0r0 = h[0][0][i], h1r0 = h[1][0][i], h2r0 = h[2][0][i], h3r0 = h[3][0][i];
    cf_t h0r1 = h[0][1][i], h1r1 = h[1][1][i], h2r1 = h[2][1][i], h3r1 = h[3][1][i];

    // H_eff = H * W  (2x2)
    // H_eff[rx][layer] = sum_port( h[port][rx] * W[port][layer] )
    cf_t H00 = h0r0*Wn[0][0] + h1r0*Wn[1][0] + h2r0*Wn[2][0] + h3r0*Wn[3][0];
    cf_t H01 = h0r0*Wn[0][1] + h1r0*Wn[1][1] + h2r0*Wn[2][1] + h3r0*Wn[3][1];
    cf_t H10 = h0r1*Wn[0][0] + h1r1*Wn[1][0] + h2r1*Wn[2][0] + h3r1*Wn[3][0];
    cf_t H11 = h0r1*Wn[0][1] + h1r1*Wn[1][1] + h2r1*Wn[2][1] + h3r1*Wn[3][1];

    // MMSE equalization
    srsran_mat_2x2_mmse_csi_gen(y[0][i], y[1][i], H00, H01, H10, H11,
                                &x[0][i], &x[1][i], &csi[0][i], &csi[1][i],
                                noise_estimate, norm);

    // Collect stats
    float mag0 = cabsf(x[0][i]);
    float mag1 = cabsf(x[1][i]);
    x0_pwr += mag0 * mag0;
    x1_pwr += mag1 * mag1;
    x0_mag_sum += mag0;
    x1_mag_sum += mag1;

    // Check if QPSK-like (magnitude near 1/sqrt(2) ≈ 0.707)
    if (mag0 > 0.4f && mag0 < 1.2f) qpsk_like_0++;
    if (mag1 > 0.4f && mag1 < 1.2f) qpsk_like_1++;
  }

  if (debug_count < 5) {
    printf("Output stats:\n");
    printf("  Layer0: avg_mag=%.3f, pwr=%.3f, QPSK-like=%d/%d (%.1f%%)\n",
           x0_mag_sum/nof_symbols, x0_pwr/nof_symbols,
           qpsk_like_0, nof_symbols, 100.0f*qpsk_like_0/nof_symbols);
    printf("  Layer1: avg_mag=%.3f, pwr=%.3f, QPSK-like=%d/%d (%.1f%%)\n",
           x1_mag_sum/nof_symbols, x1_pwr/nof_symbols,
           qpsk_like_1, nof_symbols, 100.0f*qpsk_like_1/nof_symbols);

    // Print first few symbols
    printf("First 4 equalized symbols:\n");
    for (int i = 0; i < 4 && i < nof_symbols; i++) {
      printf("  [%d] x0=(%+.3f,%+.3f) mag=%.3f, x1=(%+.3f,%+.3f) mag=%.3f\n",
             i, crealf(x[0][i]), cimagf(x[0][i]), cabsf(x[0][i]),
             crealf(x[1][i]), cimagf(x[1][i]), cabsf(x[1][i]));
    }

    debug_count++;
  }

  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_multiplex_2x2_mmse(cf_t* y[SRSRAN_MAX_PORTS],
                                                 cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                 cf_t* x[SRSRAN_MAX_LAYERS],
                                                 int   codebook_idx,
                                                 int   nof_symbols,
                                                 float scaling,
                                                 float noise_estimate)
{
  float norm = 1.0;
  int   i    = 0;

  switch (codebook_idx) {
    case 0:
      norm = (float)M_SQRT2 / scaling;
      break;
    case 1:
    case 2:
      norm = 2.0f / scaling;
      break;
    default:
      ERROR("Wrong codebook_idx=%d", codebook_idx);
      return SRSRAN_ERROR;
  }

#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00i = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01i = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h10i = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11i = srsran_simd_cfi_load(&h[1][1][i]);

    simd_cf_t h00, h01, h10, h11;
    switch (codebook_idx) {
      case 0:
        h00 = h00i;
        h01 = h10i;
        h10 = h01i;
        h11 = h11i;
        break;
      case 1:
        h00 = srsran_simd_cf_add(h00i, h10i);
        h01 = srsran_simd_cf_sub(h00i, h10i);
        h10 = srsran_simd_cf_add(h01i, h11i);
        h11 = srsran_simd_cf_sub(h01i, h11i);
        break;
      case 2:
        h00 = srsran_simd_cf_add(h00i, srsran_simd_cf_mulj(h10i));
        h01 = srsran_simd_cf_sub(h00i, srsran_simd_cf_mulj(h10i));
        h10 = srsran_simd_cf_add(h01i, srsran_simd_cf_mulj(h11i));
        h11 = srsran_simd_cf_sub(h01i, srsran_simd_cf_mulj(h11i));
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t x0, x1;
    simd_f_t  csi0, csi1;
    srsran_mat_2x2_mmse_csi_simd(y0, y1, h00, h01, h10, h11, &x0, &x1, &csi0, &csi1, noise_estimate, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);
  }
#endif /* SRSRAN_SIMD_CF_SIZE */

  for (; i < nof_symbols; i++) {
    cf_t h00, h01, h10, h11;

    switch (codebook_idx) {
      case 0:
        h00 = h[0][0][i];
        h01 = h[1][0][i];
        h10 = h[0][1][i];
        h11 = h[1][1][i];
        break;
      case 1:
        h00 = h[0][0][i] + h[1][0][i];
        h01 = h[0][0][i] - h[1][0][i];
        h10 = h[0][1][i] + h[1][1][i];
        h11 = h[0][1][i] - h[1][1][i];
        break;
      case 2:
        h00 = h[0][0][i] + _Complex_I * h[1][0][i];
        h01 = h[0][0][i] - _Complex_I * h[1][0][i];
        h10 = h[0][1][i] + _Complex_I * h[1][1][i];
        h11 = h[0][1][i] - _Complex_I * h[1][1][i];
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    srsran_mat_2x2_mmse_gen(y[0][i], y[1][i], h00, h01, h10, h11, &x[0][i], &x[1][i], noise_estimate, norm);
  }
  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_multiplex_4x1_mmse(cf_t*  y[SRSRAN_MAX_PORTS],
                                                 cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                 cf_t*  x[SRSRAN_MAX_LAYERS],
                                                 int    codebook_idx,
                                                 int    nof_symbols,
                                                 float  scaling,
                                                 float  noise_estimate)
{
  float norm = 0.5f / scaling;

  int i = 0;

#if SRSRAN_SIMD_CF_SIZE != 0
  simd_f_t noise_simd = srsran_simd_f_set1(noise_estimate);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00 = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01 = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h02 = srsran_simd_cfi_load(&h[0][2][i]);
    simd_cf_t h03 = srsran_simd_cfi_load(&h[0][3][i]);
    simd_cf_t h10 = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11 = srsran_simd_cfi_load(&h[1][1][i]);
    simd_cf_t h12 = srsran_simd_cfi_load(&h[1][2][i]);
    simd_cf_t h13 = srsran_simd_cfi_load(&h[1][3][i]);

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t h_eff0, h_eff1;

    switch (codebook_idx) {
      case 0:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h01), srsran_simd_cf_add(h02, h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h11), srsran_simd_cf_add(h12, h13));
        break;
      case 1:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_add(h02, h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_add(h12, h13)));
        break;
      case 2:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h01), srsran_simd_cf_add(h02, h03));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h11), srsran_simd_cf_add(h12, h13));
        break;
      case 3:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_add(h02, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_add(h12, h13)));
        break;
      case 4:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_add(h02, srsran_simd_cf_mulj(h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_add(h12, srsran_simd_cf_mulj(h13)));
        break;
      case 5:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_sub(srsran_simd_cf_mulj(h02), h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_sub(srsran_simd_cf_mulj(h12), h13));
        break;
      case 6:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h01)), srsran_simd_cf_add(h02, srsran_simd_cf_mulj(h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h11)), srsran_simd_cf_add(h12, srsran_simd_cf_mulj(h13)));
        break;
      case 7:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h02)), srsran_simd_cf_add(srsran_simd_cf_mulj(h01), h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h12)), srsran_simd_cf_add(srsran_simd_cf_mulj(h11), h13));
        break;
      case 8:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_sub(h02, h03));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_sub(h12, h13));
        break;
      case 9:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_sub(h02, h03)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_sub(h12, h13)));
        break;
      case 10:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_sub(h02, h03));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_sub(h12, h13));
        break;
      case 11:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h01), srsran_simd_cf_mulj(srsran_simd_cf_sub(h02, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h11), srsran_simd_cf_mulj(srsran_simd_cf_sub(h12, h13)));
        break;
      case 12:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_add(h00, h02), srsran_simd_cf_mulj(srsran_simd_cf_add(h01, h03)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_add(h10, h12), srsran_simd_cf_mulj(srsran_simd_cf_add(h11, h13)));
        break;
      case 13:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_add(h00, h03), srsran_simd_cf_sub(srsran_simd_cf_mulj(h02), srsran_simd_cf_mulj(h01)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_add(h10, h13), srsran_simd_cf_sub(srsran_simd_cf_mulj(h12), srsran_simd_cf_mulj(h11)));
        break;
      case 14:
        h_eff0 = srsran_simd_cf_add(srsran_simd_cf_sub(h00, h02), srsran_simd_cf_mulj(srsran_simd_cf_sub(h03, h01)));
        h_eff1 = srsran_simd_cf_add(srsran_simd_cf_sub(h10, h12), srsran_simd_cf_mulj(srsran_simd_cf_sub(h13, h11)));
        break;
      case 15:
        h_eff0 = srsran_simd_cf_sub(srsran_simd_cf_sub(h00, h03), srsran_simd_cf_mulj(srsran_simd_cf_add(h01, h02)));
        h_eff1 = srsran_simd_cf_sub(srsran_simd_cf_sub(h10, h13), srsran_simd_cf_mulj(srsran_simd_cf_add(h11, h12)));
        break;
      default:
        ERROR("Invalid codebook index %d for single layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t h_eff0_conj = srsran_simd_cf_conj(h_eff0);
    simd_cf_t h_eff1_conj = srsran_simd_cf_conj(h_eff1);

    simd_cf_t numer = srsran_simd_cf_add(srsran_simd_cf_prod(h_eff0_conj, y0),
                                          srsran_simd_cf_prod(h_eff1_conj, y1));

    simd_f_t h_eff0_sq = srsran_simd_cf_re(srsran_simd_cf_prod(h_eff0, h_eff0_conj));
    simd_f_t h_eff1_sq = srsran_simd_cf_re(srsran_simd_cf_prod(h_eff1, h_eff1_conj));
    simd_f_t chan_pwr = srsran_simd_f_add(h_eff0_sq, h_eff1_sq);
    simd_f_t denom = srsran_simd_f_add(chan_pwr, noise_simd);

    simd_f_t inv_denom = srsran_simd_f_rcp(denom);
    simd_f_t inv_denom_norm = srsran_simd_f_mul(inv_denom, srsran_simd_f_set1(norm));
    simd_cf_t x0 = srsran_simd_cf_mul(numer, inv_denom_norm);

    srsran_simd_cfi_store(&x[0][i], x0);
  }
#endif

  for (; i < nof_symbols; i++) {
    cf_t h00 = h[0][0][i], h01 = h[0][1][i], h02 = h[0][2][i], h03 = h[0][3][i];
    cf_t h10 = h[1][0][i], h11 = h[1][1][i], h12 = h[1][2][i], h13 = h[1][3][i];

    cf_t h_eff0, h_eff1;

    switch (codebook_idx) {
      case 0:  h_eff0 = h00 + h01 + h02 + h03;
               h_eff1 = h10 + h11 + h12 + h13; break;
      case 1:  h_eff0 = h00 + h01 + _Complex_I*(h02 + h03);
               h_eff1 = h10 + h11 + _Complex_I*(h12 + h13); break;
      case 2:  h_eff0 = h00 + h01 - h02 - h03;
               h_eff1 = h10 + h11 - h12 - h13; break;
      case 3:  h_eff0 = h00 + h01 - _Complex_I*(h02 + h03);
               h_eff1 = h10 + h11 - _Complex_I*(h12 + h13); break;
      case 4:  h_eff0 = h00 + _Complex_I*h01 + h02 + _Complex_I*h03;
               h_eff1 = h10 + _Complex_I*h11 + h12 + _Complex_I*h13; break;
      case 5:  h_eff0 = h00 + _Complex_I*h01 + _Complex_I*h02 - h03;
               h_eff1 = h10 + _Complex_I*h11 + _Complex_I*h12 - h13; break;
      case 6:  h_eff0 = h00 + _Complex_I*h01 - h02 - _Complex_I*h03;
               h_eff1 = h10 + _Complex_I*h11 - h12 - _Complex_I*h13; break;
      case 7:  h_eff0 = h00 + _Complex_I*h01 - _Complex_I*h02 + h03;
               h_eff1 = h10 + _Complex_I*h11 - _Complex_I*h12 + h13; break;
      case 8:  h_eff0 = h00 - h01 + h02 - h03;
               h_eff1 = h10 - h11 + h12 - h13; break;
      case 9:  h_eff0 = h00 - h01 + _Complex_I*(h02 - h03);
               h_eff1 = h10 - h11 + _Complex_I*(h12 - h13); break;
      case 10: h_eff0 = h00 - h01 - h02 + h03;
               h_eff1 = h10 - h11 - h12 + h13; break;
      case 11: h_eff0 = h00 - h01 - _Complex_I*(h02 - h03);
               h_eff1 = h10 - h11 - _Complex_I*(h12 - h13); break;
      case 12: h_eff0 = h00 - _Complex_I*h01 + h02 - _Complex_I*h03;
               h_eff1 = h10 - _Complex_I*h11 + h12 - _Complex_I*h13; break;
      case 13: h_eff0 = h00 - _Complex_I*h01 + _Complex_I*h02 + h03;
               h_eff1 = h10 - _Complex_I*h11 + _Complex_I*h12 + h13; break;
      case 14: h_eff0 = h00 - _Complex_I*h01 - h02 + _Complex_I*h03;
               h_eff1 = h10 - _Complex_I*h11 - h12 + _Complex_I*h13; break;
      case 15: h_eff0 = h00 - _Complex_I*h01 - _Complex_I*h02 - h03;
               h_eff1 = h10 - _Complex_I*h11 - _Complex_I*h12 - h13; break;
      default:
        ERROR("Invalid codebook index %d for single layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    float chan_pwr = crealf(h_eff0 * conjf(h_eff0)) + crealf(h_eff1 * conjf(h_eff1));
    float denom = chan_pwr + noise_estimate;

    cf_t numer = conjf(h_eff0) * y[0][i] + conjf(h_eff1) * y[1][i];
    x[0][i] = numer * norm / denom;
  }

  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_multiplex_4x2_mmse(cf_t*  y[SRSRAN_MAX_PORTS],
                                                 cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                 cf_t*  x[SRSRAN_MAX_LAYERS],
                                                 int    codebook_idx,
                                                 int    nof_symbols,
                                                 float  scaling,
                                                 float  noise_estimate)
{
  float norm = 0.5f / scaling;

  int i = 0;

  // printf("Processing 4x2 multiplexing MIMO with codebook_idx=%d, nof_symbols=%d, scaling=%.02f, noise_estimate=%.02f\n", codebook_idx, nof_symbols, scaling, noise_estimate);


#if SRSRAN_SIMD_CF_SIZE != 0
  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t h00 = srsran_simd_cfi_load(&h[0][0][i]);
    simd_cf_t h01 = srsran_simd_cfi_load(&h[0][1][i]);
    simd_cf_t h02 = srsran_simd_cfi_load(&h[0][2][i]);
    simd_cf_t h03 = srsran_simd_cfi_load(&h[0][3][i]);
    simd_cf_t h10 = srsran_simd_cfi_load(&h[1][0][i]);
    simd_cf_t h11 = srsran_simd_cfi_load(&h[1][1][i]);
    simd_cf_t h12 = srsran_simd_cfi_load(&h[1][2][i]);
    simd_cf_t h13 = srsran_simd_cfi_load(&h[1][3][i]);

    simd_cf_t y0 = srsran_simd_cfi_load(&y[0][i]);
    simd_cf_t y1 = srsran_simd_cfi_load(&y[1][i]);

    simd_cf_t h_eff00, h_eff01, h_eff10, h_eff11;

    switch (codebook_idx) {
      case 0:
        h_eff00 = srsran_simd_cf_add(h00, h02);
        h_eff01 = srsran_simd_cf_sub(h01, h03);
        h_eff10 = srsran_simd_cf_add(h10, h12);
        h_eff11 = srsran_simd_cf_sub(h11, h13);
        break;
      case 1:
        h_eff00 = srsran_simd_cf_add(h00, h02);
        h_eff01 = srsran_simd_cf_add(h01, h03);
        h_eff10 = srsran_simd_cf_add(h10, h12);
        h_eff11 = srsran_simd_cf_add(h11, h13);
        break;
      case 2:
        h_eff00 = srsran_simd_cf_sub(h00, h02);
        h_eff01 = srsran_simd_cf_add(h01, h03);
        h_eff10 = srsran_simd_cf_sub(h10, h12);
        h_eff11 = srsran_simd_cf_add(h11, h13);
        break;
      case 3:
        h_eff00 = srsran_simd_cf_sub(h00, h02);
        h_eff01 = srsran_simd_cf_sub(h01, h03);
        h_eff10 = srsran_simd_cf_sub(h10, h12);
        h_eff11 = srsran_simd_cf_sub(h11, h13);
        break;
      case 4:
        h_eff00 = srsran_simd_cf_add(h00, h03);
        h_eff01 = srsran_simd_cf_sub(h01, h02);
        h_eff10 = srsran_simd_cf_add(h10, h13);
        h_eff11 = srsran_simd_cf_sub(h11, h12);
        break;
      case 5:
        h_eff00 = srsran_simd_cf_add(h00, h03);
        h_eff01 = srsran_simd_cf_add(h01, h02);
        h_eff10 = srsran_simd_cf_add(h10, h13);
        h_eff11 = srsran_simd_cf_add(h11, h12);
        break;
      case 6:
        h_eff00 = srsran_simd_cf_sub(h00, h03);
        h_eff01 = srsran_simd_cf_add(h01, h02);
        h_eff10 = srsran_simd_cf_sub(h10, h13);
        h_eff11 = srsran_simd_cf_add(h11, h12);
        break;
      case 7:
        h_eff00 = srsran_simd_cf_sub(h00, h03);
        h_eff01 = srsran_simd_cf_sub(h01, h02);
        h_eff10 = srsran_simd_cf_sub(h10, h13);
        h_eff11 = srsran_simd_cf_sub(h11, h12);
        break;
      case 8:
        h_eff00 = srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h02));
        h_eff01 = srsran_simd_cf_add(h01, srsran_simd_cf_mulj(h03));
        h_eff10 = srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h12));
        h_eff11 = srsran_simd_cf_add(h11, srsran_simd_cf_mulj(h13));
        break;
      case 9:
        h_eff00 = srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h02));
        h_eff01 = srsran_simd_cf_sub(h01, srsran_simd_cf_mulj(h03));
        h_eff10 = srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h12));
        h_eff11 = srsran_simd_cf_sub(h11, srsran_simd_cf_mulj(h13));
        break;
      case 10:
        h_eff00 = srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h02));
        h_eff01 = srsran_simd_cf_add(h01, srsran_simd_cf_mulj(h03));
        h_eff10 = srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h12));
        h_eff11 = srsran_simd_cf_add(h11, srsran_simd_cf_mulj(h13));
        break;
      case 11:
        h_eff00 = srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h02));
        h_eff01 = srsran_simd_cf_sub(h01, srsran_simd_cf_mulj(h03));
        h_eff10 = srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h12));
        h_eff11 = srsran_simd_cf_sub(h11, srsran_simd_cf_mulj(h13));
        break;
      case 12:
        h_eff00 = srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h03));
        h_eff01 = srsran_simd_cf_add(h01, srsran_simd_cf_mulj(h02));
        h_eff10 = srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h13));
        h_eff11 = srsran_simd_cf_add(h11, srsran_simd_cf_mulj(h12));
        break;
      case 13:
        h_eff00 = srsran_simd_cf_add(h00, srsran_simd_cf_mulj(h03));
        h_eff01 = srsran_simd_cf_sub(h01, srsran_simd_cf_mulj(h02));
        h_eff10 = srsran_simd_cf_add(h10, srsran_simd_cf_mulj(h13));
        h_eff11 = srsran_simd_cf_sub(h11, srsran_simd_cf_mulj(h12));
        break;
      case 14:
        h_eff00 = srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h03));
        h_eff01 = srsran_simd_cf_add(h01, srsran_simd_cf_mulj(h02));
        h_eff10 = srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h13));
        h_eff11 = srsran_simd_cf_add(h11, srsran_simd_cf_mulj(h12));
        break;
      case 15:
        h_eff00 = srsran_simd_cf_sub(h00, srsran_simd_cf_mulj(h03));
        h_eff01 = srsran_simd_cf_sub(h01, srsran_simd_cf_mulj(h02));
        h_eff10 = srsran_simd_cf_sub(h10, srsran_simd_cf_mulj(h13));
        h_eff11 = srsran_simd_cf_sub(h11, srsran_simd_cf_mulj(h12));
        break;
      default:
        ERROR("Invalid codebook index %d for dual layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    simd_cf_t x0, x1;
    srsran_mat_2x2_mmse_simd(y0, y1, h_eff00, h_eff01, h_eff10, h_eff11,
                             &x0, &x1, noise_estimate, norm);

    srsran_simd_cfi_store(&x[0][i], x0);
    srsran_simd_cfi_store(&x[1][i], x1);
  }
#endif

  for (; i < nof_symbols; i++) {
    cf_t h00 = h[0][0][i], h01 = h[0][1][i], h02 = h[0][2][i], h03 = h[0][3][i];
    cf_t h10 = h[1][0][i], h11 = h[1][1][i], h12 = h[1][2][i], h13 = h[1][3][i];

    cf_t h_eff00, h_eff01, h_eff10, h_eff11;

    switch (codebook_idx) {
      case 0:
        h_eff00 = h00 + h02;           h_eff01 = h01 - h03;
        h_eff10 = h10 + h12;           h_eff11 = h11 - h13;
        break;
      case 1:
        h_eff00 = h00 + h02;           h_eff01 = h01 + h03;
        h_eff10 = h10 + h12;           h_eff11 = h11 + h13;
        break;
      case 2:
        h_eff00 = h00 - h02;           h_eff01 = h01 + h03;
        h_eff10 = h10 - h12;           h_eff11 = h11 + h13;
        break;
      case 3:
        h_eff00 = h00 - h02;           h_eff01 = h01 - h03;
        h_eff10 = h10 - h12;           h_eff11 = h11 - h13;
        break;
      case 4:
        h_eff00 = h00 + h03;           h_eff01 = h01 - h02;
        h_eff10 = h10 + h13;           h_eff11 = h11 - h12;
        break;
      case 5:
        h_eff00 = h00 + h03;           h_eff01 = h01 + h02;
        h_eff10 = h10 + h13;           h_eff11 = h11 + h12;
        break;
      case 6:
        h_eff00 = h00 - h03;           h_eff01 = h01 + h02;
        h_eff10 = h10 - h13;           h_eff11 = h11 + h12;
        break;
      case 7:
        h_eff00 = h00 - h03;           h_eff01 = h01 - h02;
        h_eff10 = h10 - h13;           h_eff11 = h11 - h12;
        break;
      case 8:
        h_eff00 = h00 + _Complex_I*h02; h_eff01 = h01 + _Complex_I*h03;
        h_eff10 = h10 + _Complex_I*h12; h_eff11 = h11 + _Complex_I*h13;
        break;
      case 9:
        h_eff00 = h00 + _Complex_I*h02; h_eff01 = h01 - _Complex_I*h03;
        h_eff10 = h10 + _Complex_I*h12; h_eff11 = h11 - _Complex_I*h13;
        break;
      case 10:
        h_eff00 = h00 - _Complex_I*h02; h_eff01 = h01 + _Complex_I*h03;
        h_eff10 = h10 - _Complex_I*h12; h_eff11 = h11 + _Complex_I*h13;
        break;
      case 11:
        h_eff00 = h00 - _Complex_I*h02; h_eff01 = h01 - _Complex_I*h03;
        h_eff10 = h10 - _Complex_I*h12; h_eff11 = h11 - _Complex_I*h13;
        break;
      case 12:
        h_eff00 = h00 + _Complex_I*h03; h_eff01 = h01 + _Complex_I*h02;
        h_eff10 = h10 + _Complex_I*h13; h_eff11 = h11 + _Complex_I*h12;
        break;
      case 13:
        h_eff00 = h00 + _Complex_I*h03; h_eff01 = h01 - _Complex_I*h02;
        h_eff10 = h10 + _Complex_I*h13; h_eff11 = h11 - _Complex_I*h12;
        break;
      case 14:
        h_eff00 = h00 - _Complex_I*h03; h_eff01 = h01 + _Complex_I*h02;
        h_eff10 = h10 - _Complex_I*h13; h_eff11 = h11 + _Complex_I*h12;
        break;
      case 15:
        h_eff00 = h00 - _Complex_I*h03; h_eff01 = h01 - _Complex_I*h02;
        h_eff10 = h10 - _Complex_I*h13; h_eff11 = h11 - _Complex_I*h12;
        break;
      default:
        ERROR("Invalid codebook index %d for dual layer 4-antenna", codebook_idx);
        return SRSRAN_ERROR;
    }

    srsran_mat_2x2_mmse_gen(y[0][i], y[1][i], h_eff00, h_eff01, h_eff10, h_eff11,
                            &x[0][i], &x[1][i], noise_estimate, norm);
  }

  return SRSRAN_SUCCESS;
}

// Implementation of MRC 2x1 (two antennas into one layer) Spatial Multiplexing equalizer
static int srsran_predecoding_multiplex_2x1_mrc(cf_t* y[SRSRAN_MAX_PORTS],
                                                cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                cf_t* x[SRSRAN_MAX_LAYERS],
                                                int   codebook_idx,
                                                int   nof_symbols,
                                                float scaling)
{
  float norm = (float)M_SQRT2 / scaling;
  int   i    = 0;

#if SRSRAN_SIMD_CF_SIZE != 0
  simd_f_t _norm = srsran_simd_f_set1(norm);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t x0 = srsran_simd_cf_set1(0.0f);
    simd_f_t  hh = srsran_simd_f_set1(0.0f);

    for (int k = 0; k < 2; k++) {
      simd_cf_t h0xi = srsran_simd_cfi_load(&h[0][k][i]);
      simd_cf_t h1xi = srsran_simd_cfi_load(&h[1][k][i]);
      simd_cf_t yx   = srsran_simd_cfi_load(&y[k][i]);

      simd_cf_t hx;
      switch (codebook_idx) {
        case 0:
          hx = srsran_simd_cf_add(h0xi, h1xi);
          break;
        case 1:
          hx = srsran_simd_cf_sub(h0xi, h1xi);
          break;
        case 2:
          hx = srsran_simd_cf_add(h0xi, srsran_simd_cf_mulj(h1xi));
          break;
        case 3:
          hx = srsran_simd_cf_sub(h0xi, srsran_simd_cf_mulj(h1xi));
          break;
        default:
          ERROR("Wrong codebook_idx=%d", codebook_idx);
          return SRSRAN_ERROR;
      }

      hh = srsran_simd_f_add(srsran_simd_cf_re(srsran_simd_cf_conjprod(hx, hx)), hh);
      x0 = srsran_simd_cf_add(srsran_simd_cf_conjprod(yx, hx), x0);
    }

    hh = srsran_simd_f_mul(_norm, srsran_simd_f_rcp(hh));
    srsran_simd_cfi_store(&x[0][i], srsran_simd_cf_mul(x0, hh));
  }
#endif /* SRSRAN_SIMD_CF_SIZE */

  for (; i < nof_symbols; i += 1) {
    cf_t  h0, h1;
    float hh;

    switch (codebook_idx) {
      case 0:
        h0 = h[0][0][i] + h[1][0][i];
        h1 = h[0][1][i] + h[1][1][i];
        break;
      case 1:
        h0 = h[0][0][i] - h[1][0][i];
        h1 = h[0][1][i] - h[1][1][i];
        break;
      case 2:
        h0 = h[0][0][i] + _Complex_I * h[1][0][i];
        h1 = h[0][1][i] + _Complex_I * h[1][1][i];
        break;
      case 3:
        h0 = h[0][0][i] - _Complex_I * h[1][0][i];
        h1 = h[0][1][i] - _Complex_I * h[1][1][i];
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    hh = norm / (crealf(h0) * crealf(h0) + cimagf(h0) * cimagf(h0) + crealf(h1) * crealf(h1) + cimagf(h1) * cimagf(h1));

    x[0][i] = (conjf(h0) * y[0][i] + conjf(h1) * y[1][i]) * hh;
  }
  return SRSRAN_SUCCESS;
}

// Generic implementation of MRC 2x1 (two antennas into one layer) Spatial Multiplexing equalizer
static int srsran_predecoding_multiplex_2x1_mrc_csi(cf_t*  y[SRSRAN_MAX_PORTS],
                                                    cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                                    cf_t*  x[SRSRAN_MAX_LAYERS],
                                                    float* csi,
                                                    int    codebook_idx,
                                                    int    nof_symbols,
                                                    float  scaling)
{
  float norm = (float)M_SQRT2 / scaling;
  int   i    = 0;

#if SRSRAN_SIMD_CF_SIZE != 0
  simd_f_t _norm = srsran_simd_f_set1(norm);

  for (; i < nof_symbols - SRSRAN_SIMD_CF_SIZE + 1; i += SRSRAN_SIMD_CF_SIZE) {
    simd_cf_t x0 = srsran_simd_cf_set1(0.0f);
    simd_f_t  hh = srsran_simd_f_set1(0.0f);

    for (int k = 0; k < 2; k++) {
      simd_cf_t h0xi = srsran_simd_cfi_load(&h[0][k][i]);
      simd_cf_t h1xi = srsran_simd_cfi_load(&h[1][k][i]);
      simd_cf_t yx   = srsran_simd_cfi_load(&y[k][i]);

      simd_cf_t hx;
      switch (codebook_idx) {
        case 0:
          hx = srsran_simd_cf_add(h0xi, h1xi);
          break;
        case 1:
          hx = srsran_simd_cf_sub(h0xi, h1xi);
          break;
        case 2:
          hx = srsran_simd_cf_add(h0xi, srsran_simd_cf_mulj(h1xi));
          break;
        case 3:
          hx = srsran_simd_cf_sub(h0xi, srsran_simd_cf_mulj(h1xi));
          break;
        default:
          ERROR("Wrong codebook_idx=%d", codebook_idx);
          return SRSRAN_ERROR;
      }

      hh = srsran_simd_f_add(srsran_simd_cf_re(srsran_simd_cf_conjprod(hx, hx)), hh);
      x0 = srsran_simd_cf_add(srsran_simd_cf_conjprod(yx, hx), x0);
    }

    hh = srsran_simd_f_mul(_norm, srsran_simd_f_rcp(hh));
    srsran_simd_cfi_store(&x[0][i], srsran_simd_cf_mul(x0, hh));
    srsran_simd_f_store(&csi[i], srsran_simd_f_mul(srsran_simd_f_rcp(hh), srsran_simd_f_set1((float)M_SQRT1_2)));
  }
#endif /* SRSRAN_SIMD_CF_SIZE */

  for (; i < nof_symbols; i += 1) {
    cf_t  h0, h1;
    float hh, _csi;

    switch (codebook_idx) {
      case 0:
        h0 = h[0][0][i] + h[1][0][i];
        h1 = h[0][1][i] + h[1][1][i];
        break;
      case 1:
        h0 = h[0][0][i] - h[1][0][i];
        h1 = h[0][1][i] - h[1][1][i];
        break;
      case 2:
        h0 = h[0][0][i] + _Complex_I * h[1][0][i];
        h1 = h[0][1][i] + _Complex_I * h[1][1][i];
        break;
      case 3:
        h0 = h[0][0][i] - _Complex_I * h[1][0][i];
        h1 = h[0][1][i] - _Complex_I * h[1][1][i];
        break;
      default:
        ERROR("Wrong codebook_idx=%d", codebook_idx);
        return SRSRAN_ERROR;
    }

    _csi = crealf(h0) * crealf(h0) + cimagf(h0) * cimagf(h0) + crealf(h1) * crealf(h1) + cimagf(h1) * cimagf(h1);
    hh   = norm / _csi;

    x[0][i] = (conjf(h0) * y[0][i] + conjf(h1) * y[1][i]) * hh;
    csi[i]  = _csi / norm * (float)M_SQRT1_2;
  }
  return SRSRAN_SUCCESS;
}

static int srsran_predecoding_multiplex(cf_t*  y[SRSRAN_MAX_PORTS],
                                        cf_t*  h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                        cf_t*  x[SRSRAN_MAX_LAYERS],
                                        float* csi[SRSRAN_MAX_CODEWORDS],
                                        int    nof_rxant,
                                        int    nof_ports,
                                        int    nof_layers,
                                        int    codebook_idx,
                                        int    nof_symbols,
                                        float  scaling,
                                        float  noise_estimate)
{
  if (nof_ports == 2 && nof_rxant <= 2) {
    if (nof_layers == 2) {
      switch (mimo_decoder) {
        case SRSRAN_MIMO_DECODER_ZF:
          if (csi && csi[0]) {
            return srsran_predecoding_multiplex_2x2_zf_csi(y, h, x, csi[0], codebook_idx, nof_symbols, scaling);
          } else {
            return srsran_predecoding_multiplex_2x2_zf(y, h, x, codebook_idx, nof_symbols, scaling);
          }
          break;
        case SRSRAN_MIMO_DECODER_MMSE:
          if (csi && csi[0]) {
            return srsran_predecoding_multiplex_2x2_mmse_csi(
                y, h, x, csi, codebook_idx, nof_symbols, scaling, noise_estimate);
          } else {
            return srsran_predecoding_multiplex_2x2_mmse(y, h, x, codebook_idx, nof_symbols, scaling, noise_estimate);
          }
          break;
      }
    } else {
      if (csi && csi[0]) {
        return srsran_predecoding_multiplex_2x1_mrc_csi(y, h, x, csi[0], codebook_idx, nof_symbols, scaling);
      } else {
        return srsran_predecoding_multiplex_2x1_mrc(y, h, x, codebook_idx, nof_symbols, scaling);
      }
    }
  } else if (nof_ports == 4) {
    // return SRSRAN_ERROR;
    if (nof_layers == 1){
        switch(mimo_decoder){
            case SRSRAN_MIMO_DECODER_ZF:
                // return SRSRAN_ERROR;
                if (csi && csi[0]){
                    return srsran_predecoding_multiplex_4x1_zf_csi(y, h, x, csi[0], codebook_idx, nof_symbols, scaling);
                } else {
                    return srsran_predecoding_multiplex_4x1_zf(y, h, x, codebook_idx, nof_symbols, scaling);
                }
                break;
            case SRSRAN_MIMO_DECODER_MMSE:
                // return SRSRAN_ERROR;
                if (csi && csi[0]) {
                  return srsran_predecoding_multiplex_4x1_mmse_csi(
                      y, h, x, csi[0], codebook_idx, nof_symbols, scaling, noise_estimate);
                } else {
                  return srsran_predecoding_multiplex_4x1_mmse(y, h, x, codebook_idx, nof_symbols, scaling, noise_estimate);
                }
                break;
        }
    }
    // return SRSRAN_ERROR;
    if (nof_layers == 2){
        switch(mimo_decoder){
            case SRSRAN_MIMO_DECODER_ZF:
                if (csi && csi[0]){
                    return srsran_predecoding_multiplex_4x2_zf_csi(y, h, x, csi, codebook_idx, nof_symbols, scaling);
                } else {
                    return srsran_predecoding_multiplex_4x2_zf(y, h, x, codebook_idx, nof_symbols, scaling);
                }
                break;
            case SRSRAN_MIMO_DECODER_MMSE:
                // return SRSRAN_ERROR;
                if (csi && csi[0]) {
                  return srsran_predecoding_multiplex_4x2_mmse_csi(
                      y, h, x, csi, codebook_idx, nof_symbols, scaling, noise_estimate);
                } else {
                  return srsran_predecoding_multiplex_4x2_mmse(y, h, x, codebook_idx, nof_symbols, scaling, noise_estimate);
                }
                break;
        }
    }

    ERROR("Error predecoding multiplex: not implemented for %d Tx ports and %d layers", nof_ports, nof_layers);
    fprintf(stderr,"Error predecoding multiplex: not implemented for %d Tx ports and %d layers\n", nof_ports, nof_layers);
  } else {
    ERROR("Error predecoding multiplex: Invalid combination of ports %d and rx antennas %d", nof_ports, nof_rxant);
    fprintf(stderr,"Error predecoding multiplex: Invalid combination of ports %d and rx antennas %d\n", nof_ports, nof_rxant);
  }
  return SRSRAN_ERROR;
}

void srsran_predecoding_set_mimo_decoder(srsran_mimo_decoder_t _mimo_decoder)
{
  mimo_decoder = _mimo_decoder;
}

/* 36.211 v10.3.0 Section 6.3.4 */
int srsran_predecoding_type(cf_t*              y[SRSRAN_MAX_PORTS],
                            cf_t*              h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                            cf_t*              x[SRSRAN_MAX_LAYERS],
                            float*             csi[SRSRAN_MAX_CODEWORDS],
                            int                nof_rxant,
                            int                nof_ports,
                            int                nof_layers,
                            int                codebook_idx,
                            int                nof_symbols,
                            srsran_tx_scheme_t type,
                            float              scaling,
                            float              noise_estimate)
{
  if (nof_ports > SRSRAN_MAX_PORTS) {
    ERROR("Maximum number of ports is %d (nof_ports=%d)", SRSRAN_MAX_PORTS, nof_ports);
    fprintf(stderr, "Maximum number of ports is %d (nof_ports=%d)", SRSRAN_MAX_PORTS, nof_ports);
    return SRSRAN_ERROR;
  }
  if (nof_layers > SRSRAN_MAX_LAYERS) {
    ERROR("Maximum number of layers is %d (nof_layers=%d)", SRSRAN_MAX_LAYERS, nof_layers);
    fprintf(stderr, "Maximum number of layers is %d (nof_layers=%d)", SRSRAN_MAX_LAYERS, nof_layers);
    return SRSRAN_ERROR;
  }

  switch (type) {
    case SRSRAN_TXSCHEME_CDD:
      if (nof_layers == 2) {
        switch (mimo_decoder) {
          case SRSRAN_MIMO_DECODER_ZF:
              // printf("srsran_mimo_decoder_zf\n");
            return srsran_predecoding_ccd_zf(y, h, x, csi, nof_rxant, nof_ports, nof_layers, nof_symbols, scaling);
          case SRSRAN_MIMO_DECODER_MMSE:
              // printf("srsran_mimo_decoder_mmse\n");
            return srsran_predecoding_ccd_mmse(
                y, h, x, csi, nof_rxant, nof_ports, nof_layers, nof_symbols, scaling, noise_estimate);
        }
      } else {
        ERROR("Invalid number of layers %d", nof_layers);
        fprintf(stderr, "Invalid number of layers %d\n", nof_layers);
        return SRSRAN_ERROR;
      }
      fprintf(stderr, "This should never be here?\n");
      return SRSRAN_ERROR;
    case SRSRAN_TXSCHEME_PORT0:
      if (nof_ports == 1 && nof_layers == 1) {
          printf("srsran_txscheme_port0\n");
        return srsran_predecoding_single_multi(y, h[0], x[0], csi, nof_rxant, nof_symbols, scaling, noise_estimate);
      } else {
        ERROR("Number of ports and layers must be 1 for transmission on single antenna ports (%d, %d)",
              nof_ports,
              nof_layers);
        fprintf(stderr, "Number of ports and layers must be 1 for transmission on single antenna ports (%d, %d)",
              nof_ports,
              nof_layers);
        return SRSRAN_ERROR;
      }
    case SRSRAN_TXSCHEME_DIVERSITY:
      if (nof_ports == nof_layers) {
          // printf("srsran_txscheme_diversity\n");
        return srsran_predecoding_diversity_multi(y, h, x, csi, nof_rxant, nof_ports, nof_symbols, scaling);
      } else {
        ERROR("Error number of layers must equal number of ports in transmit diversity");
        fprintf(stderr, "Error number of layers must equal number of ports in transmit diversity");
        return SRSRAN_ERROR;
      }
    case SRSRAN_TXSCHEME_SPATIALMUX:
        // printf("srsran_txscheme_spatialmux\n");
      return srsran_predecoding_multiplex(
          y, h, x, csi, nof_rxant, nof_ports, nof_layers, codebook_idx, nof_symbols, scaling, noise_estimate);
    default:
      ERROR("Invalid Txscheme=%d", type);
      fprintf(stderr, "Invalid Txscheme=%d\n",type);
      return SRSRAN_ERROR;
  }
}

/************************************************
 *
 * TRANSMITTER SIDE FUNCTIONS
 *
 **************************************************/

int srsran_precoding_single(cf_t* x, cf_t* y, int nof_symbols, float scaling)
{
  if (scaling == 1.0f) {
    memcpy(y, x, nof_symbols * sizeof(cf_t));
  } else {
    srsran_vec_sc_prod_cfc(x, scaling, y, (uint32_t)nof_symbols);
  }
  return nof_symbols;
}
int srsran_precoding_diversity(cf_t* x[SRSRAN_MAX_LAYERS],
                               cf_t* y[SRSRAN_MAX_PORTS],
                               int   nof_ports,
                               int   nof_symbols,
                               float scaling)
{
  int i;
  if (nof_ports == 2) {
    for (i = 0; i < nof_symbols; i++) {
      y[0][2 * i]     = x[0][i];
      y[1][2 * i]     = -conjf(x[1][i]);
      y[0][2 * i + 1] = x[1][i];
      y[1][2 * i + 1] = conjf(x[0][i]);
    }
    // normalize
    srsran_vec_sc_prod_cfc(y[0], scaling * M_SQRT1_2, y[0], 2 * nof_symbols);
    srsran_vec_sc_prod_cfc(y[1], scaling * M_SQRT1_2, y[1], 2 * nof_symbols);
    return 2 * i;
  } else if (nof_ports == 4) {
    scaling /= M_SQRT2;

    // int m_ap = (nof_symbols%4)?(nof_symbols*4-2):nof_symbols*4;
    int m_ap = 4 * nof_symbols;
    for (i = 0; i < m_ap / 4; i++) {
      y[0][4 * i] = x[0][i] * scaling;
      y[1][4 * i] = 0;
      y[2][4 * i] = -conjf(x[1][i]) * scaling;
      y[3][4 * i] = 0;

      y[0][4 * i + 1] = x[1][i] * scaling;
      y[1][4 * i + 1] = 0;
      y[2][4 * i + 1] = conjf(x[0][i]) * scaling;
      y[3][4 * i + 1] = 0;

      y[0][4 * i + 2] = 0;
      y[1][4 * i + 2] = x[2][i] * scaling;
      y[2][4 * i + 2] = 0;
      y[3][4 * i + 2] = -conjf(x[3][i]) * scaling;

      y[0][4 * i + 3] = 0;
      y[1][4 * i + 3] = x[3][i] * scaling;
      y[2][4 * i + 3] = 0;
      y[3][4 * i + 3] = conjf(x[2][i]) * scaling;
    }
    return 4 * i;
  } else {
    ERROR("Number of ports must be 2 or 4 for transmit diversity (nof_ports=%d)", nof_ports);
    return -1;
  }
}

#ifdef LV_HAVE_AVX

int srsran_precoding_cdd_2x2_avx(cf_t* x[SRSRAN_MAX_LAYERS], cf_t* y[SRSRAN_MAX_PORTS], int nof_symbols, float scaling)
{
  __m256 norm_avx = _mm256_set1_ps(0.5f * scaling);
  for (int i = 0; i < nof_symbols - 3; i += 4) {
    __m256 x0 = _mm256_load_ps((float*)&x[0][i]);
    __m256 x1 = _mm256_load_ps((float*)&x[1][i]);

    __m256 y0 = _mm256_mul_ps(norm_avx, _mm256_add_ps(x0, x1));

    x0 = _mm256_xor_ps(x0, _mm256_setr_ps(+0.0f, +0.0f, -0.0f, -0.0f, +0.0f, +0.0f, -0.0f, -0.0f));
    x1 = _mm256_xor_ps(x1, _mm256_set_ps(+0.0f, +0.0f, -0.0f, -0.0f, +0.0f, +0.0f, -0.0f, -0.0f));

    __m256 y1 = _mm256_mul_ps(norm_avx, _mm256_add_ps(x0, x1));

    _mm256_store_ps((float*)&y[0][i], y0);
    _mm256_store_ps((float*)&y[1][i], y1);
  }

  return 2 * nof_symbols;
}

#endif /* LV_HAVE_AVX */

#ifdef LV_HAVE_SSE

int srsran_precoding_cdd_2x2_sse(cf_t* x[SRSRAN_MAX_LAYERS], cf_t* y[SRSRAN_MAX_PORTS], int nof_symbols, float scaling)
{
  __m128 norm_sse = _mm_set1_ps(0.5f * scaling);
  for (int i = 0; i < nof_symbols - 1; i += 2) {
    __m128 x0 = _mm_load_ps((float*)&x[0][i]);
    __m128 x1 = _mm_load_ps((float*)&x[1][i]);

    __m128 y0 = _mm_mul_ps(norm_sse, _mm_add_ps(x0, x1));

    x0 = _mm_xor_ps(x0, _mm_setr_ps(+0.0f, +0.0f, -0.0f, -0.0f));
    x1 = _mm_xor_ps(x1, _mm_set_ps(+0.0f, +0.0f, -0.0f, -0.0f));

    __m128 y1 = _mm_mul_ps(norm_sse, _mm_add_ps(x0, x1));

    _mm_store_ps((float*)&y[0][i], y0);
    _mm_store_ps((float*)&y[1][i], y1);
  }

  return 2 * nof_symbols;
}

#endif /* LV_HAVE_SSE */

int srsran_precoding_cdd_2x2_gen(cf_t* x[SRSRAN_MAX_LAYERS], cf_t* y[SRSRAN_MAX_PORTS], int nof_symbols, float scaling)
{
  scaling /= 2.0f;
  for (int i = 0; i < nof_symbols; i++) {
    y[0][i] = (x[0][i] + x[1][i]) * scaling;
    y[1][i] = (x[0][i] - x[1][i]) * scaling;
    i++;
    y[0][i] = (x[0][i] + x[1][i]) * scaling;
    y[1][i] = (-x[0][i] + x[1][i]) * scaling;
  }
  return 2 * nof_symbols;
}

int srsran_precoding_cdd(cf_t* x[SRSRAN_MAX_LAYERS],
                         cf_t* y[SRSRAN_MAX_PORTS],
                         int   nof_layers,
                         int   nof_ports,
                         int   nof_symbols,
                         float scaling)
{
  if (nof_ports == 2) {
    if (nof_layers != 2) {
      ERROR("Invalid number of layers %d for 2 ports", nof_layers);
      return -1;
    }
#ifdef LV_HAVE_AVX
    return srsran_precoding_cdd_2x2_avx(x, y, nof_symbols, scaling);
#else
#ifdef LV_HAVE_SSE
    return srsran_precoding_cdd_2x2_sse(x, y, nof_symbols, scaling);
#else
    return srsran_precoding_cdd_2x2_gen(x, y, nof_symbols, scaling);
#endif /* LV_HAVE_SSE */
#endif /* LV_HAVE_AVX */
  } else if (nof_ports == 4) {
    ERROR("Not implemented");
    return -1;
  } else {
    ERROR("Number of ports must be 2 or 4 for transmit diversity (nof_ports=%d)", nof_ports);
    return -1;
  }
}

int srsran_precoding_multiplex(cf_t*    x[SRSRAN_MAX_LAYERS],
                               cf_t*    y[SRSRAN_MAX_PORTS],
                               int      nof_layers,
                               int      nof_ports,
                               int      codebook_idx,
                               uint32_t nof_symbols,
                               float    scaling)
{
  int i = 0;
  if (nof_ports == 2) {
    if (nof_layers == 1) {
      scaling *= M_SQRT1_2;
      switch (codebook_idx) {
        case 0:
          srsran_vec_sc_prod_cfc(x[0], scaling, y[0], nof_symbols);
          srsran_vec_sc_prod_cfc(x[0], scaling, y[1], nof_symbols);
          break;
        case 1:
          srsran_vec_sc_prod_cfc(x[0], scaling, y[0], nof_symbols);
          srsran_vec_sc_prod_cfc(x[0], -scaling, y[1], nof_symbols);
          break;
        case 2:
          srsran_vec_sc_prod_cfc(x[0], scaling, y[0], nof_symbols);
          srsran_vec_sc_prod_ccc(x[0], _Complex_I * scaling, y[1], nof_symbols);
          break;
        case 3:
          srsran_vec_sc_prod_cfc(x[0], scaling, y[0], nof_symbols);
          srsran_vec_sc_prod_ccc(x[0], -_Complex_I * scaling, y[1], nof_symbols);
          break;
        default:
          ERROR("Invalid multiplex combination: codebook_idx=%d, nof_layers=%d, nof_ports=%d",
                codebook_idx,
                nof_layers,
                nof_ports);
          return SRSRAN_ERROR;
      }
    } else if (nof_layers == 2) {
      switch (codebook_idx) {
        case 0:
          scaling *= M_SQRT1_2;
          srsran_vec_sc_prod_cfc(x[0], scaling, y[0], nof_symbols);
          srsran_vec_sc_prod_cfc(x[1], scaling, y[1], nof_symbols);
          break;
        case 1:
          scaling /= 2.0f;
#ifdef LV_HAVE_AVX
          for (; i < nof_symbols - 3; i += 4) {
            __m256 x0 = _mm256_load_ps((float*)&x[0][i]);
            __m256 x1 = _mm256_load_ps((float*)&x[1][i]);

            __m256 y0 = _mm256_mul_ps(_mm256_set1_ps(scaling), _mm256_add_ps(x0, x1));
            __m256 y1 = _mm256_mul_ps(_mm256_set1_ps(scaling), _mm256_sub_ps(x0, x1));

            _mm256_store_ps((float*)&y[0][i], y0);
            _mm256_store_ps((float*)&y[1][i], y1);
          }
#endif /* LV_HAVE_AVX */

#ifdef LV_HAVE_SSE
          for (; i < nof_symbols - 1; i += 2) {
            __m128 x0 = _mm_load_ps((float*)&x[0][i]);
            __m128 x1 = _mm_load_ps((float*)&x[1][i]);

            __m128 y0 = _mm_mul_ps(_mm_set1_ps(scaling), _mm_add_ps(x0, x1));
            __m128 y1 = _mm_mul_ps(_mm_set1_ps(scaling), _mm_sub_ps(x0, x1));

            _mm_store_ps((float*)&y[0][i], y0);
            _mm_store_ps((float*)&y[1][i], y1);
          }
#endif /* LV_HAVE_SSE */

          for (; i < nof_symbols; i++) {
            y[0][i] = (x[0][i] + x[1][i]) * scaling;
            y[1][i] = (x[0][i] - x[1][i]) * scaling;
          }
          break;
        case 2:
          scaling /= 2.0f;
#ifdef LV_HAVE_AVX
          for (; i < nof_symbols - 3; i += 4) {
            __m256 x0 = _mm256_load_ps((float*)&x[0][i]);
            __m256 x1 = _mm256_load_ps((float*)&x[1][i]);

            __m256 y0 = _mm256_mul_ps(_mm256_set1_ps(scaling), _mm256_add_ps(x0, x1));
            __m256 y1 = _mm256_mul_ps(_mm256_set1_ps(scaling), _MM256_MULJ_PS(_mm256_sub_ps(x0, x1)));

            _mm256_store_ps((float*)&y[0][i], y0);
            _mm256_store_ps((float*)&y[1][i], y1);
          }
#endif /* LV_HAVE_AVX */

#ifdef LV_HAVE_SSE
          for (; i < nof_symbols - 1; i += 2) {
            __m128 x0 = _mm_load_ps((float*)&x[0][i]);
            __m128 x1 = _mm_load_ps((float*)&x[1][i]);

            __m128 y0 = _mm_mul_ps(_mm_set1_ps(scaling), _mm_add_ps(x0, x1));
            __m128 y1 = _mm_mul_ps(_mm_set1_ps(scaling), _MM_MULJ_PS(_mm_sub_ps(x0, x1)));

            _mm_store_ps((float*)&y[0][i], y0);
            _mm_store_ps((float*)&y[1][i], y1);
          }
#endif /* LV_HAVE_SSE */

          for (; i < nof_symbols; i++) {
            y[0][i] = (x[0][i] + x[1][i]) * scaling;
            y[1][i] = (_Complex_I * x[0][i] - _Complex_I * x[1][i]) * scaling;
          }
          break;
        case 3:
        default:
          ERROR("Invalid multiplex combination: codebook_idx=%d, nof_layers=%d, nof_ports=%d",
                codebook_idx,
                nof_layers,
                nof_ports);
          return SRSRAN_ERROR;
      }
    } else {
      ERROR("Not implemented");
    }
  } else {
    ERROR("Not implemented");
  }
  return SRSRAN_SUCCESS;
}

/* 36.211 v10.3.0 Section 6.3.4 */
int srsran_precoding_type(cf_t*              x[SRSRAN_MAX_LAYERS],
                          cf_t*              y[SRSRAN_MAX_PORTS],
                          int                nof_layers,
                          int                nof_ports,
                          int                codebook_idx,
                          int                nof_symbols,
                          float              scaling,
                          srsran_tx_scheme_t type)
{
  if (nof_ports > SRSRAN_MAX_PORTS) {
    ERROR("Maximum number of ports is %d (nof_ports=%d)", SRSRAN_MAX_PORTS, nof_ports);
    return -1;
  }
  if (nof_layers > SRSRAN_MAX_LAYERS) {
    ERROR("Maximum number of layers is %d (nof_layers=%d)", SRSRAN_MAX_LAYERS, nof_layers);
    return -1;
  }

  switch (type) {
    case SRSRAN_TXSCHEME_CDD:
      return srsran_precoding_cdd(x, y, nof_layers, nof_ports, nof_symbols, scaling);
    case SRSRAN_TXSCHEME_PORT0:
      if (nof_ports == 1 && nof_layers == 1) {
        return srsran_precoding_single(x[0], y[0], nof_symbols, scaling);
      } else {
        ERROR("Number of ports and layers must be 1 for transmission on single antenna ports");
        return -1;
      }
      break;
    case SRSRAN_TXSCHEME_DIVERSITY:
      if (nof_ports == nof_layers) {
        return srsran_precoding_diversity(x, y, nof_ports, nof_symbols, scaling);
      } else {
        ERROR("Error number of layers must equal number of ports in transmit diversity");
        return -1;
      }
    case SRSRAN_TXSCHEME_SPATIALMUX:
      return srsran_precoding_multiplex(x, y, nof_layers, nof_ports, codebook_idx, (uint32_t)nof_symbols, scaling);
    default:
      return SRSRAN_ERROR;
  }
  return SRSRAN_ERROR;
}

#define PMI_SEL_PRECISION 24

/* PMI Select for 1 layer */
int srsran_precoding_pmi_select_1l_gen(cf_t*     h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                       uint32_t  nof_symbols,
                                       float     noise_estimate,
                                       uint32_t* pmi,
                                       float     sinr_list[SRSRAN_MAX_CODEBOOKS])
{
#define SQRT1_2 ((float)M_SQRT1_2)
  float    max_sinr = 0.0;
  uint32_t i, count;

  for (i = 0; i < 4; i++) {
    sinr_list[i] = 0;
    count        = 0;

    for (uint32_t j = 0; j < nof_symbols; j += PMI_SEL_PRECISION) {
      /* 0. Load channel matrix */
      cf_t h00 = h[0][0][j];
      cf_t h01 = h[1][0][j];
      cf_t h10 = h[0][1][j];
      cf_t h11 = h[1][1][j];

      /* 1. B = W'* H' */
      cf_t a0, a1;
      switch (i) {
        case 0:
          a0 = conjf(h00) + conjf(h01);
          a1 = conjf(h10) + conjf(h11);
          break;
        case 1:
          a0 = conjf(h00) - conjf(h01);
          a1 = conjf(h10) - conjf(h11);
          break;
        case 2:
          a0 = conjf(h00) - _Complex_I * conjf(h01);
          a1 = conjf(h10) - _Complex_I * conjf(h11);
          break;
        case 3:
          a0 = conjf(h00) + _Complex_I * conjf(h01);
          a1 = conjf(h10) + _Complex_I * conjf(h11);
          break;
      }
      a0 *= SQRT1_2;
      a1 *= SQRT1_2;

      /* 2. B = W' * H' * H = A * H */
      cf_t b0 = a0 * h00 + a1 * h10;
      cf_t b1 = a0 * h01 + a1 * h11;

      /* 3. C = W' * H' * H * W' = B * W */
      cf_t c;
      switch (i) {
        case 0:
          c = b0 + b1;
          break;
        case 1:
          c = b0 - b1;
          break;
        case 2:
          c = b0 + _Complex_I * b1;
          break;
        case 3:
          c = b0 - _Complex_I * b1;
          break;
        default:
          return SRSRAN_ERROR;
      }
      c *= SQRT1_2;

      /* Add for averaging */
      sinr_list[i] += crealf(c);

      count++;
    }

    /* Divide average by noise */
    sinr_list[i] /= noise_estimate * count;

    if (sinr_list[i] > max_sinr) {
      max_sinr = sinr_list[i];
      *pmi     = i;
    }
  }

  return i;
}

#if SRSRAN_SIMD_CF_SIZE != 0

/* PMI Select for 1 layer */
int srsran_precoding_pmi_select_1l_simd(cf_t*     h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                        uint32_t  nof_symbols,
                                        float     noise_estimate,
                                        uint32_t* pmi,
                                        float     sinr_list[SRSRAN_MAX_CODEBOOKS])
{
  float    max_sinr    = 0.0;
  simd_f_t simd_f_norm = srsran_simd_f_set1(0.5f);

  for (uint32_t i = 0; i < 4; i++) {
    float sinr_acc = 0;
    float count    = 0;

    for (uint32_t j = 0; j < nof_symbols - PMI_SEL_PRECISION * SRSRAN_SIMD_CF_SIZE + 1;
         j += PMI_SEL_PRECISION * SRSRAN_SIMD_CF_SIZE) {
      // 0. Load channel matrix
      srsran_simd_aligned cf_t h00_v[SRSRAN_SIMD_CF_SIZE];
      srsran_simd_aligned cf_t h01_v[SRSRAN_SIMD_CF_SIZE];
      srsran_simd_aligned cf_t h10_v[SRSRAN_SIMD_CF_SIZE];
      srsran_simd_aligned cf_t h11_v[SRSRAN_SIMD_CF_SIZE];

      for (uint32_t k = 0; k < SRSRAN_SIMD_CF_SIZE; k++) {
        h00_v[k] = h[0][0][j + PMI_SEL_PRECISION * k];
        h01_v[k] = h[1][0][j + PMI_SEL_PRECISION * k];
        h10_v[k] = h[0][1][j + PMI_SEL_PRECISION * k];
        h11_v[k] = h[1][1][j + PMI_SEL_PRECISION * k];
      }

      simd_cf_t h00 = srsran_simd_cfi_load(h00_v);
      simd_cf_t h01 = srsran_simd_cfi_load(h01_v);
      simd_cf_t h10 = srsran_simd_cfi_load(h10_v);
      simd_cf_t h11 = srsran_simd_cfi_load(h11_v);

      /* 1. B = W'* H' */
      simd_cf_t a0, a1;
      switch (i) {
        case 0:
          a0 = srsran_simd_cf_add(srsran_simd_cf_conj(h00), srsran_simd_cf_conj(h01));
          a1 = srsran_simd_cf_add(srsran_simd_cf_conj(h10), srsran_simd_cf_conj(h11));
          break;
        case 1:
          a0 = srsran_simd_cf_sub(srsran_simd_cf_conj(h00), srsran_simd_cf_conj(h01));
          a1 = srsran_simd_cf_sub(srsran_simd_cf_conj(h10), srsran_simd_cf_conj(h11));
          break;
        case 2:
          a0 = srsran_simd_cf_sub(srsran_simd_cf_conj(h00), srsran_simd_cf_mulj(srsran_simd_cf_conj(h01)));
          a1 = srsran_simd_cf_sub(srsran_simd_cf_conj(h10), srsran_simd_cf_mulj(srsran_simd_cf_conj(h11)));
          break;
        default:
          a0 = srsran_simd_cf_add(srsran_simd_cf_conj(h00), srsran_simd_cf_mulj(srsran_simd_cf_conj(h01)));
          a1 = srsran_simd_cf_add(srsran_simd_cf_conj(h10), srsran_simd_cf_mulj(srsran_simd_cf_conj(h11)));
          break;
      }

      /* 2. B = W' * H' * H = A * H */
      simd_cf_t b0 = srsran_simd_cf_add(srsran_simd_cf_prod(a0, h00), srsran_simd_cf_prod(a1, h10));
      simd_cf_t b1 = srsran_simd_cf_add(srsran_simd_cf_prod(a0, h01), srsran_simd_cf_prod(a1, h11));

      /* 3. C = W' * H' * H * W' = B * W */
      simd_cf_t c;
      switch (i) {
        case 0:
          c = srsran_simd_cf_add(b0, b1);
          break;
        case 1:
          c = srsran_simd_cf_sub(b0, b1);
          break;
        case 2:
          c = srsran_simd_cf_add(b0, srsran_simd_cf_mulj(b1));
          break;
        case 3:
          c = srsran_simd_cf_sub(b0, srsran_simd_cf_mulj(b1));
          break;
        default:
          return SRSRAN_ERROR;
      }

      simd_f_t gamma = srsran_simd_f_mul(srsran_simd_cf_re(c), simd_f_norm);

      // Horizontal accumulation
      for (int k = 1; k < SRSRAN_SIMD_F_SIZE; k *= 2) {
        gamma = srsran_simd_f_hadd(gamma, gamma);
      }

      // Temporal store accumulated values
      srsran_simd_aligned float v[SRSRAN_SIMD_F_SIZE];
      srsran_simd_f_store(v, gamma);

      // Average and accumulate SINR loop
      sinr_acc += (v[0] / SRSRAN_SIMD_CF_SIZE);

      // Increase loop counter
      count += 1;
    }

    // Average accumulated SINR
    if (count) {
      sinr_acc /= (noise_estimate * count);
    } else {
      sinr_acc = 1e+9f;
    }

    // Save SINR if available
    if (sinr_list) {
      sinr_list[i] = sinr_acc;
    }

    // Select maximum SINR Codebook
    if (pmi && sinr_acc > max_sinr) {
      max_sinr = sinr_acc;
      *pmi     = i;
    }
  }

  return 4;
}

#endif /* SRSRAN_SIMD_CF_SIZE != 0 */

int srsran_precoding_pmi_select_1l(cf_t*     h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                   uint32_t  nof_symbols,
                                   float     noise_estimate,
                                   uint32_t* pmi,
                                   float     sinr_list[SRSRAN_MAX_CODEBOOKS])
{
  int ret;
#if SRSRAN_SIMD_CF_SIZE != 0
  ret = srsran_precoding_pmi_select_1l_simd(h, nof_symbols, noise_estimate, pmi, sinr_list);
#else
  ret = srsran_precoding_pmi_select_1l_gen(h, nof_symbols, noise_estimate, pmi, sinr_list);
#endif /* SRSRAN_SIMD_CF_SIZE != 0 */
  INFO("Precoder PMI Select for 1 layer SINR=[%.1fdB; %.1fdB; %.1fdB; %.1fdB] PMI=%d",
       srsran_convert_power_to_dB(sinr_list[0]),
       srsran_convert_power_to_dB(sinr_list[1]),
       srsran_convert_power_to_dB(sinr_list[2]),
       srsran_convert_power_to_dB(sinr_list[3]),
       *pmi);

  return ret;
}

int srsran_precoding_pmi_select_2l_gen(cf_t*     h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                       uint32_t  nof_symbols,
                                       float     noise_estimate,
                                       uint32_t* pmi,
                                       float     sinr_list[SRSRAN_MAX_CODEBOOKS])
{
  float    max_sinr = 0.0;
  uint32_t i, count;

  for (i = 0; i < 2; i++) {
    sinr_list[i] = 0;
    count        = 0;

    for (uint32_t j = 0; j < nof_symbols; j += PMI_SEL_PRECISION) {
      /* 0. Load channel matrix */
      cf_t h00 = h[0][0][j];
      cf_t h01 = h[1][0][j];
      cf_t h10 = h[0][1][j];
      cf_t h11 = h[1][1][j];

      /* 1. B = W'* H' */
      cf_t a00, a01, a10, a11;
      switch (i) {
        case 0:
          a00 = conjf(h00) + conjf(h01);
          a01 = conjf(h10) + conjf(h11);
          a10 = conjf(h00) - conjf(h01);
          a11 = conjf(h10) - conjf(h11);
          break;
        case 1:
          a00 = conjf(h00) - _Complex_I * conjf(h01);
          a01 = conjf(h10) - _Complex_I * conjf(h11);
          a10 = conjf(h00) + _Complex_I * conjf(h01);
          a11 = conjf(h10) + _Complex_I * conjf(h11);
          break;
        default:
          return SRSRAN_ERROR;
      }

      /* 2. B = W' * H' * H = A * H */
      cf_t b00 = a00 * h00 + a01 * h10;
      cf_t b01 = a00 * h01 + a01 * h11;
      cf_t b10 = a10 * h00 + a11 * h10;
      cf_t b11 = a10 * h01 + a11 * h11;

      /* 3. C = W' * H' * H * W' = B * W */
      cf_t c00, c01, c10, c11;
      switch (i) {
        case 0:
          c00 = b00 + b01;
          c01 = b00 - b01;
          c10 = b10 + b11;
          c11 = b10 - b11;
          break;
        case 1:
          c00 = b00 + _Complex_I * b01;
          c01 = b00 - _Complex_I * b01;
          c10 = b10 + _Complex_I * b11;
          c11 = b10 - _Complex_I * b11;
          break;
        default:
          return SRSRAN_ERROR;
      }
      c00 *= 0.25;
      c01 *= 0.25;
      c10 *= 0.25;
      c11 *= 0.25;

      /* 4. C += noise * I */
      c00 += noise_estimate;
      c11 += noise_estimate;

      /* 5. detC */
      cf_t detC     = c00 * c11 - c01 * c10;
      cf_t inv_detC = conjf(detC) / (crealf(detC) * crealf(detC) + cimagf(detC) * cimagf(detC));

      cf_t den0 = noise_estimate * c00 * inv_detC;
      cf_t den1 = noise_estimate * c11 * inv_detC;

      float gamma0 = crealf((conjf(den0) / (crealf(den0) * crealf(den0) + cimagf(den0) * cimagf(den0))) - 1);
      float gamma1 = crealf((conjf(den1) / (crealf(den1) * crealf(den1) + cimagf(den1) * cimagf(den1))) - 1);

      /* Add for averaging */
      sinr_list[i] += (gamma0 + gamma1);

      count++;
    }

    /* Divide average by noise */
    if (count) {
      sinr_list[i] /= count;
    }

    if (sinr_list[i] > max_sinr) {
      max_sinr = sinr_list[i];
      *pmi     = i;
    }
  }

  return i;
}

#if SRSRAN_SIMD_CF_SIZE != 0

int srsran_precoding_pmi_select_2l_simd(cf_t*     h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                        int       nof_symbols,
                                        float     noise_estimate,
                                        uint32_t* pmi,
                                        float     sinr_list[SRSRAN_MAX_CODEBOOKS])
{
  // SIMD Constants
  const simd_cf_t simd_cf_noise_estimate = srsran_simd_cf_set1(noise_estimate);
  const simd_f_t  simd_f_noise_estimate  = srsran_simd_f_set1(noise_estimate);
  const simd_f_t  simd_f_norm            = srsran_simd_f_set1(0.25f);
  const simd_f_t  simd_f_ones            = srsran_simd_f_set1(1.0f);
  const simd_f_t  simd_f_det_min         = srsran_simd_f_set1(1e-10f);
  const simd_f_t  simd_f_gamma_min       = srsran_simd_f_set1(1e-9f);

  float max_sinr = 0.0f;

  for (uint32_t i = 0; i < 2; i++) {
    float count    = 0.0f;
    float sinr_acc = 0.0f;

    for (uint32_t j = 0; j < nof_symbols - PMI_SEL_PRECISION * SRSRAN_SIMD_CF_SIZE + 1;
         j += PMI_SEL_PRECISION * SRSRAN_SIMD_CF_SIZE) {
      // 0. Load channel matrix
      srsran_simd_aligned cf_t h00_v[SRSRAN_SIMD_CF_SIZE];
      srsran_simd_aligned cf_t h01_v[SRSRAN_SIMD_CF_SIZE];
      srsran_simd_aligned cf_t h10_v[SRSRAN_SIMD_CF_SIZE];
      srsran_simd_aligned cf_t h11_v[SRSRAN_SIMD_CF_SIZE];

      for (uint32_t k = 0; k < SRSRAN_SIMD_CF_SIZE; k++) {
        h00_v[k] = h[0][0][j + PMI_SEL_PRECISION * k];
        h01_v[k] = h[1][0][j + PMI_SEL_PRECISION * k];
        h10_v[k] = h[0][1][j + PMI_SEL_PRECISION * k];
        h11_v[k] = h[1][1][j + PMI_SEL_PRECISION * k];
      }

      simd_cf_t h00 = srsran_simd_cfi_load(h00_v);
      simd_cf_t h01 = srsran_simd_cfi_load(h01_v);
      simd_cf_t h10 = srsran_simd_cfi_load(h10_v);
      simd_cf_t h11 = srsran_simd_cfi_load(h11_v);

      // 1. B = W'* H'
      simd_cf_t a00, a01, a10, a11;
      switch (i) {
        case 0:
          a00 = srsran_simd_cf_add(srsran_simd_cf_conj(h00), srsran_simd_cf_conj(h01));
          a01 = srsran_simd_cf_add(srsran_simd_cf_conj(h10), srsran_simd_cf_conj(h11));
          a10 = srsran_simd_cf_sub(srsran_simd_cf_conj(h00), srsran_simd_cf_conj(h01));
          a11 = srsran_simd_cf_sub(srsran_simd_cf_conj(h10), srsran_simd_cf_conj(h11));
          break;
        case 1:
          a00 = srsran_simd_cf_sub(srsran_simd_cf_conj(h00), srsran_simd_cf_mulj(srsran_simd_cf_conj(h01)));
          a01 = srsran_simd_cf_sub(srsran_simd_cf_conj(h10), srsran_simd_cf_mulj(srsran_simd_cf_conj(h11)));
          a10 = srsran_simd_cf_add(srsran_simd_cf_conj(h00), srsran_simd_cf_mulj(srsran_simd_cf_conj(h01)));
          a11 = srsran_simd_cf_add(srsran_simd_cf_conj(h10), srsran_simd_cf_mulj(srsran_simd_cf_conj(h11)));
          break;
        default:
          return SRSRAN_ERROR;
      }

      // 2. B = W' * H' * H = A * H
      simd_cf_t b00 = srsran_simd_cf_add(srsran_simd_cf_prod(a00, h00), srsran_simd_cf_prod(a01, h10));
      simd_cf_t b01 = srsran_simd_cf_add(srsran_simd_cf_prod(a00, h01), srsran_simd_cf_prod(a01, h11));
      simd_cf_t b10 = srsran_simd_cf_add(srsran_simd_cf_prod(a10, h00), srsran_simd_cf_prod(a11, h10));
      simd_cf_t b11 = srsran_simd_cf_add(srsran_simd_cf_prod(a10, h01), srsran_simd_cf_prod(a11, h11));

      // 3. C = W' * H' * H * W' = B * W
      simd_cf_t c00, c01, c10, c11;
      switch (i) {
        case 0:
          c00 = srsran_simd_cf_add(b00, b01);
          c01 = srsran_simd_cf_sub(b00, b01);
          c10 = srsran_simd_cf_add(b10, b11);
          c11 = srsran_simd_cf_sub(b10, b11);
          break;
        case 1:
          c00 = srsran_simd_cf_add(b00, srsran_simd_cf_mulj(b01));
          c01 = srsran_simd_cf_sub(b00, srsran_simd_cf_mulj(b01));
          c10 = srsran_simd_cf_add(b10, srsran_simd_cf_mulj(b11));
          c11 = srsran_simd_cf_sub(b10, srsran_simd_cf_mulj(b11));
          break;
        default:
          return SRSRAN_ERROR;
      }
      c00 = srsran_simd_cf_mul(c00, simd_f_norm);
      c01 = srsran_simd_cf_mul(c01, simd_f_norm);
      c10 = srsran_simd_cf_mul(c10, simd_f_norm);
      c11 = srsran_simd_cf_mul(c11, simd_f_norm);

      // 4. C += noise * I
      c00 = srsran_simd_cf_add(c00, simd_cf_noise_estimate);
      c11 = srsran_simd_cf_add(c11, simd_cf_noise_estimate);

      // 5. detC
      simd_f_t detC = srsran_simd_cf_re(srsran_mat_2x2_det_simd(c00, c01, c10, c11));

      // Avoid zero determinant
      detC = srsran_simd_f_select(detC, simd_f_det_min, srsran_simd_f_min(detC, simd_f_det_min));

      simd_f_t inv_detC = srsran_simd_f_rcp(detC);
      inv_detC          = srsran_simd_f_mul(simd_f_noise_estimate, inv_detC);

      simd_f_t den0 = srsran_simd_f_mul(srsran_simd_cf_re(c00), inv_detC);
      simd_f_t den1 = srsran_simd_f_mul(srsran_simd_cf_re(c11), inv_detC);

      simd_f_t gamma0 = srsran_simd_f_sub(srsran_simd_f_rcp(den0), simd_f_ones);
      simd_f_t gamma1 = srsran_simd_f_sub(srsran_simd_f_rcp(den1), simd_f_ones);

      // Avoid negative gamma
      gamma0 = srsran_simd_f_select(gamma0, simd_f_gamma_min, srsran_simd_f_min(gamma0, simd_f_gamma_min));
      gamma1 = srsran_simd_f_select(gamma1, simd_f_gamma_min, srsran_simd_f_min(gamma1, simd_f_gamma_min));

      simd_f_t gamma_sum = srsran_simd_f_hadd(gamma0, gamma1);

      // Horizontal accumulation
      for (int k = 1; k < SRSRAN_SIMD_F_SIZE; k *= 2) {
        gamma_sum = srsran_simd_f_hadd(gamma_sum, gamma_sum);
      }

      // Temporal store accumulated values
      srsran_simd_aligned float v[SRSRAN_SIMD_F_SIZE];
      srsran_simd_f_store(v, gamma_sum);

      // Average and accumulate SINR loop
      sinr_acc += (v[0] / SRSRAN_SIMD_CF_SIZE);

      // Increase loop counter
      count += 1.0f;
    }

    // Average loop accumulator
    if (isnormal(count)) {
      sinr_acc /= count;
    } else {
      sinr_acc = 1e+9f;
    }

    // Set SINR if available
    if (sinr_list) {
      sinr_list[i] = sinr_acc;
    }

    // Set PMI if available
    if (pmi && sinr_acc > max_sinr) {
      max_sinr = sinr_acc;
      *pmi     = i;
    }
  }

  // Return number of codebooks
  return 2;
}

#endif /* SRSRAN_SIMD_CF_SIZE != 0 */

/* PMI Select for 2 layers */
int srsran_precoding_pmi_select_2l(cf_t*     h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                   uint32_t  nof_symbols,
                                   float     noise_estimate,
                                   uint32_t* pmi,
                                   float     sinr_list[SRSRAN_MAX_CODEBOOKS])
{
  int ret;
#if SRSRAN_SIMD_CF_SIZE != 0
  ret = srsran_precoding_pmi_select_2l_simd(h, nof_symbols, noise_estimate, pmi, sinr_list);
#else
  ret = srsran_precoding_pmi_select_2l_gen(h, nof_symbols, noise_estimate, pmi, sinr_list);
#endif /* SRSRAN_SIMD_CF_SIZE != 0 */

  INFO("Precoder PMI Select for 2 layers SINR=[%.1fdB; %.1fdB] PMI=%d",
       srsran_convert_power_to_dB(sinr_list[0]),
       srsran_convert_power_to_dB(sinr_list[1]),
       *pmi);

  return ret;
}

int srsran_precoding_pmi_select(cf_t*     h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                                uint32_t  nof_symbols,
                                float     noise_estimate,
                                int       nof_layers,
                                uint32_t* pmi,
                                float     sinr[SRSRAN_MAX_CODEBOOKS])
{
  int ret;

  // Bound noise estimate value
  if (!isnormal(noise_estimate) || noise_estimate < 1e-9f) {
    noise_estimate = 1e-9f;
  }

  if (nof_layers == 1) {
    ret = srsran_precoding_pmi_select_1l(h, nof_symbols, noise_estimate, pmi, sinr);
  } else if (nof_layers == 2) {
    ret = srsran_precoding_pmi_select_2l(h, nof_symbols, noise_estimate, pmi, sinr);
  } else {
    ERROR("Unsupported number of layers");
    ret = SRSRAN_ERROR_INVALID_INPUTS;
  }

  return ret;
}

/* PMI Select for 1 layer */
float srsran_precoding_2x2_cn_gen(cf_t* h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS], uint32_t nof_symbols)
{
  uint32_t count  = 0;
  float    cn_avg = 0.0f;

  for (uint32_t i = 0; i < nof_symbols; i += PMI_SEL_PRECISION) {
    /* 0. Load channel matrix */
    cf_t h00 = h[0][0][i];
    cf_t h01 = h[1][0][i];
    cf_t h10 = h[0][1][i];
    cf_t h11 = h[1][1][i];

    float cn = 0.0f;
    if (srsran_mat_2x2_cn(h00, h01, h10, h11, &cn) == SRSRAN_SUCCESS) {
      cn_avg += cn;
      count++;
    }
  }

  if (count) {
    cn_avg /= count;
  }

  return cn_avg;
}

/* Computes the condition number for a given number of antennas,
 * stores in the parameter *cn the Condition Number in dB */
int srsran_precoding_cn(cf_t*    h[SRSRAN_MAX_PORTS][SRSRAN_MAX_PORTS],
                        uint32_t nof_tx_antennas,
                        uint32_t nof_rx_antennas,
                        uint32_t nof_symbols,
                        float*   cn)
{
  if (nof_tx_antennas == 2 && nof_rx_antennas == 2) {
    *cn = srsran_precoding_2x2_cn_gen(h, nof_symbols);
    return SRSRAN_SUCCESS;
  } else {
    ERROR("MIMO Condition Number calculation not implemented for %d×%d", nof_tx_antennas, nof_rx_antennas);
    return SRSRAN_ERROR;
  }
}
