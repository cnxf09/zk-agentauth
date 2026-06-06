// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "circuits/sha/flatsm3_witness.h"

#include "util/ceildiv.h"
#include "util/panic.h"

namespace proofs {
namespace {

static inline uint32_t rotl(uint32_t x, size_t b) {
  return (x << b) | (x >> (32 - b));
}

static inline uint32_t p0(uint32_t x) {
  return x ^ rotl(x, 9) ^ rotl(x, 17);
}

static inline uint32_t p1(uint32_t x) {
  return x ^ rotl(x, 15) ^ rotl(x, 23);
}

static inline uint32_t ff(size_t j, uint32_t x, uint32_t y, uint32_t z) {
  return j < 16 ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

static inline uint32_t gg(size_t j, uint32_t x, uint32_t y, uint32_t z) {
  return j < 16 ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

static inline uint32_t tj(size_t j) {
  return j < 16 ? 0x79cc4519u : 0x7a879d8au;
}

void wu64be(uint8_t* d, uint64_t n) {
  for (size_t i = 0; i < 8; ++i) {
    d[7 - i] = (n >> (8 * i)) & 0xffu;
  }
}

const uint32_t kSM3IV[8] = {0x7380166fu, 0x4914b2b9u, 0x172442d7u,
                            0xda8a0600u, 0xa96f30bcu, 0x163138aau,
                            0xe38dee4du, 0xb0fb0e4eu};

}  // namespace

uint32_t SM3_ru32be(const uint8_t* d) {
  uint32_t r = 0;
  for (size_t i = 0; i < 4; ++i) {
    r = (r << 8) + (d[i] & 0xffu);
  }
  return r;
}

void FlatSM3Witness::transform_and_witness_block(
    const uint32_t in[16], const uint32_t H0[8], uint32_t outw[52],
    uint32_t outss1[64], uint32_t outtt2[64], uint32_t oute[64],
    uint32_t outa[64], uint32_t H1[8]) {
  uint32_t w[68];
  uint32_t w1[64];
  for (size_t i = 0; i < 16; ++i) {
    w[i] = in[i];
  }
  for (size_t i = 16; i < 68; ++i) {
    outw[i - 16] = w[i] =
        p1(w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) ^
        rotl(w[i - 13], 7) ^ w[i - 6];
  }
  for (size_t i = 0; i < 64; ++i) {
    w1[i] = w[i] ^ w[i + 4];
  }

  uint32_t a = H0[0];
  uint32_t b = H0[1];
  uint32_t c = H0[2];
  uint32_t d = H0[3];
  uint32_t e = H0[4];
  uint32_t f = H0[5];
  uint32_t g = H0[6];
  uint32_t h = H0[7];

  for (size_t j = 0; j < 64; ++j) {
    outss1[j] = rotl(a, 12) + e + rotl(tj(j), j % 32);
    const uint32_t ss1 = rotl(outss1[j], 7);
    const uint32_t ss2 = ss1 ^ rotl(a, 12);
    const uint32_t tt1 = ff(j, a, b, c) + d + ss2 + w1[j];
    const uint32_t tt2 = gg(j, e, f, g) + h + ss1 + w[j];
    d = c;
    c = rotl(b, 9);
    b = a;
    outa[j] = a = tt1;
    h = g;
    g = rotl(f, 19);
    f = e;
    outtt2[j] = tt2;
    oute[j] = e = p0(tt2);
  }

  H1[0] = H0[0] ^ a;
  H1[1] = H0[1] ^ b;
  H1[2] = H0[2] ^ c;
  H1[3] = H0[3] ^ d;
  H1[4] = H0[4] ^ e;
  H1[5] = H0[5] ^ f;
  H1[6] = H0[6] ^ g;
  H1[7] = H0[7] ^ h;
}

void FlatSM3Witness::transform_and_witness_message(
    size_t n, const uint8_t msg[/*n*/], size_t max, uint8_t& numb,
    uint8_t in[/*64*max*/], BlockWitness bw[/*max*/]) {
  numb = ceildiv<size_t>(n + 9, 64);

  size_t ii = 0;
  for (size_t i = 0; i < n; ++i, ++ii) {
    in[ii] = msg[i];
  }
  in[ii++] = 0x80;
  if ((ii % 64) == 0 || (ii % 64) > 56) {
    while (ii % 64) in[ii++] = 0;
  }
  while ((ii % 64) < 56) in[ii++] = 0;
  wu64be(&in[ii], n * 8);
  ii += 8;
  check(ii % 64 == 0, "Invalid SM3 padding");
  while (ii < 64 * max) in[ii++] = 0;

  uint32_t data[16];
  const uint32_t* h = kSM3IV;
  for (size_t bl = 0; bl < max; ++bl) {
    for (size_t i = 0; i < 16; ++i) {
      data[i] = SM3_ru32be(&in[bl * 64 + i * 4]);
    }
    transform_and_witness_block(data, h, bw[bl].outw, bw[bl].outss1,
                                bw[bl].outtt2, bw[bl].oute, bw[bl].outa,
                                bw[bl].h1);
    h = bw[bl].h1;
  }
}

}  // namespace proofs
