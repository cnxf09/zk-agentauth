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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA_FLATSM3_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA_FLATSM3_CIRCUIT_H_

#include <stddef.h>

#include <vector>

#include "circuits/logic/bit_adder.h"

namespace proofs {

template <class Logic, class BitPlucker>
class FlatSM3Circuit {
 public:
  using BitW = typename Logic::BitW;
  using v8 = typename Logic::v8;
  using v32 = typename Logic::v32;
  using v64 = typename Logic::v64;
  using v256 = typename Logic::v256;
  using EltW = typename Logic::EltW;
  using packed_v32 = typename BitPlucker::packed_v32;

  const Logic& l_;
  BitPlucker bp_;

  static packed_v32 packed_input(const Logic& lc) {
    return BitPlucker::template packed_input<packed_v32>(lc);
  }

  struct BlockWitness {
    packed_v32 outw[52];
    packed_v32 outss1[64];
    packed_v32 outtt2[64];
    packed_v32 oute[64];
    packed_v32 outa[64];
    packed_v32 h1[8];

    void input(const Logic& lc) {
      for (size_t i = 0; i < 52; ++i) outw[i] = packed_input(lc);
      for (size_t i = 0; i < 64; ++i) {
        outss1[i] = packed_input(lc);
        outtt2[i] = packed_input(lc);
        oute[i] = packed_input(lc);
        outa[i] = packed_input(lc);
      }
      for (size_t i = 0; i < 8; ++i) h1[i] = packed_input(lc);
    }
  };

  explicit FlatSM3Circuit(const Logic& l) : l_(l), bp_(l_) {}

  void assert_transform_block(const v32 in[16], const v32 H0[8],
                              const packed_v32 poutw[52],
                              const packed_v32 poutss1[64],
                              const packed_v32 pouttt2[64],
                              const packed_v32 poute[64],
                              const packed_v32 pouta[64],
                              const packed_v32 pH1[8]) const {
    std::vector<v32> w(68);
    std::vector<v32> w1(64);
    std::vector<v32> outw(52);
    std::vector<v32> outss1(64), outtt2(64), oute(64), outa(64);
    std::vector<v32> H1(8);
    for (size_t i = 0; i < 16; ++i) w[i] = in[i];
    for (size_t i = 0; i < 52; ++i) outw[i] = bp_.unpack_v32(poutw[i]);
    for (size_t i = 0; i < 64; ++i) {
      outss1[i] = bp_.unpack_v32(poutss1[i]);
      outtt2[i] = bp_.unpack_v32(pouttt2[i]);
      oute[i] = bp_.unpack_v32(poute[i]);
      outa[i] = bp_.unpack_v32(pouta[i]);
    }
    for (size_t i = 0; i < 8; ++i) H1[i] = bp_.unpack_v32(pH1[i]);

    BitAdder<Logic, 32> BA(l_);
    for (size_t i = 16; i < 68; ++i) {
      auto x = l_.vxor3(&w[i - 16], &w[i - 9], rotl(w[i - 3], 15));
      auto p1x = p1(x);
      auto r13 = rotl(w[i - 13], 7);
      w[i] = outw[i - 16];
      auto want = l_.vxor3(&p1x, &r13, w[i - 6]);
      l_.vassert_eq(&w[i], want);
    }
    for (size_t i = 0; i < 64; ++i) {
      w1[i] = l_.vxor(&w[i], w[i + 4]);
    }

    v32 a = H0[0], b = H0[1], c = H0[2], d = H0[3];
    v32 e = H0[4], f = H0[5], g = H0[6], h = H0[7];

    for (size_t j = 0; j < 64; ++j) {
      auto a12 = rotl(a, 12);
      auto tjr = l_.template vbit<32>(rotl_const(tj(j), j % 32));
      EltW ss1_sum = BA.add({a12, e, tjr});
      BA.assert_eqmod(outss1[j], ss1_sum, 3);
      v32 ss1 = rotl(outss1[j], 7);
      auto ss2 = l_.vxor(&ss1, a12);

      auto tt1 = outa[j];
      std::vector<v32> tt1_terms = {ff(j, a, b, c), d, ss2, w1[j]};
      BA.assert_eqmod(tt1, BA.add(tt1_terms), 4);

      auto tt2 = outtt2[j];
      std::vector<v32> tt2_terms = {gg(j, e, f, g), h, ss1, w[j]};
      BA.assert_eqmod(tt2, BA.add(tt2_terms), 4);
      auto want_e = p0(tt2);
      l_.vassert_eq(&oute[j], want_e);

      d = c;
      c = rotl(b, 9);
      b = a;
      a = tt1;
      h = g;
      g = rotl(f, 19);
      f = e;
      e = oute[j];
    }

    l_.vassert_eq(&H1[0], l_.vxor(&H0[0], a));
    l_.vassert_eq(&H1[1], l_.vxor(&H0[1], b));
    l_.vassert_eq(&H1[2], l_.vxor(&H0[2], c));
    l_.vassert_eq(&H1[3], l_.vxor(&H0[3], d));
    l_.vassert_eq(&H1[4], l_.vxor(&H0[4], e));
    l_.vassert_eq(&H1[5], l_.vxor(&H0[5], f));
    l_.vassert_eq(&H1[6], l_.vxor(&H0[6], g));
    l_.vassert_eq(&H1[7], l_.vxor(&H0[7], h));
  }

  void assert_transform_block(const v32 in[16], const packed_v32 pH0[8],
                              const packed_v32 poutw[52],
                              const packed_v32 poutss1[64],
                              const packed_v32 pouttt2[64],
                              const packed_v32 poute[64],
                              const packed_v32 pouta[64],
                              const packed_v32 pH1[8]) const {
    std::vector<v32> H0(8);
    for (size_t i = 0; i < 8; ++i) H0[i] = bp_.unpack_v32(pH0[i]);
    assert_transform_block(in, H0.data(), poutw, poutss1, pouttt2, poute,
                           pouta, pH1);
  }

  void assert_message(size_t max, const v8& nb, const v8 in[/*64*max*/],
                      const BlockWitness bw[/*max*/]) const {
    const packed_v32* H = nullptr;
    std::vector<v32> tmp(16);
    for (size_t b = 0; b < max; ++b) {
      const v8* inb = &in[64 * b];
      for (size_t i = 0; i < 16; ++i) {
        tmp[i] = l_.vappend(l_.vappend(inb[4 * i + 3], inb[4 * i + 2]),
                            l_.vappend(inb[4 * i + 1], inb[4 * i + 0]));
      }
      if (b == 0) {
        v32 H0[8];
        initial_context(H0);
        assert_transform_block(tmp.data(), H0, bw[b].outw, bw[b].outss1,
                               bw[b].outtt2, bw[b].oute, bw[b].outa,
                               bw[b].h1);
      } else {
        assert_transform_block(tmp.data(), H, bw[b].outw, bw[b].outss1,
                               bw[b].outtt2, bw[b].oute, bw[b].outa,
                               bw[b].h1);
      }
      H = bw[b].h1;
    }
    assert_zero_padding(max, nb, in);
  }

  void assert_message_hash(size_t max, const v8& nb, const v8 in[/*64*max*/],
                           const v256& target,
                           const BlockWitness bw[/*max*/]) const {
    assert_message(max, nb, in, bw);
    assert_hash(max, target, nb, bw);
  }

  void assert_hash(size_t max, const v256& e, const v8& nb,
                   const BlockWitness bw[/*max*/]) const {
    v256 mm = hash_from_witness(max, nb, bw);
    l_.vassert_eq(&mm, e);
  }

  v256 hash_from_witness(size_t max, const v8& nb,
                         const BlockWitness bw[/*max*/]) const {
    packed_v32 x[8];
    for (size_t b = 0; b < max; ++b) {
      auto bt = l_.veq(nb, b + 1);
      auto ebt = l_.eval(bt);
      for (size_t i = 0; i < 8; ++i) {
        for (size_t k = 0; k < bp_.kNv32Elts; ++k) {
          if (b == 0) {
            x[i][k] = l_.mul(&ebt, bw[b].h1[i][k]);
          } else {
            auto maybe_sm3 = l_.mul(&ebt, bw[b].h1[i][k]);
            x[i][k] = l_.add(&x[i][k], maybe_sm3);
          }
        }
      }
    }
    v256 mm;
    for (size_t j = 0; j < 8; ++j) {
      auto hj = bp_.unpack_v32(x[j]);
      for (size_t k = 0; k < 32; ++k) {
        mm[((7 - j) * 32 + k)] = hj[k];
      }
    }
    return mm;
  }

 private:
  void initial_context(v32 H[8]) const {
    static const uint32_t initial[8] = {0x7380166fu, 0x4914b2b9u, 0x172442d7u,
                                        0xda8a0600u, 0xa96f30bcu, 0x163138aau,
                                        0xe38dee4du, 0xb0fb0e4eu};
    for (size_t i = 0; i < 8; ++i) H[i] = l_.template vbit<32>(initial[i]);
  }

  v32 rotl(const v32& x, size_t n) const { return l_.vrotr(x, 32 - n); }
  static uint32_t rotl_const(uint32_t x, size_t n) {
    return n == 0 ? x : ((x << n) | (x >> (32 - n)));
  }
  static uint32_t tj(size_t j) { return j < 16 ? 0x79cc4519u : 0x7a879d8au; }

  v32 p0(const v32& x) const {
    auto r9 = rotl(x, 9);
    return l_.vxor3(&x, &r9, rotl(x, 17));
  }
  v32 p1(const v32& x) const {
    auto r15 = rotl(x, 15);
    return l_.vxor3(&x, &r15, rotl(x, 23));
  }
  v32 ff(size_t j, const v32& x, const v32& y, const v32& z) const {
    return j < 16 ? l_.vxor3(&x, &y, z) : l_.vMaj(&x, &y, z);
  }
  v32 gg(size_t j, const v32& x, const v32& y, const v32& z) const {
    return j < 16 ? l_.vxor3(&x, &y, z) : l_.vCh(&x, &y, z);
  }

  void assert_zero_padding(size_t max, const v8 nb,
                           const v8 in[/*64 * max*/]) const {
    for (size_t i = 0; i < max; ++i) {
      auto wantzero = l_.vleq(nb, i);
      for (size_t j = 0; j < 64; ++j) {
        size_t ind = i * 64 + j;
        auto zero = l_.veq(in[ind], 0);
        l_.assert_implies(&wantzero, zero);
      }
    }
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA_FLATSM3_CIRCUIT_H_
