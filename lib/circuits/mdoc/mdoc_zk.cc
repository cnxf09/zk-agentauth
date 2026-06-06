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

#include "circuits/mdoc/mdoc_zk.h"

#include <stdint.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/ecdsa/pk_witness.h"
#include "cbor/host_decoder.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "circuits/mdoc/mdoc_decompress.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/sha/flatsm3_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "ec/p256.h"
#include "ec/sm2.h"
#include "gf2k/gf2_128.h"
#include "gf2k/lch14_reed_solomon.h"
#include "proto/circuit.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "zstd.h"

// The result of getHashMacIndex is derived from the circuit layout.
// It represents the location of the hash MAC wire in the hash verification
// circuit and must be updated if the public interface of the hash circuit is
// changed.
// This index is part of the public input, but it is needed so that the prover
// can commit the rest of the witness (including its portion of the MAC key),
// the verifier can then select its a_v half of the mac key, the prover can
// then compute the MAC and finally place it into the correct part of the
// dense witness array.
// ex: numAttrs = 1, this function returns (1*768 + 8) + 161
size_t getHashMacIndex(size_t numAttrs, size_t version) {
  // The length of the attribute field that is added in version 4.
  return numAttrs * 8 * (96 + (version < 7 ? 1 : 2)) + 160 + 1;
}

namespace proofs {

// ======= Global typedefs for convenience ==========
// P256-related types
using N = Fp256Base::N;
using Scalar = Fp256Base::Elt;
using Elt = Fp256Base::Elt;
using f2_p256 = Fp2<Fp256Base>;
using Elt2 = f2_p256::Elt;
using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
using RSFactory_b = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;
using SM2N = FpSM2Base::N;
using SM2Elt = FpSM2Base::Elt;
using f2_sm2 = Fp2<FpSM2Base>;
using SM2Elt2 = f2_sm2::Elt;
using SM2FftExtConvolutionFactory =
    FFTExtConvolutionFactory<FpSM2Base, f2_sm2>;
using SM2RSFactory_b =
    ReedSolomonFactory<FpSM2Base, SM2FftExtConvolutionFactory>;
using f_128 = GF2_128<>;
using gf2k = f_128::Elt;

using RSFactory = LCH14ReedSolomonFactory<f_128>;

bool is_sm_delegation_spec(const ZkSpecStruct* zk_spec) {
  return zk_spec != nullptr &&
         std::strcmp(zk_spec->system, "zk-agentauth-sm-delegation-v1") == 0;
}

// Root of unity for the f_p256^2 extension field.
static constexpr char kRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
static constexpr char kRootY[] =
    "84087994358540907695740461427818660560182168997182378749313018254450460212"
    "908";

// Root of unity for the f_sm2^2 extension field. This is a 2^31-th root,
// generated from (2, 7)^((p^2 - 1) / 2^31) over sm2p256v1 base field.
static constexpr char kSm2RootX[] =
    "98316849790531968137732767118645795515924309091740457905448201861165618"
    "099731";
static constexpr char kSm2RootY[] =
    "73926473467919460029392182226315578904409523214222254033588702131259041"
    "028876";

// Magic constant 4 is derived from the circuit layout.
// It represents the location of the signature MAC wire in the signature
// verification circuit and must be updated if the public interface of the sig
// circuit is changed. This index is part of the public input, but it is needed
// so that the prover can commit the rest of the witness (including its portion
// of the MAC key), the verifier can then select its a_v half of the mac key,
// the prover can then compute the MAC and finally place it into the correct
// part of the dense witness array.
static constexpr size_t kSigMacIndex = 4;

// Flags that indicate whether the prover and/or verifier ought
// to check the circuit id stored in the circuit itself.
//
// In this particular application the ID's of the individual circuits
// are trusted, and we don't want to incur the performance cost
// of verifying the ID for every proof or verification.
//
// The larger application is expected to contain a hardcoded
// list of supported circuit IDs.  After downloading the circuit
// (or compiling it locally) the application is expected to
// check the ID once, and then store the checked circuit in
// trusted local storage.
static constexpr bool enforce_circuit_id_in_prover = false;
static constexpr bool enforce_circuit_id_in_verifier = false;

// =========== Helper methods for the main exported C functions.

// Specialization for filling the mac when using f_128.
template <>
void fill_gf2k<f_128, f_128>(const typename f_128::Elt &m,
                             DenseFiller<f_128> &df, const f_128 &f) {
  df.push_back(m);
}

void compute_macs(size_t len, const Elt x[], gf2k gmacs[/* 6 */],
                  uint8_t macs[/* 2.len.gf2k_size */],
                  const gf2k ap[/* 2.len */], gf2k av) {
  // This code relies on the assumption that an Elt can be mac'ed in 2
  // gf2k elements.
  check(f_128::kBits * 2 >= Fp256Base::kBits, "Mac is not large enough");
  f_128 gf;
  MACReference<f_128> mac_ref;
  uint8_t buf[Fp256Base::kBytes];

  for (size_t i = 0; i < len; ++i) {
    p256_base.to_bytes_field(buf, x[i]);
    mac_ref.compute(&gmacs[2 * i], av, &ap[i * 2], buf);
    gf.to_bytes_field(&macs[2 * i * f_128::kBytes], gmacs[2 * i]);
    gf.to_bytes_field(&macs[(2 * i + 1) * f_128::kBytes], gmacs[2 * i + 1]);
  }
}

template <class Field>
void compute_macs_for_field(size_t len, const typename Field::Elt x[],
                            gf2k gmacs[], uint8_t macs[],
                            const gf2k ap[], gf2k av, const Field& field) {
  check(f_128::kBits * 2 >= Field::kBits, "Mac is not large enough");
  f_128 gf;
  MACReference<f_128> mac_ref;
  uint8_t buf[Field::kBytes];

  for (size_t i = 0; i < len; ++i) {
    field.to_bytes_field(buf, x[i]);
    mac_ref.compute(&gmacs[2 * i], av, &ap[i * 2], buf);
    gf.to_bytes_field(&macs[2 * i * f_128::kBytes], gmacs[2 * i]);
    gf.to_bytes_field(&macs[(2 * i + 1) * f_128::kBytes], gmacs[2 * i + 1]);
  }
}

struct ProverState {
  Elt common[3];  //  e2, dpkx, dpky
  gf2k ap[6];     //  mac keys for the above
  using mac_witness = MacGF2Witness;
  mac_witness macs[3];
};

struct DelegatedProverState {
  Elt common[5];  // e2, dpkx, dpky, delegation digest, revocation status digest
  gf2k ap[10];
  using mac_witness = MacGF2Witness;
  mac_witness macs[5];
};

static constexpr size_t kDelegatedSigMacIndex = 6;

struct SmDelegatedProverState {
  Elt p256_common[6];   // e, dpkx, dpky, delegation digest, revocation digest, sk
  SM2Elt sm2_common[3]; // delegation digest, revocation digest, sk
  gf2k ap[12];
  using mac_witness = MacGF2Witness;
  mac_witness hash_macs[5];
};

MdocProverErrorCode fill_attributes(DenseFiller<f_128>& hash_filler,
                                    const RequestedAttribute* attrs,
                                    size_t attrs_len, const uint8_t* now,
                                    const f_128& Fs, size_t version);

void fill_signature_inputs(DenseFiller<Fp256Base>& sig_filler, const Elt& pkX,
                           const Elt& pkY, const Elt& e);

size_t delegation_public_inputs_size(size_t num_attrs) {
  return 8 * (32 + 32 + 1 + kDelegationMaxClaims * kDelegationClaimHashSize +
              kDelegationExpiresSize + kDelegationAgentIdHashSize +
              num_attrs * kDelegationClaimHashSize +
              32 + kDelegationRevocationEpochSize + kDelegationExpiresSize +
              kDelegationRevocationFlagSize);
}

size_t getDelegatedHashMacIndex(size_t numAttrs, size_t version) {
  return getHashMacIndex(numAttrs, version) +
         delegation_public_inputs_size(numAttrs);
}

bool parse_signature_rs(const uint8_t* sig, size_t len, N* r, N* s) {
  if (sig == nullptr || len != 64 || r == nullptr || s == nullptr) {
    return false;
  }
  *r = nat_from_be<N>(sig);
  *s = nat_from_be<N>(sig + 32);
  return true;
}

bool parse_sm2_signature_rs(const uint8_t* sig, size_t len, SM2N* r,
                            SM2N* s) {
  if (sig == nullptr || len != 64 || r == nullptr || s == nullptr) {
    return false;
  }
  *r = nat_from_be<SM2N>(sig);
  *s = nat_from_be<SM2N>(sig + 32);
  return true;
}

int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool parse_hex_32(const char* hex, uint8_t out[32]) {
  if (hex == nullptr) return false;
  size_t off = (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) ? 2 : 0;
  if (std::strlen(hex + off) != 64) return false;
  for (size_t i = 0; i < 32; ++i) {
    int hi = hex_nibble(hex[off + 2 * i]);
    int lo = hex_nibble(hex[off + 2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

bool parse_device_sk(const char* sk_hex, N* p256_sk, SM2N* sm2_sk,
                     Elt* p256_sk_e, SM2Elt* sm2_sk_e) {
  uint8_t sk_be[32];
  if (!parse_hex_32(sk_hex, sk_be)) return false;
  N psk = nat_from_be<N>(sk_be);
  SM2N ssk = nat_from_be<SM2N>(sk_be);
  if (!(psk < n256_order) || !(ssk < nsm2_order)) {
    return false;
  }
  if (p256_sk != nullptr) *p256_sk = psk;
  if (sm2_sk != nullptr) *sm2_sk = ssk;
  if (p256_sk_e != nullptr) *p256_sk_e = p256_base.to_montgomery(psk);
  if (sm2_sk_e != nullptr) *sm2_sk_e = sm2_base.to_montgomery(ssk);
  return true;
}

void u32_digest_to_be(uint8_t out[32], const uint32_t h[8]) {
  for (size_t i = 0; i < 8; ++i) {
    out[4 * i] = static_cast<uint8_t>((h[i] >> 24) & 0xff);
    out[4 * i + 1] = static_cast<uint8_t>((h[i] >> 16) & 0xff);
    out[4 * i + 2] = static_cast<uint8_t>((h[i] >> 8) & 0xff);
    out[4 * i + 3] = static_cast<uint8_t>(h[i] & 0xff);
  }
}

bool sm3_digest_message(const std::vector<uint8_t>& msg, uint8_t digest[32]) {
  if (msg.empty()) {
    return false;
  }
  const size_t blocks = (msg.size() + 9 + 63) / 64;
  std::vector<uint8_t> in(blocks * 64);
  std::vector<FlatSM3Witness::BlockWitness> bw(blocks);
  uint8_t nb = 0;
  FlatSM3Witness::transform_and_witness_message(
      msg.size(), msg.data(), blocks, nb, in.data(), bw.data());
  u32_digest_to_be(digest, bw[blocks - 1].h1);
  return true;
}

std::vector<uint8_t> build_device_authentication_bytes(
    const uint8_t transcript[], size_t len,
    const std::vector<uint8_t>* docType = nullptr) {
  std::vector<uint8_t> deviceAuthentication = {
      0x84, 0x74, 'D', 'e', 'v', 'i', 'c', 'e', 'A', 'u', 't',
      'h',  'e',  'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n',
  };
  std::vector<uint8_t> docTypeBytes = {
      0x75, 'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8',
      '0',  '1', '3', '.', '5', '.', '1', '.', 'm', 'D', 'L',
  };
  std::vector<uint8_t> deviceNameSpacesBytes = {0xD8, 0x18, 0x41, 0xA0};

  if (docType != nullptr && docType->size() < 256) {
    docTypeBytes.clear();
    append_text_len(docTypeBytes, docType->size());
    docTypeBytes.insert(docTypeBytes.end(), docType->begin(), docType->end());
  }
  std::vector<uint8_t> da(deviceAuthentication);
  da.insert(da.end(), transcript, transcript + len);
  da.insert(da.end(), docTypeBytes.begin(), docTypeBytes.end());
  da.insert(da.end(), deviceNameSpacesBytes.begin(),
            deviceNameSpacesBytes.end());

  std::vector<uint8_t> cose1{0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E,
                             0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
                             0x43, 0xA1, 0x01, 0x26, 0x40};
  uint8_t tag[] = {0xD8, 0x18};
  size_t l1 = da.size();
  size_t l2 = l1 + (l1 < 256 ? 4 : 5);
  append_bytes_len(cose1, l2);
  cose1.insert(cose1.end(), tag, tag + 2);
  append_bytes_len(cose1, l1);
  cose1.insert(cose1.end(), da.begin(), da.end());
  return cose1;
}

void field_to_be_bytes(uint8_t out[32], const Elt& x) {
  uint8_t le[32];
  p256_base.to_bytes_field(le, x);
  for (size_t i = 0; i < 32; ++i) {
    out[i] = le[31 - i];
  }
}

template <class Field>
void field_to_be_bytes_for(uint8_t out[32], const typename Field::Elt& x,
                           const Field& field) {
  uint8_t le[32];
  field.to_bytes_field(le, x);
  for (size_t i = 0; i < 32; ++i) {
    out[i] = le[31 - i];
  }
}

template <class Field>
std::vector<uint8_t> build_delegation_message_bytes(
    const typename Field::Elt& agent_pkX, const typename Field::Elt& agent_pkY,
    const uint8_t* allowed_claim_hashes, size_t allowed_claim_count,
    const char* policy_expires, const uint8_t* agent_id_hash,
    const Field& field) {
  static constexpr uint8_t kDomain[kDelegationMsgDomainSize] = {
      'Z', 'K', 'D', 'E', 'L', 'G', '1', 0x00};
  std::vector<uint8_t> msg;
  msg.reserve(kDelegationMsgSize);
  msg.insert(msg.end(), std::begin(kDomain), std::end(kDomain));
  uint8_t buf[32];
  field_to_be_bytes_for<Field>(buf, agent_pkX, field);
  msg.insert(msg.end(), buf, buf + 32);
  field_to_be_bytes_for<Field>(buf, agent_pkY, field);
  msg.insert(msg.end(), buf, buf + 32);
  msg.push_back(static_cast<uint8_t>(allowed_claim_count));
  for (size_t i = 0; i < kDelegationMaxClaims; ++i) {
    if (i < allowed_claim_count) {
      msg.insert(msg.end(), allowed_claim_hashes + i * kDelegationClaimHashSize,
                 allowed_claim_hashes + (i + 1) * kDelegationClaimHashSize);
    } else {
      msg.insert(msg.end(), kDelegationClaimHashSize, 0);
    }
  }
  msg.insert(msg.end(), reinterpret_cast<const uint8_t*>(policy_expires),
             reinterpret_cast<const uint8_t*>(policy_expires) +
                 kDelegationExpiresSize);
  msg.insert(msg.end(), agent_id_hash,
             agent_id_hash + kDelegationAgentIdHashSize);
  return msg;
}

std::vector<uint8_t> build_delegation_message_bytes(
    const Elt& agent_pkX, const Elt& agent_pkY,
    const uint8_t* allowed_claim_hashes, size_t allowed_claim_count,
    const char* policy_expires, const uint8_t* agent_id_hash) {
  return build_delegation_message_bytes<Fp256Base>(
      agent_pkX, agent_pkY, allowed_claim_hashes, allowed_claim_count,
      policy_expires, agent_id_hash, p256_base);
}

std::vector<uint8_t> build_revocation_id_message_bytes(
    const uint8_t delegation_digest[32]) {
  static constexpr uint8_t kDomain[kDelegationRevocationIdDomainSize] = {
      'Z', 'K', 'D', 'E', 'L', 'I', 'D', '1'};
  std::vector<uint8_t> msg;
  msg.reserve(kDelegationRevocationIdMsgSize);
  msg.insert(msg.end(), std::begin(kDomain), std::end(kDomain));
  msg.insert(msg.end(), delegation_digest, delegation_digest + 32);
  return msg;
}

std::vector<uint8_t> build_revocation_status_message_bytes(
    const uint8_t revocation_id[32], const uint8_t* revocation_epoch_be,
    const char* revocation_expires, uint8_t revocation_revoked) {
  static constexpr uint8_t kDomain[kDelegationRevocationStatusDomainSize] = {
      'Z', 'K', 'D', 'E', 'L', 'S', 'T', '1'};
  std::vector<uint8_t> msg;
  msg.reserve(kDelegationRevocationStatusMsgSize);
  msg.insert(msg.end(), std::begin(kDomain), std::end(kDomain));
  msg.insert(msg.end(), revocation_id, revocation_id + 32);
  msg.insert(msg.end(), revocation_epoch_be,
             revocation_epoch_be + kDelegationRevocationEpochSize);
  msg.insert(msg.end(), reinterpret_cast<const uint8_t*>(revocation_expires),
             reinterpret_cast<const uint8_t*>(revocation_expires) +
                 kDelegationExpiresSize);
  msg.push_back(revocation_revoked);
  return msg;
}

std::vector<uint8_t> build_sm2_za_message_bytes(
    const uint8_t signer_id[kSm2UserIdSize], const SM2Elt& pkX,
    const SM2Elt& pkY) {
  static constexpr uint8_t kA[32] = {
      0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
  static constexpr uint8_t kB[32] = {
      0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34,
      0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
      0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92,
      0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93};
  static constexpr uint8_t kGx[32] = {
      0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19,
      0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
      0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1,
      0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7};
  static constexpr uint8_t kGy[32] = {
      0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c,
      0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
      0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40,
      0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0};
  std::vector<uint8_t> msg;
  msg.reserve(kSm2ZaMessageSize);
  msg.push_back(0x00);
  msg.push_back(static_cast<uint8_t>(kSm2UserIdSize * 8));
  msg.insert(msg.end(), signer_id, signer_id + kSm2UserIdSize);
  msg.insert(msg.end(), std::begin(kA), std::end(kA));
  msg.insert(msg.end(), std::begin(kB), std::end(kB));
  msg.insert(msg.end(), std::begin(kGx), std::end(kGx));
  msg.insert(msg.end(), std::begin(kGy), std::end(kGy));
  uint8_t buf[32];
  field_to_be_bytes_for<FpSM2Base>(buf, pkX, sm2_base);
  msg.insert(msg.end(), buf, buf + 32);
  field_to_be_bytes_for<FpSM2Base>(buf, pkY, sm2_base);
  msg.insert(msg.end(), buf, buf + 32);
  return msg;
}

std::vector<uint8_t> build_sm2_digest_signature_message_bytes(
    const uint8_t digest[32], const uint8_t signer_id[kSm2UserIdSize],
    const SM2Elt& pkX, const SM2Elt& pkY) {
  const std::vector<uint8_t> za_msg =
      build_sm2_za_message_bytes(signer_id, pkX, pkY);
  uint8_t za[32];
  if (!sm3_digest_message(za_msg, za)) {
    return {};
  }
  std::vector<uint8_t> msg;
  msg.reserve(kSm2DigestMessageSize);
  msg.insert(msg.end(), za, za + 32);
  msg.insert(msg.end(), digest, digest + 32);
  return msg;
}

const uint8_t* sm2_device_id() {
  static constexpr uint8_t kDeviceId[kSm2UserIdSize] = {
      'Z', 'K', 'A', 'A', '-', 'D', 'E', 'V',
      'I', 'C', 'E', '-', '0', '0', '0', '1'};
  return kDeviceId;
}

const uint8_t* sm2_agent_id() {
  static constexpr uint8_t kAgentId[kSm2UserIdSize] = {
      'Z', 'K', 'A', 'A', '-', 'A', 'G', 'E',
      'N', 'T', '-', '-', '0', '0', '0', '1'};
  return kAgentId;
}

void fill_delegation_public_inputs(DenseFiller<f_128>& hash_filler,
                                   const Elt& agent_pkX,
                                   const Elt& agent_pkY,
                                   const uint8_t* allowed_claim_hashes,
                                   size_t allowed_claim_count,
                                   const char* policy_expires,
                                   const uint8_t* agent_id_hash,
                                   const uint8_t* requested_claim_hashes,
                                   size_t attrs_len,
                                   const uint8_t* revocation_id,
                                   const uint8_t* revocation_epoch_be,
                                   const char* revocation_expires,
                                   uint8_t revocation_revoked,
                                   const f_128& Fs) {
  uint8_t buf[32];
  field_to_be_bytes(buf, agent_pkX);
  fill_bit_string(hash_filler, buf, 32, 32, Fs);
  field_to_be_bytes(buf, agent_pkY);
  fill_bit_string(hash_filler, buf, 32, 32, Fs);
  hash_filler.push_back(allowed_claim_count, 8, Fs);
  for (size_t i = 0; i < kDelegationMaxClaims; ++i) {
    if (i < allowed_claim_count) {
      fill_bit_string(hash_filler,
                      allowed_claim_hashes + i * kDelegationClaimHashSize,
                      kDelegationClaimHashSize, kDelegationClaimHashSize, Fs);
    } else {
      uint8_t zero[kDelegationClaimHashSize] = {};
      fill_bit_string(hash_filler, zero, kDelegationClaimHashSize,
                      kDelegationClaimHashSize, Fs);
    }
  }
  fill_bit_string(hash_filler, reinterpret_cast<const uint8_t*>(policy_expires),
                  kDelegationExpiresSize, kDelegationExpiresSize, Fs);
  fill_bit_string(hash_filler, agent_id_hash, kDelegationAgentIdHashSize,
                  kDelegationAgentIdHashSize, Fs);
  for (size_t i = 0; i < attrs_len; ++i) {
    fill_bit_string(hash_filler,
                    requested_claim_hashes + i * kDelegationClaimHashSize,
                    kDelegationClaimHashSize, kDelegationClaimHashSize, Fs);
  }
  fill_bit_string(hash_filler, revocation_id, 32, 32, Fs);
  fill_bit_string(hash_filler, revocation_epoch_be,
                  kDelegationRevocationEpochSize,
                  kDelegationRevocationEpochSize, Fs);
  fill_bit_string(hash_filler,
                  reinterpret_cast<const uint8_t*>(revocation_expires),
                  kDelegationExpiresSize, kDelegationExpiresSize, Fs);
  hash_filler.push_back(revocation_revoked, 8, Fs);
}

void fill_delegation_public_inputs_sm2(
    DenseFiller<f_128>& hash_filler, const SM2Elt& agent_pkX,
    const SM2Elt& agent_pkY, const uint8_t* allowed_claim_hashes,
    size_t allowed_claim_count, const char* policy_expires,
    const uint8_t* agent_id_hash, const uint8_t* requested_claim_hashes,
    size_t attrs_len, const uint8_t* revocation_id,
    const uint8_t* revocation_epoch_be, const char* revocation_expires,
    uint8_t revocation_revoked, const f_128& Fs) {
  uint8_t buf[32];
  field_to_be_bytes_for<FpSM2Base>(buf, agent_pkX, sm2_base);
  fill_bit_string(hash_filler, buf, 32, 32, Fs);
  field_to_be_bytes_for<FpSM2Base>(buf, agent_pkY, sm2_base);
  fill_bit_string(hash_filler, buf, 32, 32, Fs);
  hash_filler.push_back(allowed_claim_count, 8, Fs);
  for (size_t i = 0; i < kDelegationMaxClaims; ++i) {
    if (i < allowed_claim_count) {
      fill_bit_string(hash_filler,
                      allowed_claim_hashes + i * kDelegationClaimHashSize,
                      kDelegationClaimHashSize, kDelegationClaimHashSize, Fs);
    } else {
      uint8_t zero[kDelegationClaimHashSize] = {};
      fill_bit_string(hash_filler, zero, kDelegationClaimHashSize,
                      kDelegationClaimHashSize, Fs);
    }
  }
  fill_bit_string(hash_filler, reinterpret_cast<const uint8_t*>(policy_expires),
                  kDelegationExpiresSize, kDelegationExpiresSize, Fs);
  fill_bit_string(hash_filler, agent_id_hash, kDelegationAgentIdHashSize,
                  kDelegationAgentIdHashSize, Fs);
  for (size_t i = 0; i < attrs_len; ++i) {
    fill_bit_string(hash_filler,
                    requested_claim_hashes + i * kDelegationClaimHashSize,
                    kDelegationClaimHashSize, kDelegationClaimHashSize, Fs);
  }
  fill_bit_string(hash_filler, revocation_id, 32, 32, Fs);
  fill_bit_string(hash_filler, revocation_epoch_be,
                  kDelegationRevocationEpochSize,
                  kDelegationRevocationEpochSize, Fs);
  fill_bit_string(hash_filler,
                  reinterpret_cast<const uint8_t*>(revocation_expires),
                  kDelegationExpiresSize, kDelegationExpiresSize, Fs);
  hash_filler.push_back(revocation_revoked, 8, Fs);
}

void fill_delegated_signature_public_inputs(
    DenseFiller<Fp256Base>& sig_filler, const Elt& pkX, const Elt& pkY,
    const Elt& htr, const Elt& agent_pkX, const Elt& agent_pkY,
    const gf2k macs[], gf2k av) {
  fill_signature_inputs(sig_filler, pkX, pkY, htr);
  sig_filler.push_back(agent_pkX);
  sig_filler.push_back(agent_pkY);
  for (size_t i = 0; i < 10; ++i) {
    fill_gf2k<f_128, Fp256Base>(macs[i], sig_filler, p256_base);
  }
  fill_gf2k<f_128, Fp256Base>(av, sig_filler, p256_base);
}

bool fill_delegated_public_inputs(
    DenseFiller<Fp256Base>& sig_filler, DenseFiller<f_128>& hash_filler,
    const Elt& pkX, const Elt& pkY, const Elt& agent_pkX,
    const Elt& agent_pkY, const uint8_t* tr, size_t tr_len,
    const RequestedAttribute* attrs, size_t attrs_len, const uint8_t* now,
    const uint8_t* docType, size_t dt_len, const uint8_t* allowed_hashes,
    size_t allowed_count, const char* policy_expires,
    const uint8_t* agent_id_hash, const uint8_t* requested_hashes,
    const uint8_t* revocation_id, const uint8_t* revocation_epoch_be,
    const char* revocation_expires, uint8_t revocation_revoked,
    const gf2k macs[], gf2k av, const f_128& Fs, size_t version) {
  if (fill_attributes(hash_filler, attrs, attrs_len, now, Fs, version) !=
      MDOC_PROVER_SUCCESS) {
    return false;
  }
  fill_delegation_public_inputs(hash_filler, agent_pkX, agent_pkY,
                                allowed_hashes, allowed_count, policy_expires,
                                agent_id_hash, requested_hashes, attrs_len,
                                revocation_id, revocation_epoch_be,
                                revocation_expires,
                                revocation_revoked, Fs);
  for (size_t i = 0; i < 10; ++i) {
    fill_gf2k<f_128, f_128>(macs[i], hash_filler, Fs);
  }
  fill_gf2k<f_128, f_128>(av, hash_filler, Fs);

  std::vector<uint8_t> docTypeBytes(docType, docType + dt_len);
  Elt htr = p256_base.to_montgomery(
      compute_transcript_hash<N>(tr, tr_len, &docTypeBytes));
  fill_delegated_signature_public_inputs(sig_filler, pkX, pkY, htr, agent_pkX,
                                         agent_pkY, macs, av);
  return true;
}

void fill_sm_mdoc_signature_public_inputs(
    DenseFiller<Fp256Base>& sig_filler, const Elt& pkX, const Elt& pkY,
    const Elt& htr, const gf2k macs[], gf2k av) {
  fill_signature_inputs(sig_filler, pkX, pkY, htr);
  for (size_t i = 0; i < 6; ++i) {
    fill_gf2k<f_128, Fp256Base>(macs[i], sig_filler, p256_base);
  }
  fill_gf2k<f_128, Fp256Base>(macs[10], sig_filler, p256_base);
  fill_gf2k<f_128, Fp256Base>(macs[11], sig_filler, p256_base);
  fill_gf2k<f_128, Fp256Base>(av, sig_filler, p256_base);
}

void fill_sm2_delegation_signature_public_inputs(
    DenseFiller<FpSM2Base>& sig_filler, const SM2Elt& htr,
    const SM2Elt& agent_pkX, const SM2Elt& agent_pkY, const gf2k macs[],
    gf2k av) {
  sig_filler.push_back(sm2_base.one());
  sig_filler.push_back(htr);
  sig_filler.push_back(agent_pkX);
  sig_filler.push_back(agent_pkY);
  fill_gf2k<f_128, FpSM2Base>(macs[6], sig_filler, sm2_base);
  fill_gf2k<f_128, FpSM2Base>(macs[7], sig_filler, sm2_base);
  fill_gf2k<f_128, FpSM2Base>(macs[8], sig_filler, sm2_base);
  fill_gf2k<f_128, FpSM2Base>(macs[9], sig_filler, sm2_base);
  fill_gf2k<f_128, FpSM2Base>(macs[10], sig_filler, sm2_base);
  fill_gf2k<f_128, FpSM2Base>(macs[11], sig_filler, sm2_base);
  fill_gf2k<f_128, FpSM2Base>(av, sig_filler, sm2_base);
}

bool fill_sm_delegated_public_inputs(
    DenseFiller<Fp256Base>& p256_sig_filler,
    DenseFiller<FpSM2Base>& sm2_sig_filler, DenseFiller<f_128>& hash_filler,
    const Elt& pkX, const Elt& pkY, const SM2Elt& agent_pkX,
    const SM2Elt& agent_pkY, const uint8_t* tr, size_t tr_len,
    const RequestedAttribute* attrs, size_t attrs_len, const uint8_t* now,
    const uint8_t* docType, size_t dt_len, const uint8_t* allowed_hashes,
    size_t allowed_count, const char* policy_expires,
    const uint8_t* agent_id_hash, const uint8_t* requested_hashes,
    const uint8_t* revocation_id, const uint8_t* revocation_epoch_be,
    const char* revocation_expires, uint8_t revocation_revoked,
    const gf2k macs[], gf2k av, const f_128& Fs, size_t version) {
  if (fill_attributes(hash_filler, attrs, attrs_len, now, Fs, version) !=
      MDOC_PROVER_SUCCESS) {
    return false;
  }
  fill_delegation_public_inputs_sm2(
      hash_filler, agent_pkX, agent_pkY, allowed_hashes, allowed_count,
      policy_expires, agent_id_hash, requested_hashes, attrs_len, revocation_id,
      revocation_epoch_be, revocation_expires, revocation_revoked, Fs);
  for (size_t i = 0; i < 10; ++i) {
    fill_gf2k<f_128, f_128>(macs[i], hash_filler, Fs);
  }
  fill_gf2k<f_128, f_128>(av, hash_filler, Fs);

  std::vector<uint8_t> docTypeBytes(docType, docType + dt_len);
  Elt p256_htr = p256_base.to_montgomery(
      compute_transcript_hash<N>(tr, tr_len, &docTypeBytes));
  fill_sm_mdoc_signature_public_inputs(p256_sig_filler, pkX, pkY, p256_htr,
                                       macs, av);

  std::vector<uint8_t> da =
      build_device_authentication_bytes(tr, tr_len, &docTypeBytes);
  uint8_t sm3_htr_digest[32];
  if (!sm3_digest_message(da, sm3_htr_digest)) return false;
  std::vector<uint8_t> sm2_agent_msg =
      build_sm2_digest_signature_message_bytes(
          sm3_htr_digest, sm2_agent_id(), agent_pkX, agent_pkY);
  uint8_t sm2_agent_digest[32];
  if (!sm3_digest_message(sm2_agent_msg, sm2_agent_digest)) return false;
  SM2Elt sm2_htr =
      sm2_base.to_montgomery(nat_from_be<SM2N>(sm2_agent_digest));
  fill_sm2_delegation_signature_public_inputs(sm2_sig_filler, sm2_htr,
                                              agent_pkX, agent_pkY, macs, av);
  return true;
}

template <class Field>
void fill_sha_witness(DenseFiller<Field>& filler,
                      const FlatSHA256Witness::BlockWitness& bw,
                      const Field& fn) {
  BitPluckerEncoder<Field, kSHAPluckerBits> BPENC(fn);
  for (size_t k = 0; k < 48; ++k) {
    filler.push_back(BPENC.mkpacked_v32(bw.outw[k]));
  }
  for (size_t k = 0; k < 64; ++k) {
    filler.push_back(BPENC.mkpacked_v32(bw.oute[k]));
    filler.push_back(BPENC.mkpacked_v32(bw.outa[k]));
  }
  for (size_t k = 0; k < 8; ++k) {
    filler.push_back(BPENC.mkpacked_v32(bw.h1[k]));
  }
}

template <class Field>
void fill_sm3_witness(DenseFiller<Field>& filler,
                      const FlatSM3Witness::BlockWitness& bw,
                      const Field& fn) {
  BitPluckerEncoder<Field, kSHAPluckerBits> BPENC(fn);
  for (size_t k = 0; k < 52; ++k) {
    filler.push_back(BPENC.mkpacked_v32(bw.outw[k]));
  }
  for (size_t k = 0; k < 64; ++k) {
    filler.push_back(BPENC.mkpacked_v32(bw.outss1[k]));
    filler.push_back(BPENC.mkpacked_v32(bw.outtt2[k]));
    filler.push_back(BPENC.mkpacked_v32(bw.oute[k]));
    filler.push_back(BPENC.mkpacked_v32(bw.outa[k]));
  }
  for (size_t k = 0; k < 8; ++k) {
    filler.push_back(BPENC.mkpacked_v32(bw.h1[k]));
  }
}

// Fills the hash witness with the attributes and the time input.
MdocProverErrorCode fill_attributes(DenseFiller<f_128>& hash_filler,
                                    const RequestedAttribute* attrs,
                                    size_t attrs_len, const uint8_t* now,
                                    const f_128& Fs, size_t version) {
  hash_filler.push_back(Fs.one());
  for (size_t ai = 0; ai < attrs_len; ++ai) {
    MdocProverErrorCode err =
        fill_attribute(hash_filler, attrs[ai], Fs, version);
    if (err != MDOC_PROVER_SUCCESS) {
      return err;
    }
  }
  fill_bit_string(hash_filler, now, 20, 20, Fs);
  return MDOC_PROVER_SUCCESS;
}

// Fills the signature witness with the public inputs pkX, pkY, and e.
void fill_signature_inputs(DenseFiller<Fp256Base> &sig_filler, const Elt &pkX,
                           const Elt &pkY, const Elt &e) {
  sig_filler.push_back(p256_base.one());
  sig_filler.push_back(pkX);
  sig_filler.push_back(pkY);
  sig_filler.push_back(e);
}

// Fills the public inputs for the hash and signature circuits.
// Empty values for the MAC inputs and AV are used.
bool fill_public_inputs(DenseFiller<Fp256Base> &sig_filler,
                        DenseFiller<f_128> &hash_filler, const Elt &pkX,
                        const Elt &pkY, const uint8_t *tr, size_t tr_len,
                        const RequestedAttribute *attrs, size_t attrs_len,
                        const uint8_t *now, const uint8_t *docType,
                        size_t dt_len, const gf2k macs[], gf2k av,
                        const f_128 &Fs, size_t version) {
  if (fill_attributes(hash_filler, attrs, attrs_len, now, Fs, version) !=
      MDOC_PROVER_SUCCESS) {
    return false;
  }

  for (size_t i = 0; i < 6; ++i) { /* 6 mac + 1 av */
    fill_gf2k<f_128, f_128>(macs[i], hash_filler, Fs);
  }
  fill_gf2k<f_128, f_128>(av, hash_filler, Fs);

  std::vector<uint8_t> docTypeBytes(docType, docType + dt_len);

  // The verify_ecdsa circuit requires that e2 != 0. We consider the pr that the
  // adversary produces a SHA-256 preimage of 0 to be negligible. Thus, we
  // satisfy the pre-condition here by directly computing the transcript hash
  // and assume it is not 0.
  Elt e2 = p256_base.to_montgomery(
      compute_transcript_hash<N>(tr, tr_len, &docTypeBytes));
  fill_signature_inputs(sig_filler, pkX, pkY, e2);

  for (size_t i = 0; i < 6; ++i) {
    fill_gf2k<f_128, Fp256Base>(macs[i], sig_filler, p256_base);
  }
  fill_gf2k<f_128, Fp256Base>(av, sig_filler, p256_base);
  return true;
}

// Fills the hash and signature public inputs and private witnesses.
MdocProverErrorCode fill_witness(
    DenseFiller<Fp256Base>& fill_b, DenseFiller<f_128>& fill_s,
    const uint8_t* mdoc, size_t mdoc_len, const Elt& pkX, const Elt& pkY,
    const uint8_t* tr, size_t tr_len, const RequestedAttribute* attrs,
    size_t attrs_len, const uint8_t* now, ProverState& state,
    SecureRandomEngine& rng, const f_128& Fs, size_t version) {
  using MdocHW = MdocHashWitness<P256, f_128>;
  using MdocSW = MdocSignatureWitness<P256, Fp256Scalar>;

  // Allocate these objects on the heap because Android has a small stack.
  auto hw = std::make_unique<MdocHW>(attrs_len, p256, Fs);
  auto sw = std::make_unique<MdocSW>(p256, p256_scalar, Fs);

  // hash public inputs
  MdocProverErrorCode err =
      fill_attributes(fill_s, attrs, attrs_len, now, Fs, version);
  if (err != MDOC_PROVER_SUCCESS) {
    return err;
  }

  // init mac+av to 0
  for (size_t i = 0; i < 6 + 1; ++i) { /* 6 mac + 1 av */
    fill_gf2k<f_128, f_128>(Fs.zero(), fill_s, Fs);
  }

  MdocProverErrorCode ok_h = hw->compute_witness(mdoc, mdoc_len, tr, tr_len,
                                                 attrs, attrs_len, version);
  if (ok_h != MDOC_PROVER_SUCCESS) return ok_h;

  MdocProverErrorCode ok_s =
      sw->compute_witness(pkX, pkY, mdoc, mdoc_len, tr, tr_len);
  if (ok_s != MDOC_PROVER_SUCCESS) return ok_s;

  // signature public inputs
  fill_signature_inputs(fill_b, pkX, pkY, sw->e2_);
  for (size_t i = 0; i < 7; ++i) {
    fill_gf2k<f_128, Fp256Base>(Fs.zero(), fill_b, p256_base);
  }

  // compute macs
  state = {.common = {hw->e_, hw->dpkx_, hw->dpky_}};
  MACReference<f_128> mac_ref;
  mac_ref.sample(state.ap, 6, &rng);

  uint8_t buf[Fp256Base::kBytes];

  Fp256Base::Elt tt[3] = {hw->e_, hw->dpkx_, hw->dpky_};
  for (size_t i = 0; i < 3; ++i) {
    p256_base.to_bytes_field(buf, tt[i]);
    sw->macs_[i].compute_witness(&state.ap[2 * i], buf);
    state.macs[i].compute_witness(&state.ap[2 * i]);
    fill_bit_string(fill_s, buf, 32, 32, Fs);
  }

  // private witnesses
  hw->fill_witness(fill_s, version);
  for (auto &mac : state.macs) {
    mac.fill_witness(fill_s);
  }

  sw->fill_witness(fill_b);

  return MDOC_PROVER_SUCCESS;
}

MdocProverErrorCode fill_delegated_witness(
    DenseFiller<Fp256Base>& fill_b, DenseFiller<f_128>& fill_s,
    const uint8_t* mdoc, size_t mdoc_len, const Elt& pkX, const Elt& pkY,
    const Elt& agent_pkX, const Elt& agent_pkY, const uint8_t* tr,
    size_t tr_len, const RequestedAttribute* attrs, size_t attrs_len,
    const uint8_t* now, const uint8_t* delegation_sig,
    size_t delegation_sig_len, const uint8_t* agent_sig, size_t agent_sig_len,
    const uint8_t* allowed_hashes, size_t allowed_count,
    const char* policy_expires, const uint8_t* agent_id_hash,
    const uint8_t* requested_hashes, const uint8_t* revocation_id_public,
    const uint8_t* revocation_epoch_be, const char* revocation_expires,
    uint8_t revocation_revoked, const uint8_t* revocation_sig,
    size_t revocation_sig_len,
    DelegatedProverState& state,
    SecureRandomEngine& rng, const f_128& Fs, size_t version) {
  using MdocHW = MdocHashWitness<P256, f_128>;
  using MdocSW = MdocSignatureWitness<P256, Fp256Scalar>;
  using EcdsaWitness = VerifyWitness3<P256, Fp256Scalar>;
  using MacWitnessF = MacWitness<Fp256Base>;

  auto hw = std::make_unique<MdocHW>(attrs_len, p256, Fs);
  auto sw = std::make_unique<MdocSW>(p256, p256_scalar, Fs);

  MdocProverErrorCode err =
      fill_attributes(fill_s, attrs, attrs_len, now, Fs, version);
  if (err != MDOC_PROVER_SUCCESS) {
    return err;
  }
  fill_delegation_public_inputs(fill_s, agent_pkX, agent_pkY, allowed_hashes,
                                allowed_count, policy_expires, agent_id_hash,
                                requested_hashes, attrs_len,
                                revocation_id_public, revocation_epoch_be,
                                revocation_expires, revocation_revoked, Fs);
  for (size_t i = 0; i < 10 + 1; ++i) {
    fill_gf2k<f_128, f_128>(Fs.zero(), fill_s, Fs);
  }

  MdocProverErrorCode ok_h = hw->compute_witness(mdoc, mdoc_len, tr, tr_len,
                                                 attrs, attrs_len, version);
  if (ok_h != MDOC_PROVER_SUCCESS) return ok_h;

  MdocProverErrorCode ok_s =
      sw->compute_witness(pkX, pkY, mdoc, mdoc_len, tr, tr_len);
  if (ok_s != MDOC_PROVER_SUCCESS) return ok_s;

  std::vector<uint8_t> delegation_msg = build_delegation_message_bytes(
      agent_pkX, agent_pkY, allowed_hashes, allowed_count, policy_expires,
      agent_id_hash);
  uint8_t delegation_digest[kSHA256DigestSize];
  SHA256 delegation_sha;
  delegation_sha.Update(delegation_msg.data(), delegation_msg.size());
  delegation_sha.DigestData(delegation_digest);
  N delegation_ne = nat_from_be<N>(delegation_digest);
  Elt delegation_e = p256_base.to_montgomery(delegation_ne);

  std::vector<uint8_t> revocation_id_msg =
      build_revocation_id_message_bytes(delegation_digest);
  uint8_t revocation_id[kSHA256DigestSize];
  SHA256 revocation_id_sha;
  revocation_id_sha.Update(revocation_id_msg.data(), revocation_id_msg.size());
  revocation_id_sha.DigestData(revocation_id);
  if (std::memcmp(revocation_id, revocation_id_public, kSHA256DigestSize) != 0) {
    return MDOC_PROVER_INVALID_INPUT;
  }

  std::vector<uint8_t> revocation_status_msg =
      build_revocation_status_message_bytes(revocation_id, revocation_epoch_be,
                                            revocation_expires,
                                            revocation_revoked);
  uint8_t revocation_status_digest[kSHA256DigestSize];
  SHA256 revocation_status_sha;
  revocation_status_sha.Update(revocation_status_msg.data(),
                               revocation_status_msg.size());
  revocation_status_sha.DigestData(revocation_status_digest);
  N revocation_status_ne = nat_from_be<N>(revocation_status_digest);
  Elt revocation_status_e = p256_base.to_montgomery(revocation_status_ne);

  N del_r, del_s, agent_r, agent_s, rev_r, rev_s;
  if (!parse_signature_rs(delegation_sig, delegation_sig_len, &del_r, &del_s) ||
      !parse_signature_rs(agent_sig, agent_sig_len, &agent_r, &agent_s) ||
      !parse_signature_rs(revocation_sig, revocation_sig_len, &rev_r, &rev_s)) {
    return MDOC_PROVER_INVALID_INPUT;
  }

  EcdsaWitness delegation_w(p256_scalar, p256);
  if (!delegation_w.compute_witness(sw->dpkx_, sw->dpky_, delegation_ne, del_r,
                                    del_s)) {
    return MDOC_PROVER_SIGNATURE_FAILURE;
  }
  EcdsaWitness revocation_w(p256_scalar, p256);
  if (!revocation_w.compute_witness(sw->dpkx_, sw->dpky_,
                                    revocation_status_ne, rev_r, rev_s)) {
    return MDOC_PROVER_SIGNATURE_FAILURE;
  }
  N agent_ne = compute_transcript_hash<N>(tr, tr_len, &hw->pm_.doc_type_);
  EcdsaWitness agent_w(p256_scalar, p256);
  if (!agent_w.compute_witness(agent_pkX, agent_pkY, agent_ne, agent_r,
                               agent_s)) {
    return MDOC_PROVER_SIGNATURE_FAILURE;
  }

  gf2k zero_macs[10];
  for (auto& m : zero_macs) {
    m = Fs.zero();
  }
  fill_delegated_signature_public_inputs(fill_b, pkX, pkY, sw->e2_, agent_pkX,
                                         agent_pkY, zero_macs, Fs.zero());

  state = {.common = {hw->e_, hw->dpkx_, hw->dpky_, delegation_e,
                      revocation_status_e}};
  MACReference<f_128> mac_ref;
  mac_ref.sample(state.ap, 10, &rng);

  uint8_t buf[Fp256Base::kBytes];
  Fp256Base::Elt tt[5] = {hw->e_, hw->dpkx_, hw->dpky_, delegation_e,
                          revocation_status_e};
  for (size_t i = 0; i < 3; ++i) {
    p256_base.to_bytes_field(buf, tt[i]);
    sw->macs_[i].compute_witness(&state.ap[2 * i], buf);
    state.macs[i].compute_witness(&state.ap[2 * i]);
    fill_bit_string(fill_s, buf, 32, 32, Fs);
  }
  p256_base.to_bytes_field(buf, delegation_e);
  MacWitnessF delegation_mac(p256_base, Fs);
  delegation_mac.compute_witness(&state.ap[6], buf);
  state.macs[3].compute_witness(&state.ap[6]);
  fill_bit_string(fill_s, buf, 32, 32, Fs);
  p256_base.to_bytes_field(buf, revocation_status_e);
  MacWitnessF revocation_status_mac(p256_base, Fs);
  revocation_status_mac.compute_witness(&state.ap[8], buf);
  state.macs[4].compute_witness(&state.ap[8]);
  fill_bit_string(fill_s, buf, 32, 32, Fs);

  hw->fill_witness(fill_s, version);

  uint8_t delegation_nb;
  uint8_t delegation_in[kDelegationMsgSHABlocks * 64];
  FlatSHA256Witness::BlockWitness delegation_bw[kDelegationMsgSHABlocks];
  FlatSHA256Witness::transform_and_witness_message(
      delegation_msg.size(), delegation_msg.data(), kDelegationMsgSHABlocks,
      delegation_nb, delegation_in, delegation_bw);
  for (size_t i = 0; i < kDelegationMsgSHABlocks; ++i) {
    fill_sha_witness(fill_s, delegation_bw[i], Fs);
  }
  uint8_t revocation_id_nb;
  uint8_t revocation_id_in[kDelegationRevocationIdSHABlocks * 64];
  FlatSHA256Witness::BlockWitness
      revocation_id_bw[kDelegationRevocationIdSHABlocks];
  FlatSHA256Witness::transform_and_witness_message(
      revocation_id_msg.size(), revocation_id_msg.data(),
      kDelegationRevocationIdSHABlocks, revocation_id_nb, revocation_id_in,
      revocation_id_bw);
  for (size_t i = 0; i < kDelegationRevocationIdSHABlocks; ++i) {
    fill_sha_witness(fill_s, revocation_id_bw[i], Fs);
  }
  uint8_t revocation_status_nb;
  uint8_t revocation_status_in[kDelegationRevocationStatusSHABlocks * 64];
  FlatSHA256Witness::BlockWitness
      revocation_status_bw[kDelegationRevocationStatusSHABlocks];
  FlatSHA256Witness::transform_and_witness_message(
      revocation_status_msg.size(), revocation_status_msg.data(),
      kDelegationRevocationStatusSHABlocks, revocation_status_nb,
      revocation_status_in, revocation_status_bw);
  for (size_t i = 0; i < kDelegationRevocationStatusSHABlocks; ++i) {
    fill_sha_witness(fill_s, revocation_status_bw[i], Fs);
  }

  for (auto& mac : state.macs) {
    mac.fill_witness(fill_s);
  }

  sw->fill_witness(fill_b);
  fill_b.push_back(delegation_e);
  fill_b.push_back(revocation_status_e);
  delegation_w.fill_witness(fill_b);
  revocation_w.fill_witness(fill_b);
  agent_w.fill_witness(fill_b);
  delegation_mac.fill_witness(fill_b);
  revocation_status_mac.fill_witness(fill_b);

  return MDOC_PROVER_SUCCESS;
}

MdocProverErrorCode fill_sm_delegated_witness(
    DenseFiller<Fp256Base>& p256_fill, DenseFiller<FpSM2Base>& sm2_fill,
    DenseFiller<f_128>& hash_fill, const uint8_t* mdoc, size_t mdoc_len,
    const Elt& pkX, const Elt& pkY, const char* device_sk_hex,
    const SM2Elt& agent_pkX, const SM2Elt& agent_pkY, const uint8_t* tr,
    size_t tr_len, const RequestedAttribute* attrs, size_t attrs_len,
    const uint8_t* now, const uint8_t* delegation_sig,
    size_t delegation_sig_len, const uint8_t* agent_sig, size_t agent_sig_len,
    const uint8_t* allowed_hashes, size_t allowed_count,
    const char* policy_expires, const uint8_t* agent_id_hash,
    const uint8_t* requested_hashes, const uint8_t* revocation_id_public,
    const uint8_t* revocation_epoch_be, const char* revocation_expires,
    uint8_t revocation_revoked, const uint8_t* revocation_sig,
    size_t revocation_sig_len, SmDelegatedProverState& state,
    SecureRandomEngine& rng, const f_128& Fs, size_t version) {
  using MdocHW = MdocHashWitness<P256, f_128>;
  using MdocSW = MdocSignatureWitness<P256, Fp256Scalar>;
  using P256PkWitness = PkWitness<P256, Fp256Scalar>;
  using SM2PkWitness = PkWitness<SM2, FpSM2Scalar>;
  using SM2SigWitness = VerifyWitness3<SM2, FpSM2Scalar>;
  using P256MacWitness = MacWitness<Fp256Base>;
  using SM2MacWitness = MacWitness<FpSM2Base>;

  auto hw = std::make_unique<MdocHW>(attrs_len, p256, Fs);
  auto sw = std::make_unique<MdocSW>(p256, p256_scalar, Fs);

  MdocProverErrorCode ok_h = hw->compute_witness(mdoc, mdoc_len, tr, tr_len,
                                                 attrs, attrs_len, version);
  if (ok_h != MDOC_PROVER_SUCCESS) return ok_h;
  MdocProverErrorCode ok_s =
      sw->compute_witness(pkX, pkY, mdoc, mdoc_len, tr, tr_len);
  if (ok_s != MDOC_PROVER_SUCCESS) return ok_s;

  N p256_sk;
  SM2N sm2_sk;
  Elt p256_sk_e;
  SM2Elt sm2_sk_e;
  if (!parse_device_sk(device_sk_hex, &p256_sk, &sm2_sk, &p256_sk_e,
                       &sm2_sk_e)) {
    log(ERROR, "invalid SM device secret key");
    return MDOC_PROVER_INVALID_INPUT;
  }

  P256PkWitness p256_pk_w(p256_scalar, p256);
  if (!p256_pk_w.compute_witness(p256_sk)) {
    return MDOC_PROVER_WITNESS_CREATION_FAILURE;
  }
  SM2PkWitness sm2_pk_w(sm2_scalar, sm2);
  if (!sm2_pk_w.compute_witness(sm2_sk)) {
    return MDOC_PROVER_WITNESS_CREATION_FAILURE;
  }
  auto sm2_device_pk = sm2.scalar_multf(sm2.generator(), sm2_sk);
  sm2.normalize(sm2_device_pk);

  std::vector<uint8_t> delegation_msg =
      build_delegation_message_bytes<FpSM2Base>(
          agent_pkX, agent_pkY, allowed_hashes, allowed_count, policy_expires,
          agent_id_hash, sm2_base);
  uint8_t delegation_digest[32];
  if (!sm3_digest_message(delegation_msg, delegation_digest)) {
    log(ERROR, "failed to compute SM3 delegation digest, msg_size=%zu",
        delegation_msg.size());
    return MDOC_PROVER_INVALID_INPUT;
  }
  std::vector<uint8_t> delegation_sig_msg =
      build_sm2_digest_signature_message_bytes(
          delegation_digest, sm2_device_id(), sm2_device_pk.x,
          sm2_device_pk.y);
  uint8_t delegation_sig_digest[32];
  if (!sm3_digest_message(delegation_sig_msg, delegation_sig_digest)) {
    log(ERROR, "failed to compute SM2 delegation signature digest");
    return MDOC_PROVER_INVALID_INPUT;
  }
  SM2N delegation_ne = nat_from_be<SM2N>(delegation_sig_digest);
  SM2Elt delegation_e_sm2 = sm2_base.to_montgomery(delegation_ne);
  Elt delegation_e_p256 =
      p256_base.to_montgomery(nat_from_be<N>(delegation_sig_digest));

  std::vector<uint8_t> revocation_id_msg =
      build_revocation_id_message_bytes(delegation_digest);
  uint8_t revocation_id[32];
  if (!sm3_digest_message(revocation_id_msg, revocation_id)) {
    log(ERROR, "failed to compute SM3 revocation id");
    return MDOC_PROVER_INVALID_INPUT;
  }
  if (std::memcmp(revocation_id, revocation_id_public, 32) != 0) {
    log(ERROR, "SM3 revocation id mismatch");
    return MDOC_PROVER_INVALID_INPUT;
  }

  std::vector<uint8_t> revocation_status_msg =
      build_revocation_status_message_bytes(revocation_id, revocation_epoch_be,
                                            revocation_expires,
                                            revocation_revoked);
  uint8_t revocation_status_digest[32];
  if (!sm3_digest_message(revocation_status_msg, revocation_status_digest)) {
    log(ERROR, "failed to compute SM3 revocation status digest");
    return MDOC_PROVER_INVALID_INPUT;
  }
  std::vector<uint8_t> revocation_sig_msg =
      build_sm2_digest_signature_message_bytes(
          revocation_status_digest, sm2_device_id(), sm2_device_pk.x,
          sm2_device_pk.y);
  uint8_t revocation_sig_digest[32];
  if (!sm3_digest_message(revocation_sig_msg, revocation_sig_digest)) {
    log(ERROR, "failed to compute SM2 revocation signature digest");
    return MDOC_PROVER_INVALID_INPUT;
  }
  SM2N revocation_status_ne = nat_from_be<SM2N>(revocation_sig_digest);
  SM2Elt revocation_status_e_sm2 =
      sm2_base.to_montgomery(revocation_status_ne);
  Elt revocation_status_e_p256 =
      p256_base.to_montgomery(nat_from_be<N>(revocation_sig_digest));

  std::vector<uint8_t> da =
      build_device_authentication_bytes(tr, tr_len, &hw->pm_.doc_type_);
  uint8_t agent_digest[32];
  if (!sm3_digest_message(da, agent_digest)) {
    log(ERROR, "failed to compute SM3 agent digest");
    return MDOC_PROVER_INVALID_INPUT;
  }
  std::vector<uint8_t> agent_sig_msg =
      build_sm2_digest_signature_message_bytes(agent_digest, sm2_agent_id(),
                                               agent_pkX, agent_pkY);
  uint8_t agent_sig_digest[32];
  if (!sm3_digest_message(agent_sig_msg, agent_sig_digest)) {
    log(ERROR, "failed to compute SM2 agent signature digest");
    return MDOC_PROVER_INVALID_INPUT;
  }
  SM2N agent_ne = nat_from_be<SM2N>(agent_sig_digest);
  SM2Elt agent_e_sm2 = sm2_base.to_montgomery(agent_ne);

  SM2N del_r, del_s, agent_r, agent_s, rev_r, rev_s;
  if (!parse_sm2_signature_rs(delegation_sig, delegation_sig_len, &del_r,
                              &del_s) ||
      !parse_sm2_signature_rs(agent_sig, agent_sig_len, &agent_r, &agent_s) ||
      !parse_sm2_signature_rs(revocation_sig, revocation_sig_len, &rev_r,
                              &rev_s)) {
    log(ERROR, "failed to parse SM2 signatures");
    return MDOC_PROVER_INVALID_INPUT;
  }

  SM2SigWitness delegation_w(sm2_scalar, sm2);
  if (!delegation_w.compute_sm2_witness(sm2_device_pk.x, sm2_device_pk.y,
                                        delegation_ne, del_r, del_s)) {
    log(ERROR, "SM2 delegation signature witness failed");
    return MDOC_PROVER_SIGNATURE_FAILURE;
  }
  SM2SigWitness revocation_w(sm2_scalar, sm2);
  if (!revocation_w.compute_sm2_witness(sm2_device_pk.x, sm2_device_pk.y,
                                        revocation_status_ne, rev_r, rev_s)) {
    log(ERROR, "SM2 revocation signature witness failed");
    return MDOC_PROVER_SIGNATURE_FAILURE;
  }
  SM2SigWitness agent_w(sm2_scalar, sm2);
  if (!agent_w.compute_sm2_witness(agent_pkX, agent_pkY, agent_ne, agent_r,
                                   agent_s)) {
    log(ERROR, "SM2 agent signature witness failed");
    return MDOC_PROVER_SIGNATURE_FAILURE;
  }

  gf2k zero_macs[12];
  for (auto& m : zero_macs) {
    m = Fs.zero();
  }
  fill_sm_delegated_public_inputs(
      p256_fill, sm2_fill, hash_fill, pkX, pkY, agent_pkX, agent_pkY, tr,
      tr_len, attrs, attrs_len, now, hw->pm_.doc_type_.data(),
      hw->pm_.doc_type_.size(), allowed_hashes, allowed_count, policy_expires,
      agent_id_hash, requested_hashes, revocation_id_public,
      revocation_epoch_be, revocation_expires, revocation_revoked, zero_macs,
      Fs.zero(), Fs, version);

  state = {.p256_common = {hw->e_, hw->dpkx_, hw->dpky_, delegation_e_p256,
                           revocation_status_e_p256, p256_sk_e},
           .sm2_common = {delegation_e_sm2, revocation_status_e_sm2,
                          sm2_sk_e}};
  MACReference<f_128> mac_ref;
  mac_ref.sample(state.ap, 12, &rng);

  uint8_t buf[Fp256Base::kBytes];
  for (size_t i = 0; i < 3; ++i) {
    p256_base.to_bytes_field(buf, state.p256_common[i]);
    sw->macs_[i].compute_witness(&state.ap[2 * i], buf);
    state.hash_macs[i].compute_witness(&state.ap[2 * i]);
    fill_bit_string(hash_fill, buf, 32, 32, Fs);
  }
  p256_base.to_bytes_field(buf, delegation_e_p256);
  state.hash_macs[3].compute_witness(&state.ap[6]);
  fill_bit_string(hash_fill, buf, 32, 32, Fs);
  p256_base.to_bytes_field(buf, revocation_status_e_p256);
  state.hash_macs[4].compute_witness(&state.ap[8]);
  fill_bit_string(hash_fill, buf, 32, 32, Fs);
  uint8_t sm2_pk_buf[FpSM2Base::kBytes];
  field_to_be_bytes_for<FpSM2Base>(sm2_pk_buf, sm2_device_pk.x, sm2_base);
  fill_bit_string(hash_fill, sm2_pk_buf, 32, 32, Fs);
  field_to_be_bytes_for<FpSM2Base>(sm2_pk_buf, sm2_device_pk.y, sm2_base);
  fill_bit_string(hash_fill, sm2_pk_buf, 32, 32, Fs);

  hw->fill_witness(hash_fill, version);

  uint8_t delegation_nb;
  uint8_t delegation_in[kDelegationMsgSHABlocks * 64];
  FlatSM3Witness::BlockWitness delegation_bw[kDelegationMsgSHABlocks];
  FlatSM3Witness::transform_and_witness_message(
      delegation_msg.size(), delegation_msg.data(), kDelegationMsgSHABlocks,
      delegation_nb, delegation_in, delegation_bw);
  for (size_t i = 0; i < kDelegationMsgSHABlocks; ++i) {
    fill_sm3_witness(hash_fill, delegation_bw[i], Fs);
  }
  const std::vector<uint8_t> device_za_msg =
      build_sm2_za_message_bytes(sm2_device_id(), sm2_device_pk.x,
                                 sm2_device_pk.y);
  uint8_t device_za_nb;
  uint8_t device_za_in[kSm2ZaMessageSM3Blocks * 64];
  FlatSM3Witness::BlockWitness device_za_bw[kSm2ZaMessageSM3Blocks];
  FlatSM3Witness::transform_and_witness_message(
      device_za_msg.size(), device_za_msg.data(), kSm2ZaMessageSM3Blocks,
      device_za_nb, device_za_in, device_za_bw);
  for (size_t i = 0; i < kSm2ZaMessageSM3Blocks; ++i) {
    fill_sm3_witness(hash_fill, device_za_bw[i], Fs);
  }
  uint8_t delegation_sig_nb;
  uint8_t delegation_sig_in[kSm2DigestMessageSM3Blocks * 64];
  FlatSM3Witness::BlockWitness
      delegation_sig_bw[kSm2DigestMessageSM3Blocks];
  FlatSM3Witness::transform_and_witness_message(
      delegation_sig_msg.size(), delegation_sig_msg.data(),
      kSm2DigestMessageSM3Blocks, delegation_sig_nb, delegation_sig_in,
      delegation_sig_bw);
  for (size_t i = 0; i < kSm2DigestMessageSM3Blocks; ++i) {
    fill_sm3_witness(hash_fill, delegation_sig_bw[i], Fs);
  }
  uint8_t revocation_id_nb;
  uint8_t revocation_id_in[kDelegationRevocationIdSHABlocks * 64];
  FlatSM3Witness::BlockWitness
      revocation_id_bw[kDelegationRevocationIdSHABlocks];
  FlatSM3Witness::transform_and_witness_message(
      revocation_id_msg.size(), revocation_id_msg.data(),
      kDelegationRevocationIdSHABlocks, revocation_id_nb, revocation_id_in,
      revocation_id_bw);
  for (size_t i = 0; i < kDelegationRevocationIdSHABlocks; ++i) {
    fill_sm3_witness(hash_fill, revocation_id_bw[i], Fs);
  }
  uint8_t revocation_status_nb;
  uint8_t revocation_status_in[kDelegationRevocationStatusSHABlocks * 64];
  FlatSM3Witness::BlockWitness
      revocation_status_bw[kDelegationRevocationStatusSHABlocks];
  FlatSM3Witness::transform_and_witness_message(
      revocation_status_msg.size(), revocation_status_msg.data(),
      kDelegationRevocationStatusSHABlocks, revocation_status_nb,
      revocation_status_in, revocation_status_bw);
  for (size_t i = 0; i < kDelegationRevocationStatusSHABlocks; ++i) {
    fill_sm3_witness(hash_fill, revocation_status_bw[i], Fs);
  }
  uint8_t revocation_sig_nb;
  uint8_t revocation_sig_in[kSm2DigestMessageSM3Blocks * 64];
  FlatSM3Witness::BlockWitness
      revocation_sig_bw[kSm2DigestMessageSM3Blocks];
  FlatSM3Witness::transform_and_witness_message(
      revocation_sig_msg.size(), revocation_sig_msg.data(),
      kSm2DigestMessageSM3Blocks, revocation_sig_nb, revocation_sig_in,
      revocation_sig_bw);
  for (size_t i = 0; i < kSm2DigestMessageSM3Blocks; ++i) {
    fill_sm3_witness(hash_fill, revocation_sig_bw[i], Fs);
  }
  for (auto& mac : state.hash_macs) {
    mac.fill_witness(hash_fill);
  }

  sw->fill_witness(p256_fill);
  P256MacWitness p256_sk_mac(p256_base, Fs);
  p256_base.to_bytes_field(buf, p256_sk_e);
  p256_sk_mac.compute_witness(&state.ap[10], buf);
  p256_pk_w.fill_witness(p256_fill);
  p256_sk_mac.fill_witness(p256_fill);

  uint8_t sm2_buf[FpSM2Base::kBytes];
  sm2_fill.push_back(sm2_device_pk.x);
  sm2_fill.push_back(sm2_device_pk.y);
  sm2_fill.push_back(delegation_e_sm2);
  sm2_fill.push_back(revocation_status_e_sm2);
  delegation_w.fill_sm2_witness(sm2_fill);
  revocation_w.fill_sm2_witness(sm2_fill);
  agent_w.fill_sm2_witness(sm2_fill);
  SM2MacWitness delegation_mac(sm2_base, Fs);
  sm2_base.to_bytes_field(sm2_buf, delegation_e_sm2);
  delegation_mac.compute_witness(&state.ap[6], sm2_buf);
  SM2MacWitness revocation_mac(sm2_base, Fs);
  sm2_base.to_bytes_field(sm2_buf, revocation_status_e_sm2);
  revocation_mac.compute_witness(&state.ap[8], sm2_buf);
  delegation_mac.fill_witness(sm2_fill);
  revocation_mac.fill_witness(sm2_fill);
  SM2MacWitness sm2_sk_mac(sm2_base, Fs);
  sm2_base.to_bytes_field(sm2_buf, sm2_sk_e);
  sm2_sk_mac.compute_witness(&state.ap[10], sm2_buf);
  sm2_pk_w.fill_witness(sm2_fill);
  sm2_sk_mac.fill_witness(sm2_fill);

  return MDOC_PROVER_SUCCESS;
}

gf2k generate_mac_key(Transcript &t) {
  f_128 gf;
  uint8_t buf[f_128::kBytes];
  t.bytes(buf, f_128::kBytes);
  return gf.of_bytes_field(buf).value();
}

// Updates the dense input array with a mac.The location
// of the start of the macs+av inputs must be passed in as (si, hi).
void update_mac_in_dense(Dense<Fp256Base> &W_sig, Dense<f_128> &W_hash,
                         size_t &si, size_t &hi, const gf2k mac,
                         const f_128 &Fs) {
  for (size_t j = 0; j < f_128::kBits; ++j) {
    W_sig.v_[si++] = mac[j] ? p256_base.one() : p256_base.zero();
  }
  W_hash.v_[hi++] = mac;
}

template <class Field>
void update_mac_in_prime_dense(Dense<Field>& W_sig, size_t& si,
                               const gf2k mac, const Field& field) {
  for (size_t j = 0; j < f_128::kBits; ++j) {
    W_sig.v_[si++] = mac[j] ? field.one() : field.zero();
  }
}

// Updates all macs in both dense arrays. The (si,hi) should be the index
// of the first mac in the respective dense arrays.
void update_macs(Dense<Fp256Base> &W_sig, Dense<f_128> &W_hash, size_t si,
                 size_t hi, const gf2k macs[], gf2k av, const f_128 &Fs) {
  for (size_t mi = 0; mi < 6; ++mi) {
    update_mac_in_dense(W_sig, W_hash, si, hi, macs[mi], Fs);
  }
  update_mac_in_dense(W_sig, W_hash, si, hi, av, Fs);
}

void update_macs_count(Dense<Fp256Base>& W_sig, Dense<f_128>& W_hash,
                       size_t si, size_t hi, const gf2k macs[], size_t nmacs,
                       gf2k av, const f_128& Fs) {
  for (size_t mi = 0; mi < nmacs; ++mi) {
    update_mac_in_dense(W_sig, W_hash, si, hi, macs[mi], Fs);
  }
  update_mac_in_dense(W_sig, W_hash, si, hi, av, Fs);
}

template <class Field>
void update_prime_macs_count(Dense<Field>& W_sig, size_t si,
                             const gf2k macs[], size_t nmacs, gf2k av,
                             const Field& field) {
  for (size_t mi = 0; mi < nmacs; ++mi) {
    update_mac_in_prime_dense(W_sig, si, macs[mi], field);
  }
  update_mac_in_prime_dense(W_sig, si, av, field);
}

bool parsePk(const char *pkx, const char *pky, Elt &pkX, Elt &pkY) {
  auto maybe_x = p256_base.of_untrusted_string(pkx);
  auto maybe_y = p256_base.of_untrusted_string(pky);
  if (!maybe_x.has_value() || !maybe_y.has_value()) {
    return false;
  }
  pkX = maybe_x.value();
  pkY = maybe_y.value();
  return true;
}

bool parsePkSm2(const char* pkx, const char* pky, SM2Elt& pkX,
                SM2Elt& pkY) {
  auto maybe_x = sm2_base.of_untrusted_string(pkx);
  auto maybe_y = sm2_base.of_untrusted_string(pky);
  if (!maybe_x.has_value() || !maybe_y.has_value()) {
    return false;
  }
  pkX = maybe_x.value();
  pkY = maybe_y.value();
  return true;
}

bool sameNamespace(const RequestedAttribute attrs[/*n*/], size_t n) {
  for (size_t i = 1; i < n; ++i) {
    if (attrs[i].namespace_len != attrs[0].namespace_len ||
        memcmp(attrs[i].namespace_id, attrs[0].namespace_id,
               attrs[0].namespace_len) != 0) {
      return false;
    }
  }
  return true;
}

// Validates that the input is a valid CBOR encoding of one of the following:
// - String (TEXT)
// - Boolean (PRIMITIVE TRUE/FALSE)
// - Integer (UNSIGNED/NEGATIVE)
// - Binary String (BYTES)
// - Fulldate (TAG 1004) -> must be 14 bytes total
// - Tdate (TAG 0) -> must be 22 bytes total
bool cbor_validate(const uint8_t* in, size_t len) {
  uint8_t dummy[1];  // For 0-length checks if needed, though len > 0 usually
  const uint8_t* buf = in ? in : dummy;
  size_t pos = 0;
  CborDoc doc;

  if (!doc.decode(buf, len, pos, 0)) {
    return false;
  }

  // Ensure we consumed the entire buffer
  if (pos != len) {
    return false;
  }

  switch (doc.t_) {
    case TEXT:
    case BYTES:
    case UNSIGNED:
    case NEGATIVE:
      return true;

    case PRIMITIVE:
      return (doc.u_.p == CTRUE || doc.u_.p == CFALSE);

    case TAG: {
      // items.n is the tag value
      size_t tag = doc.u_.items.n;
      if (tag == 1004) {  // Fulldate
        if (len != 14) return false;
        // Check inner type is TEXT? CborDoc handles valid children decode.
        // host_decoder.h: case 6 (TAG) ... decode_items ...
        // We know it has 1 child.
        if (doc.children_.empty() || doc.children_[0].t_ != TEXT) return false;
        return true;
      }
      if (tag == 0) {  // Tdate
        if (len != 22) return false;
        if (doc.children_.empty() || doc.children_[0].t_ != TEXT) return false;
        return true;
      }
      return false;
    }

    default:
      return false;
  }
}

// =========== End of helper functions =====================
extern "C" {
/*
API version that uses 2 circuits over different fields.
*/
using MdocSWw = MdocSignatureWitness<P256, Fp256Scalar>;

// Main endpoint for producing a ZK proof for mdoc properties.
// This implementation uses 2 separate circuits over 2 fields to verify
// the signature and the hash components of the mdoc.
// It is the caller's job to free the memory pointed to by prf.
MdocProverErrorCode run_mdoc_prover(
    const uint8_t *bcp, size_t bcsz, /* circuit data */
    const uint8_t *mdoc, size_t mdoc_len, const char *pkx,
    const char *pky,                          /* string rep of public key */
    const uint8_t *transcript, size_t tr_len, /* session transcript */
    const RequestedAttribute *attrs, size_t attrs_len,
    const char *now, /* time formatted as "2023-11-02T09:00:00Z" */
    uint8_t **prf, size_t *proof_len, const ZkSpecStruct *zk_spec) {
  if (bcp == nullptr || mdoc == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || attrs == nullptr || now == nullptr ||
      prf == nullptr || proof_len == nullptr || zk_spec == nullptr) {
    return MDOC_PROVER_NULL_INPUT;
  }

  Elt pkX, pkY;
  if (!parsePk(pkx, pky, pkX, pkY)) {
    log(ERROR, "invalid pkx, pky");
    return MDOC_PROVER_INVALID_INPUT;
  }

  if (!sameNamespace(attrs, attrs_len)) {
    log(ERROR, "attributes must all be in the same namespace");
    return MDOC_PROVER_INVALID_INPUT;
  }

  // Parse circuits from cached byte representation.
  const f2_p256 p256_2(p256_base);
  const f_128 Fs;

  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, bcp, bcsz);

  if (full_size == 0) {
    return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
  }

  log(INFO, "bytes len: %zu", full_size);
  ReadBuffer rb_circuit(bytes.data(), full_size);

  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
  if (c_sig == nullptr) {
    log(ERROR, "signature circuit could not be parsed");
    return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
  }
  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_prover);

  if (c_hash == nullptr) {
    log(ERROR, "hash circuit could not be parsed");
    return MDOC_PROVER_HASH_PARSING_FAILURE;
  }
  log(INFO, "circuit created. h[in:%zu q:%zu], s[in:%zu q:%zu]",
      c_hash->ninputs, c_hash->nl, c_sig->ninputs, c_sig->nl);

  //  ============ Produce zk witness ==============
  auto W_sig = Dense<Fp256Base>(1, c_sig->ninputs);
  auto W_hash = Dense<f_128>(1, c_hash->ninputs);
  DenseFiller<Fp256Base> sig_filler(W_sig);
  DenseFiller<f_128> hash_filler(W_hash);

  SecureRandomEngine rng;
  ProverState state;
  MdocProverErrorCode ok = fill_witness(
      sig_filler, hash_filler, mdoc, mdoc_len, pkX, pkY, transcript, tr_len,
      attrs, attrs_len, (const uint8_t*)now, state, rng, Fs, zk_spec->version);
  if (ok != MDOC_PROVER_SUCCESS) {
    log(ERROR, "fill_witness failed");
    return ok;
  }

  // ========= Run prover ==============
  // Use the transcript from the session to select the random oracle.
  Transcript tp(transcript, tr_len, zk_spec->version);

  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);

  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> h_zk(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> sig_zk(*c_sig, r, req, zk_spec->block_enc_sig);

  ZkProver<f_128, RSFactory> hash_p(*c_hash, Fs, the_reed_solomon_factory);
  ZkProver<Fp256Base, RSFactory_b> sig_p(*c_sig, p256_base, rsf_b);

  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(sig_zk, W_sig, tp, rng);

  log(INFO,
      "commit created. h[nl:%zu, ni:%zu], s[nl:%zu, ni:%zu] hc[b:%zu r:%zu] "
      "sc[b:%zu r:%zu]",
      c_hash->nl, c_hash->ninputs, c_sig->nl, c_sig->ninputs, h_zk.param.block,
      h_zk.param.nrow, sig_zk.param.block, sig_zk.param.nrow);

  // After prover has committed to the public inputs, compute
  // verifier challenge av, and then compute MACs of the common public
  // inputs.

  gf2k av = generate_mac_key(tp), macs[6];
  uint8_t macs_b[6 * f_128::kBytes];
  compute_macs(3, state.common, macs, macs_b, state.ap, av);
  update_macs(W_sig, W_hash, kSigMacIndex,
              getHashMacIndex(attrs_len, zk_spec->version), macs, av, Fs);

  if (!hash_p.prove(h_zk, W_hash, tp)) {
    return MDOC_PROVER_GENERAL_FAILURE;
  };
  log(INFO, "ZK hash proof done");

  if (!sig_p.prove(sig_zk, W_sig, tp)) {
    return MDOC_PROVER_GENERAL_FAILURE;
  };
  log(INFO, "ZK signature proof done");

  // Serialize proof to bytes.
  // [6 mac values] [docType] [hash proof] [sig proof]
  std::vector<uint8_t> buf;
  // This sum will not overflow based on constraints of circuit & proof size.
  size_t tt = 6 * f_128::kBytes + h_zk.size() + sig_zk.size();
  buf.reserve(tt);
  buf.insert(buf.begin(), macs_b, macs_b + 6 * f_128::kBytes);
  h_zk.write(buf, Fs);
  sig_zk.write(buf, p256_base);
  *proof_len = buf.size();
  log(INFO, "proof_len: %zu ", *proof_len);

  // Allocate memory and copy proof bytes.
  *prf = (uint8_t *)malloc(*proof_len);
  if (!prf) {
    log(ERROR, "malloc failed");
    return MDOC_PROVER_MEMORY_ALLOCATION_FAILURE;
  }
  memcpy(*prf, buf.data(), buf.size());
  return MDOC_PROVER_SUCCESS;
}

MdocVerifierErrorCode run_mdoc_verifier(
    const uint8_t *bcp, size_t bcsz,          /* circuit data */
    const char *pkx, const char *pky,         /* string rep of public key */
    const uint8_t *transcript, size_t tr_len, /* session Transcript */
    const RequestedAttribute *attrs, size_t attrs_len,
    const char *now, /* time formatted as "2023-11-02T09:00:00Z" */
    const uint8_t *zkproof, size_t proof_len, const char *docType,
    const ZkSpecStruct *zk_spec) {
  if (bcp == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || now == nullptr || attrs == nullptr ||
      zkproof == nullptr || docType == nullptr || zk_spec == nullptr) {
    return MDOC_VERIFIER_NULL_INPUT;
  }

  Elt pkX, pkY;
  if (!parsePk(pkx, pky, pkX, pkY)) {
    log(ERROR, "invalid pkx, pky");
    return MDOC_VERIFIER_INVALID_INPUT;
  }

  if (!sameNamespace(attrs, attrs_len)) {
    log(ERROR, "attributes must all be in the same namespace");
    return MDOC_VERIFIER_INVALID_INPUT;
  }

  // Verify that the values in the RequestedAttribute structure are valid cbor.
  for (size_t i = 0; i < attrs_len; ++i) {
    if (!cbor_validate(attrs[i].cbor_value, attrs[i].cbor_value_len)) {
      log(ERROR, "invalid cbor value");
      return MDOC_VERIFIER_INVALID_CBOR;
    }
  }

  const f_128 Fs;

  // Sanity check input sizes.
  if (bcsz < 50000 || tr_len < 1 || attrs_len < 1 || proof_len < 20000) {
    return MDOC_VERIFIER_ARGUMENTS_TOO_SMALL;
  }

  const f2_p256 p256_2(p256_base);

  // Parse circuits from cached byte representation.
  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, bcp, bcsz);

  // For now, we are not using the ZKSpec version anywhere and assuming no
  // backwards compatibility. As soon as we have a use case for it, we have to
  // pass the ZkSpecStruct to all required downstream functions.
  log(INFO, "bytes len: %zu", full_size);

  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_sig == nullptr) {
    log(ERROR, "signature circuit could not be parsed");
    return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  }

  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);

  if (c_hash == nullptr) {
    log(ERROR, "circuit could not be parsed");
    return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  }
  log(INFO, "circuit created. h[in:%zu], s[in:%zu]", c_hash->ninputs,
      c_sig->ninputs);

  // Parse proofs
  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> pr_hash(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> pr_sig(*c_sig, r, req, zk_spec->block_enc_sig);

  log(INFO,
      "proof params: h[nl:%zu, ni:%zu], s[nl:%zu, ni:%zu] hc[b:%zu r:%zu] "
      "sc[b:%zu r:%zu]",
      c_hash->nl, c_hash->ninputs, c_sig->nl, c_sig->ninputs,
      pr_hash.param.block, pr_hash.param.nrow, pr_sig.param.block,
      pr_sig.param.nrow);

  const std::vector<uint8_t> zbuf(zkproof, zkproof + proof_len);
  ReadBuffer rb(zbuf);

  // Read macs from proof string.
  // The sanity check above ensures that the proof is big enough for the MACs.
  gf2k macs[6];

  for (size_t i = 0; i < 6; ++i) {
    macs[i] = Fs.of_bytes_field(rb.next(f_128::kBytes)).value();
  }

  // The proof read methods check proof length internally.
  if (!pr_hash.read(rb, Fs)) {
    log(ERROR, "hash proof could not be parsed");
    return MDOC_VERIFIER_HASH_PARSING_FAILURE;
  };
  if (!pr_sig.read(rb, p256_base)) {
    log(ERROR, "sig proof could not be parsed");
    return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  }
  if (rb.remaining() != 0) {
    log(ERROR, "proof bytes contains extra data: %zu bytes", rb.remaining());
    return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  }

  log(INFO, "proofs read");

  // =============== Verify

  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);

  ZkVerifier<f_128, RSFactory> hash_v(*c_hash, the_reed_solomon_factory, r, req,
                                      zk_spec->block_enc_hash, Fs);
  ZkVerifier<Fp256Base, RSFactory_b> sig_v(*c_sig, rsf_b, r, req,
                                           zk_spec->block_enc_sig, p256_base);

  // Use the transcript from the session to select the random oracle.
  class Transcript tv(transcript, tr_len, zk_spec->version);

  hash_v.recv_commitment(pr_hash, tv);
  sig_v.recv_commitment(pr_sig, tv);

  gf2k av = generate_mac_key(tv);

  // =============== Create public inputs
  auto pub_hash = Dense<f_128>(1, c_hash->npub_in);
  auto pub_sig = Dense<Fp256Base>(1, c_sig->npub_in);
  DenseFiller<f_128> hash_filler(pub_hash);
  DenseFiller<Fp256Base> sig_filler(pub_sig);

  size_t dlen = strlen(docType);
  if (!fill_public_inputs(sig_filler, hash_filler, pkX, pkY, transcript, tr_len,
                          attrs, attrs_len, (const uint8_t *)now,
                          (const uint8_t *)docType, dlen, macs, av, Fs,
                          zk_spec->version)) {
    return MDOC_VERIFIER_GENERAL_FAILURE;
  }

  if (hash_filler.size() != c_hash->npub_in ||
      sig_filler.size() != c_sig->npub_in) {
    return MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH;
  }

  bool ok = hash_v.verify(pr_hash, pub_hash, tv);
  bool ok2 = sig_v.verify(pr_sig, pub_sig, tv);

  return ok && ok2 ? MDOC_VERIFIER_SUCCESS : MDOC_VERIFIER_GENERAL_FAILURE;
}

MdocProverErrorCode run_mdoc_delegated_prover(
    const uint8_t* bcp, size_t bcsz, const uint8_t* mdoc, size_t mdoc_len,
    const char* pkx, const char* pky, const uint8_t* transcript, size_t tr_len,
    const RequestedAttribute* attrs, size_t attrs_len, const char* now,
    const char* agent_pkx, const char* agent_pky,
    const uint8_t* delegation_sig, size_t delegation_sig_len,
    const uint8_t* agent_sig, size_t agent_sig_len,
    const uint8_t* allowed_claim_hashes, size_t allowed_claim_count,
    const char* policy_expires, const uint8_t* agent_id_hash,
    const uint8_t* requested_claim_hashes,
    const uint8_t* revocation_id, const uint8_t* revocation_epoch_be,
    const char* revocation_expires, uint8_t revocation_revoked,
    const uint8_t* revocation_sig, size_t revocation_sig_len,
    uint8_t** prf, size_t* proof_len,
    const ZkSpecStruct* zk_spec) {
  if (bcp == nullptr || mdoc == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || attrs == nullptr || now == nullptr ||
      agent_pkx == nullptr || agent_pky == nullptr ||
      delegation_sig == nullptr || agent_sig == nullptr ||
      allowed_claim_hashes == nullptr || policy_expires == nullptr ||
      agent_id_hash == nullptr || requested_claim_hashes == nullptr ||
      revocation_id == nullptr || revocation_epoch_be == nullptr ||
      revocation_expires == nullptr || revocation_sig == nullptr ||
      prf == nullptr || proof_len == nullptr || zk_spec == nullptr) {
    return MDOC_PROVER_NULL_INPUT;
  }
  if (allowed_claim_count > kDelegationMaxClaims ||
      strlen(policy_expires) != kDelegationExpiresSize ||
      strlen(revocation_expires) != kDelegationExpiresSize ||
      delegation_sig_len != 64 || agent_sig_len != 64 ||
      revocation_sig_len != 64) {
    return MDOC_PROVER_INVALID_INPUT;
  }
  if (is_sm_delegation_spec(zk_spec)) {
    log(ERROR,
        "SM delegation profile uses a three-circuit proof bundle and is not "
        "compatible with run_mdoc_delegated_prover");
    return MDOC_PROVER_VERSION_NOT_SUPPORTED;
  }

  Elt pkX, pkY, agent_pkX, agent_pkY;
  if (!parsePk(pkx, pky, pkX, pkY) ||
      !parsePk(agent_pkx, agent_pky, agent_pkX, agent_pkY)) {
    return MDOC_PROVER_INVALID_INPUT;
  }
  if (!sameNamespace(attrs, attrs_len)) {
    return MDOC_PROVER_INVALID_INPUT;
  }

  const f2_p256 p256_2(p256_base);
  const f_128 Fs;
  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, bcp, bcsz);
  if (full_size == 0) return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;

  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
  if (c_sig == nullptr) return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
  if (c_hash == nullptr) return MDOC_PROVER_HASH_PARSING_FAILURE;

  auto W_sig = Dense<Fp256Base>(1, c_sig->ninputs);
  auto W_hash = Dense<f_128>(1, c_hash->ninputs);
  DenseFiller<Fp256Base> sig_filler(W_sig);
  DenseFiller<f_128> hash_filler(W_hash);

  SecureRandomEngine rng;
  DelegatedProverState state;
  MdocProverErrorCode ok = fill_delegated_witness(
      sig_filler, hash_filler, mdoc, mdoc_len, pkX, pkY, agent_pkX, agent_pkY,
      transcript, tr_len, attrs, attrs_len, (const uint8_t*)now,
      delegation_sig, delegation_sig_len, agent_sig, agent_sig_len,
      allowed_claim_hashes, allowed_claim_count, policy_expires, agent_id_hash,
      requested_claim_hashes, revocation_id, revocation_epoch_be,
      revocation_expires, revocation_revoked, revocation_sig,
      revocation_sig_len, state, rng, Fs, zk_spec->version);
  if (ok != MDOC_PROVER_SUCCESS) return ok;

  Transcript tp(transcript, tr_len, zk_spec->version);
  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);

  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> h_zk(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> sig_zk(*c_sig, r, req, zk_spec->block_enc_sig);
  ZkProver<f_128, RSFactory> hash_p(*c_hash, Fs, the_reed_solomon_factory);
  ZkProver<Fp256Base, RSFactory_b> sig_p(*c_sig, p256_base, rsf_b);

  hash_p.commit(h_zk, W_hash, tp, rng);
  sig_p.commit(sig_zk, W_sig, tp, rng);

  gf2k av = generate_mac_key(tp), macs[10];
  uint8_t macs_b[10 * f_128::kBytes];
  compute_macs(5, state.common, macs, macs_b, state.ap, av);
  update_macs_count(W_sig, W_hash, kDelegatedSigMacIndex,
                    getDelegatedHashMacIndex(attrs_len, zk_spec->version),
                    macs, 10, av, Fs);

  if (!hash_p.prove(h_zk, W_hash, tp)) return MDOC_PROVER_GENERAL_FAILURE;
  if (!sig_p.prove(sig_zk, W_sig, tp)) return MDOC_PROVER_GENERAL_FAILURE;

  std::vector<uint8_t> buf;
  buf.reserve(10 * f_128::kBytes + h_zk.size() + sig_zk.size());
  buf.insert(buf.begin(), macs_b, macs_b + 10 * f_128::kBytes);
  h_zk.write(buf, Fs);
  sig_zk.write(buf, p256_base);
  *proof_len = buf.size();
  *prf = (uint8_t*)malloc(*proof_len);
  if (!*prf) return MDOC_PROVER_MEMORY_ALLOCATION_FAILURE;
  memcpy(*prf, buf.data(), buf.size());
  return MDOC_PROVER_SUCCESS;
}

MdocVerifierErrorCode run_mdoc_delegated_verifier(
    const uint8_t* bcp, size_t bcsz, const char* pkx, const char* pky,
    const uint8_t* transcript, size_t tr_len, const RequestedAttribute* attrs,
    size_t attrs_len, const char* now, const uint8_t* zkproof,
    size_t proof_len, const char* docType, const char* agent_pkx,
    const char* agent_pky, const uint8_t* allowed_claim_hashes,
    size_t allowed_claim_count, const char* policy_expires,
    const uint8_t* agent_id_hash, const uint8_t* requested_claim_hashes,
    const uint8_t* revocation_id, const uint8_t* revocation_epoch_be,
    const char* revocation_expires, uint8_t revocation_revoked,
    const ZkSpecStruct* zk_spec) {
  if (bcp == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || attrs == nullptr || now == nullptr ||
      zkproof == nullptr || docType == nullptr || agent_pkx == nullptr ||
      agent_pky == nullptr || allowed_claim_hashes == nullptr ||
      policy_expires == nullptr || agent_id_hash == nullptr ||
      requested_claim_hashes == nullptr || revocation_id == nullptr ||
      revocation_epoch_be == nullptr || revocation_expires == nullptr ||
      zk_spec == nullptr) {
    return MDOC_VERIFIER_NULL_INPUT;
  }
  if (allowed_claim_count > kDelegationMaxClaims ||
      strlen(policy_expires) != kDelegationExpiresSize ||
      strlen(revocation_expires) != kDelegationExpiresSize ||
      proof_len < 20000) {
    return MDOC_VERIFIER_INVALID_INPUT;
  }
  if (is_sm_delegation_spec(zk_spec)) {
    log(ERROR,
        "SM delegation profile uses a three-circuit proof bundle and is not "
        "compatible with run_mdoc_delegated_verifier");
    return MDOC_VERIFIER_INVALID_ZK_SPEC_VERSION;
  }

  Elt pkX, pkY, agent_pkX, agent_pkY;
  if (!parsePk(pkx, pky, pkX, pkY) ||
      !parsePk(agent_pkx, agent_pky, agent_pkX, agent_pkY)) {
    return MDOC_VERIFIER_INVALID_INPUT;
  }
  if (!sameNamespace(attrs, attrs_len)) return MDOC_VERIFIER_INVALID_INPUT;
  for (size_t i = 0; i < attrs_len; ++i) {
    if (!cbor_validate(attrs[i].cbor_value, attrs[i].cbor_value_len)) {
      return MDOC_VERIFIER_INVALID_CBOR;
    }
  }

  const f_128 Fs;
  const f2_p256 p256_2(p256_base);
  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, bcp, bcsz);
  if (full_size == 0) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_s(p256_base, P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_sig == nullptr) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_hash == nullptr) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;

  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> pr_hash(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> pr_sig(*c_sig, r, req, zk_spec->block_enc_sig);
  const std::vector<uint8_t> zbuf(zkproof, zkproof + proof_len);
  ReadBuffer rb(zbuf);

  gf2k macs[10];
  for (size_t i = 0; i < 10; ++i) {
    macs[i] = Fs.of_bytes_field(rb.next(f_128::kBytes)).value();
  }
  if (!pr_hash.read(rb, Fs)) return MDOC_VERIFIER_HASH_PARSING_FAILURE;
  if (!pr_sig.read(rb, p256_base)) {
    return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  }
  if (rb.remaining() != 0) return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;

  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory_b rsf_b(fft_b, p256_base);
  const RSFactory the_reed_solomon_factory(Fs);
  ZkVerifier<f_128, RSFactory> hash_v(*c_hash, the_reed_solomon_factory, r, req,
                                      zk_spec->block_enc_hash, Fs);
  ZkVerifier<Fp256Base, RSFactory_b> sig_v(*c_sig, rsf_b, r, req,
                                           zk_spec->block_enc_sig, p256_base);

  Transcript tv(transcript, tr_len, zk_spec->version);
  hash_v.recv_commitment(pr_hash, tv);
  sig_v.recv_commitment(pr_sig, tv);
  gf2k av = generate_mac_key(tv);

  auto pub_hash = Dense<f_128>(1, c_hash->npub_in);
  auto pub_sig = Dense<Fp256Base>(1, c_sig->npub_in);
  DenseFiller<f_128> hash_filler(pub_hash);
  DenseFiller<Fp256Base> sig_filler(pub_sig);
  size_t dlen = strlen(docType);
  if (!fill_delegated_public_inputs(
          sig_filler, hash_filler, pkX, pkY, agent_pkX, agent_pkY, transcript,
          tr_len, attrs, attrs_len, (const uint8_t*)now, (const uint8_t*)docType,
          dlen, allowed_claim_hashes, allowed_claim_count, policy_expires,
          agent_id_hash, requested_claim_hashes, revocation_id,
          revocation_epoch_be, revocation_expires, revocation_revoked, macs,
          av, Fs, zk_spec->version)) {
    return MDOC_VERIFIER_GENERAL_FAILURE;
  }
  if (hash_filler.size() != c_hash->npub_in ||
      sig_filler.size() != c_sig->npub_in) {
    return MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH;
  }

  bool ok = hash_v.verify(pr_hash, pub_hash, tv);
  bool ok2 = sig_v.verify(pr_sig, pub_sig, tv);
  return ok && ok2 ? MDOC_VERIFIER_SUCCESS : MDOC_VERIFIER_GENERAL_FAILURE;
}

MdocProverErrorCode run_mdoc_delegated_sm_prover(
    const uint8_t* bcp, size_t bcsz, const uint8_t* mdoc, size_t mdoc_len,
    const char* pkx, const char* pky, const char* device_sk,
    const uint8_t* transcript, size_t tr_len, const RequestedAttribute* attrs,
    size_t attrs_len, const char* now, const char* agent_pkx_sm2,
    const char* agent_pky_sm2, const uint8_t* delegation_sig_sm2,
    size_t delegation_sig_sm2_len, const uint8_t* agent_sig_sm2,
    size_t agent_sig_sm2_len, const uint8_t* allowed_claim_hashes,
    size_t allowed_claim_count, const char* policy_expires,
    const uint8_t* agent_id_hash, const uint8_t* requested_claim_hashes,
    const uint8_t* revocation_id, const uint8_t* revocation_epoch_be,
    const char* revocation_expires, uint8_t revocation_revoked,
    const uint8_t* revocation_sig_sm2, size_t revocation_sig_sm2_len,
    uint8_t** prf, size_t* proof_len, const ZkSpecStruct* zk_spec) {
  if (bcp == nullptr || mdoc == nullptr || pkx == nullptr || pky == nullptr ||
      device_sk == nullptr || transcript == nullptr || attrs == nullptr ||
      now == nullptr || agent_pkx_sm2 == nullptr || agent_pky_sm2 == nullptr ||
      delegation_sig_sm2 == nullptr || agent_sig_sm2 == nullptr ||
      allowed_claim_hashes == nullptr || policy_expires == nullptr ||
      agent_id_hash == nullptr || requested_claim_hashes == nullptr ||
      revocation_id == nullptr || revocation_epoch_be == nullptr ||
      revocation_expires == nullptr || revocation_sig_sm2 == nullptr ||
      prf == nullptr || proof_len == nullptr || zk_spec == nullptr) {
    return MDOC_PROVER_NULL_INPUT;
  }
  if (!is_sm_delegation_spec(zk_spec) ||
      allowed_claim_count > kDelegationMaxClaims ||
      strlen(policy_expires) != kDelegationExpiresSize ||
      strlen(revocation_expires) != kDelegationExpiresSize ||
      delegation_sig_sm2_len != 64 || agent_sig_sm2_len != 64 ||
      revocation_sig_sm2_len != 64) {
    log(ERROR,
        "invalid SM prover input: spec=%s allowed=%zu policy_exp_len=%zu "
        "rev_exp_len=%zu sig_lens=(%zu,%zu,%zu)",
        zk_spec->system, allowed_claim_count, strlen(policy_expires),
        strlen(revocation_expires), delegation_sig_sm2_len, agent_sig_sm2_len,
        revocation_sig_sm2_len);
    return MDOC_PROVER_INVALID_INPUT;
  }

  Elt pkX, pkY;
  SM2Elt agent_pkX, agent_pkY;
  if (!parsePk(pkx, pky, pkX, pkY) ||
      !parsePkSm2(agent_pkx_sm2, agent_pky_sm2, agent_pkX, agent_pkY) ||
      !sameNamespace(attrs, attrs_len)) {
    log(ERROR, "invalid SM prover key or namespace input");
    return MDOC_PROVER_INVALID_INPUT;
  }

  const f_128 Fs;
  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, bcp, bcsz);
  if (full_size == 0) return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_p256(p256_base, P256_ID);
  auto c_p256 = cr_p256.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
  if (c_p256 == nullptr) return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
  CircuitRep<FpSM2Base> cr_sm2(sm2_base, SM2_ID);
  auto c_sm2 = cr_sm2.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
  if (c_sm2 == nullptr) return MDOC_PROVER_CIRCUIT_PARSING_FAILURE;
  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_prover);
  if (c_hash == nullptr) return MDOC_PROVER_HASH_PARSING_FAILURE;

  auto W_p256 = Dense<Fp256Base>(1, c_p256->ninputs);
  auto W_sm2 = Dense<FpSM2Base>(1, c_sm2->ninputs);
  auto W_hash = Dense<f_128>(1, c_hash->ninputs);
  DenseFiller<Fp256Base> p256_filler(W_p256);
  DenseFiller<FpSM2Base> sm2_filler(W_sm2);
  DenseFiller<f_128> hash_filler(W_hash);

  SecureRandomEngine rng;
  SmDelegatedProverState state;
  MdocProverErrorCode ok = fill_sm_delegated_witness(
      p256_filler, sm2_filler, hash_filler, mdoc, mdoc_len, pkX, pkY,
      device_sk, agent_pkX, agent_pkY, transcript, tr_len, attrs, attrs_len,
      (const uint8_t*)now, delegation_sig_sm2, delegation_sig_sm2_len,
      agent_sig_sm2, agent_sig_sm2_len, allowed_claim_hashes,
      allowed_claim_count, policy_expires, agent_id_hash,
      requested_claim_hashes, revocation_id, revocation_epoch_be,
      revocation_expires, revocation_revoked, revocation_sig_sm2,
      revocation_sig_sm2_len, state, rng, Fs, zk_spec->version);
  if (ok != MDOC_PROVER_SUCCESS) return ok;

  Transcript tp(transcript, tr_len, zk_spec->version);
  const f2_p256 p256_2(p256_base);
  const Elt2 p256_omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory p256_fft(p256_base, p256_2, p256_omega,
                                          1ull << 31);
  const RSFactory_b p256_rsf(p256_fft, p256_base);
  const f2_sm2 sm2_2(sm2_base);
  const SM2Elt2 sm2_omega = sm2_2.of_string(kSm2RootX, kSm2RootY);
  const SM2FftExtConvolutionFactory sm2_fft(sm2_base, sm2_2, sm2_omega,
                                            1ull << 31);
  const SM2RSFactory_b sm2_rsf(sm2_fft, sm2_base);
  const RSFactory hash_rsf(Fs);

  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> h_zk(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> p256_zk(*c_p256, r, req, zk_spec->block_enc_sig);
  ZkProof<FpSM2Base> sm2_zk(*c_sm2, r, req, zk_spec->block_enc_sig);
  ZkProver<f_128, RSFactory> hash_p(*c_hash, Fs, hash_rsf);
  ZkProver<Fp256Base, RSFactory_b> p256_p(*c_p256, p256_base, p256_rsf);
  ZkProver<FpSM2Base, SM2RSFactory_b> sm2_p(*c_sm2, sm2_base, sm2_rsf);

  hash_p.commit(h_zk, W_hash, tp, rng);
  p256_p.commit(p256_zk, W_p256, tp, rng);
  sm2_p.commit(sm2_zk, W_sm2, tp, rng);

  gf2k av = generate_mac_key(tp), macs[12];
  uint8_t macs_b[12 * f_128::kBytes];
  compute_macs_for_field<Fp256Base>(6, state.p256_common, macs, macs_b,
                                    state.ap, av, p256_base);

  size_t hi = getDelegatedHashMacIndex(attrs_len, zk_spec->version);
  for (size_t i = 0; i < 10; ++i) W_hash.v_[hi++] = macs[i];
  W_hash.v_[hi++] = av;

  size_t pi = kSigMacIndex;
  for (size_t i = 0; i < 6; ++i) {
    update_mac_in_prime_dense(W_p256, pi, macs[i], p256_base);
  }
  update_mac_in_prime_dense(W_p256, pi, macs[10], p256_base);
  update_mac_in_prime_dense(W_p256, pi, macs[11], p256_base);
  update_mac_in_prime_dense(W_p256, pi, av, p256_base);

  size_t si = kSigMacIndex;
  for (size_t i = 6; i < 12; ++i) {
    update_mac_in_prime_dense(W_sm2, si, macs[i], sm2_base);
  }
  update_mac_in_prime_dense(W_sm2, si, av, sm2_base);

  if (!hash_p.prove(h_zk, W_hash, tp)) return MDOC_PROVER_GENERAL_FAILURE;
  if (!p256_p.prove(p256_zk, W_p256, tp)) {
    return MDOC_PROVER_GENERAL_FAILURE;
  }
  if (!sm2_p.prove(sm2_zk, W_sm2, tp)) return MDOC_PROVER_GENERAL_FAILURE;

  std::vector<uint8_t> buf;
  buf.reserve(12 * f_128::kBytes + h_zk.size() + p256_zk.size() +
              sm2_zk.size());
  buf.insert(buf.begin(), macs_b, macs_b + 12 * f_128::kBytes);
  h_zk.write(buf, Fs);
  p256_zk.write(buf, p256_base);
  sm2_zk.write(buf, sm2_base);
  *proof_len = buf.size();
  *prf = (uint8_t*)malloc(*proof_len);
  if (!*prf) return MDOC_PROVER_MEMORY_ALLOCATION_FAILURE;
  memcpy(*prf, buf.data(), buf.size());
  return MDOC_PROVER_SUCCESS;
}

MdocVerifierErrorCode run_mdoc_delegated_sm_verifier(
    const uint8_t* bcp, size_t bcsz, const char* pkx, const char* pky,
    const uint8_t* transcript, size_t tr_len, const RequestedAttribute* attrs,
    size_t attrs_len, const char* now, const uint8_t* zkproof,
    size_t proof_len, const char* docType, const char* agent_pkx_sm2,
    const char* agent_pky_sm2, const uint8_t* allowed_claim_hashes,
    size_t allowed_claim_count, const char* policy_expires,
    const uint8_t* agent_id_hash, const uint8_t* requested_claim_hashes,
    const uint8_t* revocation_id, const uint8_t* revocation_epoch_be,
    const char* revocation_expires, uint8_t revocation_revoked,
    const ZkSpecStruct* zk_spec) {
  if (bcp == nullptr || pkx == nullptr || pky == nullptr ||
      transcript == nullptr || attrs == nullptr || now == nullptr ||
      zkproof == nullptr || docType == nullptr || agent_pkx_sm2 == nullptr ||
      agent_pky_sm2 == nullptr || allowed_claim_hashes == nullptr ||
      policy_expires == nullptr || agent_id_hash == nullptr ||
      requested_claim_hashes == nullptr || revocation_id == nullptr ||
      revocation_epoch_be == nullptr || revocation_expires == nullptr ||
      zk_spec == nullptr) {
    return MDOC_VERIFIER_NULL_INPUT;
  }
  if (!is_sm_delegation_spec(zk_spec) ||
      allowed_claim_count > kDelegationMaxClaims ||
      strlen(policy_expires) != kDelegationExpiresSize ||
      strlen(revocation_expires) != kDelegationExpiresSize ||
      proof_len < 20000) {
    return MDOC_VERIFIER_INVALID_INPUT;
  }

  Elt pkX, pkY;
  SM2Elt agent_pkX, agent_pkY;
  if (!parsePk(pkx, pky, pkX, pkY) ||
      !parsePkSm2(agent_pkx_sm2, agent_pky_sm2, agent_pkX, agent_pkY) ||
      !sameNamespace(attrs, attrs_len)) {
    return MDOC_VERIFIER_INVALID_INPUT;
  }
  for (size_t i = 0; i < attrs_len; ++i) {
    if (!cbor_validate(attrs[i].cbor_value, attrs[i].cbor_value_len)) {
      return MDOC_VERIFIER_INVALID_CBOR;
    }
  }

  const f_128 Fs;
  size_t len = kCircuitSizeMax;
  std::vector<uint8_t> bytes(len);
  size_t full_size = decompress(bytes, bcp, bcsz);
  if (full_size == 0) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  ReadBuffer rb_circuit(bytes.data(), full_size);
  CircuitRep<Fp256Base> cr_p256(p256_base, P256_ID);
  auto c_p256 = cr_p256.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_p256 == nullptr) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  CircuitRep<FpSM2Base> cr_sm2(sm2_base, SM2_ID);
  auto c_sm2 = cr_sm2.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_sm2 == nullptr) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;
  CircuitRep<f_128> cr_h(Fs, GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, enforce_circuit_id_in_verifier);
  if (c_hash == nullptr) return MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE;

  size_t r = zk_spec->version < 7 ? kLigeroRate : kLigeroRatev7;
  size_t req = zk_spec->version < 7 ? kLigeroNreq : kLigeroNreqv7;
  ZkProof<f_128> pr_hash(*c_hash, r, req, zk_spec->block_enc_hash);
  ZkProof<Fp256Base> pr_p256(*c_p256, r, req, zk_spec->block_enc_sig);
  ZkProof<FpSM2Base> pr_sm2(*c_sm2, r, req, zk_spec->block_enc_sig);
  const std::vector<uint8_t> zbuf(zkproof, zkproof + proof_len);
  ReadBuffer rb(zbuf);
  gf2k macs[12];
  for (size_t i = 0; i < 12; ++i) {
    macs[i] = Fs.of_bytes_field(rb.next(f_128::kBytes)).value();
  }
  if (!pr_hash.read(rb, Fs)) return MDOC_VERIFIER_HASH_PARSING_FAILURE;
  if (!pr_p256.read(rb, p256_base)) {
    return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  }
  if (!pr_sm2.read(rb, sm2_base)) {
    return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;
  }
  if (rb.remaining() != 0) return MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE;

  const f2_p256 p256_2(p256_base);
  const Elt2 p256_omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory p256_fft(p256_base, p256_2, p256_omega,
                                          1ull << 31);
  const RSFactory_b p256_rsf(p256_fft, p256_base);
  const f2_sm2 sm2_2(sm2_base);
  const SM2Elt2 sm2_omega = sm2_2.of_string(kSm2RootX, kSm2RootY);
  const SM2FftExtConvolutionFactory sm2_fft(sm2_base, sm2_2, sm2_omega,
                                            1ull << 31);
  const SM2RSFactory_b sm2_rsf(sm2_fft, sm2_base);
  const RSFactory hash_rsf(Fs);
  ZkVerifier<f_128, RSFactory> hash_v(*c_hash, hash_rsf, r, req,
                                      zk_spec->block_enc_hash, Fs);
  ZkVerifier<Fp256Base, RSFactory_b> p256_v(
      *c_p256, p256_rsf, r, req, zk_spec->block_enc_sig, p256_base);
  ZkVerifier<FpSM2Base, SM2RSFactory_b> sm2_v(
      *c_sm2, sm2_rsf, r, req, zk_spec->block_enc_sig, sm2_base);

  Transcript tv(transcript, tr_len, zk_spec->version);
  hash_v.recv_commitment(pr_hash, tv);
  p256_v.recv_commitment(pr_p256, tv);
  sm2_v.recv_commitment(pr_sm2, tv);
  gf2k av = generate_mac_key(tv);

  auto pub_hash = Dense<f_128>(1, c_hash->npub_in);
  auto pub_p256 = Dense<Fp256Base>(1, c_p256->npub_in);
  auto pub_sm2 = Dense<FpSM2Base>(1, c_sm2->npub_in);
  DenseFiller<f_128> hash_filler(pub_hash);
  DenseFiller<Fp256Base> p256_filler(pub_p256);
  DenseFiller<FpSM2Base> sm2_filler(pub_sm2);
  size_t dlen = strlen(docType);
  if (!fill_sm_delegated_public_inputs(
          p256_filler, sm2_filler, hash_filler, pkX, pkY, agent_pkX, agent_pkY,
          transcript, tr_len, attrs, attrs_len, (const uint8_t*)now,
          (const uint8_t*)docType, dlen, allowed_claim_hashes,
          allowed_claim_count, policy_expires, agent_id_hash,
          requested_claim_hashes, revocation_id, revocation_epoch_be,
          revocation_expires, revocation_revoked, macs, av, Fs,
          zk_spec->version)) {
    return MDOC_VERIFIER_GENERAL_FAILURE;
  }
  if (hash_filler.size() != c_hash->npub_in ||
      p256_filler.size() != c_p256->npub_in ||
      sm2_filler.size() != c_sm2->npub_in) {
    return MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH;
  }

  bool ok_h = hash_v.verify(pr_hash, pub_hash, tv);
  bool ok_p = p256_v.verify(pr_p256, pub_p256, tv);
  bool ok_s = sm2_v.verify(pr_sm2, pub_sm2, tv);
  return ok_h && ok_p && ok_s ? MDOC_VERIFIER_SUCCESS
                              : MDOC_VERIFIER_GENERAL_FAILURE;
}

} /* extern "C" */
}  // namespace proofs
