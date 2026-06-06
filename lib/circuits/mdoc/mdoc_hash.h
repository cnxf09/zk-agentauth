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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "circuits/cbor_parser/cbor_byte_decoder.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/memcmp.h"
#include "circuits/logic/routing.h"
#include "circuits/mdoc/mdoc_constants.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "circuits/sha/flatsm3_circuit.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {

static constexpr size_t kSHAPluckerBits = 4u;

// This class (only) verifies the hashing and pseudo-parsing of an mdoc.
// Specifically, it checks
//   (a) the hash of the mdoc matches its mac.
//   (b) the values dpk_{x,y} appear in approximate cbor form, and their macs
//       match the expected values
//   (c) validFrom, validUntil appear in approximate cbor form, and that
//         validFrom <= now <= validUntil
//   (d) For each expected attribute, there exists a preimage to a sha hash
//       that appears in the mso, the preimage is approximately cbor formatted,
//       and the preimage includes the expected attribute id and value.
template <class LogicCircuit, class Field>
class MdocHash {
  using BitW = typename LogicCircuit::BitW;
  using v8 = typename LogicCircuit::v8;
  using v32 = typename LogicCircuit::v32;
  using v64 = typename LogicCircuit::v64;
  using v256 = typename LogicCircuit::v256;

  using vind = typename LogicCircuit::template bitvec<kCborIndexBits>;

  using Flatsha = FlatSHA256Circuit<LogicCircuit,
                                    BitPlucker<LogicCircuit, kSHAPluckerBits>>;
  using Flatsm3 = FlatSM3Circuit<LogicCircuit,
                                 BitPlucker<LogicCircuit, kSHAPluckerBits>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using Sm3BlockWitness = typename Flatsm3::BlockWitness;
  using sha_packed_v32 = typename Flatsha::packed_v32;

 public:
  // These structures mimic the similarly named structures in Witness, but
  // their members are circuit wire objects instead of size_t.
  struct OpenedAttribute {
    v8 attr[32]; /* 32b representing attribute name in be. */
    v8 v1[64];   /* 64b of attribute value */
    // NOTE: although these arrays are sized {32,64}, other aspects of the
    // system constrain the sum of the elementIdentifier and elementValue to be
    // at most 56 bytes for a proof to succeed.  We will maintain this API, but
    // publish the constraint about the sum in the documentation.
    v8 len;      /* public length of the encoded attribute id */
    v8 vlen;     /* public length of the encoded attribute value */
    void input(const LogicCircuit& lc) {
      for (size_t j = 0; j < 32; ++j) {
        attr[j] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < 64; ++j) {
        v1[j] = lc.template vinput<8>();
      }
      len = lc.template vinput<8>();
      vlen = lc.template vinput<8>();
    }
  };
  struct CborIndex {
    vind k;
    void input(const LogicCircuit& lc) {
      k = lc.template vinput<kCborIndexBits>();
    }
  };

  struct AttrShift {
    vind offset;
    vind len;
    void input(const LogicCircuit& lc) {
      offset = lc.template vinput<kCborIndexBits>();
      len = lc.template vinput<kCborIndexBits>();
    }
  };

  struct SaltedHash {
    vind i1, i2, i3;
    vind l[4];
    v8 perm;
    void input(const LogicCircuit& lc) {
      i1 = lc.template vinput<kCborIndexBits>();
      i2 = lc.template vinput<kCborIndexBits>();
      i3 = lc.template vinput<kCborIndexBits>();
      for (size_t j = 0; j < 4; ++j) {
        l[j] = lc.template vinput<kCborIndexBits>();
      }
      perm = lc.template vinput<8>();
    }
  };

  struct DelegationPolicyInput {
    v8 agent_pkx[32];
    v8 agent_pky[32];
    v8 allowed_count;
    v8 allowed_claim_hashes[kDelegationMaxClaims][kDelegationClaimHashSize];
    v8 expires[kDelegationExpiresSize];
    v8 agent_id_hash[kDelegationAgentIdHashSize];
    std::vector<std::vector<v8>> requested_claim_hashes;
    v8 revocation_id[32];
    v8 revocation_epoch[kDelegationRevocationEpochSize];
    v8 revocation_expires[kDelegationExpiresSize];
    v8 revocation_revoked;

    explicit DelegationPolicyInput(size_t num_attr) {
      requested_claim_hashes.resize(num_attr);
      for (auto& h : requested_claim_hashes) {
        h.resize(kDelegationClaimHashSize);
      }
    }

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < 32; ++i) {
        agent_pkx[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < 32; ++i) {
        agent_pky[i] = lc.template vinput<8>();
      }
      allowed_count = lc.template vinput<8>();
      for (size_t i = 0; i < kDelegationMaxClaims; ++i) {
        for (size_t j = 0; j < kDelegationClaimHashSize; ++j) {
          allowed_claim_hashes[i][j] = lc.template vinput<8>();
        }
      }
      for (size_t i = 0; i < kDelegationExpiresSize; ++i) {
        expires[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kDelegationAgentIdHashSize; ++i) {
        agent_id_hash[i] = lc.template vinput<8>();
      }
      for (auto& h : requested_claim_hashes) {
        for (size_t i = 0; i < kDelegationClaimHashSize; ++i) {
          h[i] = lc.template vinput<8>();
        }
      }
      for (size_t i = 0; i < 32; ++i) {
        revocation_id[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kDelegationRevocationEpochSize; ++i) {
        revocation_epoch[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kDelegationExpiresSize; ++i) {
        revocation_expires[i] = lc.template vinput<8>();
      }
      revocation_revoked = lc.template vinput<8>();
    }
  };

  struct DelegationPolicyWitness {
    ShaBlockWitness delegation_msg_sha[kDelegationMsgSHABlocks];
    ShaBlockWitness revocation_id_sha[kDelegationRevocationIdSHABlocks];
    ShaBlockWitness
        revocation_status_sha[kDelegationRevocationStatusSHABlocks];

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kDelegationMsgSHABlocks; ++i) {
        delegation_msg_sha[i].input(lc);
      }
      for (size_t i = 0; i < kDelegationRevocationIdSHABlocks; ++i) {
        revocation_id_sha[i].input(lc);
      }
      for (size_t i = 0; i < kDelegationRevocationStatusSHABlocks; ++i) {
        revocation_status_sha[i].input(lc);
      }
    }
  };

  struct DelegationPolicySm3Witness {
    Sm3BlockWitness delegation_msg_sm3[kDelegationMsgSHABlocks];
    Sm3BlockWitness device_za_sm3[kSm2ZaMessageSM3Blocks];
    Sm3BlockWitness delegation_sig_sm3[kSm2DigestMessageSM3Blocks];
    Sm3BlockWitness revocation_id_sm3[kDelegationRevocationIdSHABlocks];
    Sm3BlockWitness
        revocation_status_sm3[kDelegationRevocationStatusSHABlocks];
    Sm3BlockWitness revocation_sig_sm3[kSm2DigestMessageSM3Blocks];

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kDelegationMsgSHABlocks; ++i) {
        delegation_msg_sm3[i].input(lc);
      }
      for (size_t i = 0; i < kSm2ZaMessageSM3Blocks; ++i) {
        device_za_sm3[i].input(lc);
      }
      for (size_t i = 0; i < kSm2DigestMessageSM3Blocks; ++i) {
        delegation_sig_sm3[i].input(lc);
      }
      for (size_t i = 0; i < kDelegationRevocationIdSHABlocks; ++i) {
        revocation_id_sm3[i].input(lc);
      }
      for (size_t i = 0; i < kDelegationRevocationStatusSHABlocks; ++i) {
        revocation_status_sm3[i].input(lc);
      }
      for (size_t i = 0; i < kSm2DigestMessageSM3Blocks; ++i) {
        revocation_sig_sm3[i].input(lc);
      }
    }
  };

  class Witness {
   public:
    v8 in_[64 * kMaxSHABlocks]; /* input bytes, 64 * MAX */

    v8 nb_; /* index of sha block that contains the real hash  */
    ShaBlockWitness sig_sha_[kMaxSHABlocks];

    std::vector<std::vector<ShaBlockWitness>> attr_sha_;
    std::vector<std::vector<v8>> attrb_;

    CborIndex valid_from_, valid_until_;
    CborIndex dev_key_info_;
    CborIndex value_digests_;
    std::vector<CborIndex> attr_mso_;
    std::vector<AttrShift> attr_ei_;
    std::vector<AttrShift> attr_ev_;
    std::vector<SaltedHash> salted_hashes_;
    size_t num_attr_;

    explicit Witness(size_t num_attr) {
      num_attr_ = num_attr;
      attr_mso_.resize(num_attr);
      attr_ei_.resize(num_attr);
      attr_ev_.resize(num_attr);
      attr_sha_.resize(num_attr);
      salted_hashes_.resize(num_attr);
      for (size_t i = 0; i < num_attr; ++i) {
        attr_sha_[i].resize(2);
      }

      attrb_.resize(num_attr);
    }

    void input(const LogicCircuit& lc) {
      nb_ = lc.template vinput<8>();

      // sha input init =========================
      for (size_t i = 0; i + kCose1PrefixLen < 64 * kMaxSHABlocks; ++i) {
        in_[i] = lc.template vinput<8>();
      }
      for (size_t j = 0; j < kMaxSHABlocks; j++) {
        sig_sha_[j].input(lc);
      }

      valid_from_.input(lc);
      valid_until_.input(lc);
      dev_key_info_.input(lc);
      value_digests_.input(lc);

      // Attribute opening witnesses
      for (size_t ai = 0; ai < num_attr_; ++ai) {
        for (size_t i = 0; i < 64 * 2; ++i) {
          attrb_[ai].push_back(lc.template vinput<8>());
        }
        for (size_t j = 0; j < 2; j++) {
          attr_sha_[ai][j].input(lc);
        }
        attr_mso_[ai].input(lc);
        attr_ei_[ai].input(lc);
        attr_ev_[ai].input(lc);
        salted_hashes_[ai].input(lc);
      }
    }
  };

  explicit MdocHash(const LogicCircuit& lc)
      : lc_(lc), sha_(lc), sm3_(lc), r_(lc), cb_(lc) {}

  void assert_valid_hash_mdoc(OpenedAttribute oa[/* NUM_ATTR */],
                              const v8 now[/*20*/], const v256& e,
                              const v256& dpkx, const v256& dpky,
                              const Witness& vw) const {
    auto preimage = construct_signature_preimage(vw);
    lc_.vassert_is_bit(vw.nb_);
    lc_.vleq(vw.nb_, kMaxSHABlocks);
    sha_.assert_message_hash(kMaxSHABlocks, vw.nb_, preimage.data(), e,
                             vw.sig_sha_);

    // Find the length of the MSO in bytes. Use this to range check each index.
    v64 len = sha_.find_len(kMaxSHABlocks, preimage.data(), vw.nb_);

    // Shift a portion of the MSO into buf and check it.
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings
    std::vector<v8> cmp_buf(kMaxMsoLen);
    const Memcmp<LogicCircuit> CMP(lc_);

    // In the shifting below, the +5 corresponds to the prefix
    // D8 18 <len2> prefix of the mso that we want to skip parsing.
    // The +2 corresponds to the length.

    // validFrom <= now
    check_index(vw.valid_from_.k, len);
    r_.shift(vw.valid_from_.k, kValidFromLen + kDateLen, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kValidFromLen, &cmp_buf[0], kValidFromCheck);
    auto cmp = CMP.leq(kDateLen, &cmp_buf[kValidFromLen], &now[0]);
    lc_.assert1(cmp);

    // now <= validUntil
    check_index(vw.valid_until_.k, len);
    r_.shift(vw.valid_until_.k, kValidUntilLen + kDateLen, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kValidUntilLen, &cmp_buf[0], kValidUntilCheck);
    cmp = CMP.leq(kDateLen, &now[0], &cmp_buf[kValidUntilLen]);
    lc_.assert1(cmp);

    // DPK_{x,y}
    check_index(vw.dev_key_info_.k, len);
    r_.shift(vw.dev_key_info_.k, kDeviceKeyInfoLen + 3 + 32 + 32, &cmp_buf[0],
             kMaxMsoLen, vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(kDeviceKeyInfoLen, &cmp_buf[0], kDeviceKeyInfoCheck);
    uint8_t dpkyCheck[] = {0x22, 0x58, 0x20};
    assert_bytes_at(sizeof(dpkyCheck), &cmp_buf[65], dpkyCheck);

    assert_key(dpkx, &cmp_buf[kPkxInd]);
    assert_key(dpky, &cmp_buf[kPkyInd]);

    // Attributes parsing
    // valueDigests, ignore byte 13 \in {A1,A2} representing map size.
    check_index(vw.value_digests_.k, len);
    r_.shift(vw.value_digests_.k, kValueDigestsLen, cmp_buf.data(), kMaxMsoLen,
             vw.in_ + 5 + 2, zz, /*unroll=*/3);
    assert_bytes_at(13, &cmp_buf[0], kValueDigestsCheck);

    // Attributes: Equality of hash with MSO value.

    for (size_t ai = 0; ai < vw.num_attr_; ++ai) {
      // Recall that the MSO contains a hash value e2 where
      //   e2 = hash( cbor.bstr( IssuerSignedItem ))
      // and IssuerSignedItem is a CBOR structure defined as:
      // IssuerSignedItem = {
      //     "digestID" : uint,
      //     "random" : bstr,
      //     "elementIdentifier" : DataElementIdentifier,
      //     "elementValue" : DataElementValue };
      // The order of the elements in the IssuerSignedItem is not specified.
      //
      // The constraints below verify the following:
      //     1. the index attr_mso_[ai].k < len(mso)
      //     2. a 32-byte cbor array e2 occurs at index attr_mso_[ai].k in mso
      //     -- attrb_[ai] is a SHA-256 length-padded 128-byte witness array
      //     3. e2 = hash(attrb_[ai].data())
      //     4. sl is the length of attrb_[ai] as per the SHA-256 padding rule
      //     5. The attrb_[ai] array is well-formed cbor that includes the
      //        expected elementIdentifier, and elementValue fields as per the
      //        public oa[ai] argument.
      check_index(vw.attr_mso_[ai].k, len);
      r_.shift(vw.attr_mso_[ai].k, 2 + 32, &cmp_buf[0], kMaxMsoLen,
               vw.in_ + 5 + 2, zz, /*unroll=*/3);

      // 2. Basic CBOR check of the Tag
      assert_bytes_at(2, &cmp_buf[0], kTag32);

      v256 mm;
      // The loop below accounts for endian and v256 vs v8 types.
      for (size_t j = 0; j < 256; ++j) {
        mm[j] = cmp_buf[2 + (255 - j) / 8][(j % 8)];
      }
      lc_.vassert_is_bit(mm);

      // 3. Check the hash matches the value in the witness.
      auto two = lc_.template vbit<8>(2);
      sha_.assert_message_hash(2, two, vw.attrb_[ai].data(), mm,
                               vw.attr_sha_[ai].data());

      // 4. Check the length of the witness.
      v64 salted_len = sha_.find_len(2, vw.attrb_[ai].data(), two);

      // 5. Check the attribute is well-formed and matches the public argument.
      assert_attribute(128, vw.attrb_[ai].data(), vw.salted_hashes_[ai], oa[ai],
                       salted_len);
    }
  }

  void assert_delegation_policy(const DelegationPolicyInput& in,
                                const v8 now[/*20*/],
                                const v256& delegation_e,
                                const v256& revocation_status_e,
                                const DelegationPolicyWitness& vw) const {
    assert_delegation_policy_common(in, now);

    auto msg = construct_delegation_message(in);
    const v8 nb = lc_.template vbit<8>((kDelegationMsgSize + 9 + 63) / 64);
    sha_.assert_message_hash(kDelegationMsgSHABlocks, nb, msg.data(),
                             delegation_e, vw.delegation_msg_sha);

    auto id_msg = construct_revocation_id_message(delegation_e);
    v256 revocation_id;
    for (size_t i = 0; i < 256; ++i) {
      revocation_id[i] = in.revocation_id[31 - (i / 8)][i % 8];
    }
    const v8 id_nb = lc_.template vbit<8>(
        (kDelegationRevocationIdMsgSize + 9 + 63) / 64);
    sha_.assert_message_hash(kDelegationRevocationIdSHABlocks, id_nb,
                             id_msg.data(), revocation_id,
                             vw.revocation_id_sha);

    auto status_msg = construct_revocation_status_message(in);
    const v8 status_nb = lc_.template vbit<8>(
        (kDelegationRevocationStatusMsgSize + 9 + 63) / 64);
    sha_.assert_message_hash(kDelegationRevocationStatusSHABlocks, status_nb,
                             status_msg.data(), revocation_status_e,
                             vw.revocation_status_sha);
  }

  void assert_delegation_policy_sm3(
      const DelegationPolicyInput& in, const v8 now[/*20*/],
      const v256& dpkx, const v256& dpky, const v256& delegation_e,
      const v256& revocation_status_e, const DelegationPolicySm3Witness& vw)
      const {
    assert_delegation_policy_common(in, now);

    auto msg = construct_delegation_message(in);
    const v8 nb = lc_.template vbit<8>((kDelegationMsgSize + 9 + 63) / 64);
    sm3_.assert_message(kDelegationMsgSHABlocks, nb, msg.data(),
                        vw.delegation_msg_sm3);
    v256 delegation_digest = sm3_.hash_from_witness(
        kDelegationMsgSHABlocks, nb, vw.delegation_msg_sm3);

    auto device_za_msg =
        construct_sm2_za_message(delegation_device_id(), dpkx, dpky);
    const v8 za_nb = lc_.template vbit<8>(kSm2ZaMessageSM3Blocks);
    sm3_.assert_message(kSm2ZaMessageSM3Blocks, za_nb,
                        device_za_msg.data(), vw.device_za_sm3);
    v256 device_za = sm3_.hash_from_witness(kSm2ZaMessageSM3Blocks, za_nb,
                                            vw.device_za_sm3);

    auto delegation_sig_msg =
        construct_sm2_digest_signature_message(device_za, delegation_digest);
    const v8 sig_nb = lc_.template vbit<8>(kSm2DigestMessageSM3Blocks);
    sm3_.assert_message_hash(kSm2DigestMessageSM3Blocks, sig_nb,
                             delegation_sig_msg.data(), delegation_e,
                             vw.delegation_sig_sm3);

    auto id_msg = construct_revocation_id_message(delegation_digest);
    v256 revocation_id;
    for (size_t i = 0; i < 256; ++i) {
      revocation_id[i] = in.revocation_id[31 - (i / 8)][i % 8];
    }
    const v8 id_nb = lc_.template vbit<8>(
        (kDelegationRevocationIdMsgSize + 9 + 63) / 64);
    sm3_.assert_message_hash(kDelegationRevocationIdSHABlocks, id_nb,
                             id_msg.data(), revocation_id,
                             vw.revocation_id_sm3);

    auto status_msg = construct_revocation_status_message(in);
    const v8 status_nb = lc_.template vbit<8>(
        (kDelegationRevocationStatusMsgSize + 9 + 63) / 64);
    sm3_.assert_message(kDelegationRevocationStatusSHABlocks, status_nb,
                        status_msg.data(), vw.revocation_status_sm3);
    v256 revocation_status_digest = sm3_.hash_from_witness(
        kDelegationRevocationStatusSHABlocks, status_nb,
        vw.revocation_status_sm3);

    auto revocation_sig_msg = construct_sm2_digest_signature_message(
        device_za, revocation_status_digest);
    sm3_.assert_message_hash(kSm2DigestMessageSM3Blocks, sig_nb,
                             revocation_sig_msg.data(), revocation_status_e,
                             vw.revocation_sig_sm3);
  }

 private:
  void assert_delegation_policy_common(const DelegationPolicyInput& in,
                                       const v8 now[/*20*/]) const {
    const Memcmp<LogicCircuit> CMP(lc_);
    lc_.vassert_is_bit(in.allowed_count);
    lc_.assert1(lc_.vleq(in.allowed_count, kDelegationMaxClaims));
    lc_.assert1(CMP.lt(kDelegationExpiresSize, now, in.expires));
    lc_.vassert_eq(in.revocation_revoked, 0);
    lc_.assert1(CMP.lt(kDelegationExpiresSize, now, in.revocation_expires));

    for (const auto& requested : in.requested_claim_hashes) {
      BitW allowed = lc_.bit(0);
      for (size_t i = 0; i < kDelegationMaxClaims; ++i) {
        BitW active = lc_.vlt(i, in.allowed_count);
        BitW same = hash_eq(requested.data(), in.allowed_claim_hashes[i]);
        allowed = lc_.lor(&allowed, lc_.land(&active, same));
      }
      lc_.assert1(allowed);
    }
  }

  BitW hash_eq(const v8 a[/*32*/], const v8 b[/*32*/]) const {
    std::vector<BitW> abits(256);
    std::vector<BitW> bbits(256);
    for (size_t i = 0; i < 32; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        abits[8 * i + j] = a[i][j];
        bbits[8 * i + j] = b[i][j];
      }
    }
    return lc_.eq(abits.size(), abits.data(), bbits.data());
  }

  const uint8_t* delegation_device_id() const {
    static constexpr uint8_t kDeviceId[kSm2UserIdSize] = {
        'Z', 'K', 'A', 'A', '-', 'D', 'E', 'V',
        'I', 'C', 'E', '-', '0', '0', '0', '1'};
    return kDeviceId;
  }

  std::vector<v8> construct_sm2_za_message(
      const uint8_t signer_id[kSm2UserIdSize], const v256& pkx,
      const v256& pky) const {
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
    const v8 zero = lc_.template vbit<8>(0x00);
    std::vector<v8> msg(64 * kSm2ZaMessageSM3Blocks, zero);
    size_t p = 0;
    auto put_const = [&](uint8_t b) { msg[p++] = lc_.template vbit<8>(b); };
    put_const(0x00);
    put_const(static_cast<uint8_t>(kSm2UserIdSize * 8));
    for (size_t i = 0; i < kSm2UserIdSize; ++i) put_const(signer_id[i]);
    for (uint8_t b : kA) put_const(b);
    for (uint8_t b : kB) put_const(b);
    for (uint8_t b : kGx) put_const(b);
    for (uint8_t b : kGy) put_const(b);
    put_v256_bytes(&msg, &p, pkx);
    put_v256_bytes(&msg, &p, pky);
    finish_sha_padding(&msg, &p, kSm2ZaMessageSize);
    return msg;
  }

  std::vector<v8> construct_sm2_digest_signature_message(
      const v256& za, const v256& digest) const {
    const v8 zero = lc_.template vbit<8>(0x00);
    std::vector<v8> msg(64 * kSm2DigestMessageSM3Blocks, zero);
    size_t p = 0;
    put_v256_be(&msg, &p, za);
    put_v256_be(&msg, &p, digest);
    finish_sha_padding(&msg, &p, kSm2DigestMessageSize);
    return msg;
  }

  std::vector<v8> construct_delegation_message(
      const DelegationPolicyInput& in) const {
    static constexpr uint8_t kDomain[kDelegationMsgDomainSize] = {
        'Z', 'K', 'D', 'E', 'L', 'G', '1', 0x00};
    const v8 zero = lc_.template vbit<8>(0x00);
    std::vector<v8> msg(64 * kDelegationMsgSHABlocks, zero);
    size_t p = 0;
    auto put_const = [&](uint8_t b) { msg[p++] = lc_.template vbit<8>(b); };
    auto put_v8 = [&](const v8& b) { msg[p++] = b; };
    for (uint8_t b : kDomain) put_const(b);
    for (size_t i = 0; i < 32; ++i) put_v8(in.agent_pkx[i]);
    for (size_t i = 0; i < 32; ++i) put_v8(in.agent_pky[i]);
    put_v8(in.allowed_count);
    for (size_t i = 0; i < kDelegationMaxClaims; ++i) {
      for (size_t j = 0; j < kDelegationClaimHashSize; ++j) {
        put_v8(in.allowed_claim_hashes[i][j]);
      }
    }
    for (size_t i = 0; i < kDelegationExpiresSize; ++i) put_v8(in.expires[i]);
    for (size_t i = 0; i < kDelegationAgentIdHashSize; ++i) {
      put_v8(in.agent_id_hash[i]);
    }
    put_const(0x80);
    if ((p % 64) == 0 || (p % 64) > 56) {
      while (p % 64) put_const(0x00);
    }
    while ((p % 64) < 56) put_const(0x00);
    const uint64_t bit_len = kDelegationMsgSize * 8;
    for (size_t i = 0; i < 8; ++i) {
      put_const(static_cast<uint8_t>(bit_len >> (8 * (7 - i))));
    }
    return msg;
  }

  void put_v256_be(std::vector<v8>* msg, size_t* p, const v256& e) const {
    for (size_t i = 0; i < 32; ++i) {
      v8 b;
      for (size_t j = 0; j < 8; ++j) {
        b[j] = e[(31 - i) * 8 + j];
      }
      (*msg)[(*p)++] = b;
    }
  }

  void put_v256_bytes(std::vector<v8>* msg, size_t* p, const v256& e) const {
    for (size_t i = 0; i < 32; ++i) {
      v8 b;
      for (size_t j = 0; j < 8; ++j) {
        b[j] = e[i * 8 + j];
      }
      (*msg)[(*p)++] = b;
    }
  }

  void finish_sha_padding(std::vector<v8>* msg, size_t* p,
                          uint64_t payload_size) const {
    auto put_const = [&](uint8_t b) {
      (*msg)[(*p)++] = lc_.template vbit<8>(b);
    };
    put_const(0x80);
    if (((*p) % 64) == 0 || ((*p) % 64) > 56) {
      while ((*p) % 64) put_const(0x00);
    }
    while (((*p) % 64) < 56) put_const(0x00);
    const uint64_t bit_len = payload_size * 8;
    for (size_t i = 0; i < 8; ++i) {
      put_const(static_cast<uint8_t>(bit_len >> (8 * (7 - i))));
    }
  }

  std::vector<v8> construct_revocation_id_message(
      const v256& delegation_e) const {
    static constexpr uint8_t kDomain[kDelegationRevocationIdDomainSize] = {
        'Z', 'K', 'D', 'E', 'L', 'I', 'D', '1'};
    const v8 zero = lc_.template vbit<8>(0x00);
    std::vector<v8> msg(64 * kDelegationRevocationIdSHABlocks, zero);
    size_t p = 0;
    auto put_const = [&](uint8_t b) { msg[p++] = lc_.template vbit<8>(b); };
    for (uint8_t b : kDomain) put_const(b);
    put_v256_be(&msg, &p, delegation_e);
    finish_sha_padding(&msg, &p, kDelegationRevocationIdMsgSize);
    return msg;
  }

  std::vector<v8> construct_revocation_status_message(
      const DelegationPolicyInput& in) const {
    static constexpr uint8_t kDomain[kDelegationRevocationStatusDomainSize] = {
        'Z', 'K', 'D', 'E', 'L', 'S', 'T', '1'};
    const v8 zero = lc_.template vbit<8>(0x00);
    std::vector<v8> msg(64 * kDelegationRevocationStatusSHABlocks, zero);
    size_t p = 0;
    auto put_const = [&](uint8_t b) { msg[p++] = lc_.template vbit<8>(b); };
    auto put_v8 = [&](const v8& b) { msg[p++] = b; };
    for (uint8_t b : kDomain) put_const(b);
    for (size_t i = 0; i < 32; ++i) put_v8(in.revocation_id[i]);
    for (size_t i = 0; i < kDelegationRevocationEpochSize; ++i) {
      put_v8(in.revocation_epoch[i]);
    }
    for (size_t i = 0; i < kDelegationExpiresSize; ++i) {
      put_v8(in.revocation_expires[i]);
    }
    put_v8(in.revocation_revoked);
    finish_sha_padding(&msg, &p, kDelegationRevocationStatusMsgSize);
    return msg;
  }

  std::vector<v8> construct_signature_preimage(const Witness& vw) const {
    std::vector<v8> bbuf(64 * kMaxSHABlocks);
    for (size_t i = 0; i < 64 * kMaxSHABlocks; ++i) {
      if (i < kCose1PrefixLen) {
        lc_.bits(8, bbuf[i].data(), kCose1Prefix[i]);
      } else {
        bbuf[i] = vw.in_[i - kCose1PrefixLen];
      }
    }
    return bbuf;
  }

  vind extract_vind(v64 len) const {
    auto low = lc_.template slice<0, 3>(len);
    auto mid = lc_.template slice<3, 3 + kCborIndexBits>(len);
    auto hi = lc_.template slice<3 + kCborIndexBits, 64>(len);
    // Because check_index is called on several indices, the following two
    // checks will be called several times. However, the compiler removes
    // redundant checks, and it is convenient to verify the ranges in one
    // function. An alternative would be to verify the low 3 bits of len
    // and upper 40+ bits of len are 0, and then rely on that invariant in
    // this method, but that separates the logic, and this is easier to audit.
    lc_.vassert0(low);
    lc_.vassert0(hi);
    return mid;
  }

  // Checks that the index is less than the length. The len is given as bits
  // in a v64 in big endian order, and the index is given as a byte index.
  void check_index(vind index, v64 len) const {
    lc_.vassert_is_bit(index);
    auto mid = extract_vind(len);
    lc_.assert1(lc_.vlt(&index, mid));
  }

  void assert_bytes_at(size_t len, const v8 buf[/*>=len*/],
                       const uint8_t want[/*len*/]) const {
    for (size_t i = 0; i < len; ++i) {
      auto want_i = lc_.template vbit<8>(want[i]);
      lc_.vassert_eq(&buf[i], want_i);
    }
  }

  void format_element(v8 buf[/*max*/], size_t max,
                      const uint8_t prefix[/*prefix_len*/], size_t prefix_len,
                      const v8 str[/*str_len*/], size_t str_len) const {
    for (size_t i = 0; i < max; ++i) {
      buf[i] = lc_.template vbit<8>(0);
    }
    for (size_t i = 0; i < prefix_len; ++i) {
      buf[i] = lc_.template vbit<8>(prefix[i]);
    }
    for (size_t i = 0; i < str_len && prefix_len + i < max; ++i) {
      buf[prefix_len + i] = str[i];
    }
  }

  // This function verifies that the length of a cbor key-value pair in an array
  // matches the claimed length.
  //    key_len: the length of the key with its header byte included.
  //    val_hdr_index: the index of the value's cbor header
  //                   byte in the buffer.
  //    atom:  true if the value is an atom, e.g., the digestID.
  //           false it is a string or array.
  void check_cbor_length(const v8 buf[/*max*/], size_t max,
                         const vind& expected_len, size_t val_hdr_index,
                         bool atom = false) const {
    // The length of a key-value field for a known key will be:
    // len(encoding of key) + len(key) + len(header of value) + len(value)

    auto cbor = cb_.decode_one_v8(buf[val_hdr_index]);
    lc_.assert0(cbor.invalid);

    vind l1 = lc_.template vbit<kCborIndexBits>(0),  // len of value
        l2 = lc_.template vbit<kCborIndexBits>(0);   // len of header of value
    vind one = lc_.template vbit<kCborIndexBits>(1),
         two = lc_.template vbit<kCborIndexBits>(2);
    if (!atom) {
      // Mux the length of the value into l1.
      // In this case, the value is either encoded in the last 5 bits of the
      // header byte, or in the next byte.  The array length is < 256 by
      // external constraints, and thus its length is in 1 or 2 bytes.
      for (size_t j = 0; j < 8; ++j) {
        l1[j] = lc_.mux(&cbor.length_plus_next_v8, &buf[val_hdr_index + 1][j],
                        j < 5 ? buf[val_hdr_index][j] : lc_.bit(0));
      }
      lc_.vmux(cbor.length_plus_next_v8, l2, two, one);
    } else {
      // For atoms, the value length is zero. The header length is 1,2,3, or 5
      // because the digestID is constrained to be < 2^31 [18013-5, 9.1.2.4].
      lc_.assert0(cbor.count27);
      l2[2] = cbor.count26;
      l2[1] = lc_.lor(&cbor.count24, cbor.count25);
      l2[0] = lc_.lnot(cbor.count24);
    }

    // Compute the read length.
    vind k_len = lc_.template vbit<kCborIndexBits>(val_hdr_index);
    vind v_len = lc_.template vadd<kCborIndexBits>(l1, l2);
    lc_.assert_sum(kCborIndexBits, expected_len.data(), k_len.data(),
                   v_len.data());
  }

  // assert_attribute checks that the bytes in buf correspond to a valid
  // cbor structure that encodes the OpenedAttribute oa.
  void assert_attribute(size_t max, const v8 buf[/*max*/], const SaltedHash& sh,
                        const OpenedAttribute& oa, const v64 salted_len) const {
    // Perform a cbor parsing of the buffer, which is expected to be
    // a 4-element key-value array consisting of keys digestId, random,
    // elementIdentifier, and elementValue. Then perform a check on the
    // last two.  The complexity of check stems from the fact that the 4 pairs
    // can occur in any order.
    // The prover provides the following witnesses in SaltedHash:
    // -- (5, l0), (i1, l1), (i2, l2), (i3, l3)
    //    where li is the length of the i-th element in bytes.
    // -- j7j6 j5j4 j3j2 j1j0 where ji \in {0,1}, and
    //    j1j0: specifies the index in the previous array of digestId
    //    j3j2: specifies the index in the previous array of random
    //    j5j4: specifies the index in the previous array of elementIdentifier
    //    j7j6: specifies the index in the previous array of elementValue

    // Verify the cbor prefix for IssuerSignedItem.
    static const uint8_t cbor_tag[] = {0xD8, 0x18, 0x58};
    static const uint8_t cbor_array[] = {0xA4};
    assert_bytes_at(3, buf, cbor_tag);
    assert_bytes_at(1, &buf[4], cbor_array);

    // Verify all of the indices and lengths are contiguous and consistent.
    vind five = lc_.template vbit<kCborIndexBits>(5);
    vind tot = extract_vind(salted_len);
    lc_.assert_sum(kCborIndexBits, sh.i1.data(), five.data(), sh.l[0].data());
    lc_.assert_sum(kCborIndexBits, sh.i2.data(), sh.i1.data(), sh.l[1].data());
    lc_.assert_sum(kCborIndexBits, sh.i3.data(), sh.i2.data(), sh.l[2].data());
    lc_.assert_sum(kCborIndexBits, tot.data(), sh.i3.data(), sh.l[3].data());

    // Verify expected structure of the salted hash cbor array.
    vind shift, len;
    const size_t MAX_BUF = 119;
    v8 got[MAX_BUF];  // Max buffer length for a 2-block SHA hash.
    const v8 zz = lc_.template vbit<8>(0);  // cannot appear in strings

    // Shift each of the 4 fields into place, and perform consistency checks.
    // "digestID" checks the cbor key and consistency with the total length.
    mux_offset(0, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    assert_bytes_at(kDigestLen, &got[0], kDigestID);
    check_cbor_length(got, MAX_BUF, len, 9, true);

    // "random" checks the cbor key and consistency with the total length.
    mux_offset(1, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    assert_bytes_at(kRandomLen, &got[0], kRandomID);
    check_cbor_length(got, MAX_BUF, len, 7);

    const size_t MAX_EI =
        1 + 17 + 32;  // The 32/64 includes len of any headers.
    const size_t MAX_EV = 1 + 12 + 64;
    v8 want_ei[MAX_EI], want_ev[MAX_EV];
    uint8_t ei_bytes[] = {0x60 + 17, 'e', 'l', 'e', 'm', 'e', 'n', 't', 'I',
                          'd',       'e', 'n', 't', 'i', 'f', 'i', 'e', 'r'};
    uint8_t ev_bytes[] = {0x60 + 12, 'e', 'l', 'e', 'm', 'e', 'n',
                          't',       'V', 'a', 'l', 'u', 'e'};
    format_element(want_ei, MAX_EI, ei_bytes, sizeof(ei_bytes), oa.attr, 32);
    format_element(want_ev, MAX_EV, ev_bytes, sizeof(ev_bytes), oa.v1, 64);

    // "elementIdentifier" checks the full cbor key-value, because it is public.
    mux_offset(2, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    for (size_t j = 0; j < MAX_EI; ++j) {
      auto ll = lc_.vlt(j, oa.len);
      for (size_t i = 0; i < 8; ++i) {
        auto same = lc_.eq(1, &got[j][i], &want_ei[j][i]);
        lc_.assert_implies(&ll, same);
      }
    }
    v8 tmp;
    std::copy(len.begin(), len.begin() + 8, tmp.begin());  // cast vind into v8.
    lc_.vassert_eq(&tmp, oa.len);

    // "elementValue" checks the full cbor key-value, because it is public.
    mux_offset(3, shift, len, sh);
    r_.shift(shift, MAX_BUF, got, max, buf, zz, 3);
    for (size_t j = 0; j < MAX_EV; ++j) {
      auto ll = lc_.vlt(j, oa.vlen);
      for (size_t i = 0; i < 8; ++i) {
        auto same = lc_.eq(1, &got[j][i], &want_ev[j][i]);
        lc_.assert_implies(&ll, same);
      }
    }
    std::copy(len.begin(), len.begin() + 8, tmp.begin());  // cast vind into v8.
    lc_.vassert_eq(&tmp, oa.vlen);
  }

  void mux_offset(size_t slot, vind& shift, vind& len,
                  const SaltedHash& sh) const {
    vind t[2];
    vind five = lc_.template vbit<kCborIndexBits>(5);
    lc_.vmux(sh.perm[2 * slot + 1], t[0], sh.i2, five);
    lc_.vmux(sh.perm[2 * slot + 1], t[1], sh.i3, sh.i1);
    lc_.vmux(sh.perm[2 * slot], shift, t[1], t[0]);

    lc_.vmux(sh.perm[2 * slot + 1], t[0], sh.l[2], sh.l[0]);
    lc_.vmux(sh.perm[2 * slot + 1], t[1], sh.l[3], sh.l[1]);
    lc_.vmux(sh.perm[2 * slot], len, t[1], t[0]);
  }

  // Asserts that the key is equal to the value in big-endian order in buf_be.
  void assert_key(v256 key, const v8 buf_be[/*32*/]) const {
    v256 m;
    for (size_t i = 0; i < 256; ++i) {
      m[i] = buf_be[31 - (i / 8)][i % 8];
    }
    lc_.vassert_eq(&m, key);
  }

  // The constants below define the prefix of each field that is verified
  // in the MDOC. This string matching approach is substantially faster than
  // parsing the MDOC into cbor, and its soundness analysis provides at least 96
  // bits of static security.  These constants differ from similarly named ones
  // in mdoc_constants because they include header bytes; the mdoc_constants
  // values are used for cbor parsing of the raw mdoc, whereas these are used by
  // the circuit.

  // 69 [text(9)] 76616C696446726F6D [validFrom] C0 [tag(0)] 74 [len 20]
  static constexpr uint8_t kValidFromCheck[] = {
      0x69, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x46, 0x72, 0x6F, 0x6D, 0xC0, 0x74};
  static constexpr size_t kValidFromLen = sizeof(kValidFromCheck);

  // 6A [text(10)] 76616C6964556E74696C [validUntil] C0 [tag(0)] 74
  static constexpr uint8_t kValidUntilCheck[] = {0x6A, 0x76, 0x61, 0x6C, 0x69,
                                                 0x64, 0x55, 0x6E, 0x74, 0x69,
                                                 0x6C, 0xC0, 0x74};
  static constexpr size_t kValidUntilLen = sizeof(kValidUntilCheck);

  // 6D text(13) 6465766963654B6579496E666F "deviceKeyInfo"
  //   A1 map(1) 69 text(9) 6465766963654B6579 "deviceKey"
  //      A4 map(4) 01 02 20 01
  //      21 negative(1) 58 20 bytes(32)
  //      <dpkx>
  //      22 negative(2) 58 20 bytes(32)
  //      <dpky>
  static constexpr uint8_t kDeviceKeyInfoCheck[] = {
      0x6D, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4B, 0x65, 0x79, 0x49,
      0x6E, 0x66, 0x6F, 0xA1, 0x69, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65,
      0x4B, 0x65, 0x79, 0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20};
  static constexpr size_t kDeviceKeyInfoLen = sizeof(kDeviceKeyInfoCheck);
  static constexpr size_t kPkxInd = kDeviceKeyInfoLen;
  static constexpr size_t kPkyInd = 68; /* 64 + 3 byte tag + 1*/

  // 6C text(12) 76616C756544696765737473  "valueDigests" A{1,2} # map(1,2)
  //     71 text(17) 6F72672E69736F2E31383031332E352E31 "org.iso.18013.5.1"
  static constexpr uint8_t kValueDigestsCheck[] = {
      0x6C, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x44,
      0x69, 0x67, 0x65, 0x73, 0x74, 0x73,
  };
  static constexpr size_t kValueDigestsLen = sizeof(kValueDigestsCheck);

  static constexpr size_t kDateLen = 20;

  const LogicCircuit& lc_;
  Flatsha sha_;
  Flatsm3 sm3_;
  Routing<LogicCircuit> r_;
  CborByteDecoder<LogicCircuit> cb_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_HASH_H_
