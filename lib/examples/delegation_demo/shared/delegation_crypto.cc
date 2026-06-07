#include "examples/delegation_demo/shared/delegation_crypto.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "examples/mdoc_anoncred/shared/crypto.h"
#include "util/crypto.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"

namespace proofs {
namespace {

std::vector<std::string> Split(const std::string& s, char delim) {
  std::vector<std::string> out;
  std::string cur;
  std::istringstream iss(s);
  while (std::getline(iss, cur, delim)) {
    out.push_back(cur);
  }
  return out;
}

std::string CanonicalPredicates(const std::vector<PolicyPredicate>& ps) {
  std::string out = "[";
  for (size_t i = 0; i < ps.size(); ++i) {
    if (i > 0) out += ",";
    out += "{\"claim\":\"" + ps[i].claim + "\",\"op\":\"" +
           PredicateOpName(ps[i].op) + "\",\"values\":[";
    for (size_t j = 0; j < ps[i].values.size(); ++j) {
      if (j > 0) out += ",";
      out += "\"" + ps[i].values[j] + "\"";
    }
    out += "]}";
  }
  out += "]";
  return out;
}

const ReaderClaim* FindClaim(const std::vector<ReaderClaim>& claims,
                             const std::string& alias) {
  for (const auto& claim : claims) {
    if (claim.alias == alias) return &claim;
  }
  return nullptr;
}

bool CborToText(const std::vector<uint8_t>& cbor, std::string* out) {
  if (cbor.empty()) return false;
  if (cbor.size() == 1 && cbor[0] == 0xf4) {
    *out = "false";
    return true;
  }
  if (cbor.size() == 1 && cbor[0] == 0xf5) {
    *out = "true";
    return true;
  }
  const uint8_t major = cbor[0] >> 5;
  const uint8_t add = cbor[0] & 0x1f;
  if (major == 0) {
    uint64_t v = 0;
    if (add < 24) {
      v = add;
    } else if (add == 24 && cbor.size() == 2) {
      v = cbor[1];
    } else if (add == 25 && cbor.size() == 3) {
      v = (static_cast<uint64_t>(cbor[1]) << 8) | cbor[2];
    } else {
      return false;
    }
    *out = std::to_string(v);
    return true;
  }
  if (major == 3) {
    size_t len = 0;
    size_t off = 1;
    if (add < 24) {
      len = add;
    } else if (add == 24 && cbor.size() >= 2) {
      len = cbor[1];
      off = 2;
    } else {
      return false;
    }
    if (off + len != cbor.size()) return false;
    out->assign(reinterpret_cast<const char*>(cbor.data() + off), len);
    return true;
  }
  if (cbor.size() >= 4 && cbor[0] == 0xd9 && cbor[1] == 0x03 &&
      cbor[2] == 0xec && (cbor[3] >> 5) == 3) {
    std::vector<uint8_t> inner(cbor.begin() + 3, cbor.end());
    return CborToText(inner, out);
  }
  return false;
}

bool ParseInt64(const std::string& s, int64_t* out) {
  if (s.empty()) return false;
  size_t pos = 0;
  try {
    const long long v = std::stoll(s, &pos, 10);
    if (pos != s.size()) return false;
    *out = static_cast<int64_t>(v);
    return true;
  } catch (...) {
    return false;
  }
}

bool DigestWithEvp(const EVP_MD* md, const uint8_t* data, size_t len,
                   std::vector<uint8_t>* digest) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) return false;
  bool ok = false;
  unsigned int out_len = 0;
  digest->assign(EVP_MD_get_size(md), 0);
  if (EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
      EVP_DigestUpdate(ctx, data, len) == 1 &&
      EVP_DigestFinal_ex(ctx, digest->data(), &out_len) == 1 &&
      out_len == digest->size()) {
    ok = true;
  }
  EVP_MD_CTX_free(ctx);
  return ok;
}

bool ComputeSm2MessageDigest(const char* signer_id,
                             const std::vector<uint8_t>& pkx,
                             const std::vector<uint8_t>& pky,
                             const uint8_t* msg, size_t msg_len,
                             uint8_t e_bytes[32], std::string* err) {
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
  if (signer_id == nullptr || msg == nullptr || e_bytes == nullptr ||
      pkx.size() != 32 || pky.size() != 32) {
    if (err != nullptr) *err = "invalid SM2 digest input";
    return false;
  }
  const size_t id_len = std::strlen(signer_id);
  if (id_len == 0 || id_len > 8191) {
    if (err != nullptr) *err = "invalid SM2 signer id length";
    return false;
  }
  const uint16_t entl = static_cast<uint16_t>(id_len * 8);
  std::vector<uint8_t> za_msg;
  za_msg.reserve(2 + id_len + 32 * 6);
  za_msg.push_back(static_cast<uint8_t>(entl >> 8));
  za_msg.push_back(static_cast<uint8_t>(entl));
  za_msg.insert(za_msg.end(), signer_id, signer_id + id_len);
  za_msg.insert(za_msg.end(), std::begin(kA), std::end(kA));
  za_msg.insert(za_msg.end(), std::begin(kB), std::end(kB));
  za_msg.insert(za_msg.end(), std::begin(kGx), std::end(kGx));
  za_msg.insert(za_msg.end(), std::begin(kGy), std::end(kGy));
  za_msg.insert(za_msg.end(), pkx.begin(), pkx.end());
  za_msg.insert(za_msg.end(), pky.begin(), pky.end());
  std::vector<uint8_t> za;
  if (!DigestWithEvp(EVP_sm3(), za_msg.data(), za_msg.size(), &za) ||
      za.size() != 32) {
    if (err != nullptr) *err = "SM2 ZA digest failed";
    return false;
  }
  std::vector<uint8_t> e_msg;
  e_msg.reserve(za.size() + msg_len);
  e_msg.insert(e_msg.end(), za.begin(), za.end());
  e_msg.insert(e_msg.end(), msg, msg + msg_len);
  std::vector<uint8_t> e;
  if (!DigestWithEvp(EVP_sm3(), e_msg.data(), e_msg.size(), &e) ||
      e.size() != 32) {
    if (err != nullptr) *err = "SM2 message digest failed";
    return false;
  }
  std::copy(e.begin(), e.end(), e_bytes);
  return true;
}

bool BuildSm2PkeyFromPrivateKey(const std::string& sk_hex, EVP_PKEY** pkey,
                                std::string* err) {
  *pkey = nullptr;
  std::vector<uint8_t> sk_bytes;
  if (!HexToBytes(sk_hex, &sk_bytes, err)) {
    return false;
  }
  if (sk_bytes.size() != 32) {
    if (err != nullptr) *err = "SM2 private key must be 32 bytes";
    return false;
  }

  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_sm2);
  if (ec_key == nullptr) {
    if (err != nullptr) *err = "failed to initialize SM2 key";
    return false;
  }
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  BIGNUM* priv = BN_bin2bn(sk_bytes.data(), sk_bytes.size(), nullptr);
  EC_POINT* pub = EC_POINT_new(group);
  EVP_PKEY* local = EVP_PKEY_new();
  bool ok = false;
  do {
    if (priv == nullptr || pub == nullptr || local == nullptr) {
      if (err != nullptr) *err = "failed to allocate SM2 key components";
      break;
    }
    if (BN_is_zero(priv) ||
        EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr) != 1 ||
        EC_KEY_set_private_key(ec_key, priv) != 1 ||
        EC_KEY_set_public_key(ec_key, pub) != 1 ||
        EVP_PKEY_assign_EC_KEY(local, ec_key) != 1) {
      if (err != nullptr) *err = "failed to construct SM2 private key";
      break;
    }
    ec_key = nullptr;  // ownership moved to local
    *pkey = local;
    local = nullptr;
    ok = true;
  } while (false);

  if (priv != nullptr) BN_free(priv);
  if (pub != nullptr) EC_POINT_free(pub);
  if (local != nullptr) EVP_PKEY_free(local);
  if (ec_key != nullptr) EC_KEY_free(ec_key);
  return ok;
}

bool BuildSm2PkeyFromPublicKey(const std::string& pkx_hex,
                               const std::string& pky_hex, EVP_PKEY** pkey,
                               std::string* err) {
  *pkey = nullptr;
  std::vector<uint8_t> pkx_bytes, pky_bytes;
  if (!HexToBytes(pkx_hex, &pkx_bytes, err) ||
      !HexToBytes(pky_hex, &pky_bytes, err)) {
    return false;
  }
  if (pkx_bytes.size() != 32 || pky_bytes.size() != 32) {
    if (err != nullptr) *err = "SM2 public key coordinates must be 32 bytes";
    return false;
  }

  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_sm2);
  if (ec_key == nullptr) {
    if (err != nullptr) *err = "failed to initialize SM2 public key";
    return false;
  }
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  BIGNUM* bx = BN_bin2bn(pkx_bytes.data(), pkx_bytes.size(), nullptr);
  BIGNUM* by = BN_bin2bn(pky_bytes.data(), pky_bytes.size(), nullptr);
  EC_POINT* pub = EC_POINT_new(group);
  EVP_PKEY* local = EVP_PKEY_new();
  bool ok = false;
  do {
    if (bx == nullptr || by == nullptr || pub == nullptr || local == nullptr) {
      if (err != nullptr) *err = "failed to allocate SM2 public key";
      break;
    }
    if (EC_POINT_set_affine_coordinates_GFp(group, pub, bx, by, nullptr) != 1 ||
        EC_KEY_set_public_key(ec_key, pub) != 1 ||
        EVP_PKEY_assign_EC_KEY(local, ec_key) != 1) {
      if (err != nullptr) *err = "failed to construct SM2 public key";
      break;
    }
    ec_key = nullptr;  // ownership moved to local
    *pkey = local;
    local = nullptr;
    ok = true;
  } while (false);

  if (bx != nullptr) BN_free(bx);
  if (by != nullptr) BN_free(by);
  if (pub != nullptr) EC_POINT_free(pub);
  if (local != nullptr) EVP_PKEY_free(local);
  if (ec_key != nullptr) EC_KEY_free(ec_key);
  return ok;
}

bool SerializeSm2PublicKey(EVP_PKEY* pkey, std::string* pkx_hex,
                           std::string* pky_hex, std::string* err) {
  size_t pub_len = 0;
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0,
                                      &pub_len) != 1 ||
      pub_len == 0) {
    if (err != nullptr) *err = "failed to query SM2 public key";
    return false;
  }
  std::vector<uint8_t> pub(pub_len);
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub.data(),
                                      pub.size(), &pub_len) != 1) {
    if (err != nullptr) *err = "failed to serialize SM2 public key";
    return false;
  }
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
  EC_POINT* point = group == nullptr ? nullptr : EC_POINT_new(group);
  BIGNUM* bx = BN_new();
  BIGNUM* by = BN_new();
  std::array<uint8_t, 32> x{};
  std::array<uint8_t, 32> y{};
  bool ok = false;
  do {
    if (group == nullptr || point == nullptr || bx == nullptr || by == nullptr) {
      if (err != nullptr) *err = "failed to allocate SM2 public key buffers";
      break;
    }
    if (EC_POINT_oct2point(group, point, pub.data(), pub_len, nullptr) != 1 ||
        EC_POINT_get_affine_coordinates_GFp(group, point, bx, by, nullptr) != 1 ||
        BN_bn2binpad(bx, x.data(), x.size()) !=
            static_cast<int>(x.size()) ||
        BN_bn2binpad(by, y.data(), y.size()) !=
            static_cast<int>(y.size())) {
      if (err != nullptr) *err = "failed to decode SM2 public key";
      break;
    }
    *pkx_hex = HexPrefixed(x.data(), x.size());
    *pky_hex = HexPrefixed(y.data(), y.size());
    ok = true;
  } while (false);
  if (bx != nullptr) BN_free(bx);
  if (by != nullptr) BN_free(by);
  if (point != nullptr) EC_POINT_free(point);
  if (group != nullptr) EC_GROUP_free(group);
  return ok;
}

bool Sm2DerToRawRs(const uint8_t* der, size_t der_len,
                   std::vector<uint8_t>* sig_rs, std::string* err) {
  const uint8_t* p = der;
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, der_len);
  if (sig == nullptr || p != der + der_len) {
    if (err != nullptr) *err = "failed to parse SM2 DER signature";
    if (sig != nullptr) ECDSA_SIG_free(sig);
    return false;
  }
  const BIGNUM* r = ECDSA_SIG_get0_r(sig);
  const BIGNUM* s = ECDSA_SIG_get0_s(sig);
  sig_rs->assign(64, 0);
  const bool ok =
      BN_bn2binpad(r, sig_rs->data(), 32) == 32 &&
      BN_bn2binpad(s, sig_rs->data() + 32, 32) == 32;
  if (!ok && err != nullptr) *err = "failed to serialize SM2 r||s signature";
  ECDSA_SIG_free(sig);
  return ok;
}

bool Sm2RawRsToDer(const std::vector<uint8_t>& sig_rs,
                   std::vector<uint8_t>* der, std::string* err) {
  if (sig_rs.size() != 64) {
    if (err != nullptr) *err = "SM2 signature must be 64 bytes (r||s)";
    return false;
  }
  BIGNUM* r = BN_bin2bn(sig_rs.data(), 32, nullptr);
  BIGNUM* s = BN_bin2bn(sig_rs.data() + 32, 32, nullptr);
  ECDSA_SIG* sig = ECDSA_SIG_new();
  bool ok = false;
  do {
    if (r == nullptr || s == nullptr || sig == nullptr) {
      if (err != nullptr) *err = "failed to allocate SM2 signature";
      break;
    }
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
      if (err != nullptr) *err = "failed to set SM2 signature";
      break;
    }
    r = nullptr;
    s = nullptr;
    const int len = i2d_ECDSA_SIG(sig, nullptr);
    if (len <= 0) {
      if (err != nullptr) *err = "failed to size SM2 DER signature";
      break;
    }
    der->assign(static_cast<size_t>(len), 0);
    uint8_t* p = der->data();
    if (i2d_ECDSA_SIG(sig, &p) != len) {
      if (err != nullptr) *err = "failed to encode SM2 DER signature";
      break;
    }
    ok = true;
  } while (false);
  if (r != nullptr) BN_free(r);
  if (s != nullptr) BN_free(s);
  if (sig != nullptr) ECDSA_SIG_free(sig);
  return ok;
}

bool SetSm2Identity(EVP_MD_CTX* ctx, const char* signer_id, std::string* err) {
  if (signer_id == nullptr || signer_id[0] == '\0') {
    if (err != nullptr) *err = "SM2 signer id must be non-empty";
    return false;
  }
  EVP_PKEY_CTX* pctx = EVP_MD_CTX_pkey_ctx(ctx);
  if (pctx == nullptr ||
      EVP_PKEY_CTX_set1_id(pctx, signer_id, std::strlen(signer_id)) != 1) {
    if (err != nullptr) *err = "failed to set SM2 signer id";
    return false;
  }
  return true;
}

std::vector<uint8_t> BuildDelegationMessage(
    const std::string& agent_pkx_hex, const std::string& agent_pky_hex,
    const Policy& policy, bool use_sm3, std::string* err) {
  std::vector<uint8_t> pkx_bytes, pky_bytes;
  if (!HexToBytes(agent_pkx_hex, &pkx_bytes, err) ||
      !HexToBytes(agent_pky_hex, &pky_bytes, err)) {
    return {};
  }
  if (pkx_bytes.size() != 32 || pky_bytes.size() != 32) {
    if (err != nullptr) {
      *err = "agent public key coordinates must be 32 bytes each";
    }
    return {};
  }
  if (policy.allowed_claims.size() > kDelegationMaxClaims) {
    if (err != nullptr) {
      *err = "too many allowed claims for delegated circuit";
    }
    return {};
  }
  if (policy.expires.size() != kDelegationExpiresSize) {
    if (err != nullptr) {
      *err = "policy.expires must be 20-byte ISO 8601 UTC";
    }
    return {};
  }

  std::vector<uint8_t> msg_data;
  msg_data.reserve(kDelegationMsgSize);
  static constexpr uint8_t kDomain[kDelegationMsgDomainSize] = {
      'Z', 'K', 'D', 'E', 'L', 'G', '1', 0x00};
  msg_data.insert(msg_data.end(), std::begin(kDomain), std::end(kDomain));
  msg_data.insert(msg_data.end(), pkx_bytes.begin(), pkx_bytes.end());
  msg_data.insert(msg_data.end(), pky_bytes.begin(), pky_bytes.end());
  msg_data.push_back(static_cast<uint8_t>(policy.allowed_claims.size()));
  for (size_t i = 0; i < kDelegationMaxClaims; ++i) {
    if (i < policy.allowed_claims.size()) {
      std::vector<uint8_t> h;
      if (use_sm3) {
        Sm3Digest(reinterpret_cast<const uint8_t*>(
                      policy.allowed_claims[i].data()),
                  policy.allowed_claims[i].size(), &h);
      } else {
        HashClaimAlias(policy.allowed_claims[i], &h);
      }
      msg_data.insert(msg_data.end(), h.begin(), h.end());
    } else {
      msg_data.insert(msg_data.end(), kDelegationClaimHashSize, 0);
    }
  }
  msg_data.insert(msg_data.end(), policy.expires.begin(), policy.expires.end());
  std::vector<uint8_t> agent_id_hash;
  const std::string policy_context =
      policy.agent_id + "|" + CanonicalPredicates(policy.predicates);
  if (use_sm3) {
    Sm3Digest(reinterpret_cast<const uint8_t*>(policy_context.data()),
              policy_context.size(), &agent_id_hash);
  } else {
    HashAgentId(policy_context, &agent_id_hash);
  }
  msg_data.insert(msg_data.end(), agent_id_hash.begin(), agent_id_hash.end());
  return msg_data;
}

}  // namespace

// ----------------------------------------------------------------
// 规范化 JSON 编码（键按字母序）
// ----------------------------------------------------------------
std::string CanonicalPolicyJson(const Policy& policy) {
  // 键按字母序：agent_id, allowed_claims, created, expires, predicates
  std::string j = "{";
  // agent_id
  j += "\"agent_id\":\"" + policy.agent_id + "\"";
  // allowed_claims
  j += ",\"allowed_claims\":[";
  for (size_t i = 0; i < policy.allowed_claims.size(); ++i) {
    if (i > 0) j += ",";
    j += "\"" + policy.allowed_claims[i] + "\"";
  }
  j += "]";
  // created
  j += ",\"created\":\"" + policy.created + "\"";
  // expires
  j += ",\"expires\":\"" + policy.expires + "\"";
  j += ",\"predicates\":" + CanonicalPredicates(policy.predicates);
  j += "}";
  return j;
}

// ----------------------------------------------------------------
// 委托消息计算
// ----------------------------------------------------------------
bool ComputeDelegationMsgSm3(const std::string& agent_pkx_hex,
                             const std::string& agent_pky_hex,
                             const Policy& policy,
                             std::string* out_msg_hex,
                             std::string* err) {
  const std::vector<uint8_t> msg_data =
      BuildDelegationMessage(agent_pkx_hex, agent_pky_hex, policy, true, err);
  if (msg_data.empty()) return false;
  std::vector<uint8_t> digest;
  if (!Sm3Digest(msg_data.data(), msg_data.size(), &digest)) {
    if (err != nullptr) *err = "SM3 computation failed";
    return false;
  }
  *out_msg_hex = HexPrefixed(digest.data(), digest.size());
  return true;
}

bool Sm3Digest(const uint8_t* data, size_t len, std::vector<uint8_t>* digest) {
  return DigestWithEvp(EVP_sm3(), data, len, digest);
}

bool ComputeDeviceAuthenticationDigestSm3(
    const std::vector<uint8_t>& transcript,
    const std::string& doc_type,
    std::vector<uint8_t>* digest,
    std::string* err) {
  if (doc_type.size() >= 256) {
    if (err != nullptr) *err = "docType too long";
    return false;
  }
  auto append_major_and_count = [](std::vector<uint8_t>* out, uint8_t major,
                                   size_t count) {
    if (count < 24) {
      out->push_back(static_cast<uint8_t>((major << 5) | count));
    } else if (count < 256) {
      out->push_back(static_cast<uint8_t>((major << 5) | 24));
      out->push_back(static_cast<uint8_t>(count));
    } else {
      out->push_back(static_cast<uint8_t>((major << 5) | 25));
      out->push_back(static_cast<uint8_t>((count >> 8) & 0xff));
      out->push_back(static_cast<uint8_t>(count & 0xff));
    }
  };

  std::vector<uint8_t> doc_type_cbor;
  append_major_and_count(&doc_type_cbor, 3, doc_type.size());
  doc_type_cbor.insert(doc_type_cbor.end(), doc_type.begin(), doc_type.end());

  std::vector<uint8_t> da = {
      0x84, 0x74, 'D', 'e', 'v', 'i', 'c', 'e', 'A', 'u', 't',
      'h',  'e',  'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n',
  };
  da.insert(da.end(), transcript.begin(), transcript.end());
  da.insert(da.end(), doc_type_cbor.begin(), doc_type_cbor.end());
  da.push_back(0xD8);
  da.push_back(0x18);
  da.push_back(0x41);
  da.push_back(0xA0);

  std::vector<uint8_t> cose1 = {0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61,
                                0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xA1,
                                0x01, 0x26, 0x40};
  const size_t tagged_len = da.size() + (da.size() < 256 ? 4 : 5);
  append_major_and_count(&cose1, 2, tagged_len);
  cose1.push_back(0xD8);
  cose1.push_back(0x18);
  append_major_and_count(&cose1, 2, da.size());
  cose1.insert(cose1.end(), da.begin(), da.end());
  if (!Sm3Digest(cose1.data(), cose1.size(), digest)) {
    if (err != nullptr) *err = "SM3 device authentication digest failed";
    return false;
  }
  return true;
}

bool GenerateSM2KeyPair(std::string* sk_hex, std::string* pkx_hex,
                        std::string* pky_hex, std::string* err) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, nullptr);
  EVP_PKEY* pkey = nullptr;
  bool ok = false;
  do {
    if (ctx == nullptr || EVP_PKEY_keygen_init(ctx) != 1 ||
        EVP_PKEY_keygen(ctx, &pkey) != 1) {
      if (err != nullptr) *err = "failed to generate SM2 key pair";
      break;
    }
    BIGNUM* priv = nullptr;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1 ||
        priv == nullptr) {
      if (err != nullptr) *err = "failed to read SM2 private key";
      break;
    }
    std::array<uint8_t, 32> sk{};
    const int n = BN_bn2binpad(priv, sk.data(), sk.size());
    BN_free(priv);
    if (n != static_cast<int>(sk.size())) {
      if (err != nullptr) *err = "failed to serialize SM2 private key";
      break;
    }
    if (!SerializeSm2PublicKey(pkey, pkx_hex, pky_hex, err)) {
      break;
    }
    *sk_hex = HexPrefixed(sk.data(), sk.size());
    ok = true;
  } while (false);
  if (pkey != nullptr) EVP_PKEY_free(pkey);
  if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
  return ok;
}

bool DeriveSM2PublicKey(const std::string& sk_hex, std::string* pkx_hex,
                        std::string* pky_hex, std::string* err) {
  EVP_PKEY* pkey = nullptr;
  if (!BuildSm2PkeyFromPrivateKey(sk_hex, &pkey, err)) {
    return false;
  }
  const bool ok = SerializeSm2PublicKey(pkey, pkx_hex, pky_hex, err);
  EVP_PKEY_free(pkey);
  return ok;
}

bool SignMessageSM2(const std::string& sk_hex, const char* signer_id,
                    const uint8_t* msg, size_t msg_len,
                    std::vector<uint8_t>* sig_rs, std::string* err) {
  if (msg == nullptr || sig_rs == nullptr) {
    if (err != nullptr) *err = "invalid SM2 signing input";
    return false;
  }
  std::string pkx_hex, pky_hex;
  if (!DeriveSM2PublicKey(sk_hex, &pkx_hex, &pky_hex, err)) {
    return false;
  }
  std::vector<uint8_t> sk_bytes, pkx, pky;
  if (!HexToBytes(sk_hex, &sk_bytes, err) ||
      !HexToBytes(pkx_hex, &pkx, err) ||
      !HexToBytes(pky_hex, &pky, err)) {
    return false;
  }
  uint8_t e_bytes[32];
  if (!ComputeSm2MessageDigest(signer_id, pkx, pky, msg, msg_len, e_bytes,
                               err)) {
    return false;
  }
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
  BN_CTX* bn_ctx = BN_CTX_new();
  BIGNUM *n = BN_new(), *d = BN_new(), *e = BN_new(), *k = BN_new();
  BIGNUM *x = BN_new(), *r = BN_new(), *s = BN_new(), *tmp = BN_new();
  BIGNUM *d_plus_one = BN_new(), *inv = BN_new();
  EC_POINT* kg = group == nullptr ? nullptr : EC_POINT_new(group);
  bool ok = false;
  do {
    if (group == nullptr || bn_ctx == nullptr || n == nullptr || d == nullptr ||
        e == nullptr || k == nullptr || x == nullptr || r == nullptr ||
        s == nullptr || tmp == nullptr || d_plus_one == nullptr ||
        inv == nullptr || kg == nullptr) {
      if (err != nullptr) *err = "failed to allocate SM2 signing state";
      break;
    }
    if (EC_GROUP_get_order(group, n, bn_ctx) != 1 ||
        BN_bin2bn(sk_bytes.data(), sk_bytes.size(), d) == nullptr ||
        BN_bin2bn(e_bytes, 32, e) == nullptr) {
      if (err != nullptr) *err = "failed to initialize SM2 signing scalars";
      break;
    }
    if (BN_add(d_plus_one, d, BN_value_one()) != 1 ||
        BN_mod(d_plus_one, d_plus_one, n, bn_ctx) != 1 ||
        BN_mod_inverse(inv, d_plus_one, n, bn_ctx) == nullptr) {
      if (err != nullptr) *err = "invalid SM2 private key";
      break;
    }
    for (int tries = 0; tries < 128 && !ok; ++tries) {
      if (BN_rand_range(k, n) != 1 || BN_is_zero(k) ||
          EC_POINT_mul(group, kg, k, nullptr, nullptr, bn_ctx) != 1 ||
          EC_POINT_get_affine_coordinates_GFp(group, kg, x, nullptr,
                                              bn_ctx) != 1 ||
          BN_mod(x, x, n, bn_ctx) != 1 ||
          BN_mod_add(r, e, x, n, bn_ctx) != 1 || BN_is_zero(r) ||
          BN_mod_add(tmp, r, k, n, bn_ctx) != 1 || BN_is_zero(tmp)) {
        continue;
      }
      if (BN_mod_mul(tmp, r, d, n, bn_ctx) != 1 ||
          BN_mod_sub(tmp, k, tmp, n, bn_ctx) != 1 ||
          BN_mod_mul(s, inv, tmp, n, bn_ctx) != 1 || BN_is_zero(s)) {
        continue;
      }
      sig_rs->assign(64, 0);
      ok = BN_bn2binpad(r, sig_rs->data(), 32) == 32 &&
           BN_bn2binpad(s, sig_rs->data() + 32, 32) == 32;
    }
    if (!ok && err != nullptr) *err = "SM2 signing failed";
  } while (false);
  if (kg != nullptr) EC_POINT_free(kg);
  if (d_plus_one != nullptr) BN_free(d_plus_one);
  if (inv != nullptr) BN_free(inv);
  if (tmp != nullptr) BN_free(tmp);
  if (s != nullptr) BN_free(s);
  if (r != nullptr) BN_free(r);
  if (x != nullptr) BN_free(x);
  if (k != nullptr) BN_free(k);
  if (e != nullptr) BN_free(e);
  if (d != nullptr) BN_free(d);
  if (n != nullptr) BN_free(n);
  if (bn_ctx != nullptr) BN_CTX_free(bn_ctx);
  if (group != nullptr) EC_GROUP_free(group);
  return ok;
}

bool VerifyMessageSM2(const std::string& pkx_hex, const std::string& pky_hex,
                      const char* signer_id, const uint8_t* msg,
                      size_t msg_len, const std::vector<uint8_t>& sig_rs,
                      std::string* err) {
  if (msg == nullptr || sig_rs.size() != 64) {
    if (err != nullptr) *err = "invalid SM2 verification input";
    return false;
  }
  std::vector<uint8_t> pkx, pky;
  if (!HexToBytes(pkx_hex, &pkx, err) || !HexToBytes(pky_hex, &pky, err)) {
    return false;
  }
  uint8_t e_bytes[32];
  if (!ComputeSm2MessageDigest(signer_id, pkx, pky, msg, msg_len, e_bytes,
                               err)) {
    return false;
  }
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
  BN_CTX* bn_ctx = BN_CTX_new();
  BIGNUM *n = BN_new(), *e = BN_new(), *r = BN_new(), *s = BN_new();
  BIGNUM *t = BN_new(), *x = BN_new(), *want = BN_new();
  BIGNUM *bx = BN_new(), *by = BN_new();
  EC_POINT* pub = group == nullptr ? nullptr : EC_POINT_new(group);
  EC_POINT* q = group == nullptr ? nullptr : EC_POINT_new(group);
  bool ok = false;
  do {
    if (group == nullptr || bn_ctx == nullptr || n == nullptr || e == nullptr ||
        r == nullptr || s == nullptr || t == nullptr || x == nullptr ||
        want == nullptr || bx == nullptr || by == nullptr || pub == nullptr ||
        q == nullptr) {
      if (err != nullptr) *err = "failed to allocate SM2 verification state";
      break;
    }
    if (EC_GROUP_get_order(group, n, bn_ctx) != 1 ||
        BN_bin2bn(e_bytes, 32, e) == nullptr ||
        BN_bin2bn(sig_rs.data(), 32, r) == nullptr ||
        BN_bin2bn(sig_rs.data() + 32, 32, s) == nullptr ||
        BN_bin2bn(pkx.data(), 32, bx) == nullptr ||
        BN_bin2bn(pky.data(), 32, by) == nullptr ||
        EC_POINT_set_affine_coordinates_GFp(group, pub, bx, by, bn_ctx) != 1) {
      if (err != nullptr) *err = "failed to initialize SM2 verification input";
      break;
    }
    if (BN_is_zero(r) || BN_is_negative(r) || BN_cmp(r, n) >= 0 ||
        BN_is_zero(s) || BN_is_negative(s) || BN_cmp(s, n) >= 0 ||
        BN_mod_add(t, r, s, n, bn_ctx) != 1 || BN_is_zero(t)) {
      if (err != nullptr) *err = "SM2 signature scalar out of range";
      break;
    }
    if (EC_POINT_mul(group, q, s, pub, t, bn_ctx) != 1 ||
        EC_POINT_get_affine_coordinates_GFp(group, q, x, nullptr, bn_ctx) != 1 ||
        BN_mod(x, x, n, bn_ctx) != 1 ||
        BN_mod_add(want, e, x, n, bn_ctx) != 1) {
      if (err != nullptr) *err = "SM2 verification computation failed";
      break;
    }
    ok = BN_cmp(want, r) == 0;
    if (!ok && err != nullptr) *err = "SM2 signature verification failed";
  } while (false);
  if (q != nullptr) EC_POINT_free(q);
  if (pub != nullptr) EC_POINT_free(pub);
  if (by != nullptr) BN_free(by);
  if (bx != nullptr) BN_free(bx);
  if (want != nullptr) BN_free(want);
  if (x != nullptr) BN_free(x);
  if (t != nullptr) BN_free(t);
  if (s != nullptr) BN_free(s);
  if (r != nullptr) BN_free(r);
  if (e != nullptr) BN_free(e);
  if (n != nullptr) BN_free(n);
  if (bn_ctx != nullptr) BN_CTX_free(bn_ctx);
  if (group != nullptr) EC_GROUP_free(group);
  return ok;
}

bool SignDelegationSm2(const std::string& sk_hex,
                       const std::string& msg_hex,
                       std::string* out_sig_hex,
                       std::string* err) {
  std::vector<uint8_t> msg_bytes;
  if (!HexToBytes(msg_hex, &msg_bytes, err)) {
    return false;
  }
  std::vector<uint8_t> sig_rs;
  if (!SignMessageSM2(sk_hex, kSm2DeviceId, msg_bytes.data(),
                      msg_bytes.size(), &sig_rs, err)) {
    return false;
  }
  *out_sig_hex = HexPrefixed(sig_rs.data(), sig_rs.size());
  return true;
}

bool VerifyDelegationSigSm2(const std::string& pkx_hex,
                            const std::string& pky_hex,
                            const std::string& msg_hex,
                            const std::string& sig_hex,
                            std::string* err) {
  std::vector<uint8_t> msg_bytes, sig_bytes, der;
  if (!HexToBytes(msg_hex, &msg_bytes, err) ||
      !HexToBytes(sig_hex, &sig_bytes, err)) {
    return false;
  }
  return VerifyMessageSM2(pkx_hex, pky_hex, kSm2DeviceId, msg_bytes.data(),
                          msg_bytes.size(), sig_bytes, err);
}

bool HashClaimAlias(const std::string& alias, std::vector<uint8_t>* out_hash) {
  return Sha256Digest(reinterpret_cast<const uint8_t*>(alias.data()),
                      alias.size(), out_hash);
}

bool HashAgentId(const std::string& agent_id, std::vector<uint8_t>* out_hash) {
  return Sha256Digest(reinterpret_cast<const uint8_t*>(agent_id.data()),
                      agent_id.size(), out_hash);
}

std::string PredicateOpName(PredicateOp op) {
  switch (op) {
    case PredicateOp::DISCLOSE:
      return "DISCLOSE";
    case PredicateOp::EQ:
      return "EQ";
    case PredicateOp::IN_SET:
      return "IN_SET";
    case PredicateOp::GE:
      return "GE";
    case PredicateOp::LE:
      return "LE";
  }
  return "DISCLOSE";
}

bool ParsePolicyPredicate(const std::string& text, PolicyPredicate* predicate,
                          std::string* err) {
  const size_t p1 = text.find(':');
  const size_t p2 = p1 == std::string::npos ? std::string::npos
                                             : text.find(':', p1 + 1);
  if (p1 == std::string::npos || p2 == std::string::npos ||
      p1 == 0 || p2 == p1 + 1) {
    if (err != nullptr) {
      *err = "predicate must be claim:OP:value[,value...]";
    }
    return false;
  }
  predicate->claim = text.substr(0, p1);
  const std::string op = text.substr(p1 + 1, p2 - p1 - 1);
  if (op == "DISCLOSE") {
    predicate->op = PredicateOp::DISCLOSE;
  } else if (op == "EQ") {
    predicate->op = PredicateOp::EQ;
  } else if (op == "IN_SET") {
    predicate->op = PredicateOp::IN_SET;
  } else if (op == "GE") {
    predicate->op = PredicateOp::GE;
  } else if (op == "LE") {
    predicate->op = PredicateOp::LE;
  } else {
    if (err != nullptr) *err = "unsupported predicate op: " + op;
    return false;
  }
  predicate->values = Split(text.substr(p2 + 1), ',');
  if (predicate->op == PredicateOp::DISCLOSE) {
    predicate->values.clear();
  } else if (predicate->values.empty() || predicate->values[0].empty()) {
    if (err != nullptr) *err = "predicate value is required";
    return false;
  }
  return true;
}

bool EvaluatePolicyPredicates(const Policy& policy,
                              const std::vector<ReaderClaim>& claims,
                              std::string* err) {
  for (const auto& p : policy.predicates) {
    const ReaderClaim* claim = FindClaim(claims, p.claim);
    if (claim == nullptr) {
      if (err != nullptr) *err = "predicate claim not disclosed: " + p.claim;
      return false;
    }
    if (p.op == PredicateOp::DISCLOSE) continue;
    std::string actual;
    if (!CborToText(claim->cbor_value, &actual)) {
      if (err != nullptr) *err = "unsupported CBOR value for claim: " + p.claim;
      return false;
    }
    if (p.op == PredicateOp::EQ) {
      if (actual != p.values[0]) {
        if (err != nullptr) *err = p.claim + " EQ predicate failed";
        return false;
      }
    } else if (p.op == PredicateOp::IN_SET) {
      if (std::find(p.values.begin(), p.values.end(), actual) ==
          p.values.end()) {
        if (err != nullptr) *err = p.claim + " IN_SET predicate failed";
        return false;
      }
    } else if (p.op == PredicateOp::GE || p.op == PredicateOp::LE) {
      int64_t lhs = 0;
      int64_t rhs = 0;
      if (!ParseInt64(actual, &lhs) || !ParseInt64(p.values[0], &rhs)) {
        if (err != nullptr) *err = p.claim + " numeric predicate is invalid";
        return false;
      }
      if ((p.op == PredicateOp::GE && lhs < rhs) ||
          (p.op == PredicateOp::LE && lhs > rhs)) {
        if (err != nullptr) *err = p.claim + " numeric predicate failed";
        return false;
      }
    }
  }
  return true;
}

bool BuildDelegationCircuitInputsSm3(
    const Policy& policy, const std::vector<std::string>& requested_aliases,
    std::vector<uint8_t>* allowed_claim_hashes_padded,
    std::vector<uint8_t>* agent_id_hash,
    std::vector<uint8_t>* requested_claim_hashes, std::string* err) {
  if (policy.allowed_claims.size() > kDelegationMaxClaims) {
    if (err != nullptr) {
      *err = "too many allowed claims for delegated circuit";
    }
    return false;
  }
  if (policy.expires.size() != kDelegationExpiresSize) {
    if (err != nullptr) {
      *err = "policy.expires must be 20-byte ISO 8601 UTC";
    }
    return false;
  }
  allowed_claim_hashes_padded->assign(
      kDelegationMaxClaims * kDelegationClaimHashSize, 0);
  for (size_t i = 0; i < policy.allowed_claims.size(); ++i) {
    std::vector<uint8_t> h;
    if (!Sm3Digest(reinterpret_cast<const uint8_t*>(
                       policy.allowed_claims[i].data()),
                   policy.allowed_claims[i].size(), &h)) {
      if (err != nullptr) *err = "SM3 allowed claim hash failed";
      return false;
    }
    std::copy(h.begin(), h.end(),
              allowed_claim_hashes_padded->begin() +
                  i * kDelegationClaimHashSize);
  }
  const std::string policy_context =
      policy.agent_id + "|" + CanonicalPredicates(policy.predicates);
  if (!Sm3Digest(reinterpret_cast<const uint8_t*>(policy_context.data()),
                 policy_context.size(), agent_id_hash)) {
    if (err != nullptr) *err = "SM3 agent id hash failed";
    return false;
  }
  requested_claim_hashes->clear();
  requested_claim_hashes->reserve(requested_aliases.size() *
                                  kDelegationClaimHashSize);
  for (const auto& alias : requested_aliases) {
    std::vector<uint8_t> h;
    if (!Sm3Digest(reinterpret_cast<const uint8_t*>(alias.data()),
                   alias.size(), &h)) {
      if (err != nullptr) *err = "SM3 requested claim hash failed";
      return false;
    }
    requested_claim_hashes->insert(requested_claim_hashes->end(), h.begin(),
                                   h.end());
  }
  return true;
}

// ----------------------------------------------------------------
// 策略检查
// ----------------------------------------------------------------
bool PolicyAllowsClaim(const Policy& policy, const std::string& alias) {
  return std::find(policy.allowed_claims.begin(),
                   policy.allowed_claims.end(), alias) != policy.allowed_claims.end();
}

bool PolicyExpired(const Policy& policy, const std::string& now_iso8601) {
  // ISO 8601 字符串的字典序即时间序，直接比较即可
  return policy.expires <= now_iso8601;
}

}  // namespace proofs
