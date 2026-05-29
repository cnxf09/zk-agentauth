#include "examples/delegation_demo/shared/delegation_crypto.h"

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include "examples/mdoc_anoncred/shared/crypto.h"
#include "util/crypto.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"

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
bool ComputeDelegationMsg(const std::string& agent_pkx_hex,
                          const std::string& agent_pky_hex,
                          const Policy& policy,
                          std::string* out_msg_hex,
                          std::string* err) {
  std::vector<uint8_t> pkx_bytes, pky_bytes;
  if (!HexToBytes(agent_pkx_hex, &pkx_bytes, err) ||
      !HexToBytes(agent_pky_hex, &pky_bytes, err)) {
    return false;
  }
  if (pkx_bytes.size() != 32 || pky_bytes.size() != 32) {
    if (err != nullptr) {
      *err = "agent public key coordinates must be 32 bytes each";
    }
    return false;
  }
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
      HashClaimAlias(policy.allowed_claims[i], &h);
      msg_data.insert(msg_data.end(), h.begin(), h.end());
    } else {
      msg_data.insert(msg_data.end(), kDelegationClaimHashSize, 0);
    }
  }
  msg_data.insert(msg_data.end(), policy.expires.begin(), policy.expires.end());
  std::vector<uint8_t> agent_id_hash;
  const std::string policy_context =
      policy.agent_id + "|" + CanonicalPredicates(policy.predicates);
  HashAgentId(policy_context, &agent_id_hash);
  msg_data.insert(msg_data.end(), agent_id_hash.begin(), agent_id_hash.end());

  std::vector<uint8_t> digest;
  if (!Sha256Digest(msg_data.data(), msg_data.size(), &digest)) {
    if (err != nullptr) {
      *err = "SHA256 computation failed";
    }
    return false;
  }

  *out_msg_hex = HexPrefixed(digest.data(), digest.size());
  return true;
}

// ----------------------------------------------------------------
// 委托签名
// ----------------------------------------------------------------
bool SignDelegation(const std::string& sk_hex,
                    const std::string& msg_hex,
                    std::string* out_sig_hex,
                    std::string* err) {
  std::vector<uint8_t> msg_bytes;
  if (!HexToBytes(msg_hex, &msg_bytes, err)) {
    return false;
  }
  if (msg_bytes.size() != 32) {
    if (err != nullptr) {
      *err = "delegation message must be a 32-byte SHA256 digest";
    }
    return false;
  }

  std::vector<uint8_t> sig_rs;
  if (!SignSha256DigestP256(sk_hex, msg_bytes, &sig_rs, err)) {
    return false;
  }
  // sig_rs 是 64 字节 r(32)||s(32)
  *out_sig_hex = HexPrefixed(sig_rs.data(), sig_rs.size());
  return true;
}

// ----------------------------------------------------------------
// 委托签名验证（用于模块 B 自测）
// ----------------------------------------------------------------
bool VerifyDelegationSig(const std::string& pkx_hex,
                         const std::string& pky_hex,
                         const std::string& msg_hex,
                         const std::string& sig_hex,
                         std::string* err) {
  std::vector<uint8_t> pkx_bytes, pky_bytes, msg_bytes, sig_bytes;
  if (!HexToBytes(pkx_hex, &pkx_bytes, err) ||
      !HexToBytes(pky_hex, &pky_bytes, err) ||
      !HexToBytes(msg_hex, &msg_bytes, err) ||
      !HexToBytes(sig_hex, &sig_bytes, err)) {
    return false;
  }
  if (pkx_bytes.size() != 32 || pky_bytes.size() != 32) {
    if (err != nullptr) { *err = "invalid public key size"; }
    return false;
  }
  if (msg_bytes.size() != 32) {
    if (err != nullptr) { *err = "message must be 32 bytes"; }
    return false;
  }
  if (sig_bytes.size() != 64) {
    if (err != nullptr) { *err = "signature must be 64 bytes (r||s)"; }
    return false;
  }

  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (group == nullptr || eckey == nullptr) {
    if (err != nullptr) { *err = "failed to init EC key"; }
    if (group) EC_GROUP_free(group);
    if (eckey) EC_KEY_free(eckey);
    return false;
  }

  bool ok = false;
  BIGNUM* bx = BN_bin2bn(pkx_bytes.data(), 32, nullptr);
  BIGNUM* by = BN_bin2bn(pky_bytes.data(), 32, nullptr);
  EC_POINT* pub = EC_POINT_new(group);
  if (bx && by && pub) {
    if (EC_POINT_set_affine_coordinates_GFp(group, pub, bx, by, nullptr) == 1 &&
        EC_KEY_set_public_key(eckey, pub) == 1) {
      BIGNUM* br = BN_bin2bn(sig_bytes.data(), 32, nullptr);
      BIGNUM* bs = BN_bin2bn(sig_bytes.data() + 32, 32, nullptr);
      ECDSA_SIG* sig = ECDSA_SIG_new();
      if (br && bs && sig) {
        ECDSA_SIG_set0(sig, br, bs);  // sig takes ownership of br, bs
        br = nullptr; bs = nullptr;
        int ret = ECDSA_do_verify(msg_bytes.data(),
                                  static_cast<int>(msg_bytes.size()),
                                  sig, eckey);
        ok = (ret == 1);
        if (!ok && err != nullptr) {
          *err = (ret == 0) ? "signature verification failed"
                            : "ECDSA_do_verify error";
        }
        ECDSA_SIG_free(sig);
      }
      if (br) BN_free(br);
      if (bs) BN_free(bs);
    }
  }

  if (bx) BN_free(bx);
  if (by) BN_free(by);
  if (pub) EC_POINT_free(pub);
  EC_KEY_free(eckey);
  EC_GROUP_free(group);
  return ok;
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

bool BuildDelegationCircuitInputs(
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
    HashClaimAlias(policy.allowed_claims[i], &h);
    std::copy(h.begin(), h.end(),
              allowed_claim_hashes_padded->begin() +
                  i * kDelegationClaimHashSize);
  }
  const std::string policy_context =
      policy.agent_id + "|" + CanonicalPredicates(policy.predicates);
  HashAgentId(policy_context, agent_id_hash);
  requested_claim_hashes->clear();
  requested_claim_hashes->reserve(requested_aliases.size() *
                                  kDelegationClaimHashSize);
  for (const auto& alias : requested_aliases) {
    std::vector<uint8_t> h;
    HashClaimAlias(alias, &h);
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
