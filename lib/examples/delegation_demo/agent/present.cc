#include "examples/delegation_demo/agent/present.h"

#include <iostream>
#include <string>

#include "examples/delegation_demo/shared/delegation_crypto.h"
#include "examples/delegation_demo/shared/delegation_files.h"
#include "examples/delegation_demo/shared/delegation_revocation.h"
#include "examples/delegation_demo/shared/types.h"
#include "examples/mdoc_anoncred/shared/crypto.h"
#include "examples/mdoc_anoncred/shared/files.h"
#include "examples/mdoc_anoncred/shared/mdoc_demo.h"
#include "examples/mdoc_anoncred/shared/request_codec.h"
#include "examples/mdoc_anoncred/shared/types.h"

namespace proofs {
namespace {

std::vector<uint8_t> Uint64Be(uint64_t v) {
  std::vector<uint8_t> out(8);
  for (int i = 7; i >= 0; --i) {
    out[7 - i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
  }
  return out;
}

}  // namespace

bool RunAgentPresentCommand(const std::filesystem::path& delegation_dir,
                            const std::filesystem::path& issuer_public_dir,
                            const std::filesystem::path& request_dir,
                            const std::filesystem::path& out_dir,
                            std::string* err) {
  // 1. 读取委托材料
  HolderMdoc holder;
  std::string agent_pkx, agent_pky, agent_sk, del_msg, del_sig;
  Policy policy;
  if (!ReadDelegationDir(delegation_dir, &holder, &agent_pkx, &agent_pky,
                         &agent_sk, &del_msg, &del_sig, &policy, err)) {
    return false;
  }

  // 2. 读取颁发方公开信息
  MdocIssuerPublicBundle issuer_public;
  if (!ReadMdocIssuerPublicDir(issuer_public_dir, &issuer_public, err)) {
    return false;
  }

  // 3. 读取验证请求
  ReaderRequest request;
  if (!ReadReaderRequestDir(request_dir, &request, err)) {
    return false;
  }

  // 4. 约束⑧：策略 claim 检查
  for (const auto& claim : request.claims) {
    if (!PolicyAllowsClaim(policy, claim.alias)) {
      if (err != nullptr) {
        *err = "policy does not allow claim: " + claim.alias;
      }
      return false;
    }
  }
  std::vector<ReaderClaim> predicate_claims;
  for (const auto& requested : request.claims) {
    for (const auto& issued : holder.issued_claims) {
      if (issued.alias == requested.alias) {
        predicate_claims.push_back(issued);
        break;
      }
    }
  }
  if (!EvaluatePolicyPredicates(policy, predicate_claims, err)) {
    if (err != nullptr) {
      *err = "policy predicate check failed: " + *err;
    }
    return false;
  }

  // 5. 约束⑨：过期检查
  if (PolicyExpired(policy, request.now_iso8601)) {
    if (err != nullptr) {
      *err = "delegation expired (policy.expires=" + policy.expires +
             ", now=" + request.now_iso8601 + ")";
    }
    return false;
  }

  DelegationRevocationStatus revocation_status;
  if (!ReadDelegationRevocationStatusJson(
          delegation_dir / "delegation_revocation_status.json",
          &revocation_status, err)) {
    if (err != nullptr) *err = "failed to read delegation revocation status: " + *err;
    return false;
  }
  if (!VerifyDelegationRevocationStatus(
          revocation_status, holder.device_pkx_hex, holder.device_pky_hex,
          del_msg, request.now_iso8601, err)) {
    if (err != nullptr) *err = "delegation revocation check failed: " + *err;
    return false;
  }

  std::vector<std::string> requested_aliases;
  requested_aliases.reserve(request.claims.size());
  for (const auto& claim : request.claims) {
    requested_aliases.push_back(claim.alias);
  }

  std::vector<uint8_t> allowed_hashes;
  std::vector<uint8_t> agent_id_hash;
  std::vector<uint8_t> requested_hashes;
  if (!BuildDelegationCircuitInputs(policy, requested_aliases, &allowed_hashes,
                                    &agent_id_hash, &requested_hashes, err)) {
    return false;
  }

  std::vector<uint8_t> del_sig_bytes;
  if (!HexToBytes(del_sig, &del_sig_bytes, err)) {
    return false;
  }
  std::vector<uint8_t> revocation_sig_bytes;
  if (!HexToBytes(revocation_status.sig_hex, &revocation_sig_bytes, err)) {
    return false;
  }
  std::vector<uint8_t> revocation_id_bytes;
  if (!HexToBytes(revocation_status.delegation_id_hex, &revocation_id_bytes,
                  err)) {
    return false;
  }
  const std::vector<uint8_t> revocation_epoch_be =
      Uint64Be(revocation_status.epoch);

  std::vector<uint8_t> agent_digest;
  if (!ComputeDeviceAuthenticationDigest(request.transcript_bytes,
                                         request.doc_type, &agent_digest,
                                         err)) {
    return false;
  }
  std::vector<uint8_t> agent_sig_bytes;
  if (!SignSha256DigestP256(agent_sk, agent_digest, &agent_sig_bytes, err)) {
    return false;
  }
  const std::string agent_sig = HexPrefixed(agent_sig_bytes.data(),
                                           agent_sig_bytes.size());

  // 6. 生成包含约束⑦-⑪的 ZK 证明
  MdocPresentation presentation;
  if (!ProveDelegatedMdocPresentation(
          holder, issuer_public, request, agent_pkx, agent_pky, del_sig_bytes,
          agent_sig_bytes, allowed_hashes, policy.allowed_claims.size(),
          policy.expires, agent_id_hash, requested_hashes,
          revocation_id_bytes, revocation_epoch_be, revocation_status.expires,
          revocation_status.revoked ? 1 : 0, revocation_sig_bytes,
          &presentation, err)) {
    return false;
  }

  // 7. 写出标准 presentation 目录
  if (!WriteMdocPresentationDir(out_dir, presentation, err)) {
    return false;
  }

  // 8. 写出 verifier 需要的公开委托输入。device 公钥、委托签名和
  // Agent 签名只作为 witness / 本地材料存在，不随 presentation 发送。
  if (!WritePublicDelegationJson(out_dir / "public_delegation.json",
                                 agent_pkx, agent_pky, policy, err)) {
    return false;
  }
  if (!WritePublicDelegationRevocationStatusJson(
          out_dir / "delegation_revocation_status.json",
          revocation_status, err)) {
    return false;
  }

  return true;
}

}  // namespace proofs
