#include "examples/delegation_demo/verifier/verify.h"

#include <sstream>
#include <string>

#include "examples/delegation_demo/shared/delegation_crypto.h"
#include "examples/delegation_demo/shared/delegation_files.h"
#include "examples/delegation_demo/shared/delegation_revocation.h"
#include "examples/delegation_demo/shared/types.h"
#include "examples/mdoc_anoncred/shared/crypto.h"
#include "examples/mdoc_anoncred/shared/files.h"
#include "examples/mdoc_anoncred/shared/mdoc_demo.h"
#include "examples/mdoc_anoncred/verifier/verify.h"

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

// ----------------------------------------------------------------
// D-1: 生成验证请求
// ----------------------------------------------------------------

bool RunDelegationRequestCommand(
    const std::filesystem::path& issuer_public_dir,
    const std::vector<std::string>& claim_aliases,
    const std::filesystem::path& out_dir,
    std::string* err) {
  MdocIssuerPublicBundle issuer_public;
  ReaderRequest request;
  if (!ReadMdocIssuerPublicDir(issuer_public_dir, &issuer_public, err) ||
      !BuildDelegatedReaderRequest(issuer_public, claim_aliases, &request,
                                   err)) {
    return false;
  }
  return WriteReaderRequestDir(out_dir, request, err);
}

// ----------------------------------------------------------------
// D-2: 验证展示
// ----------------------------------------------------------------

bool RunDelegationVerifyCommand(
    const std::filesystem::path& issuer_public_dir,
    const std::filesystem::path& request_dir,
    const std::filesystem::path& presentation_dir,
    DelegationVerificationResult* result,
    std::string* err) {
  MdocIssuerPublicBundle issuer_public;
  ReaderRequest request;
  MdocPresentation presentation;
  if (!ReadMdocIssuerPublicDir(issuer_public_dir, &issuer_public, err) ||
      !ReadReaderRequestDir(request_dir, &request, err) ||
      !ReadMdocPresentationDir(presentation_dir, &presentation, err)) {
    return false;
  }

  // 1. 读取 verifier 需要的公开委托输入。签名明文和 device 公钥已经作为
  // ZK witness 进入 proof，Verifier 不再从 sidecar JSON 读取它们。
  std::string agent_pkx, agent_pky;
  Policy policy;
  if (!ReadPublicDelegationJson(presentation_dir / "public_delegation.json",
                                &agent_pkx, &agent_pky, &policy, err)) {
    return false;
  }

  DelegationRevocationStatus revocation_status;
  if (!ReadDelegationRevocationStatusJson(
          presentation_dir / "delegation_revocation_status.json",
          &revocation_status, err)) {
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
  std::vector<uint8_t> revocation_id_bytes;
  if (!HexToBytes(revocation_status.delegation_id_hex, &revocation_id_bytes,
                  err)) {
    return false;
  }

  const MdocVerificationResult zk_result = VerifyDelegatedMdocPresentation(
      issuer_public, request, presentation, agent_pkx, agent_pky,
      allowed_hashes, policy.allowed_claims.size(), policy.expires,
      agent_id_hash, requested_hashes, revocation_id_bytes,
      Uint64Be(revocation_status.epoch), revocation_status.expires,
      revocation_status.revoked ? 1 : 0);

  std::string predicate_err;
  const bool predicates_ok =
      EvaluatePolicyPredicates(policy, presentation.disclosed_claims,
                               &predicate_err);
  // 约束⑦-⑪已进入 ZK 电路；下面的布尔项用于保持 CLI 展示格式。
  result->zk_proof_ok = zk_result.ok;
  result->delegation_sig_ok = zk_result.ok;
  result->policy_claims_ok = zk_result.ok && predicates_ok;
  result->policy_not_expired = zk_result.ok;
  result->delegation_revocation_ok = zk_result.ok;
  result->overall_ok = zk_result.ok && predicates_ok;

  std::ostringstream msg;
  msg << "ZK proof: " << (result->zk_proof_ok ? "PASS" : "FAIL") << "\n";
  msg << "Delegation sig: "
      << (result->delegation_sig_ok ? "PASS" : "FAIL") << "\n";
  msg << "Policy claims: "
      << (result->policy_claims_ok ? "PASS" : "FAIL") << "\n";
  if (!predicates_ok) {
    msg << "Policy predicates: FAIL (" << predicate_err << ")\n";
  } else {
    msg << "Policy predicates: PASS\n";
  }
  msg << "Policy expiry: "
      << (result->policy_not_expired ? "PASS" : "FAIL") << "\n";
  msg << "Delegation revocation: "
      << (result->delegation_revocation_ok ? "PASS" : "FAIL");
  msg << "\n";
  msg << "Overall: " << (result->overall_ok ? "ACCEPT" : "REJECT");
  result->message = msg.str();

  return true;
}

}  // namespace proofs
