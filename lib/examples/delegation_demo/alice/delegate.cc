#include "examples/delegation_demo/alice/delegate.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "examples/delegation_demo/shared/delegation_crypto.h"
#include "examples/delegation_demo/shared/delegation_files.h"
#include "examples/delegation_demo/shared/delegation_revocation.h"
#include "examples/mdoc_anoncred/shared/crypto.h"
#include "examples/mdoc_anoncred/shared/files.h"
#include "examples/mdoc_anoncred/shared/types.h"

namespace proofs {
namespace {

// 获取当前时间的 ISO 8601 字符串（UTC）
std::string CurrentTimeISO8601() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::ostringstream oss;
  std::tm tm_utc{};
#if defined(_WIN32)
  gmtime_s(&tm_utc, &t);
#else
  gmtime_r(&t, &tm_utc);
#endif
  oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// 从 issued_claims 中筛选出 alias 在 allowed 列表中的条目
std::vector<ReaderClaim> FilterClaims(const std::vector<ReaderClaim>& all_claims,
                                       const std::vector<std::string>& allowed) {
  std::vector<ReaderClaim> result;
  for (const auto& claim : all_claims) {
    if (std::find(allowed.begin(), allowed.end(), claim.alias) != allowed.end()) {
      result.push_back(claim);
    }
  }
  return result;
}

}  // namespace

bool RunDelegateCommand(const std::filesystem::path& holder_dir,
                        const std::vector<std::string>& allowed_claims,
                        const std::vector<PolicyPredicate>& predicates,
                        const std::string& expires,
                        const std::string& agent_id,
                        bool revoked,
                        const std::filesystem::path& out_dir,
                        std::string* err) {
  // Step 1: 读取 Alice 的 holder 凭证
  HolderMdoc holder;
  if (!ReadHolderMdocDir(holder_dir, &holder, err)) {
    if (err != nullptr) *err = "failed to read holder dir: " + *err;
    return false;
  }

  // Step 2: 生成 Agent 临时密钥对 (sk_ag, pk_ag)
  std::string agent_sk_hex, agent_pkx_hex, agent_pky_hex;
  if (!GenerateP256KeyPair(&agent_sk_hex, &agent_pkx_hex, &agent_pky_hex, err)) {
    if (err != nullptr) *err = "failed to generate agent key pair: " + *err;
    return false;
  }

  // Step 3: 构造 Policy
  Policy policy;
  policy.allowed_claims = allowed_claims;
  policy.predicates = predicates;
  policy.expires = expires;
  policy.agent_id = agent_id;
  policy.created = CurrentTimeISO8601();

  // Step 4: 计算委托消息 del_msg = SHA256(pk_ag_x || pk_ag_y || canonical_policy)
  std::string del_msg_hex;
  if (!ComputeDelegationMsg(agent_pkx_hex, agent_pky_hex, policy,
                             &del_msg_hex, err)) {
    if (err != nullptr) *err = "failed to compute delegation message: " + *err;
    return false;
  }

  // Step 5: 用 Alice 的 device_sk 签名
  std::string del_sig_hex;
  if (!SignDelegation(holder.device_sk_hex, del_msg_hex, &del_sig_hex, err)) {
    if (err != nullptr) *err = "failed to sign delegation: " + *err;
    return false;
  }

  // Step 6 (自检): 验证签名是否正确
  {
    std::string verify_err;
    if (!VerifyDelegationSig(holder.device_pkx_hex, holder.device_pky_hex,
                              del_msg_hex, del_sig_hex, &verify_err)) {
      if (err != nullptr) {
        *err = "delegation signature self-check failed: " + verify_err;
      }
      return false;
    }
  }

  // Step 7: Alice 对该委托的撤销状态签名，Verifier 后续据此判断委托是否仍有效
  DelegationRevocationStatus revocation_status;
  if (!CreateDelegationRevocationStatus(holder.device_sk_hex, del_msg_hex,
                                        1, expires, revoked,
                                        &revocation_status, err)) {
    if (err != nullptr) *err = "failed to create revocation status: " + *err;
    return false;
  }

  // Step 8: 筛选允许的 claims
  const std::vector<ReaderClaim> filtered = FilterClaims(holder.issued_claims, allowed_claims);
  if (filtered.empty() && !allowed_claims.empty()) {
    if (err != nullptr) {
      *err = "none of the requested claims exist in the issued credential";
    }
    return false;
  }

  // Step 9: 写出 delegation/ 目录
  if (!WriteDelegationDir(out_dir, holder,
                           agent_pkx_hex, agent_pky_hex, agent_sk_hex,
                           del_msg_hex, del_sig_hex,
                           policy, filtered, err)) {
    if (err != nullptr) *err = "failed to write delegation dir: " + *err;
    return false;
  }
  if (!WriteDelegationRevocationStatusJson(
          out_dir / "delegation_revocation_status.json",
          revocation_status, err)) {
    if (err != nullptr) *err = "failed to write revocation status: " + *err;
    return false;
  }

  return true;
}

}  // namespace proofs
