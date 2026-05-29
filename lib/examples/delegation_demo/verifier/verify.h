#ifndef EXAMPLES_DELEGATION_DEMO_VERIFIER_VERIFY_H_
#define EXAMPLES_DELEGATION_DEMO_VERIFIER_VERIFY_H_

#include <filesystem>
#include <string>
#include <vector>

namespace proofs {

// D-1: 生成验证请求（包装已有 RunMdocRequestCommand）
bool RunDelegationRequestCommand(
    const std::filesystem::path& issuer_public_dir,
    const std::vector<std::string>& claim_aliases,
    const std::filesystem::path& out_dir,
    std::string* err);

// D-2 结构化验证结果
struct DelegationVerificationResult {
  bool zk_proof_ok = false;        // 约束①-⑥：ZK 证明有效
  bool delegation_sig_ok = false;  // 约束⑦：委托签名正确
  bool policy_claims_ok = false;   // 约束⑧：策略覆盖所有请求 claim
  bool policy_not_expired = false; // 约束⑨：策略未过期
  bool delegation_revocation_ok = false; // 约束⑪：Alice 未撤销该委托
  bool overall_ok = false;
  std::string message;
};

// D-2: 验证展示（ZK 证明 + 委托策略检查）
bool RunDelegationVerifyCommand(
    const std::filesystem::path& issuer_public_dir,
    const std::filesystem::path& request_dir,
    const std::filesystem::path& presentation_dir,
    DelegationVerificationResult* result,
    std::string* err);

}  // namespace proofs

#endif  // EXAMPLES_DELEGATION_DEMO_VERIFIER_VERIFY_H_
