#ifndef EXAMPLES_DELEGATION_DEMO_AGENT_PRESENT_H_
#define EXAMPLES_DELEGATION_DEMO_AGENT_PRESENT_H_

#include <filesystem>
#include <string>

namespace proofs {

// 执行代理展示命令：
//   1. 读取 delegation/ 目录（Alice 的委托材料）
//   2. 读取 issuer_public/ 和 request/ 目录
//   3. 检查策略：request 中的 claims 必须在 policy.allowed_claims 内（约束⑧）
//   4. 检查过期：request.now < policy.expires（约束⑨）
//   5. 调用 ProveMdocPresentation 生成 ZK 证明（约束①-⑥在电路内）
//   6. 输出 presentation/ 目录 + public_delegation.json
bool RunAgentPresentCommand(const std::filesystem::path& delegation_dir,
                            const std::filesystem::path& issuer_public_dir,
                            const std::filesystem::path& request_dir,
                            const std::filesystem::path& out_dir,
                            std::string* err);

}  // namespace proofs

#endif  // EXAMPLES_DELEGATION_DEMO_AGENT_PRESENT_H_
