#ifndef EXAMPLES_DELEGATION_DEMO_ALICE_DELEGATE_H_
#define EXAMPLES_DELEGATION_DEMO_ALICE_DELEGATE_H_

#include <filesystem>
#include <string>
#include <vector>

#include "examples/delegation_demo/shared/types.h"

namespace proofs {

// 执行委托命令：
//   1. 从 holder_dir 读取 Alice 的凭证
//   2. 生成 Agent 临时密钥对
//   3. 构造 Policy，计算委托消息，用 Alice 的 device_sk 签名
//   4. 从 issued_claims 中筛选 allowed_claims，写出 delegation/ 目录
//
// 参数：
//   holder_dir:      issuer issue 输出的 holder/ 目录
//   allowed_claims:  委托允许的 claim alias 列表
//   expires:         委托过期时间，ISO 8601，如 "2027-01-01T00:00:00Z"
//   agent_id:        Agent 标识，如 "bookstore-agent"
//   revoked:         写出已撤销状态，用于本地验证负例
//   out_dir:         输出 delegation/ 目录
bool RunDelegateCommand(const std::filesystem::path& holder_dir,
                        const std::vector<std::string>& allowed_claims,
                        const std::vector<PolicyPredicate>& predicates,
                        const std::string& expires,
                        const std::string& agent_id,
                        bool revoked,
                        const std::filesystem::path& out_dir,
                        std::string* err);

}  // namespace proofs

#endif  // EXAMPLES_DELEGATION_DEMO_ALICE_DELEGATE_H_
