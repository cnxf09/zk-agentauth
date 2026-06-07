#ifndef EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_FILES_H_
#define EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_FILES_H_

#include <filesystem>
#include <string>
#include <vector>

#include "examples/delegation_demo/shared/types.h"
#include "examples/delegation_demo/shared/delegation_revocation.h"
#include "examples/mdoc_anoncred/shared/types.h"

namespace proofs {

// ---- policy.json 读写 ----

// 将 Policy 写成格式化的 JSON 文件
bool WritePolicyJson(const std::filesystem::path& path,
                     const Policy& policy,
                     std::string* err);

// 从 JSON 文件读取 Policy
bool ReadPolicyJson(const std::filesystem::path& path,
                    Policy* policy,
                    std::string* err);

// SM2/SM3-only delegation directory used by the default business flow.
bool WriteDelegationSmDir(const std::filesystem::path& dir,
                          const HolderMdoc& holder,
                          const std::string& agent_sk_hex,
                          const std::string& device_pkx_sm2,
                          const std::string& device_pky_sm2,
                          const std::string& agent_pkx_sm2,
                          const std::string& agent_pky_sm2,
                          const std::string& del_msg_sm3,
                          const std::string& del_sig_sm2,
                          const DelegationRevocationStatus& rev_sm2,
                          const Policy& policy,
                          const std::vector<ReaderClaim>& allowed_claims,
                          std::string* err);

bool ReadDelegationSmDir(const std::filesystem::path& dir,
                         HolderMdoc* holder,
                         std::string* agent_sk_hex,
                         std::string* device_pkx_sm2,
                         std::string* device_pky_sm2,
                         std::string* agent_pkx_sm2,
                         std::string* agent_pky_sm2,
                         std::string* del_msg_sm3,
                         std::string* del_sig_sm2,
                         DelegationRevocationStatus* rev_sm2,
                         Policy* policy,
                         std::string* err);

// ---- public_delegation.json 读写 ----
// Module C 写出，Module D 读入。只包含 verifier 需要的公开输入；
// device public key、delegation signature、agent signature 等材料留在
// prover witness / 本地 delegation 目录中，不随 presentation 发送。

bool WritePublicDelegationJson(const std::filesystem::path& path,
                              const std::string& agent_pkx_hex,
                              const std::string& agent_pky_hex,
                              const Policy& policy,
                              std::string* err);

bool ReadPublicDelegationJson(const std::filesystem::path& path,
                             std::string* agent_pkx_hex,
                             std::string* agent_pky_hex,
                             Policy* policy,
                             std::string* err);

}  // namespace proofs

#endif  // EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_FILES_H_
