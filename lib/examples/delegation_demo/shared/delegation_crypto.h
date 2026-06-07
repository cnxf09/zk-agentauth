#ifndef EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_CRYPTO_H_
#define EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_CRYPTO_H_

#include <string>
#include <vector>

#include "circuits/mdoc/mdoc_zk.h"
#include "examples/delegation_demo/shared/types.h"
#include "examples/mdoc_anoncred/shared/types.h"

namespace proofs {

// 生成策略的规范化 JSON 字符串（键按字母序，紧凑格式），用于签名
// 输出示例：{"agent_id":"x","allowed_claims":["age_over_18"],"created":"...","expires":"..."}
std::string CanonicalPolicyJson(const Policy& policy);

static constexpr const char kHybridCryptoProfile[] =
    "sm2-sm3-zk";

// 国密 profile：SM3(固定宽度委托消息)，其结果作为标准 SM2 签名的
// message，并进入 SM3/SM2 ZK 约束。
bool ComputeDelegationMsgSm3(const std::string& agent_pkx_hex,
                             const std::string& agent_pky_hex,
                             const Policy& policy,
                             std::string* out_msg_hex,
                             std::string* err);

bool Sm3Digest(const uint8_t* data, size_t len, std::vector<uint8_t>* digest);

bool ComputeDeviceAuthenticationDigestSm3(
    const std::vector<uint8_t>& transcript,
    const std::string& doc_type,
    std::vector<uint8_t>* digest,
    std::string* err);

bool GenerateSM2KeyPair(std::string* sk_hex, std::string* pkx_hex,
                        std::string* pky_hex, std::string* err);

bool DeriveSM2PublicKey(const std::string& sk_hex, std::string* pkx_hex,
                        std::string* pky_hex, std::string* err);

static constexpr const char kSm2IssuerId[] = "ZKAA-ISSUER-0001";
static constexpr const char kSm2DeviceId[] = "ZKAA-DEVICE-0001";
static constexpr const char kSm2AgentId[] = "ZKAA-AGENT--0001";

bool SignMessageSM2(const std::string& sk_hex, const char* signer_id,
                    const uint8_t* msg, size_t msg_len,
                    std::vector<uint8_t>* sig_rs, std::string* err);

bool VerifyMessageSM2(const std::string& pkx_hex, const std::string& pky_hex,
                      const char* signer_id, const uint8_t* msg,
                      size_t msg_len, const std::vector<uint8_t>& sig_rs,
                      std::string* err);

bool SignDelegationSm2(const std::string& sk_hex,
                       const std::string& msg_hex,
                       std::string* out_sig_hex,
                       std::string* err);

bool VerifyDelegationSigSm2(const std::string& pkx_hex,
                            const std::string& pky_hex,
                            const std::string& msg_hex,
                            const std::string& sig_hex,
                            std::string* err);

bool HashClaimAlias(const std::string& alias, std::vector<uint8_t>* out_hash);

bool HashAgentId(const std::string& agent_id, std::vector<uint8_t>* out_hash);

bool ParsePolicyPredicate(const std::string& text, PolicyPredicate* predicate,
                          std::string* err);

std::string PredicateOpName(PredicateOp op);

bool EvaluatePolicyPredicates(const Policy& policy,
                              const std::vector<ReaderClaim>& claims,
                              std::string* err);

bool BuildDelegationCircuitInputsSm3(
    const Policy& policy, const std::vector<std::string>& requested_aliases,
    std::vector<uint8_t>* allowed_claim_hashes_padded,
    std::vector<uint8_t>* agent_id_hash,
    std::vector<uint8_t>* requested_claim_hashes, std::string* err);

// 检查 claim alias 是否在策略允许范围内（约束⑧应用层实现）
bool PolicyAllowsClaim(const Policy& policy, const std::string& alias);

// 检查策略是否已过期（约束⑨应用层实现）
// now_iso8601: 当前时间 ISO 8601 字符串
// 策略过期 <=> policy.expires <= now
bool PolicyExpired(const Policy& policy, const std::string& now_iso8601);

}  // namespace proofs

#endif  // EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_CRYPTO_H_
