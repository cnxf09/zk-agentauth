#ifndef EXAMPLES_DELEGATION_DEMO_SHARED_TYPES_H_
#define EXAMPLES_DELEGATION_DEMO_SHARED_TYPES_H_

#include <string>
#include <vector>

namespace proofs {

enum class PredicateOp {
  DISCLOSE,
  EQ,
  IN_SET,
  GE,
  LE,
};

struct PolicyPredicate {
  std::string claim;
  PredicateOp op = PredicateOp::DISCLOSE;
  std::vector<std::string> values;
};

// 委托策略：Agent 被授权的声明范围和时效
struct Policy {
  std::vector<std::string> allowed_claims;  // 允许的 claim alias 列表
  std::vector<PolicyPredicate> predicates;  // AND 组合的通用谓词
  std::string expires;                       // 过期时间 ISO 8601, e.g. "2027-01-01T00:00:00Z"
  std::string agent_id;                      // Agent 标识（可选）
  std::string created;                       // 创建时间 ISO 8601
};

}  // namespace proofs

#endif  // EXAMPLES_DELEGATION_DEMO_SHARED_TYPES_H_
