#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "examples/delegation_demo/alice/delegate.h"
#include "examples/delegation_demo/shared/delegation_crypto.h"

namespace {

void Usage() {
  std::cerr << "usage:\n"
            << "  delegation_demo_alice delegate\n"
            << "    --holder <dir>        Alice 的 holder/ 目录\n"
            << "    --claim  <alias>      允许的 claim alias（可多次指定）\n"
            << "    --predicate <c:op:v>  通用谓词，如 height:GE:170，可多次指定\n"
            << "    --expires <iso8601>   委托过期时间，如 2027-01-01T00:00:00Z\n"
            << "    --agent-id <id>       Agent 标识（可选，默认 'agent'）\n"
            << "    --revoked             写出已撤销委托状态（用于负例测试）\n"
            << "    --out <dir>           输出 delegation/ 目录\n"
            << "\n示例：\n"
            << "  delegation_demo_alice delegate \\\n"
            << "    --holder run/demo/issue/holder \\\n"
            << "    --claim age_over_18 \\\n"
            << "    --expires 2027-01-01T00:00:00Z \\\n"
            << "    --agent-id bookstore-agent \\\n"
            << "    --out run/demo/delegation\n";
}

const char* GetFlag(int argc, char* argv[], const std::string& name) {
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == name) {
      return argv[i + 1];
    }
  }
  return nullptr;
}

// 收集所有 --claim 参数（可多次）
std::vector<std::string> GetFlagAll(int argc, char* argv[], const std::string& name) {
  std::vector<std::string> result;
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == name) {
      result.push_back(argv[i + 1]);
    }
  }
  return result;
}

bool HasFlag(int argc, char* argv[], const std::string& name) {
  for (int i = 0; i < argc; ++i) {
    if (std::string(argv[i]) == name) return true;
  }
  return false;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2 || std::string(argv[1]) != "delegate") {
    Usage();
    return 2;
  }

  const char* holder_c  = GetFlag(argc, argv, "--holder");
  const char* expires_c = GetFlag(argc, argv, "--expires");
  const char* out_c     = GetFlag(argc, argv, "--out");

  if (holder_c == nullptr || expires_c == nullptr || out_c == nullptr) {
    std::cerr << "error: --holder, --expires, --out are required\n\n";
    Usage();
    return 2;
  }

  const char* agent_id_c = GetFlag(argc, argv, "--agent-id");
  const std::string agent_id = (agent_id_c != nullptr) ? agent_id_c : "agent";
  const bool revoked = HasFlag(argc, argv, "--revoked");

  std::string err;
  std::vector<std::string> claims = GetFlagAll(argc, argv, "--claim");
  std::vector<proofs::PolicyPredicate> predicates;
  for (const auto& text : GetFlagAll(argc, argv, "--predicate")) {
    proofs::PolicyPredicate predicate;
    if (!proofs::ParsePolicyPredicate(text, &predicate, &err)) {
      std::cerr << "delegate failed: " << err << "\n";
      return 1;
    }
    predicates.push_back(predicate);
    bool seen = false;
    for (const auto& claim : claims) {
      if (claim == predicate.claim) {
        seen = true;
        break;
      }
    }
    if (!seen) claims.push_back(predicate.claim);
  }
  if (claims.empty()) {
    std::cerr << "error: at least one --claim or --predicate is required\n\n";
    Usage();
    return 2;
  }
  if (predicates.empty()) {
    for (const auto& claim : claims) {
      predicates.push_back({claim, proofs::PredicateOp::DISCLOSE, {}});
    }
  }
  if (!proofs::RunDelegateCommand(
          std::filesystem::path(holder_c),
          claims,
          predicates,
          std::string(expires_c),
          agent_id,
          revoked,
          std::filesystem::path(out_c),
          &err)) {
    std::cerr << "delegate failed: " << err << "\n";
    return 1;
  }

  std::cout << "delegation written to " << out_c << "\n";
  std::cout << "  allowed claims:";
  for (const auto& c : claims) std::cout << " " << c;
  std::cout << "\n";
  std::cout << "  expires: " << expires_c << "\n";
  std::cout << "  agent-id: " << agent_id << "\n";
  std::cout << "  revoked: " << (revoked ? "true" : "false") << "\n";
  return 0;
}
