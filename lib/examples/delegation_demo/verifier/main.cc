#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "examples/delegation_demo/shared/delegation_crypto.h"
#include "examples/delegation_demo/verifier/verify.h"

namespace {

void Usage() {
  std::cerr
      << "usage:\n"
      << "  delegation_demo_verifier request\n"
      << "    --issuer-public <dir>   颁发方公开信息目录\n"
      << "    --claim <alias>         请求的 claim alias（可多次指定）\n"
      << "    --predicate <c:op:v>    请求并检查的谓词，如 height:GE:170\n"
      << "    --out <dir>             输出 request/ 目录\n"
      << "\n"
      << "  delegation_demo_verifier verify\n"
      << "    --issuer-public <dir>   颁发方公开信息目录\n"
      << "    --request <dir>         request/ 目录\n"
      << "    --presentation <dir>    presentation/ 目录\n"
      << "\n示例：\n"
      << "  delegation_demo_verifier request \\\n"
      << "    --issuer-public run/demo/issue/issuer_public \\\n"
      << "    --claim age_over_18 --out run/demo/request\n"
      << "\n"
      << "  delegation_demo_verifier verify \\\n"
      << "    --issuer-public run/demo/issue/issuer_public \\\n"
      << "    --request run/demo/request \\\n"
      << "    --presentation run/demo/presentation\n";
}

const char* GetFlag(int argc, char* argv[], const std::string& name) {
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == name) return argv[i + 1];
  }
  return nullptr;
}

std::vector<std::string> GetFlagAll(int argc, char* argv[],
                                     const std::string& name) {
  std::vector<std::string> result;
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == name) result.push_back(argv[i + 1]);
  }
  return result;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2) {
    Usage();
    return 2;
  }

  const std::string subcmd = argv[1];

  if (subcmd == "request") {
    const char* issuer_public_c = GetFlag(argc, argv, "--issuer-public");
    const char* out_c           = GetFlag(argc, argv, "--out");
    auto claims                 = GetFlagAll(argc, argv, "--claim");
    for (const auto& text : GetFlagAll(argc, argv, "--predicate")) {
      proofs::PolicyPredicate predicate;
      std::string parse_err;
      if (!proofs::ParsePolicyPredicate(text, &predicate, &parse_err)) {
        std::cerr << "request failed: " << parse_err << "\n";
        return 1;
      }
      bool seen = false;
      for (const auto& claim : claims) {
        if (claim == predicate.claim) {
          seen = true;
          break;
        }
      }
      if (!seen) claims.push_back(predicate.claim);
    }

    if (issuer_public_c == nullptr || out_c == nullptr || claims.empty()) {
      std::cerr << "error: --issuer-public, --claim, --out are required\n\n";
      Usage();
      return 2;
    }

    std::string err;
    if (!proofs::RunDelegationRequestCommand(
            std::filesystem::path(issuer_public_c), claims,
            std::filesystem::path(out_c), &err)) {
      std::cerr << "request failed: " << err << "\n";
      return 1;
    }
    std::cout << "request written to " << out_c << "\n";
    return 0;
  }

  if (subcmd == "verify") {
    const char* issuer_public_c  = GetFlag(argc, argv, "--issuer-public");
    const char* request_c        = GetFlag(argc, argv, "--request");
    const char* presentation_c   = GetFlag(argc, argv, "--presentation");

    if (issuer_public_c == nullptr || request_c == nullptr ||
        presentation_c == nullptr) {
      std::cerr << "error: --issuer-public, --request, --presentation are "
                   "required\n\n";
      Usage();
      return 2;
    }

    std::string err;
    proofs::DelegationVerificationResult result;
    if (!proofs::RunDelegationVerifyCommand(
            std::filesystem::path(issuer_public_c),
            std::filesystem::path(request_c),
            std::filesystem::path(presentation_c), &result, &err)) {
      std::cerr << "verify error: " << err << "\n";
      return 1;
    }

    std::cout << "=== Delegation Verification ===\n";
    std::cout << result.message << "\n";
    return result.overall_ok ? 0 : 1;
  }

  std::cerr << "unknown subcommand: " << subcmd << "\n\n";
  Usage();
  return 2;
}
