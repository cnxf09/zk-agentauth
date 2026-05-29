#include <filesystem>
#include <iostream>
#include <string>

#include "examples/delegation_demo/agent/present.h"

namespace {

void Usage() {
  std::cerr << "usage:\n"
            << "  delegation_demo_agent present\n"
            << "    --delegation <dir>      委托目录（Module B 输出）\n"
            << "    --issuer-public <dir>   颁发方公开信息目录\n"
            << "    --request <dir>         验证请求目录（Module D-1 输出）\n"
            << "    --out <dir>             输出 presentation/ 目录\n"
            << "\n示例：\n"
            << "  delegation_demo_agent present \\\n"
            << "    --delegation run/demo/delegation \\\n"
            << "    --issuer-public run/demo/issue/issuer_public \\\n"
            << "    --request run/demo/request \\\n"
            << "    --out run/demo/presentation\n";
}

const char* GetFlag(int argc, char* argv[], const std::string& name) {
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == name) return argv[i + 1];
  }
  return nullptr;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2 || std::string(argv[1]) != "present") {
    Usage();
    return 2;
  }

  const char* delegation_c     = GetFlag(argc, argv, "--delegation");
  const char* issuer_public_c  = GetFlag(argc, argv, "--issuer-public");
  const char* request_c        = GetFlag(argc, argv, "--request");
  const char* out_c            = GetFlag(argc, argv, "--out");

  if (delegation_c == nullptr || issuer_public_c == nullptr ||
      request_c == nullptr || out_c == nullptr) {
    std::cerr << "error: --delegation, --issuer-public, --request, --out are "
                 "required\n\n";
    Usage();
    return 2;
  }

  std::string err;
  if (!proofs::RunAgentPresentCommand(
          std::filesystem::path(delegation_c),
          std::filesystem::path(issuer_public_c),
          std::filesystem::path(request_c),
          std::filesystem::path(out_c), &err)) {
    std::cerr << "present failed: " << err << "\n";
    return 1;
  }

  std::cout << "presentation written to " << out_c << "\n";
  return 0;
}
