// Module A: Issuer
// 直接调用现有的 RunMdocIssueCommand，无需修改现有代码

#include <filesystem>
#include <iostream>
#include <string>

#include "examples/mdoc_anoncred/issuer/issue.h"

namespace {

void Usage() {
  std::cerr << "usage:\n"
            << "  delegation_demo_issuer issue\n"
            << "    --example <id>   mdoc 样本 ID（默认 3）\n"
            << "    --out <dir>      输出根目录（生成 holder/ 和 issuer_public/）\n"
            << "\n示例：\n"
            << "  delegation_demo_issuer issue --example 3 --out run/demo/issue\n";
}

const char* GetFlag(int argc, char* argv[], const std::string& name) {
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == name) {
      return argv[i + 1];
    }
  }
  return nullptr;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2 || std::string(argv[1]) != "issue") {
    Usage();
    return 2;
  }

  const char* out_c = GetFlag(argc, argv, "--out");
  if (out_c == nullptr) {
    std::cerr << "error: --out is required\n\n";
    Usage();
    return 2;
  }

  const char* example_c = GetFlag(argc, argv, "--example");
  const uint32_t example_id = (example_c != nullptr)
                                   ? static_cast<uint32_t>(std::stoul(example_c))
                                   : 3u;

  std::string err;
  if (!proofs::RunMdocIssueCommand(example_id, std::filesystem::path(out_c), &err)) {
    std::cerr << "issue failed: " << err << "\n";
    return 1;
  }

  std::cout << "holder mdoc written to "
            << std::filesystem::path(out_c) / "holder" << "\n";
  std::cout << "issuer public bundle written to "
            << std::filesystem::path(out_c) / "issuer_public" << "\n";
  return 0;
}
