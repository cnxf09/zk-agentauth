#include <filesystem>
#include <iostream>
#include <string>

#include "examples/mdoc_anoncred/issuer/issue.h"
#include "examples/mdoc_anoncred/shared/interactive.h"

namespace {

const char* GetFlag(int argc, char* argv[], const std::string& name) {
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == name) {
      return argv[i + 1];
    }
  }
  return nullptr;
}

void Usage() {
  std::cerr << "usage:\n"
            << "  mdoc_anoncred_issuer issue --example <id> --out <dir>\n"
            << "  mdoc_anoncred_issuer issue-custom --out <dir>\n";
}

void PrintExamples() {
  std::cout << "Available mdoc examples:\n";
  for (const auto& example : proofs::InteractiveExamples()) {
    std::cout << "  " << example.id << ". " << example.label << "\n";
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2) {
    Usage();
    return 2;
  }
  const std::string cmd(argv[1]);
  const char* out = GetFlag(argc, argv, "--out");
  if (out == nullptr) {
    Usage();
    return 2;
  }
  std::string err;
  if (cmd == "issue-custom") {
    if (!proofs::RunMdocIssueCustomCommand(std::filesystem::path(out), &err)) {
      std::cerr << "issue-custom failed: " << err << "\n";
      return 1;
    }
    std::cout << "holder mdoc written to " << std::filesystem::path(out) / "holder"
              << "\n";
    std::cout << "issuer public bundle written to "
              << std::filesystem::path(out) / "issuer_public" << "\n";
    return 0;
  }
  if (cmd != "issue") {
    Usage();
    return 2;
  }
  const char* example = GetFlag(argc, argv, "--example");
  uint32_t example_id = 3u;
  if (example == nullptr) {
    PrintExamples();
    const std::string selected = proofs::PromptLine("Select example id", "3");
    try {
      example_id = static_cast<uint32_t>(std::stoul(selected));
    } catch (...) {
      std::cerr << "invalid example id\n";
      return 1;
    }
  } else {
    example_id = static_cast<uint32_t>(std::stoul(example));
  }
  if (!proofs::RunMdocIssueCommand(example_id, std::filesystem::path(out), &err)) {
    std::cerr << "issue failed: " << err << "\n";
    return 1;
  }
  std::cout << "holder mdoc written to " << std::filesystem::path(out) / "holder" << "\n";
  std::cout << "issuer public bundle written to " << std::filesystem::path(out) / "issuer_public" << "\n";
  return 0;
}
