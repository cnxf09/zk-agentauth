#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "examples/mdoc_anoncred/holder/prove.h"
#include "examples/mdoc_anoncred/issuer/issue.h"
#include "examples/mdoc_anoncred/shared/files.h"
#include "examples/mdoc_anoncred/shared/interactive.h"
#include "examples/mdoc_anoncred/verifier/verify.h"

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
            << "  mdoc_anoncred_console guided [--out-root <dir>]\n";
}

void PrintExamples() {
  std::cout << "Available mdoc examples:\n";
  for (const auto& example : proofs::InteractiveExamples()) {
    std::cout << "  " << example.id << ". " << example.label << "\n";
  }
}

std::vector<std::string> PromptClaimsFromAliases(
    const std::vector<std::string>& aliases) {
  std::cout << "\nSupported claims:\n";
  for (size_t i = 0; i < aliases.size(); ++i) {
    std::cout << "  " << (i + 1) << ". " << aliases[i] << "\n";
  }
  const std::string claims_text =
      proofs::PromptLine("Select 1-2 claims by number, comma separated", "1");
  std::vector<size_t> selections;
  if (!proofs::ParseSelectionList(claims_text, aliases.size(), &selections) ||
      selections.size() > 2) {
    return {};
  }
  std::vector<std::string> claims;
  for (size_t idx : selections) {
    claims.push_back(aliases[idx]);
  }
  return claims;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2 || std::string(argv[1]) != "guided") {
    Usage();
    return 2;
  }

  const char* out_root_flag = GetFlag(argc, argv, "--out-root");
  const std::filesystem::path out_root =
      out_root_flag == nullptr ? std::filesystem::path("run/mdoc-interactive")
                               : std::filesystem::path(out_root_flag);

  std::cout << "Interactive mdoc anonymous credential demo\n";
  std::cout << "Choose issuance mode:\n";
  std::cout << "  1. Real sample-based mdoc\n";
  std::cout << "  2. Custom interactive mdoc\n\n";

  std::string err;
  const auto issue_dir = out_root / "issue";
  const auto request_dir = out_root / "request";
  const auto presentation_dir = out_root / "presentation";

  const std::string mode_text = proofs::PromptLine("Select mode", "1");
  std::vector<std::string> claims;
  if (mode_text == "2") {
    if (!proofs::RunMdocIssueCustomCommand(issue_dir, &err)) {
      std::cerr << "interactive flow failed: " << err << "\n";
      return 1;
    }
    proofs::MdocIssuerPublicBundle issuer_public;
    if (!proofs::ReadMdocIssuerPublicDir(issue_dir / "issuer_public", &issuer_public,
                                         &err)) {
      std::cerr << "interactive flow failed: " << err << "\n";
      return 1;
    }
    claims = PromptClaimsFromAliases(issuer_public.supported_claim_aliases);
    if (claims.empty()) {
      std::cerr << "invalid claim selection\n";
      return 1;
    }
  } else {
    PrintExamples();
    const std::string example_text = proofs::PromptLine("Select example id", "3");
    uint32_t example_id = 3;
    try {
      example_id = static_cast<uint32_t>(std::stoul(example_text));
    } catch (...) {
      std::cerr << "invalid example id\n";
      return 1;
    }
    const proofs::InteractiveExample* example =
        proofs::FindInteractiveExample(example_id);
    if (example == nullptr) {
      std::cerr << "unsupported example id: " << example_id << "\n";
      return 1;
    }
    claims = PromptClaimsFromAliases(example->claims);
    if (claims.empty()) {
      std::cerr << "invalid claim selection\n";
      return 1;
    }
    if (!proofs::RunMdocIssueCommand(example_id, issue_dir, &err)) {
      std::cerr << "interactive flow failed: " << err << "\n";
      return 1;
    }
  }

  if (!proofs::RunMdocRequestCommand(issue_dir / "issuer_public", claims, request_dir,
                                     &err) ||
      !proofs::RunMdocProveCommand(issue_dir / "holder", issue_dir / "issuer_public",
                                   request_dir, presentation_dir, &err)) {
    std::cerr << "interactive flow failed: " << err << "\n";
    return 1;
  }

  bool verified = false;
  if (!proofs::RunMdocVerifyCommand(issue_dir / "issuer_public", request_dir,
                                    presentation_dir, &verified, &err)) {
    std::cerr << "interactive flow failed: " << err << "\n";
    return 1;
  }
  if (!verified) {
    std::cerr << "verification failed: " << err << "\n";
    return 1;
  }

  std::cout << "\nverification ok:";
  for (size_t i = 0; i < claims.size(); ++i) {
    std::cout << (i == 0 ? " " : ", ") << claims[i];
  }
  std::cout << "\n";
  std::cout << "issue dir: " << issue_dir << "\n";
  std::cout << "request dir: " << request_dir << "\n";
  std::cout << "presentation dir: " << presentation_dir << "\n";
  return 0;
}
