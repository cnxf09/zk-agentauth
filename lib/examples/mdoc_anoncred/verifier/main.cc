#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

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

std::vector<std::string> GetFlags(int argc, char* argv[], const std::string& name) {
  std::vector<std::string> values;
  for (int i = 0; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == name) {
      values.push_back(argv[i + 1]);
    }
  }
  return values;
}

void Usage() {
  std::cerr << "usage:\n"
            << "  mdoc_anoncred_verifier request --issuer-public <dir> --claim <alias> [--claim <alias>] --out <dir>\n"
            << "  mdoc_anoncred_verifier verify --issuer-public <dir> --request <dir> --presentation <dir>\n";
}

std::vector<std::string> PromptClaimsForExample(uint32_t example_id) {
  const proofs::InteractiveExample* example = proofs::FindInteractiveExample(example_id);
  if (example == nullptr) {
    return {};
  }
  std::cout << "Supported claims for example " << example_id << ":\n";
  for (size_t i = 0; i < example->claims.size(); ++i) {
    std::cout << "  " << (i + 1) << ". " << example->claims[i] << "\n";
  }
  const std::string text =
      proofs::PromptLine("Select 1-2 claims by number, comma separated", "1");
  std::vector<size_t> selections;
  if (!proofs::ParseSelectionList(text, example->claims.size(), &selections) ||
      selections.size() > 2) {
    return {};
  }
  std::vector<std::string> claims;
  for (size_t idx : selections) {
    claims.push_back(example->claims[idx]);
  }
  return claims;
}

std::vector<std::string> PromptClaimsFromAliases(
    const std::vector<std::string>& aliases) {
  if (aliases.empty()) {
    return {};
  }
  std::cout << "Supported claims:\n";
  for (size_t i = 0; i < aliases.size(); ++i) {
    std::cout << "  " << (i + 1) << ". " << aliases[i] << "\n";
  }
  const std::string text =
      proofs::PromptLine("Select 1-2 claims by number, comma separated", "1");
  std::vector<size_t> selections;
  if (!proofs::ParseSelectionList(text, aliases.size(), &selections) ||
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
  if (argc < 2) {
    Usage();
    return 2;
  }
  const std::string cmd(argv[1]);
  std::string err;
  if (cmd == "request") {
    const char* issuer_public = GetFlag(argc, argv, "--issuer-public");
    const char* out = GetFlag(argc, argv, "--out");
    std::vector<std::string> claims = GetFlags(argc, argv, "--claim");
    if (issuer_public == nullptr || out == nullptr) {
      Usage();
      return 2;
    }
    if (claims.empty()) {
      std::string err;
      proofs::MdocIssuerPublicBundle issuer_public_bundle;
      if (!proofs::ReadMdocIssuerPublicDir(std::filesystem::path(issuer_public),
                                           &issuer_public_bundle, &err)) {
        std::cerr << "request failed: " << err << "\n";
        return 1;
      }
      if (!issuer_public_bundle.supported_claim_aliases.empty()) {
        claims = PromptClaimsFromAliases(
            issuer_public_bundle.supported_claim_aliases);
      } else {
        claims = PromptClaimsForExample(issuer_public_bundle.example_id);
      }
      if (claims.empty()) {
        std::cerr << "request failed: invalid claim selection\n";
        return 1;
      }
    }
    if (!proofs::RunMdocRequestCommand(std::filesystem::path(issuer_public), claims,
                                       std::filesystem::path(out), &err)) {
      std::cerr << "request failed: " << err << "\n";
      return 1;
    }
    std::cout << "reader request written to " << out << "\n";
    return 0;
  }
  if (cmd == "verify") {
    const char* issuer_public = GetFlag(argc, argv, "--issuer-public");
    const char* request = GetFlag(argc, argv, "--request");
    const char* presentation = GetFlag(argc, argv, "--presentation");
    if (issuer_public == nullptr || request == nullptr || presentation == nullptr) {
      Usage();
      return 2;
    }
    bool verified = false;
    if (!proofs::RunMdocVerifyCommand(std::filesystem::path(issuer_public),
                                      std::filesystem::path(request),
                                      std::filesystem::path(presentation),
                                      &verified, &err)) {
      std::cerr << "verify failed: " << err << "\n";
      return 1;
    }
    if (!verified) {
      std::cerr << "verification failed: " << err << "\n";
      return 1;
    }
    proofs::ReaderRequest request_data;
    if (!proofs::ReadReaderRequestDir(std::filesystem::path(request), &request_data,
                                      &err)) {
      std::cerr << "verify failed: " << err << "\n";
      return 1;
    }
    std::cout << "verification ok:";
    for (size_t i = 0; i < request_data.claims.size(); ++i) {
      std::cout << (i == 0 ? " " : ", ") << request_data.claims[i].alias;
    }
    std::cout << "\n";
    return 0;
  }
  Usage();
  return 2;
}
