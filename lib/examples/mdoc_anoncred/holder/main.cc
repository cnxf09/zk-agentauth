#include <filesystem>
#include <iostream>
#include <string>

#include "examples/mdoc_anoncred/holder/prove.h"

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
            << "  mdoc_anoncred_holder prove --holder <dir> --issuer-public <dir> --request <dir> --out <dir>\n";
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2 || std::string(argv[1]) != "prove") {
    Usage();
    return 2;
  }
  const char* holder = GetFlag(argc, argv, "--holder");
  const char* issuer_public = GetFlag(argc, argv, "--issuer-public");
  const char* request = GetFlag(argc, argv, "--request");
  const char* out = GetFlag(argc, argv, "--out");
  if (holder == nullptr || issuer_public == nullptr || request == nullptr || out == nullptr) {
    Usage();
    return 2;
  }
  std::string err;
  if (!proofs::RunMdocProveCommand(std::filesystem::path(holder),
                                   std::filesystem::path(issuer_public),
                                   std::filesystem::path(request),
                                   std::filesystem::path(out), &err)) {
    std::cerr << "prove failed: " << err << "\n";
    return 1;
  }
  std::cout << "presentation written to " << out << "\n";
  return 0;
}
