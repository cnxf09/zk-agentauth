#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_VERIFIER_VERIFY_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_VERIFIER_VERIFY_H_

#include <filesystem>
#include <string>
#include <vector>

namespace proofs {

bool RunMdocRequestCommand(const std::filesystem::path& issuer_public_dir,
                           const std::vector<std::string>& claim_aliases,
                           const std::filesystem::path& out_dir,
                           std::string* err);

bool RunMdocVerifyCommand(const std::filesystem::path& issuer_public_dir,
                          const std::filesystem::path& request_dir,
                          const std::filesystem::path& presentation_dir,
                          bool* verified, std::string* err);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_VERIFIER_VERIFY_H_
