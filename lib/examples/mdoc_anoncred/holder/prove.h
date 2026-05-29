#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_HOLDER_PROVE_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_HOLDER_PROVE_H_

#include <filesystem>
#include <string>

namespace proofs {

bool RunMdocProveCommand(const std::filesystem::path& holder_dir,
                         const std::filesystem::path& issuer_public_dir,
                         const std::filesystem::path& request_dir,
                         const std::filesystem::path& out_dir,
                         std::string* err);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_HOLDER_PROVE_H_
