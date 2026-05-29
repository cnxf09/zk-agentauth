#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_ISSUE_CUSTOM_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_ISSUE_CUSTOM_H_

#include <filesystem>
#include <string>

#include "examples/mdoc_anoncred/builder/input.h"
#include "examples/mdoc_anoncred/shared/types.h"

namespace proofs {

bool BuildCustomMdoc(const IssuedMdocInput& input, HolderMdoc* holder,
                     MdocIssuerPublicBundle* issuer_public, std::string* err);

bool RunMdocIssueCustomCommand(const std::filesystem::path& out_root,
                               std::string* err);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_ISSUE_CUSTOM_H_
