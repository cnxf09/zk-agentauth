#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_ISSUER_ISSUE_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_ISSUER_ISSUE_H_

#include <cstdint>
#include <filesystem>
#include <string>

namespace proofs {

bool RunMdocIssueCommand(uint32_t example_id, const std::filesystem::path& out_root,
                         std::string* err);

bool RunMdocIssueCustomCommand(const std::filesystem::path& out_root,
                               std::string* err);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_ISSUER_ISSUE_H_
