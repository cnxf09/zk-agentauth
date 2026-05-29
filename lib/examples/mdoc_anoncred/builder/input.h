#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_INPUT_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_INPUT_H_

#include <string>

namespace proofs {

struct IssuedMdocInput {
  std::string family_name = "Mustermann";
  std::string given_name = "Erika";
  std::string birth_date = "1971-09-01";
  std::string issue_date = "2024-01-01";
  std::string expiry_date = "2035-01-01";
  std::string issuing_country = "DE";
  bool age_over_18 = true;
};

bool ValidateIssuedMdocInput(const IssuedMdocInput& input, std::string* err);

bool PromptIssuedMdocInput(IssuedMdocInput* input, std::string* err);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_INPUT_H_
