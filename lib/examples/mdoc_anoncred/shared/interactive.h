#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_INTERACTIVE_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_INTERACTIVE_H_

#include <cstdint>
#include <string>
#include <vector>

namespace proofs {

struct InteractiveExample {
  uint32_t id;
  const char* label;
  std::vector<std::string> claims;
};

const std::vector<InteractiveExample>& InteractiveExamples();

const InteractiveExample* FindInteractiveExample(uint32_t id);

std::string PromptLine(const std::string& prompt,
                       const std::string& default_value);

bool ParseSelectionList(const std::string& text, size_t max_index,
                        std::vector<size_t>* selections);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_INTERACTIVE_H_
