#include "examples/mdoc_anoncred/shared/interactive.h"

#include <algorithm>
#include <iostream>
#include <set>
#include <sstream>

namespace proofs {
namespace {

const std::vector<InteractiveExample> kExamples = {
    {0, "Example 0: age_over_18 only", {"age_over_18"}},
    {3,
     "Example 3: age_over_18 + family_name + birth_date + height (recommended)",
     {"age_over_18", "family_name_mustermann", "birth_date_1971_09_01",
      "height_175"}},
};

}  // namespace

const std::vector<InteractiveExample>& InteractiveExamples() { return kExamples; }

const InteractiveExample* FindInteractiveExample(uint32_t id) {
  for (const auto& example : kExamples) {
    if (example.id == id) {
      return &example;
    }
  }
  return nullptr;
}

std::string PromptLine(const std::string& prompt,
                       const std::string& default_value) {
  std::cout << prompt;
  if (!default_value.empty()) {
    std::cout << " [" << default_value << "]";
  }
  std::cout << ": " << std::flush;

  std::string line;
  std::getline(std::cin, line);
  if (line.empty()) {
    return default_value;
  }
  return line;
}

bool ParseSelectionList(const std::string& text, size_t max_index,
                        std::vector<size_t>* selections) {
  std::set<size_t> seen;
  std::stringstream ss(text);
  std::string part;
  while (std::getline(ss, part, ',')) {
    if (part.empty()) {
      return false;
    }
    size_t idx = 0;
    try {
      idx = static_cast<size_t>(std::stoul(part));
    } catch (...) {
      return false;
    }
    if (idx == 0 || idx > max_index) {
      return false;
    }
    seen.insert(idx - 1);
  }
  selections->assign(seen.begin(), seen.end());
  return !selections->empty();
}

}  // namespace proofs
