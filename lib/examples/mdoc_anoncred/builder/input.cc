#include "examples/mdoc_anoncred/builder/input.h"

#include <cctype>
#include <iostream>

#include "examples/mdoc_anoncred/shared/interactive.h"

namespace proofs {
namespace {

std::string UpperAscii(std::string s) {
  for (char& c : s) {
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  }
  return s;
}

bool IsDateText(const std::string& s) {
  if (s.size() != 10) return false;
  for (size_t i = 0; i < s.size(); ++i) {
    if (i == 4 || i == 7) {
      if (s[i] != '-') return false;
      continue;
    }
    if (!std::isdigit(static_cast<unsigned char>(s[i]))) return false;
  }
  return true;
}

bool ParseBoolText(const std::string& text, bool* value) {
  if (text == "y" || text == "Y" || text == "yes" || text == "true" ||
      text == "1") {
    *value = true;
    return true;
  }
  if (text == "n" || text == "N" || text == "no" || text == "false" ||
      text == "0") {
    *value = false;
    return true;
  }
  return false;
}

}  // namespace

bool ValidateIssuedMdocInput(const IssuedMdocInput& input, std::string* err) {
  if (input.family_name.empty() || input.family_name.size() > 40) {
    if (err != nullptr) {
      *err = "family_name must be 1..40 characters";
    }
    return false;
  }
  if (!IsDateText(input.birth_date)) {
    if (err != nullptr) {
      *err = "birth_date must be formatted as YYYY-MM-DD";
    }
    return false;
  }
  if (input.given_name.empty() || input.given_name.size() > 40) {
    if (err != nullptr) {
      *err = "given_name must be 1..40 characters";
    }
    return false;
  }
  if (!IsDateText(input.issue_date)) {
    if (err != nullptr) {
      *err = "issue_date must be formatted as YYYY-MM-DD";
    }
    return false;
  }
  if (!IsDateText(input.expiry_date)) {
    if (err != nullptr) {
      *err = "expiry_date must be formatted as YYYY-MM-DD";
    }
    return false;
  }
  if (input.expiry_date < input.issue_date) {
    if (err != nullptr) {
      *err = "expiry_date must be on or after issue_date";
    }
    return false;
  }
  if (input.issuing_country.size() != 2 ||
      !std::isalpha(static_cast<unsigned char>(input.issuing_country[0])) ||
      !std::isalpha(static_cast<unsigned char>(input.issuing_country[1]))) {
    if (err != nullptr) {
      *err = "issuing_country must be a 2-letter country code";
    }
    return false;
  }
  return true;
}

bool PromptIssuedMdocInput(IssuedMdocInput* input, std::string* err) {
  input->family_name = PromptLine("family_name", input->family_name);
  input->given_name = PromptLine("given_name", input->given_name);
  input->birth_date =
      PromptLine("birth_date (YYYY-MM-DD)", input->birth_date);
  input->issue_date =
      PromptLine("issue_date (YYYY-MM-DD)", input->issue_date);
  input->expiry_date =
      PromptLine("expiry_date (YYYY-MM-DD)", input->expiry_date);
  input->issuing_country =
      UpperAscii(PromptLine("issuing_country (2 letters)", input->issuing_country));
  const std::string age_text =
      PromptLine("age_over_18 (true/false)", input->age_over_18 ? "true" : "false");
  if (!ParseBoolText(age_text, &input->age_over_18)) {
    if (err != nullptr) {
      *err = "age_over_18 must be true/false";
    }
    return false;
  }
  return ValidateIssuedMdocInput(*input, err);
}

}  // namespace proofs
