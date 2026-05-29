#include "examples/mdoc_anoncred/verifier/verify.h"

#include "examples/mdoc_anoncred/shared/files.h"
#include "examples/mdoc_anoncred/shared/mdoc_demo.h"

namespace proofs {

bool RunMdocRequestCommand(const std::filesystem::path& issuer_public_dir,
                           const std::vector<std::string>& claim_aliases,
                           const std::filesystem::path& out_dir,
                           std::string* err) {
  MdocIssuerPublicBundle issuer_public;
  ReaderRequest request;
  if (!ReadMdocIssuerPublicDir(issuer_public_dir, &issuer_public, err) ||
      !BuildReaderRequest(issuer_public, claim_aliases, &request, err)) {
    return false;
  }
  return WriteReaderRequestDir(out_dir, request, err);
}

bool RunMdocVerifyCommand(const std::filesystem::path& issuer_public_dir,
                          const std::filesystem::path& request_dir,
                          const std::filesystem::path& presentation_dir,
                          bool* verified, std::string* err) {
  MdocIssuerPublicBundle issuer_public;
  ReaderRequest request;
  MdocPresentation presentation;
  if (!ReadMdocIssuerPublicDir(issuer_public_dir, &issuer_public, err) ||
      !ReadReaderRequestDir(request_dir, &request, err) ||
      !ReadMdocPresentationDir(presentation_dir, &presentation, err)) {
    return false;
  }
  const MdocVerificationResult result =
      VerifyMdocPresentation(issuer_public, request, presentation);
  *verified = result.ok;
  *err = result.message;
  return true;
}

}  // namespace proofs
