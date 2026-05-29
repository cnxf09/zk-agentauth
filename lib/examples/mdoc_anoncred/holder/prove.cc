#include "examples/mdoc_anoncred/holder/prove.h"

#include "examples/mdoc_anoncred/shared/files.h"
#include "examples/mdoc_anoncred/shared/mdoc_demo.h"

namespace proofs {

bool RunMdocProveCommand(const std::filesystem::path& holder_dir,
                         const std::filesystem::path& issuer_public_dir,
                         const std::filesystem::path& request_dir,
                         const std::filesystem::path& out_dir,
                         std::string* err) {
  HolderMdoc holder;
  MdocIssuerPublicBundle issuer_public;
  ReaderRequest request;
  MdocPresentation presentation;
  if (!ReadHolderMdocDir(holder_dir, &holder, err) ||
      !ReadMdocIssuerPublicDir(issuer_public_dir, &issuer_public, err) ||
      !ReadReaderRequestDir(request_dir, &request, err) ||
      !ProveMdocPresentation(holder, issuer_public, request, &presentation, err)) {
    return false;
  }
  return WriteMdocPresentationDir(out_dir, presentation, err);
}

}  // namespace proofs
