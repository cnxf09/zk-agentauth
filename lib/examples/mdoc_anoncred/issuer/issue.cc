#include "examples/mdoc_anoncred/issuer/issue.h"

#include "examples/mdoc_anoncred/shared/files.h"
#include "examples/mdoc_anoncred/shared/mdoc_demo.h"

namespace proofs {

bool RunMdocIssueCommand(uint32_t example_id, const std::filesystem::path& out_root,
                         std::string* err) {
  HolderMdoc holder;
  MdocIssuerPublicBundle issuer_public;
  if (!MaterializeMdocExample(example_id, &holder, &issuer_public, err)) {
    return false;
  }
  return WriteHolderMdocDir(out_root / "holder", holder, err) &&
         WriteMdocIssuerPublicDir(out_root / "issuer_public", issuer_public, err);
}

}  // namespace proofs
