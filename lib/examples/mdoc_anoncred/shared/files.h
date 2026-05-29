#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_FILES_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_FILES_H_

#include <filesystem>
#include <string>
#include <vector>

#include "examples/mdoc_anoncred/shared/types.h"

namespace proofs {

bool WriteBytesFile(const std::filesystem::path& path,
                    const std::vector<uint8_t>& bytes, std::string* err);
bool ReadBytesFile(const std::filesystem::path& path, std::vector<uint8_t>* out,
                   std::string* err);
bool WriteStringFile(const std::filesystem::path& path, const std::string& text,
                     std::string* err);
bool ReadStringFile(const std::filesystem::path& path, std::string* out,
                    std::string* err);

bool WriteHolderMdocDir(const std::filesystem::path& dir, const HolderMdoc& holder,
                        std::string* err);
bool ReadHolderMdocDir(const std::filesystem::path& dir, HolderMdoc* holder,
                       std::string* err);

bool WriteMdocIssuerPublicDir(const std::filesystem::path& dir,
                              const MdocIssuerPublicBundle& issuer_public,
                              std::string* err);
bool ReadMdocIssuerPublicDir(const std::filesystem::path& dir,
                             MdocIssuerPublicBundle* issuer_public,
                             std::string* err);

bool WriteReaderRequestDir(const std::filesystem::path& dir,
                           const ReaderRequest& request, std::string* err);
bool ReadReaderRequestDir(const std::filesystem::path& dir,
                          ReaderRequest* request, std::string* err);

bool WriteMdocPresentationDir(const std::filesystem::path& dir,
                              const MdocPresentation& presentation,
                              std::string* err);
bool ReadMdocPresentationDir(const std::filesystem::path& dir,
                             MdocPresentation* presentation,
                             std::string* err);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_FILES_H_
