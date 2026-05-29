#include "examples/mdoc_anoncred/shared/files.h"

#include <fstream>
#include <iterator>

#include "examples/mdoc_anoncred/shared/request_codec.h"

namespace proofs {
namespace {

bool EnsureDir(const std::filesystem::path& dir, std::string* err) {
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    if (err != nullptr) {
      *err = "failed to create directory: " + dir.string() + ": " + ec.message();
    }
    return false;
  }
  return true;
}

}  // namespace

bool WriteBytesFile(const std::filesystem::path& path,
                    const std::vector<uint8_t>& bytes, std::string* err) {
  if (!EnsureDir(path.parent_path(), err)) {
    return false;
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    if (err != nullptr) {
      *err = "failed to open file for write: " + path.string();
    }
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
  if (!out.good()) {
    if (err != nullptr) {
      *err = "failed to write file: " + path.string();
    }
    return false;
  }
  return true;
}

bool ReadBytesFile(const std::filesystem::path& path, std::vector<uint8_t>* out,
                   std::string* err) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (err != nullptr) {
      *err = "failed to open file for read: " + path.string();
    }
    return false;
  }
  out->assign(std::istreambuf_iterator<char>(in),
              std::istreambuf_iterator<char>());
  if (!in.good() && !in.eof()) {
    if (err != nullptr) {
      *err = "failed to read file: " + path.string();
    }
    return false;
  }
  return true;
}

bool WriteStringFile(const std::filesystem::path& path, const std::string& text,
                     std::string* err) {
  std::vector<uint8_t> bytes(text.begin(), text.end());
  return WriteBytesFile(path, bytes, err);
}

bool ReadStringFile(const std::filesystem::path& path, std::string* out,
                    std::string* err) {
  std::vector<uint8_t> bytes;
  if (!ReadBytesFile(path, &bytes, err)) {
    return false;
  }
  out->assign(bytes.begin(), bytes.end());
  return true;
}

bool WriteHolderMdocDir(const std::filesystem::path& dir, const HolderMdoc& holder,
                        std::string* err) {
  if (!EnsureDir(dir, err)) {
    return false;
  }
  if (!WriteStringFile(dir / "example_id.txt", std::to_string(holder.example_id),
                       err) ||
      !WriteStringFile(dir / "doc_type.txt", holder.doc_type, err) ||
      !WriteStringFile(dir / "device_sk.txt", holder.device_sk_hex, err) ||
      !WriteStringFile(dir / "device_pkx.txt", holder.device_pkx_hex, err) ||
      !WriteStringFile(dir / "device_pky.txt", holder.device_pky_hex, err) ||
      !WriteBytesFile(dir / "device_response.cbor", holder.device_response_cbor,
                      err)) {
    return false;
  }
  if (!WriteStringFile(dir / "claims_count.txt",
                       std::to_string(holder.issued_claims.size()), err)) {
    return false;
  }
  for (size_t i = 0; i < holder.issued_claims.size(); ++i) {
    const auto& claim = holder.issued_claims[i];
    if (!WriteStringFile(dir / ("claim_alias_" + std::to_string(i) + ".txt"),
                         claim.alias, err) ||
        !WriteStringFile(dir / ("claim_namespace_" + std::to_string(i) + ".txt"),
                         claim.namespace_id, err) ||
        !WriteStringFile(dir / ("claim_id_" + std::to_string(i) + ".txt"),
                         claim.element_id, err) ||
        !WriteBytesFile(dir / ("claim_cbor_value_" + std::to_string(i) + ".bin"),
                        claim.cbor_value, err)) {
      return false;
    }
  }
  return true;
}

bool ReadHolderMdocDir(const std::filesystem::path& dir, HolderMdoc* holder,
                       std::string* err) {
  std::string example_id;
  if (!ReadStringFile(dir / "example_id.txt", &example_id, err) ||
      !ReadStringFile(dir / "doc_type.txt", &holder->doc_type, err) ||
      !ReadStringFile(dir / "device_sk.txt", &holder->device_sk_hex, err) ||
      !ReadStringFile(dir / "device_pkx.txt", &holder->device_pkx_hex, err) ||
      !ReadStringFile(dir / "device_pky.txt", &holder->device_pky_hex, err) ||
      !ReadBytesFile(dir / "device_response.cbor", &holder->device_response_cbor,
                     err)) {
    return false;
  }
  holder->example_id = static_cast<uint32_t>(std::stoul(example_id));
  holder->issued_claims.clear();
  std::string claims_count;
  if (ReadStringFile(dir / "claims_count.txt", &claims_count, nullptr)) {
    const size_t count = static_cast<size_t>(std::stoul(claims_count));
    holder->issued_claims.resize(count);
    for (size_t i = 0; i < count; ++i) {
      if (!ReadStringFile(dir / ("claim_alias_" + std::to_string(i) + ".txt"),
                          &holder->issued_claims[i].alias, err) ||
          !ReadStringFile(dir / ("claim_namespace_" + std::to_string(i) + ".txt"),
                          &holder->issued_claims[i].namespace_id, err) ||
          !ReadStringFile(dir / ("claim_id_" + std::to_string(i) + ".txt"),
                          &holder->issued_claims[i].element_id, err) ||
          !ReadBytesFile(dir / ("claim_cbor_value_" + std::to_string(i) + ".bin"),
                         &holder->issued_claims[i].cbor_value, err)) {
        return false;
      }
    }
  }
  return true;
}

bool WriteMdocIssuerPublicDir(const std::filesystem::path& dir,
                              const MdocIssuerPublicBundle& issuer_public,
                              std::string* err) {
  if (!EnsureDir(dir, err)) {
    return false;
  }
  if (!WriteStringFile(dir / "example_id.txt",
                       std::to_string(issuer_public.example_id), err) ||
      !WriteStringFile(dir / "issuer_pkx.txt", issuer_public.issuer_pkx_hex,
                       err) ||
      !WriteStringFile(dir / "issuer_pky.txt", issuer_public.issuer_pky_hex,
                       err) ||
      !WriteStringFile(dir / "doc_type.txt", issuer_public.doc_type, err) ||
      !WriteStringFile(dir / "now.txt", issuer_public.now_iso8601, err) ||
      !WriteStringFile(dir / "client_id.txt", issuer_public.client_id, err) ||
      !WriteStringFile(dir / "response_uri.txt", issuer_public.response_uri,
                       err)) {
    return false;
  }
  if (!WriteStringFile(dir / "supported_claims_count.txt",
                       std::to_string(issuer_public.supported_claim_aliases.size()),
                       err)) {
    return false;
  }
  for (size_t i = 0; i < issuer_public.supported_claim_aliases.size(); ++i) {
    if (!WriteStringFile(
            dir / ("supported_claim_" + std::to_string(i) + ".txt"),
            issuer_public.supported_claim_aliases[i], err)) {
      return false;
    }
  }
  return true;
}

bool ReadMdocIssuerPublicDir(const std::filesystem::path& dir,
                             MdocIssuerPublicBundle* issuer_public,
                             std::string* err) {
  std::string example_id;
  if (!ReadStringFile(dir / "example_id.txt", &example_id, err) ||
      !ReadStringFile(dir / "issuer_pkx.txt", &issuer_public->issuer_pkx_hex,
                      err) ||
      !ReadStringFile(dir / "issuer_pky.txt", &issuer_public->issuer_pky_hex,
                      err) ||
      !ReadStringFile(dir / "doc_type.txt", &issuer_public->doc_type, err) ||
      !ReadStringFile(dir / "now.txt", &issuer_public->now_iso8601, err) ||
      !ReadStringFile(dir / "client_id.txt", &issuer_public->client_id, err) ||
      !ReadStringFile(dir / "response_uri.txt", &issuer_public->response_uri,
                      err)) {
    return false;
  }
  issuer_public->example_id = static_cast<uint32_t>(std::stoul(example_id));
  issuer_public->supported_claim_aliases.clear();
  std::string claims_count;
  if (ReadStringFile(dir / "supported_claims_count.txt", &claims_count, nullptr)) {
    const size_t count = static_cast<size_t>(std::stoul(claims_count));
    issuer_public->supported_claim_aliases.resize(count);
    for (size_t i = 0; i < count; ++i) {
      if (!ReadStringFile(dir / ("supported_claim_" + std::to_string(i) + ".txt"),
                          &issuer_public->supported_claim_aliases[i], err)) {
        return false;
      }
    }
  }
  return true;
}

bool WriteReaderRequestDir(const std::filesystem::path& dir,
                           const ReaderRequest& request, std::string* err) {
  if (!EnsureDir(dir, err)) {
    return false;
  }
  if (!WriteBytesFile(dir / "reader_request.cbor", request.request_cbor, err) ||
      !WriteBytesFile(dir / "session_transcript.cbor", request.transcript_bytes,
                      err) ||
      !WriteStringFile(dir / "openid4vp_request.json",
                       request.openid4vp_request_json, err)) {
    return false;
  }
  return true;
}

bool ReadReaderRequestDir(const std::filesystem::path& dir,
                          ReaderRequest* request, std::string* err) {
  std::vector<uint8_t> encoded;
  if (!ReadBytesFile(dir / "reader_request.cbor", &encoded, err)) {
    return false;
  }
  if (!DecodeReaderRequestCbor(encoded, request, err)) {
    return false;
  }
  std::vector<uint8_t> transcript_bytes;
  if (!ReadBytesFile(dir / "session_transcript.cbor", &transcript_bytes, err)) {
    return false;
  }
  if (transcript_bytes != request->transcript_bytes) {
    if (err != nullptr) {
      *err = "session_transcript.cbor does not match reader_request.cbor";
    }
    return false;
  }
  if (!ReadStringFile(dir / "openid4vp_request.json",
                      &request->openid4vp_request_json, err)) {
    return false;
  }
  return true;
}

bool WriteMdocPresentationDir(const std::filesystem::path& dir,
                              const MdocPresentation& presentation,
                              std::string* err) {
  if (!EnsureDir(dir, err)) {
    return false;
  }
  if (!WriteBytesFile(dir / "proof.bin", presentation.proof_bytes, err) ||
      !WriteStringFile(dir / "claims_count.txt",
                       std::to_string(presentation.claim_aliases.size()), err)) {
    return false;
  }
  for (size_t i = 0; i < presentation.claim_aliases.size(); ++i) {
    if (!WriteStringFile(dir / ("claim_alias_" + std::to_string(i) + ".txt"),
                         presentation.claim_aliases[i], err)) {
      return false;
    }
  }
  if (!WriteStringFile(dir / "disclosed_claims_count.txt",
                       std::to_string(presentation.disclosed_claims.size()), err)) {
    return false;
  }
  for (size_t i = 0; i < presentation.disclosed_claims.size(); ++i) {
    const auto& claim = presentation.disclosed_claims[i];
    if (!WriteStringFile(dir / ("disclosed_alias_" + std::to_string(i) + ".txt"),
                         claim.alias, err) ||
        !WriteStringFile(
            dir / ("disclosed_namespace_" + std::to_string(i) + ".txt"),
            claim.namespace_id, err) ||
        !WriteStringFile(dir / ("disclosed_id_" + std::to_string(i) + ".txt"),
                         claim.element_id, err) ||
        !WriteBytesFile(
            dir / ("disclosed_cbor_value_" + std::to_string(i) + ".bin"),
            claim.cbor_value, err)) {
      return false;
    }
  }
  return true;
}

bool ReadMdocPresentationDir(const std::filesystem::path& dir,
                             MdocPresentation* presentation,
                             std::string* err) {
  std::string claims_count;
  if (!ReadBytesFile(dir / "proof.bin", &presentation->proof_bytes, err) ||
      !ReadStringFile(dir / "claims_count.txt", &claims_count, err)) {
    return false;
  }
  const size_t count = static_cast<size_t>(std::stoul(claims_count));
  presentation->claim_aliases.clear();
  presentation->claim_aliases.resize(count);
  for (size_t i = 0; i < count; ++i) {
    if (!ReadStringFile(dir / ("claim_alias_" + std::to_string(i) + ".txt"),
                        &presentation->claim_aliases[i], err)) {
      return false;
    }
  }
  presentation->disclosed_claims.clear();
  std::string disclosed_count;
  if (ReadStringFile(dir / "disclosed_claims_count.txt", &disclosed_count,
                     nullptr)) {
    const size_t dcount = static_cast<size_t>(std::stoul(disclosed_count));
    presentation->disclosed_claims.resize(dcount);
    for (size_t i = 0; i < dcount; ++i) {
      if (!ReadStringFile(dir / ("disclosed_alias_" + std::to_string(i) + ".txt"),
                          &presentation->disclosed_claims[i].alias, err) ||
          !ReadStringFile(
              dir / ("disclosed_namespace_" + std::to_string(i) + ".txt"),
              &presentation->disclosed_claims[i].namespace_id, err) ||
          !ReadStringFile(dir / ("disclosed_id_" + std::to_string(i) + ".txt"),
                          &presentation->disclosed_claims[i].element_id, err) ||
          !ReadBytesFile(
              dir / ("disclosed_cbor_value_" + std::to_string(i) + ".bin"),
              &presentation->disclosed_claims[i].cbor_value, err)) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace proofs
