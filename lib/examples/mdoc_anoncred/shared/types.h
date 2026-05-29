#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_TYPES_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_TYPES_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace proofs {

struct ReaderClaim {
  std::string alias;
  std::string namespace_id;
  std::string element_id;
  std::vector<uint8_t> cbor_value;
};

struct HolderMdoc {
  uint32_t example_id = 0;
  std::string doc_type;
  std::vector<uint8_t> device_response_cbor;
  std::string device_sk_hex;
  std::string device_pkx_hex;
  std::string device_pky_hex;
  std::vector<ReaderClaim> issued_claims;
};

struct MdocIssuerPublicBundle {
  uint32_t example_id = 0;
  std::string issuer_pkx_hex;
  std::string issuer_pky_hex;
  std::string doc_type;
  std::string now_iso8601;
  std::string client_id = "mdoc-anoncred-demo";
  std::string response_uri = "https://verifier.example/callback";
  std::vector<std::string> supported_claim_aliases;
};

struct ReaderRequest {
  std::string zk_system;
  std::string circuit_hash;
  size_t num_attributes = 0;
  std::vector<uint8_t> circuit_bytes;
  std::string doc_type;
  std::vector<uint8_t> transcript_bytes;
  std::string now_iso8601;
  std::string client_id;
  std::string response_uri;
  std::string nonce_hex;
  std::string state;
  std::vector<uint8_t> request_cbor;
  std::string openid4vp_request_json;
  std::vector<ReaderClaim> claims;
};

struct MdocPresentation {
  std::vector<uint8_t> proof_bytes;
  std::vector<std::string> claim_aliases;
  std::vector<ReaderClaim> disclosed_claims;
};

struct MdocVerificationResult {
  bool ok = false;
  std::string message;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_TYPES_H_
