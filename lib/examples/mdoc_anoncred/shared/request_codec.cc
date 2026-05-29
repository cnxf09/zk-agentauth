#include "examples/mdoc_anoncred/shared/request_codec.h"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "cbor/host_decoder.h"
#include "examples/mdoc_anoncred/shared/crypto.h"
#include "openssl/rand.h"

namespace proofs {
namespace {

void AppendMajorAndCount(std::vector<uint8_t>* out, uint8_t major,
                         size_t count) {
  if (count < 24) {
    out->push_back(static_cast<uint8_t>((major << 5) | count));
    return;
  }
  if (count < 256) {
    out->push_back(static_cast<uint8_t>((major << 5) | 24));
    out->push_back(static_cast<uint8_t>(count));
    return;
  }
  if (count < 65536) {
    out->push_back(static_cast<uint8_t>((major << 5) | 25));
    out->push_back(static_cast<uint8_t>((count >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>(count & 0xff));
    return;
  }
  if (count < (static_cast<size_t>(1) << 32)) {
    out->push_back(static_cast<uint8_t>((major << 5) | 26));
    out->push_back(static_cast<uint8_t>((count >> 24) & 0xff));
    out->push_back(static_cast<uint8_t>((count >> 16) & 0xff));
    out->push_back(static_cast<uint8_t>((count >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>(count & 0xff));
    return;
  }
  out->push_back(static_cast<uint8_t>((major << 5) | 27));
  for (int shift = 56; shift >= 0; shift -= 8) {
    out->push_back(static_cast<uint8_t>((count >> shift) & 0xff));
  }
}

void AppendText(std::vector<uint8_t>* out, const std::string& s) {
  AppendMajorAndCount(out, 3, s.size());
  out->insert(out->end(), s.begin(), s.end());
}

void AppendBytes(std::vector<uint8_t>* out, const std::vector<uint8_t>& bytes) {
  AppendMajorAndCount(out, 2, bytes.size());
  out->insert(out->end(), bytes.begin(), bytes.end());
}

void AppendUnsigned(std::vector<uint8_t>* out, size_t v) {
  AppendMajorAndCount(out, 0, v);
}

bool ExpectText(const std::vector<uint8_t>& doc, const CborDoc* parent,
                const char* key, std::string* out) {
  size_t ndx = 0;
  const CborDoc* node =
      parent->lookup(doc.data(), std::strlen(key), reinterpret_cast<const uint8_t*>(key), ndx);
  if (node == nullptr || node[1].t_ != TEXT) {
    return false;
  }
  out->assign(reinterpret_cast<const char*>(doc.data() + node[1].u_.string.pos),
              node[1].u_.string.len);
  return true;
}

bool ExpectBytes(const std::vector<uint8_t>& doc, const CborDoc* parent,
                 const char* key, std::vector<uint8_t>* out) {
  size_t ndx = 0;
  const CborDoc* node =
      parent->lookup(doc.data(), std::strlen(key), reinterpret_cast<const uint8_t*>(key), ndx);
  if (node == nullptr || node[1].t_ != BYTES) {
    return false;
  }
  out->assign(doc.data() + node[1].u_.string.pos,
              doc.data() + node[1].u_.string.pos + node[1].u_.string.len);
  return true;
}

bool ExpectUnsigned(const std::vector<uint8_t>& doc, const CborDoc* parent,
                    const char* key, size_t* out) {
  size_t ndx = 0;
  const CborDoc* node =
      parent->lookup(doc.data(), std::strlen(key), reinterpret_cast<const uint8_t*>(key), ndx);
  if (node == nullptr || node[1].t_ != UNSIGNED) {
    return false;
  }
  *out = static_cast<size_t>(node[1].u_.u64);
  return true;
}

std::string JsonEscape(const std::string& s) {
  std::ostringstream out;
  for (const unsigned char ch : s) {
    switch (ch) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (ch < 0x20) {
          out << "\\u00";
          const char* hex = "0123456789abcdef";
          out << hex[(ch >> 4) & 0x0f] << hex[ch & 0x0f];
        } else {
          out << static_cast<char>(ch);
        }
        break;
    }
  }
  return out.str();
}

}  // namespace

bool GenerateOpenId4VpSessionTranscript(std::vector<uint8_t>* transcript,
                                        std::string* nonce_hex,
                                        std::string* err) {
  std::vector<uint8_t> nonce(32, 0);
  if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
    if (err != nullptr) {
      *err = "failed to generate OpenID4VP nonce";
    }
    return false;
  }
  *nonce_hex = HexPrefixed(nonce.data(), nonce.size());
  transcript->clear();
  transcript->push_back(0x83);
  transcript->push_back(0xf6);
  transcript->push_back(0xf6);
  transcript->push_back(0x82);
  AppendText(transcript, "OpenID4VPDCAPIHandover");
  AppendBytes(transcript, nonce);
  return true;
}

std::string BuildOpenId4VpRequestJson(const ReaderRequest& request) {
  std::ostringstream out;
  const std::string state =
      request.state.empty() ? request.nonce_hex : request.state;
  out << "{\n"
      << "  \"response_type\": \"vp_token\",\n"
      << "  \"client_id\": \"" << JsonEscape(request.client_id) << "\",\n"
      << "  \"response_mode\": \"direct_post\",\n"
      << "  \"response_uri\": \"" << JsonEscape(request.response_uri) << "\",\n"
      << "  \"nonce\": \"" << JsonEscape(request.nonce_hex) << "\",\n"
      << "  \"state\": \"" << JsonEscape(state) << "\",\n"
      << "  \"doc_type\": \"" << JsonEscape(request.doc_type) << "\",\n"
      << "  \"presentation_definition\": {\n"
      << "    \"id\": \"zkaa-mdoc-presentation\",\n"
      << "    \"input_descriptors\": [\n"
      << "      {\n"
      << "        \"id\": \"zkaa-ligero-presentation\",\n"
      << "        \"name\": \"ZK-AgentAuth delegated presentation\",\n"
      << "        \"format\": {\"zkaa+ligero\": {\"alg\": [\"P-256+Ligero\"]}},\n"
      << "        \"constraints\": {\n"
      << "          \"fields\": [\n";
  for (size_t i = 0; i < request.claims.size(); ++i) {
    const ReaderClaim& claim = request.claims[i];
    out << "            {\"id\": \"claim-" << JsonEscape(claim.alias)
        << "\", \"path\": [\"$.claims." << JsonEscape(claim.alias)
        << "\", \"$.disclosed_claims[?(@.alias=='" << JsonEscape(claim.alias)
        << "')]\"], \"purpose\": \"Prove " << JsonEscape(claim.alias) << "\"}";
    if (i + 1 != request.claims.size()) {
      out << ",";
    }
    out << "\n";
  }
  out << "          ]\n"
      << "        }\n"
      << "      }\n"
      << "    ]\n"
      << "  },\n"
      << "  \"claims\": [\n";
  for (size_t i = 0; i < request.claims.size(); ++i) {
    const ReaderClaim& claim = request.claims[i];
    out << "    {\"alias\": \"" << JsonEscape(claim.alias) << "\", "
        << "\"namespace\": \"" << JsonEscape(claim.namespace_id) << "\", "
        << "\"element_identifier\": \"" << JsonEscape(claim.element_id) << "\"}";
    if (i + 1 != request.claims.size()) {
      out << ",";
    }
    out << "\n";
  }
  out << "  ]\n"
      << "}\n";
  return out.str();
}

bool EncodeReaderRequestCbor(const ReaderRequest& request,
                             std::vector<uint8_t>* out, std::string* err) {
  if (request.claims.empty() || request.num_attributes != request.claims.size()) {
    if (err != nullptr) {
      *err = "invalid request claim count";
    }
    return false;
  }
  out->clear();
  AppendMajorAndCount(out, 5, 12);

  AppendText(out, "zkSystem");
  AppendText(out, request.zk_system);
  AppendText(out, "circuitHash");
  AppendText(out, request.circuit_hash);
  AppendText(out, "numAttributes");
  AppendUnsigned(out, request.num_attributes);
  AppendText(out, "circuit");
  AppendBytes(out, request.circuit_bytes);
  AppendText(out, "docType");
  AppendText(out, request.doc_type);
  AppendText(out, "sessionTranscript");
  AppendBytes(out, request.transcript_bytes);
  AppendText(out, "now");
  AppendText(out, request.now_iso8601);
  AppendText(out, "clientId");
  AppendText(out, request.client_id);
  AppendText(out, "responseUri");
  AppendText(out, request.response_uri);
  AppendText(out, "nonceHex");
  AppendText(out, request.nonce_hex);
  AppendText(out, "state");
  AppendText(out, request.state.empty() ? request.nonce_hex : request.state);
  AppendText(out, "claims");
  AppendMajorAndCount(out, 4, request.claims.size());
  for (const ReaderClaim& claim : request.claims) {
    AppendMajorAndCount(out, 5, 4);
    AppendText(out, "alias");
    AppendText(out, claim.alias);
    AppendText(out, "namespace");
    AppendText(out, claim.namespace_id);
    AppendText(out, "elementIdentifier");
    AppendText(out, claim.element_id);
    AppendText(out, "cborValue");
    AppendBytes(out, claim.cbor_value);
  }
  return true;
}

bool DecodeReaderRequestCbor(const std::vector<uint8_t>& encoded,
                             ReaderRequest* request, std::string* err) {
  size_t pos = 0;
  CborDoc root;
  if (!root.decode(encoded.data(), encoded.size(), pos, 0)) {
    if (err != nullptr) {
      *err = "failed to decode reader_request.cbor root";
    }
    return false;
  }
  if (pos != encoded.size()) {
    if (err != nullptr) {
      *err = "reader_request.cbor decoded prefix only: " + std::to_string(pos) +
             "/" + std::to_string(encoded.size());
    }
    return false;
  }
  if (root.t_ != MAP) {
    if (err != nullptr) {
      *err = "reader_request.cbor root is not a map";
    }
    return false;
  }
  if (!ExpectText(encoded, &root, "zkSystem", &request->zk_system) ||
      !ExpectText(encoded, &root, "circuitHash", &request->circuit_hash) ||
      !ExpectUnsigned(encoded, &root, "numAttributes", &request->num_attributes) ||
      !ExpectBytes(encoded, &root, "circuit", &request->circuit_bytes) ||
      !ExpectText(encoded, &root, "docType", &request->doc_type) ||
      !ExpectBytes(encoded, &root, "sessionTranscript", &request->transcript_bytes) ||
      !ExpectText(encoded, &root, "now", &request->now_iso8601) ||
      !ExpectText(encoded, &root, "clientId", &request->client_id) ||
      !ExpectText(encoded, &root, "responseUri", &request->response_uri) ||
      !ExpectText(encoded, &root, "nonceHex", &request->nonce_hex)) {
    if (err != nullptr) {
      *err = "reader_request.cbor missing required fields";
    }
    return false;
  }
  if (!ExpectText(encoded, &root, "state", &request->state)) {
    request->state = request->nonce_hex;
  }
  size_t ndx = 0;
  const CborDoc* claims_key =
      root.lookup(encoded.data(), 6, reinterpret_cast<const uint8_t*>("claims"), ndx);
  if (claims_key == nullptr || claims_key[1].t_ != ARRAY) {
    if (err != nullptr) {
      *err = "reader_request.cbor missing claims";
    }
    return false;
  }
  request->claims.clear();
  for (size_t i = 0; i < claims_key[1].u_.items.nchildren; ++i) {
    const CborDoc* item = claims_key[1].index(i);
    if (item == nullptr || item->t_ != MAP) {
      if (err != nullptr) {
        *err = "invalid claim entry in reader_request.cbor";
      }
      return false;
    }
    ReaderClaim claim;
    if (!ExpectText(encoded, item, "alias", &claim.alias) ||
        !ExpectText(encoded, item, "namespace", &claim.namespace_id) ||
        !ExpectText(encoded, item, "elementIdentifier", &claim.element_id) ||
        !ExpectBytes(encoded, item, "cborValue", &claim.cbor_value)) {
      if (err != nullptr) {
        *err = "invalid claim fields in reader_request.cbor";
      }
      return false;
    }
    request->claims.push_back(claim);
  }
  request->request_cbor = encoded;
  request->openid4vp_request_json = BuildOpenId4VpRequestJson(*request);
  return request->claims.size() == request->num_attributes;
}

bool ComputeDeviceAuthenticationDigest(const std::vector<uint8_t>& transcript,
                                       const std::string& doc_type,
                                       std::vector<uint8_t>* digest,
                                       std::string* err) {
  if (doc_type.size() >= 256) {
    if (err != nullptr) {
      *err = "docType too long";
    }
    return false;
  }
  std::vector<uint8_t> doc_type_cbor;
  AppendText(&doc_type_cbor, doc_type);

  std::vector<uint8_t> da = {
      0x84, 0x74, 'D', 'e', 'v', 'i', 'c', 'e', 'A', 'u', 't',
      'h',  'e',  'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n',
  };
  da.insert(da.end(), transcript.begin(), transcript.end());
  da.insert(da.end(), doc_type_cbor.begin(), doc_type_cbor.end());
  da.push_back(0xD8);
  da.push_back(0x18);
  da.push_back(0x41);
  da.push_back(0xA0);

  std::vector<uint8_t> cose1 = {0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61,
                                0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xA1,
                                0x01, 0x26, 0x40};
  const size_t tagged_len = da.size() + (da.size() < 256 ? 4 : 5);
  AppendMajorAndCount(&cose1, 2, tagged_len);
  cose1.push_back(0xD8);
  cose1.push_back(0x18);
  AppendMajorAndCount(&cose1, 2, da.size());
  cose1.insert(cose1.end(), da.begin(), da.end());
  Sha256Digest(cose1.data(), cose1.size(), digest);
  return true;
}

}  // namespace proofs
