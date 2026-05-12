#include "examples/delegation_demo/shared/delegation_revocation.h"

#include <array>
#include <fstream>
#include <iterator>
#include <sstream>
#include <vector>

#include "examples/delegation_demo/shared/delegation_crypto.h"
#include "examples/mdoc_anoncred/shared/crypto.h"

namespace proofs {
namespace {

std::string ExtractJsonString(const std::string& json, const std::string& key) {
  const std::string key_token = "\"" + key + "\"";
  const size_t kpos = json.find(key_token);
  if (kpos == std::string::npos) return "";
  size_t cur = kpos + key_token.size();
  while (cur < json.size() &&
         (json[cur] == ' ' || json[cur] == ':' || json[cur] == '\n' ||
          json[cur] == '\r' || json[cur] == '\t')) {
    ++cur;
  }
  if (cur >= json.size() || json[cur] != '"') return "";
  const size_t start = cur + 1;
  const size_t end = json.find('"', start);
  if (end == std::string::npos) return "";
  return json.substr(start, end - start);
}

bool ExtractJsonBool(const std::string& json, const std::string& key,
                     bool* out) {
  const std::string key_token = "\"" + key + "\"";
  const size_t kpos = json.find(key_token);
  if (kpos == std::string::npos) return false;
  size_t cur = kpos + key_token.size();
  while (cur < json.size() &&
         (json[cur] == ' ' || json[cur] == ':' || json[cur] == '\n' ||
          json[cur] == '\r' || json[cur] == '\t')) {
    ++cur;
  }
  if (json.compare(cur, 4, "true") == 0) {
    *out = true;
    return true;
  }
  if (json.compare(cur, 5, "false") == 0) {
    *out = false;
    return true;
  }
  return false;
}

bool ExtractJsonUint64(const std::string& json, const std::string& key,
                       uint64_t* out) {
  const std::string key_token = "\"" + key + "\"";
  const size_t kpos = json.find(key_token);
  if (kpos == std::string::npos) return false;
  size_t cur = kpos + key_token.size();
  while (cur < json.size() &&
         (json[cur] == ' ' || json[cur] == ':' || json[cur] == '\n' ||
          json[cur] == '\r' || json[cur] == '\t')) {
    ++cur;
  }
  size_t end = cur;
  while (end < json.size() && json[end] >= '0' && json[end] <= '9') {
    ++end;
  }
  if (end == cur) return false;
  try {
    *out = static_cast<uint64_t>(std::stoull(json.substr(cur, end - cur)));
    return true;
  } catch (...) {
    return false;
  }
}

void AppendUint64Be(uint64_t v, std::vector<uint8_t>* out) {
  for (int i = 7; i >= 0; --i) {
    out->push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
  }
}

bool ComputeStatusDigestHex(const DelegationRevocationStatus& status,
                            std::string* digest_hex,
                            std::string* err) {
  std::vector<uint8_t> delegation_id;
  if (!HexToBytes(status.delegation_id_hex, &delegation_id, err)) {
    return false;
  }
  if (delegation_id.size() != 32) {
    if (err != nullptr) *err = "delegation_id must be 32 bytes";
    return false;
  }
  if (status.expires.size() != 20) {
    if (err != nullptr) *err = "revocation status expires must be 20-byte ISO 8601 UTC";
    return false;
  }

  static constexpr std::array<uint8_t, 8> kDomain = {
      'Z', 'K', 'D', 'E', 'L', 'S', 'T', '1'};
  std::vector<uint8_t> msg;
  msg.reserve(kDomain.size() + delegation_id.size() + 8 +
              status.expires.size() + 1);
  msg.insert(msg.end(), kDomain.begin(), kDomain.end());
  msg.insert(msg.end(), delegation_id.begin(), delegation_id.end());
  AppendUint64Be(status.epoch, &msg);
  msg.insert(msg.end(), status.expires.begin(), status.expires.end());
  msg.push_back(status.revoked ? 1 : 0);

  std::vector<uint8_t> digest;
  if (!Sha256Digest(msg.data(), msg.size(), &digest)) {
    if (err != nullptr) *err = "SHA256 computation failed";
    return false;
  }
  *digest_hex = HexPrefixed(digest.data(), digest.size());
  return true;
}

}  // namespace

bool ComputeDelegationIdHex(const std::string& delegation_msg_hex,
                            std::string* delegation_id_hex,
                            std::string* err) {
  std::vector<uint8_t> delegation_msg;
  if (!HexToBytes(delegation_msg_hex, &delegation_msg, err)) {
    return false;
  }
  if (delegation_msg.size() != 32) {
    if (err != nullptr) *err = "delegation message must be 32 bytes";
    return false;
  }
  static constexpr std::array<uint8_t, 8> kDomain = {
      'Z', 'K', 'D', 'E', 'L', 'I', 'D', '1'};
  std::vector<uint8_t> msg;
  msg.reserve(kDomain.size() + delegation_msg.size());
  msg.insert(msg.end(), kDomain.begin(), kDomain.end());
  msg.insert(msg.end(), delegation_msg.begin(), delegation_msg.end());

  std::vector<uint8_t> digest;
  if (!Sha256Digest(msg.data(), msg.size(), &digest)) {
    if (err != nullptr) *err = "SHA256 computation failed";
    return false;
  }
  *delegation_id_hex = HexPrefixed(digest.data(), digest.size());
  return true;
}

bool CreateDelegationRevocationStatus(
    const std::string& device_sk_hex,
    const std::string& delegation_msg_hex,
    uint64_t epoch,
    const std::string& expires,
    bool revoked,
    DelegationRevocationStatus* status,
    std::string* err) {
  status->epoch = epoch;
  status->expires = expires;
  status->revoked = revoked;
  if (!ComputeDelegationIdHex(delegation_msg_hex, &status->delegation_id_hex,
                              err)) {
    return false;
  }

  std::string digest_hex;
  if (!ComputeStatusDigestHex(*status, &digest_hex, err)) {
    return false;
  }
  if (!SignDelegation(device_sk_hex, digest_hex, &status->sig_hex, err)) {
    return false;
  }
  return true;
}

bool VerifyDelegationRevocationStatus(
    const DelegationRevocationStatus& status,
    const std::string& device_pkx_hex,
    const std::string& device_pky_hex,
    const std::string& delegation_msg_hex,
    const std::string& now_iso8601,
    std::string* err) {
  std::string expected_id;
  if (!ComputeDelegationIdHex(delegation_msg_hex, &expected_id, err)) {
    return false;
  }
  if (status.delegation_id_hex != expected_id) {
    if (err != nullptr) *err = "delegation revocation status id mismatch";
    return false;
  }
  std::string digest_hex;
  if (!ComputeStatusDigestHex(status, &digest_hex, err)) {
    return false;
  }
  if (!VerifyDelegationSig(device_pkx_hex, device_pky_hex, digest_hex,
                           status.sig_hex, err)) {
    if (err != nullptr) *err = "revocation status signature invalid: " + *err;
    return false;
  }
  if (status.revoked) {
    if (err != nullptr) *err = "delegation is revoked";
    return false;
  }
  if (status.expires <= now_iso8601) {
    if (err != nullptr) {
      *err = "revocation status expired (expires=" + status.expires +
             ", now=" + now_iso8601 + ")";
    }
    return false;
  }
  return true;
}

bool WriteDelegationRevocationStatusJson(
    const std::filesystem::path& path,
    const DelegationRevocationStatus& status,
    std::string* err) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (err != nullptr) {
      *err = "failed to create directory: " + path.parent_path().string() +
             ": " + ec.message();
    }
    return false;
  }
  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    if (err != nullptr) *err = "failed to open: " + path.string();
    return false;
  }
  out << "{\n";
  out << "  \"delegation_id\": \"" << status.delegation_id_hex << "\",\n";
  out << "  \"epoch\": " << status.epoch << ",\n";
  out << "  \"expires\": \"" << status.expires << "\",\n";
  out << "  \"revoked\": " << (status.revoked ? "true" : "false") << ",\n";
  out << "  \"sig\": \"" << status.sig_hex << "\"\n";
  out << "}\n";
  return out.good();
}

bool WritePublicDelegationRevocationStatusJson(
    const std::filesystem::path& path,
    const DelegationRevocationStatus& status,
    std::string* err) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (err != nullptr) {
      *err = "failed to create directory: " + path.parent_path().string() +
             ": " + ec.message();
    }
    return false;
  }
  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    if (err != nullptr) *err = "failed to open: " + path.string();
    return false;
  }
  out << "{\n";
  out << "  \"delegation_id\": \"" << status.delegation_id_hex << "\",\n";
  out << "  \"epoch\": " << status.epoch << ",\n";
  out << "  \"expires\": \"" << status.expires << "\",\n";
  out << "  \"revoked\": " << (status.revoked ? "true" : "false") << "\n";
  out << "}\n";
  return out.good();
}

bool ReadDelegationRevocationStatusJson(
    const std::filesystem::path& path,
    DelegationRevocationStatus* status,
    std::string* err) {
  std::ifstream in(path);
  if (!in) {
    if (err != nullptr) *err = "failed to open: " + path.string();
    return false;
  }
  const std::string json((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
  status->delegation_id_hex = ExtractJsonString(json, "delegation_id");
  status->expires = ExtractJsonString(json, "expires");
  status->sig_hex = ExtractJsonString(json, "sig");
  if (!ExtractJsonUint64(json, "epoch", &status->epoch) ||
      !ExtractJsonBool(json, "revoked", &status->revoked) ||
      status->delegation_id_hex.empty() || status->expires.empty()) {
    if (err != nullptr) {
      *err = "delegation_revocation_status.json missing required fields";
    }
    return false;
  }
  return true;
}

}  // namespace proofs
