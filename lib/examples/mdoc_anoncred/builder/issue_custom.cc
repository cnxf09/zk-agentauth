#include "examples/mdoc_anoncred/builder/issue_custom.h"

#include <array>
#include <vector>

#include "circuits/mdoc/mdoc_attribute_ids.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "examples/mdoc_anoncred/builder/cbor_encode.h"
#include "examples/mdoc_anoncred/builder/input.h"
#include "examples/mdoc_anoncred/shared/crypto.h"
#include "examples/mdoc_anoncred/shared/files.h"
#include "openssl/rand.h"

namespace proofs {
namespace {

struct CustomAttrSpec {
  const char* alias;
  const char* element_id;
  uint64_t digest_id;
};

constexpr CustomAttrSpec kCustomAttrs[] = {
    {"family_name", "family_name", 0},
    {"given_name", "given_name", 1},
    {"birth_date", "birth_date", 2},
    {"issue_date", "issue_date", 3},
    {"expiry_date", "expiry_date", 4},
    {"issuing_country", "issuing_country", 5},
    {"age_over_18", "age_over_18", 6},
};

std::string ToIso8601DateTime(const std::string& date) {
  return date + "T00:00:00Z";
}

std::string PickNowIso8601(const IssuedMdocInput& input) {
  const std::string preferred = "2026-03-09";
  if (input.issue_date <= preferred && preferred <= input.expiry_date) {
    return ToIso8601DateTime(preferred);
  }
  return ToIso8601DateTime(input.issue_date);
}

std::vector<uint8_t> MakeTextCbor(const std::string& text) {
  std::vector<uint8_t> out;
  CborAppendText(&out, text);
  return out;
}

std::vector<uint8_t> MakeDateCbor(const std::string& text) {
  std::vector<uint8_t> out;
  CborAppendTaggedDateText(&out, text);
  return out;
}

std::vector<uint8_t> MakeBoolCbor(bool value) {
  std::vector<uint8_t> out;
  CborAppendBool(&out, value);
  return out;
}

std::vector<uint8_t> RandomBytes(size_t n, std::string* err) {
  std::vector<uint8_t> out(n);
  if (n == 0) {
    return out;
  }
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    if (err != nullptr) {
      *err = "failed to generate random bytes";
    }
    return {};
  }
  return out;
}

std::vector<uint8_t> BuildIssuerSignedItem(uint64_t digest_id,
                                           const std::string& element_id,
                                           const std::vector<uint8_t>& cbor_value,
                                           const std::vector<uint8_t>& random_bytes) {
  std::vector<uint8_t> item;
  CborBeginMap(&item, 4);
  CborAppendText(&item, "digestID");
  CborAppendUnsigned(&item, digest_id);
  CborAppendText(&item, "random");
  CborAppendBytes(&item, random_bytes);
  CborAppendText(&item, "elementIdentifier");
  CborAppendText(&item, element_id);
  CborAppendText(&item, "elementValue");
  item.insert(item.end(), cbor_value.begin(), cbor_value.end());

  std::vector<uint8_t> tagged;
  CborAppendTaggedBytes(&tagged, 24, item);
  return tagged;
}

std::vector<uint8_t> BuildValueDigestsMap(
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& digests) {
  std::vector<uint8_t> out;
  CborBeginMap(&out, 1);
  CborAppendText(&out, kMDLNamespace);
  CborBeginMap(&out, digests.size());
  for (const auto& digest : digests) {
    CborAppendUnsigned(&out, digest.first);
    CborAppendBytes(&out, digest.second);
  }
  return out;
}

std::vector<uint8_t> BuildDeviceKeyInfo(const HolderMdoc& holder, std::string* err) {
  std::vector<uint8_t> pkx;
  std::vector<uint8_t> pky;
  if (!HexToBytes(holder.device_pkx_hex, &pkx, err) ||
      !HexToBytes(holder.device_pky_hex, &pky, err)) {
    return {};
  }
  std::vector<uint8_t> out;
  CborBeginMap(&out, 1);
  CborAppendText(&out, "deviceKey");
  CborBeginMap(&out, 4);
  CborAppendUnsigned(&out, 1);
  CborAppendUnsigned(&out, 2);
  out.push_back(0x20);
  CborAppendUnsigned(&out, 1);
  CborAppendNegative(&out, -1);
  CborAppendBytes(&out, pkx);
  CborAppendNegative(&out, -2);
  CborAppendBytes(&out, pky);
  return out;
}

void AppendTaggedIso8601Text(std::vector<uint8_t>* out, const std::string& value) {
  CborAppendTag(out, 0);
  CborAppendText(out, value);
}

std::vector<uint8_t> BuildValidityInfo(const IssuedMdocInput& input) {
  std::vector<uint8_t> out;
  CborBeginMap(&out, 3);
  CborAppendText(&out, "signed");
  AppendTaggedIso8601Text(&out, ToIso8601DateTime(input.issue_date));
  CborAppendText(&out, "validFrom");
  AppendTaggedIso8601Text(&out, ToIso8601DateTime(input.issue_date));
  CborAppendText(&out, "validUntil");
  AppendTaggedIso8601Text(&out, ToIso8601DateTime(input.expiry_date));
  return out;
}

std::vector<uint8_t> BuildTaggedMso(
    const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& digests,
    const HolderMdoc& holder, const IssuedMdocInput& input, std::string* err) {
  const std::vector<uint8_t> value_digests = BuildValueDigestsMap(digests);
  const std::vector<uint8_t> device_key_info = BuildDeviceKeyInfo(holder, err);
  const std::vector<uint8_t> validity_info = BuildValidityInfo(input);
  if (device_key_info.empty()) {
    return {};
  }

  std::vector<uint8_t> inner;
  CborBeginMap(&inner, 6);
  CborAppendText(&inner, "version");
  CborAppendText(&inner, "1.0");
  CborAppendText(&inner, "digestAlgorithm");
  CborAppendText(&inner, "SHA-256");
  CborAppendText(&inner, "docType");
  CborAppendText(&inner, kMDLDocType);
  CborAppendText(&inner, "validityInfo");
  inner.insert(inner.end(), validity_info.begin(), validity_info.end());
  CborAppendText(&inner, "deviceKeyInfo");
  inner.insert(inner.end(), device_key_info.begin(), device_key_info.end());
  CborAppendText(&inner, "valueDigests");
  inner.insert(inner.end(), value_digests.begin(), value_digests.end());

  std::vector<uint8_t> tagged;
  CborAppendTag(&tagged, 24);
  tagged.push_back(0x59);
  tagged.push_back(static_cast<uint8_t>((inner.size() >> 8) & 0xff));
  tagged.push_back(static_cast<uint8_t>(inner.size() & 0xff));
  tagged.insert(tagged.end(), inner.begin(), inner.end());
  return tagged;
}

std::vector<uint8_t> BuildIssuerAuth(const std::vector<uint8_t>& tagged_mso,
                                     const std::string& issuer_sk_hex,
                                     std::string* err) {
  std::vector<uint8_t> digest_input = {0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61,
                                       0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xA1,
                                       0x01, 0x26, 0x40, 0x59};
  digest_input.push_back(static_cast<uint8_t>((tagged_mso.size() >> 8) & 0xff));
  digest_input.push_back(static_cast<uint8_t>(tagged_mso.size() & 0xff));
  digest_input.insert(digest_input.end(), tagged_mso.begin(), tagged_mso.end());

  std::vector<uint8_t> digest;
  Sha256Digest(digest_input.data(), digest_input.size(), &digest);
  std::vector<uint8_t> sig_rs;
  if (!SignSha256DigestP256(issuer_sk_hex, digest, &sig_rs, err)) {
    return {};
  }

  std::vector<uint8_t> out;
  CborBeginArray(&out, 4);
  CborAppendBytes(&out, std::vector<uint8_t>{0xA1, 0x01, 0x26});
  CborBeginMap(&out, 0);
  CborAppendBytes(&out, tagged_mso);
  CborAppendBytes(&out, sig_rs);
  return out;
}

std::vector<uint8_t> BuildDeviceSignaturePlaceholder() {
  std::vector<uint8_t> out;
  CborBeginArray(&out, 4);
  CborAppendBytes(&out, std::vector<uint8_t>{0xA1, 0x01, 0x26});
  CborBeginMap(&out, 0);
  CborAppendNull(&out);
  CborAppendBytes(&out, std::vector<uint8_t>(64, 0));
  return out;
}

std::vector<uint8_t> BuildDeviceResponse(
    const std::vector<std::vector<uint8_t>>& issuer_signed_items,
    const std::vector<uint8_t>& issuer_auth) {
  const std::vector<uint8_t> device_signature = BuildDeviceSignaturePlaceholder();
  std::vector<uint8_t> out;
  CborBeginMap(&out, 2);
  CborAppendText(&out, "version");
  CborAppendText(&out, "1.0");
  CborAppendText(&out, "documents");
  CborBeginArray(&out, 1);
  CborBeginMap(&out, 3);
  CborAppendText(&out, "docType");
  CborAppendText(&out, kMDLDocType);
  CborAppendText(&out, "issuerSigned");
  CborBeginMap(&out, 2);
  CborAppendText(&out, "nameSpaces");
  CborBeginMap(&out, 1);
  CborAppendText(&out, kMDLNamespace);
  CborBeginArray(&out, issuer_signed_items.size());
  for (const auto& item : issuer_signed_items) {
    out.insert(out.end(), item.begin(), item.end());
  }
  CborAppendText(&out, "issuerAuth");
  out.insert(out.end(), issuer_auth.begin(), issuer_auth.end());
  CborAppendText(&out, "deviceSigned");
  CborBeginMap(&out, 1);
  CborAppendText(&out, "deviceAuth");
  CborBeginMap(&out, 1);
  CborAppendText(&out, "deviceSignature");
  out.insert(out.end(), device_signature.begin(), device_signature.end());
  return out;
}

}  // namespace

bool BuildCustomMdoc(const IssuedMdocInput& input, HolderMdoc* holder,
                     MdocIssuerPublicBundle* issuer_public, std::string* err) {
  holder->example_id = 1000;
  holder->doc_type = kMDLDocType;
  issuer_public->example_id = 1000;
  issuer_public->doc_type = kMDLDocType;
  issuer_public->now_iso8601 = PickNowIso8601(input);
  issuer_public->supported_claim_aliases = {
      "family_name", "given_name",      "birth_date",   "issue_date",
      "expiry_date", "issuing_country", "age_over_18"};

  std::string issuer_sk_hex;
  if (!GenerateP256KeyPair(&issuer_sk_hex, &issuer_public->issuer_pkx_hex,
                           &issuer_public->issuer_pky_hex, err) ||
      !GenerateP256KeyPair(&holder->device_sk_hex, &holder->device_pkx_hex,
                           &holder->device_pky_hex, err)) {
    return false;
  }

  holder->issued_claims = {
      ReaderClaim{"family_name", kMDLNamespace, "family_name",
                  MakeTextCbor(input.family_name)},
      ReaderClaim{"given_name", kMDLNamespace, "given_name",
                  MakeTextCbor(input.given_name)},
      ReaderClaim{"birth_date", kMDLNamespace, "birth_date",
                  MakeDateCbor(input.birth_date)},
      ReaderClaim{"issue_date", kMDLNamespace, "issue_date",
                  MakeDateCbor(input.issue_date)},
      ReaderClaim{"expiry_date", kMDLNamespace, "expiry_date",
                  MakeDateCbor(input.expiry_date)},
      ReaderClaim{"issuing_country", kMDLNamespace, "issuing_country",
                  MakeTextCbor(input.issuing_country)},
      ReaderClaim{"age_over_18", kMDLNamespace, "age_over_18",
                  MakeBoolCbor(input.age_over_18)},
  };

  std::vector<std::vector<uint8_t>> issuer_signed_items;
  std::vector<std::pair<uint64_t, std::vector<uint8_t>>> digests;
  for (size_t i = 0; i < holder->issued_claims.size(); ++i) {
    const auto& claim = holder->issued_claims[i];
    const std::vector<uint8_t> random_bytes = RandomBytes(16, err);
    if (random_bytes.empty()) {
      return false;
    }
    const std::vector<uint8_t> item = BuildIssuerSignedItem(
        kCustomAttrs[i].digest_id, claim.element_id, claim.cbor_value, random_bytes);
    issuer_signed_items.push_back(item);
    std::vector<uint8_t> digest;
    Sha256Digest(item.data(), item.size(), &digest);
    digests.push_back({kCustomAttrs[i].digest_id, digest});
  }

  const std::vector<uint8_t> tagged_mso =
      BuildTaggedMso(digests, *holder, input, err);
  if (tagged_mso.empty()) {
    return false;
  }
  const std::vector<uint8_t> issuer_auth =
      BuildIssuerAuth(tagged_mso, issuer_sk_hex, err);
  if (issuer_auth.empty()) {
    return false;
  }
  holder->device_response_cbor = BuildDeviceResponse(issuer_signed_items, issuer_auth);

  ParsedMdoc parsed;
  MdocProverErrorCode ret = parsed.parse_device_response(
      holder->device_response_cbor.size(), holder->device_response_cbor.data());
  if (ret != MDOC_PROVER_SUCCESS) {
    if (err != nullptr) {
      *err = "custom mdoc parse failed with code " + std::to_string(ret);
    }
    return false;
  }
  return true;
}

bool RunMdocIssueCustomCommand(const std::filesystem::path& out_root,
                               std::string* err) {
  IssuedMdocInput input;
  if (!PromptIssuedMdocInput(&input, err)) {
    return false;
  }

  HolderMdoc holder;
  MdocIssuerPublicBundle issuer_public;
  if (!BuildCustomMdoc(input, &holder, &issuer_public, err)) {
    return false;
  }

  return WriteHolderMdocDir(out_root / "holder", holder, err) &&
         WriteMdocIssuerPublicDir(out_root / "issuer_public", issuer_public, err);
}

}  // namespace proofs
