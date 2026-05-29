#include "examples/mdoc_anoncred/shared/mdoc_demo.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "circuits/mdoc/mdoc_examples.h"
#include "circuits/mdoc/mdoc_test_attributes.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "examples/mdoc_anoncred/shared/crypto.h"
#include "examples/mdoc_anoncred/shared/request_codec.h"

namespace proofs {
namespace {

bool IsSupportedAlias(const std::vector<std::string>& aliases,
                      const std::string& alias) {
  return std::find(aliases.begin(), aliases.end(), alias) != aliases.end();
}

const RequestedAttribute* ClaimAliasToRequestedAttribute(const std::string& alias,
                                                         std::string* err) {
  if (alias == "age_over_18") {
    return &test::age_over_18;
  }
  if (alias == "family_name_mustermann") {
    return &test::familyname_mustermann;
  }
  if (alias == "birth_date_1971_09_01") {
    return &test::birthdate_1971_09_01;
  }
  if (alias == "height_175") {
    return &test::height_175;
  }
  if (err != nullptr) {
    *err = "unsupported mdoc claim alias: " + alias;
  }
  return nullptr;
}

ReaderClaim ToReaderClaim(const std::string& alias, const RequestedAttribute& attr) {
  ReaderClaim claim;
  claim.alias = alias;
  claim.namespace_id.assign(reinterpret_cast<const char*>(attr.namespace_id),
                            attr.namespace_len);
  claim.element_id.assign(reinterpret_cast<const char*>(attr.id), attr.id_len);
  claim.cbor_value.assign(attr.cbor_value, attr.cbor_value + attr.cbor_value_len);
  return claim;
}

ReaderClaim MakeGenericClaim(const std::string& alias) {
  ReaderClaim claim;
  claim.alias = alias;
  claim.namespace_id = kMDLNamespace;
  claim.element_id = alias;
  return claim;
}

const ReaderClaim* FindClaimByAlias(const std::vector<ReaderClaim>& claims,
                                    const std::string& alias) {
  for (const ReaderClaim& claim : claims) {
    if (claim.alias == alias) {
      return &claim;
    }
  }
  return nullptr;
}

bool ResolveClaimValues(const std::vector<ReaderClaim>& claims_with_optional_values,
                        const std::vector<ReaderClaim>& available_claims,
                        std::vector<ReaderClaim>* resolved,
                        std::string* err) {
  resolved->clear();
  resolved->reserve(claims_with_optional_values.size());
  for (const ReaderClaim& requested : claims_with_optional_values) {
    if (!requested.cbor_value.empty()) {
      resolved->push_back(requested);
      continue;
    }
    const ReaderClaim* claim = FindClaimByAlias(available_claims, requested.alias);
    if (claim == nullptr) {
      if (err != nullptr) {
        *err = "missing disclosed claim value for alias: " + requested.alias;
      }
      return false;
    }
    if (claim->namespace_id != requested.namespace_id ||
        claim->element_id != requested.element_id) {
      if (err != nullptr) {
        *err = "disclosed claim metadata mismatch for alias: " + requested.alias;
      }
      return false;
    }
    resolved->push_back(*claim);
  }
  return true;
}

void FillRequestedAttribute(const ReaderClaim& claim, RequestedAttribute* out) {
  std::memset(out, 0, sizeof(*out));
  std::memcpy(out->namespace_id, claim.namespace_id.data(), claim.namespace_id.size());
  std::memcpy(out->id, claim.element_id.data(), claim.element_id.size());
  std::memcpy(out->cbor_value, claim.cbor_value.data(), claim.cbor_value.size());
  out->namespace_len = claim.namespace_id.size();
  out->id_len = claim.element_id.size();
  out->cbor_value_len = claim.cbor_value.size();
}

bool BuildRequestedAttributes(const ReaderRequest& request,
                              std::vector<RequestedAttribute>* out,
                              std::string* err) {
  if (request.claims.empty() || request.claims.size() > 2) {
    if (err != nullptr) {
      *err = "mdoc demo supports 1 or 2 claims";
    }
    return false;
  }
  out->resize(request.claims.size());
  for (size_t i = 0; i < request.claims.size(); ++i) {
    if (request.claims[i].namespace_id.size() > sizeof((*out)[i].namespace_id) ||
        request.claims[i].element_id.size() > sizeof((*out)[i].id) ||
        request.claims[i].cbor_value.size() > sizeof((*out)[i].cbor_value)) {
      if (err != nullptr) {
        *err = "claim field too long for RequestedAttribute";
      }
      return false;
    }
    FillRequestedAttribute(request.claims[i], &(*out)[i]);
  }
  return true;
}

const ZkSpecStruct* FindRequestSpec(const ReaderRequest& request,
                                    std::string* err) {
  const ZkSpecStruct* spec = find_zk_spec(request.zk_system.c_str(),
                                          request.circuit_hash.c_str());
  if (spec == nullptr) {
    if (err != nullptr) {
      *err = "failed to resolve zk spec for request";
    }
    return nullptr;
  }
  if (spec->num_attributes != request.num_attributes) {
    if (err != nullptr) {
      *err = "request num_attributes does not match zk spec";
    }
    return nullptr;
  }
  return spec;
}

bool OverwriteFixedBytes(std::vector<uint8_t>* doc, size_t pos,
                         const std::vector<uint8_t>& value, size_t expected_len,
                         std::string* err) {
  if (value.size() != expected_len || pos + expected_len > doc->size()) {
    if (err != nullptr) {
      *err = "failed to patch fixed-width bytes into DeviceResponse";
    }
    return false;
  }
  std::copy(value.begin(), value.end(), doc->begin() + pos);
  return true;
}

bool PatchDeviceKeyAndIssuerSignature(const std::string& issuer_sk_hex,
                                      HolderMdoc* holder, std::string* err) {
  ParsedMdoc parsed;
  MdocProverErrorCode ret = parsed.parse_device_response(
      holder->device_response_cbor.size(), holder->device_response_cbor.data());
  if (ret != MDOC_PROVER_SUCCESS) {
    if (err != nullptr) {
      *err = "failed to parse template DeviceResponse";
    }
    return false;
  }

  std::vector<uint8_t> pkx;
  std::vector<uint8_t> pky;
  if (!HexToBytes(holder->device_pkx_hex, &pkx, err) ||
      !HexToBytes(holder->device_pky_hex, &pky, err)) {
    return false;
  }
  const size_t mso_base = parsed.t_mso_.pos + 5;
  if (!OverwriteFixedBytes(&holder->device_response_cbor,
                           mso_base + parsed.dev_key_pkx_.pos, pkx, 32, err) ||
      !OverwriteFixedBytes(&holder->device_response_cbor,
                           mso_base + parsed.dev_key_pky_.pos, pky, 32, err)) {
    return false;
  }

  ParsedMdoc reparsed;
  ret = reparsed.parse_device_response(holder->device_response_cbor.size(),
                                       holder->device_response_cbor.data());
  if (ret != MDOC_PROVER_SUCCESS) {
    if (err != nullptr) {
      *err = "failed to reparse patched DeviceResponse";
    }
    return false;
  }
  std::vector<uint8_t> digest;
  Sha256Digest(reparsed.tagged_mso_bytes_.data(), reparsed.tagged_mso_bytes_.size(),
               &digest);
  std::vector<uint8_t> issuer_sig;
  if (!SignSha256DigestP256(issuer_sk_hex, digest, &issuer_sig, err)) {
    return false;
  }
  if (!OverwriteFixedBytes(&holder->device_response_cbor, reparsed.sig_.pos,
                           issuer_sig, reparsed.sig_.len, err)) {
    return false;
  }
  return true;
}

bool PatchDynamicDeviceSignature(const HolderMdoc& holder, const ReaderRequest& request,
                                 std::vector<uint8_t>* patched_response,
                                 std::string* err) {
  *patched_response = holder.device_response_cbor;
  ParsedMdoc parsed;
  MdocProverErrorCode ret =
      parsed.parse_device_response(patched_response->size(), patched_response->data());
  if (ret != MDOC_PROVER_SUCCESS) {
    if (err != nullptr) {
      *err = "failed to parse holder DeviceResponse";
    }
    return false;
  }
  std::vector<uint8_t> digest;
  if (!ComputeDeviceAuthenticationDigest(request.transcript_bytes, request.doc_type,
                                         &digest, err)) {
    return false;
  }
  std::vector<uint8_t> device_sig;
  if (!SignSha256DigestP256(holder.device_sk_hex, digest, &device_sig, err)) {
    return false;
  }
  return OverwriteFixedBytes(patched_response, parsed.dksig_.pos, device_sig,
                             parsed.dksig_.len, err);
}

}  // namespace

bool MaterializeMdocExample(uint32_t example_id, HolderMdoc* holder,
                            MdocIssuerPublicBundle* issuer_public,
                            std::string* err) {
  if (example_id >= sizeof(mdoc_tests) / sizeof(mdoc_tests[0])) {
    if (err != nullptr) {
      *err = "unknown mdoc example id: " + std::to_string(example_id);
    }
    return false;
  }
  const MdocTests& test = mdoc_tests[example_id];
  holder->example_id = example_id;
  holder->doc_type = test.doc_type;
  holder->device_response_cbor.assign(test.mdoc, test.mdoc + test.mdoc_size);

  std::string issuer_sk_hex;
  if (!GenerateP256KeyPair(&issuer_sk_hex, &issuer_public->issuer_pkx_hex,
                           &issuer_public->issuer_pky_hex, err) ||
      !GenerateP256KeyPair(&holder->device_sk_hex, &holder->device_pkx_hex,
                           &holder->device_pky_hex, err) ||
      !PatchDeviceKeyAndIssuerSignature(issuer_sk_hex, holder, err)) {
    return false;
  }

  ParsedMdoc parsed;
  MdocProverErrorCode parse_ret =
      parsed.parse_device_response(holder->device_response_cbor.size(),
                                   holder->device_response_cbor.data());
  if (parse_ret != MDOC_PROVER_SUCCESS) {
    if (err != nullptr) {
      *err = "failed to parse patched DeviceResponse";
    }
    return false;
  }

  issuer_public->example_id = example_id;
  issuer_public->doc_type = test.doc_type;
  issuer_public->now_iso8601 = reinterpret_cast<const char*>(test.now);
  if (example_id == 0) {
    holder->issued_claims = {
        ToReaderClaim("age_over_18", test::age_over_18),
    };
    issuer_public->supported_claim_aliases = {"age_over_18"};
  } else if (example_id == 3) {
    holder->issued_claims = {
        ToReaderClaim("age_over_18", test::age_over_18),
        ToReaderClaim("family_name", test::familyname_mustermann),
        ToReaderClaim("birth_date", test::birthdate_1971_09_01),
        ToReaderClaim("height", test::height_175),
    };
    issuer_public->supported_claim_aliases = {
        "age_over_18", "family_name_mustermann", "birth_date_1971_09_01",
        "height_175"};
  }
  return true;
}

bool BuildReaderClaim(const std::string& claim_alias, ReaderClaim* claim,
                      std::string* err) {
  if (claim_alias == "family_name" || claim_alias == "given_name" ||
      claim_alias == "birth_date" || claim_alias == "issue_date" ||
      claim_alias == "expiry_date" || claim_alias == "issuing_country" ||
      claim_alias == "height") {
    *claim = MakeGenericClaim(claim_alias);
    return true;
  }
  const RequestedAttribute* attr = ClaimAliasToRequestedAttribute(claim_alias, err);
  if (attr == nullptr) {
    return false;
  }
  *claim = ToReaderClaim(claim_alias, *attr);
  return true;
}

bool BuildReaderClaimForIssuer(const MdocIssuerPublicBundle& issuer_public,
                               const std::string& claim_alias, ReaderClaim* claim,
                               std::string* err) {
  if (!issuer_public.supported_claim_aliases.empty() &&
      IsSupportedAlias(issuer_public.supported_claim_aliases, claim_alias)) {
    if (claim_alias == "age_over_18" || claim_alias == "family_name" ||
        claim_alias == "given_name" || claim_alias == "birth_date" ||
        claim_alias == "issue_date" || claim_alias == "expiry_date" ||
        claim_alias == "issuing_country" || claim_alias == "height") {
      *claim = MakeGenericClaim(claim_alias);
      return true;
    }
  }
  return BuildReaderClaim(claim_alias, claim, err);
}

bool BuildReaderRequest(const MdocIssuerPublicBundle& issuer_public,
                        const std::vector<std::string>& claim_aliases,
                        ReaderRequest* request, std::string* err) {
  if (claim_aliases.empty() || claim_aliases.size() > 2) {
    if (err != nullptr) {
      *err = "mdoc demo supports 1 or 2 claims";
    }
    return false;
  }
  request->claims.clear();
  for (const std::string& alias : claim_aliases) {
    ReaderClaim claim;
    if (!BuildReaderClaimForIssuer(issuer_public, alias, &claim, err)) {
      return false;
    }
    request->claims.push_back(claim);
  }
  request->num_attributes = request->claims.size();
  request->doc_type = issuer_public.doc_type;
  request->now_iso8601 = issuer_public.now_iso8601;
  request->client_id = issuer_public.client_id;
  request->response_uri = issuer_public.response_uri;
  if (!GenerateOpenId4VpSessionTranscript(&request->transcript_bytes,
                                          &request->nonce_hex, err)) {
    return false;
  }
  request->state = request->nonce_hex;

  const ZkSpecStruct& spec = request->num_attributes == 1 ? kZkSpecs[0] : kZkSpecs[1];
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  CircuitGenerationErrorCode gen_ret = generate_circuit(&spec, &circuit, &circuit_len);
  if (gen_ret != CIRCUIT_GENERATION_SUCCESS) {
    if (err != nullptr) {
      *err = "failed to generate mdoc circuit";
    }
    return false;
  }
  request->zk_system = spec.system;
  request->circuit_hash = spec.circuit_hash;
  request->circuit_bytes.assign(circuit, circuit + circuit_len);
  std::free(circuit);
  request->openid4vp_request_json = BuildOpenId4VpRequestJson(*request);
  if (!EncodeReaderRequestCbor(*request, &request->request_cbor, err)) {
    return false;
  }
  return true;
}

bool BuildDelegatedReaderRequest(const MdocIssuerPublicBundle& issuer_public,
                                 const std::vector<std::string>& claim_aliases,
                                 ReaderRequest* request, std::string* err) {
  if (claim_aliases.empty() || claim_aliases.size() > 2) {
    if (err != nullptr) {
      *err = "mdoc demo supports 1 or 2 claims";
    }
    return false;
  }
  request->claims.clear();
  for (const std::string& alias : claim_aliases) {
    ReaderClaim claim;
    if (!BuildReaderClaimForIssuer(issuer_public, alias, &claim, err)) {
      return false;
    }
    request->claims.push_back(claim);
  }
  request->num_attributes = request->claims.size();
  request->doc_type = issuer_public.doc_type;
  request->now_iso8601 = issuer_public.now_iso8601;
  request->client_id = issuer_public.client_id;
  request->response_uri = issuer_public.response_uri;
  if (!GenerateOpenId4VpSessionTranscript(&request->transcript_bytes,
                                          &request->nonce_hex, err)) {
    return false;
  }
  request->state = request->nonce_hex;

  const ZkSpecStruct& spec = request->num_attributes == 1 ? kZkSpecs[0] : kZkSpecs[1];
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  CircuitGenerationErrorCode gen_ret =
      generate_delegated_circuit(&spec, &circuit, &circuit_len);
  if (gen_ret != CIRCUIT_GENERATION_SUCCESS) {
    if (err != nullptr) {
      *err = "failed to generate delegated mdoc circuit";
    }
    return false;
  }
  request->zk_system = spec.system;
  request->circuit_hash = spec.circuit_hash;
  request->circuit_bytes.assign(circuit, circuit + circuit_len);
  std::free(circuit);
  request->openid4vp_request_json = BuildOpenId4VpRequestJson(*request);
  if (!EncodeReaderRequestCbor(*request, &request->request_cbor, err)) {
    return false;
  }
  return true;
}

bool ProveMdocPresentation(const HolderMdoc& holder,
                           const MdocIssuerPublicBundle& issuer_public,
                           const ReaderRequest& request,
                           MdocPresentation* presentation,
                           std::string* err) {
  std::vector<RequestedAttribute> attrs;
  std::vector<ReaderClaim> resolved_claims;
  if (!ResolveClaimValues(request.claims, holder.issued_claims, &resolved_claims, err)) {
    return false;
  }
  ReaderRequest resolved_request = request;
  resolved_request.claims = resolved_claims;
  if (!BuildRequestedAttributes(resolved_request, &attrs, err)) {
    return false;
  }
  const ZkSpecStruct* spec = FindRequestSpec(request, err);
  if (spec == nullptr) {
    return false;
  }
  std::vector<uint8_t> patched_response;
  if (!PatchDynamicDeviceSignature(holder, request, &patched_response, err)) {
    return false;
  }
  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  MdocProverErrorCode ret = run_mdoc_prover(
      request.circuit_bytes.data(), request.circuit_bytes.size(),
      patched_response.data(), patched_response.size(),
      issuer_public.issuer_pkx_hex.c_str(), issuer_public.issuer_pky_hex.c_str(),
      request.transcript_bytes.data(), request.transcript_bytes.size(), attrs.data(),
      attrs.size(), request.now_iso8601.c_str(), &proof, &proof_len, spec);
  if (ret != MDOC_PROVER_SUCCESS) {
    if (err != nullptr) {
      *err = "mdoc proof generation failed with code " + std::to_string(ret);
    }
    return false;
  }
  presentation->proof_bytes.assign(proof, proof + proof_len);
  presentation->claim_aliases.clear();
  presentation->disclosed_claims = resolved_claims;
  for (const auto& claim : request.claims) {
    presentation->claim_aliases.push_back(claim.alias);
  }
  std::free(proof);
  return true;
}

bool ProveDelegatedMdocPresentation(
    const HolderMdoc& holder, const MdocIssuerPublicBundle& issuer_public,
    const ReaderRequest& request, const std::string& agent_pkx_hex,
    const std::string& agent_pky_hex,
    const std::vector<uint8_t>& delegation_sig,
    const std::vector<uint8_t>& agent_sig,
    const std::vector<uint8_t>& allowed_claim_hashes_padded,
    size_t allowed_claim_count, const std::string& policy_expires,
    const std::vector<uint8_t>& agent_id_hash,
    const std::vector<uint8_t>& requested_claim_hashes,
    const std::vector<uint8_t>& revocation_id,
    const std::vector<uint8_t>& revocation_epoch_be,
    const std::string& revocation_expires,
    uint8_t revocation_revoked,
    const std::vector<uint8_t>& revocation_sig,
    MdocPresentation* presentation, std::string* err) {
  std::vector<RequestedAttribute> attrs;
  std::vector<ReaderClaim> resolved_claims;
  if (!ResolveClaimValues(request.claims, holder.issued_claims, &resolved_claims, err)) {
    return false;
  }
  ReaderRequest resolved_request = request;
  resolved_request.claims = resolved_claims;
  if (!BuildRequestedAttributes(resolved_request, &attrs, err)) {
    return false;
  }
  const ZkSpecStruct& spec = request.num_attributes == 1 ? kZkSpecs[0] : kZkSpecs[1];
  std::vector<uint8_t> patched_response;
  if (!PatchDynamicDeviceSignature(holder, request, &patched_response, err)) {
    return false;
  }
  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  MdocProverErrorCode ret = run_mdoc_delegated_prover(
      request.circuit_bytes.data(), request.circuit_bytes.size(),
      patched_response.data(), patched_response.size(),
      issuer_public.issuer_pkx_hex.c_str(), issuer_public.issuer_pky_hex.c_str(),
      request.transcript_bytes.data(), request.transcript_bytes.size(),
      attrs.data(), attrs.size(), request.now_iso8601.c_str(),
      agent_pkx_hex.c_str(), agent_pky_hex.c_str(), delegation_sig.data(),
      delegation_sig.size(), agent_sig.data(), agent_sig.size(),
      allowed_claim_hashes_padded.data(), allowed_claim_count,
      policy_expires.c_str(), agent_id_hash.data(), requested_claim_hashes.data(),
      revocation_id.data(), revocation_epoch_be.data(), revocation_expires.c_str(),
      revocation_revoked, revocation_sig.data(), revocation_sig.size(),
      &proof, &proof_len, &spec);
  if (ret != MDOC_PROVER_SUCCESS) {
    if (err != nullptr) {
      *err = "delegated mdoc proof generation failed with code " + std::to_string(ret);
    }
    return false;
  }
  presentation->proof_bytes.assign(proof, proof + proof_len);
  presentation->claim_aliases.clear();
  presentation->disclosed_claims = resolved_claims;
  for (const auto& claim : request.claims) {
    presentation->claim_aliases.push_back(claim.alias);
  }
  std::free(proof);
  return true;
}

MdocVerificationResult VerifyMdocPresentation(
    const MdocIssuerPublicBundle& issuer_public, const ReaderRequest& request,
    const MdocPresentation& presentation) {
  MdocVerificationResult result;
  if (presentation.claim_aliases.size() != request.claims.size()) {
    result.message = "presentation claim count mismatch";
    return result;
  }
  for (size_t i = 0; i < presentation.claim_aliases.size(); ++i) {
    if (presentation.claim_aliases[i] != request.claims[i].alias) {
      result.message = "presentation claim alias mismatch";
      return result;
    }
  }
  std::string err;
  std::vector<RequestedAttribute> attrs;
  std::vector<ReaderClaim> resolved_claims;
  if (!ResolveClaimValues(request.claims, presentation.disclosed_claims,
                          &resolved_claims, &err)) {
    result.message = err;
    return result;
  }
  ReaderRequest resolved_request = request;
  resolved_request.claims = resolved_claims;
  if (!BuildRequestedAttributes(resolved_request, &attrs, &err)) {
    result.message = err;
    return result;
  }
  const ZkSpecStruct* spec = FindRequestSpec(request, &err);
  if (spec == nullptr) {
    result.message = err;
    return result;
  }
  MdocVerifierErrorCode ret = run_mdoc_verifier(
      request.circuit_bytes.data(), request.circuit_bytes.size(),
      issuer_public.issuer_pkx_hex.c_str(), issuer_public.issuer_pky_hex.c_str(),
      request.transcript_bytes.data(), request.transcript_bytes.size(), attrs.data(),
      attrs.size(), request.now_iso8601.c_str(), presentation.proof_bytes.data(),
      presentation.proof_bytes.size(), request.doc_type.c_str(), spec);
  result.ok = ret == MDOC_VERIFIER_SUCCESS;
  result.message =
      result.ok ? "ok" : ("mdoc verification failed with code " + std::to_string(ret));
  return result;
}

MdocVerificationResult VerifyDelegatedMdocPresentation(
    const MdocIssuerPublicBundle& issuer_public, const ReaderRequest& request,
    const MdocPresentation& presentation, const std::string& agent_pkx_hex,
    const std::string& agent_pky_hex,
    const std::vector<uint8_t>& allowed_claim_hashes_padded,
    size_t allowed_claim_count, const std::string& policy_expires,
    const std::vector<uint8_t>& agent_id_hash,
    const std::vector<uint8_t>& requested_claim_hashes,
    const std::vector<uint8_t>& revocation_id,
    const std::vector<uint8_t>& revocation_epoch_be,
    const std::string& revocation_expires,
    uint8_t revocation_revoked) {
  MdocVerificationResult result;
  if (presentation.claim_aliases.size() != request.claims.size()) {
    result.message = "presentation claim count mismatch";
    return result;
  }
  for (size_t i = 0; i < presentation.claim_aliases.size(); ++i) {
    if (presentation.claim_aliases[i] != request.claims[i].alias) {
      result.message = "presentation claim alias mismatch";
      return result;
    }
  }
  std::string err;
  std::vector<RequestedAttribute> attrs;
  std::vector<ReaderClaim> resolved_claims;
  if (!ResolveClaimValues(request.claims, presentation.disclosed_claims,
                          &resolved_claims, &err)) {
    result.message = err;
    return result;
  }
  ReaderRequest resolved_request = request;
  resolved_request.claims = resolved_claims;
  if (!BuildRequestedAttributes(resolved_request, &attrs, &err)) {
    result.message = err;
    return result;
  }
  const ZkSpecStruct& spec = request.num_attributes == 1 ? kZkSpecs[0] : kZkSpecs[1];
  MdocVerifierErrorCode ret = run_mdoc_delegated_verifier(
      request.circuit_bytes.data(), request.circuit_bytes.size(),
      issuer_public.issuer_pkx_hex.c_str(), issuer_public.issuer_pky_hex.c_str(),
      request.transcript_bytes.data(), request.transcript_bytes.size(), attrs.data(),
      attrs.size(), request.now_iso8601.c_str(), presentation.proof_bytes.data(),
      presentation.proof_bytes.size(), request.doc_type.c_str(),
      agent_pkx_hex.c_str(), agent_pky_hex.c_str(),
      allowed_claim_hashes_padded.data(), allowed_claim_count,
      policy_expires.c_str(), agent_id_hash.data(), requested_claim_hashes.data(),
      revocation_id.data(), revocation_epoch_be.data(), revocation_expires.c_str(),
      revocation_revoked,
      &spec);
  result.ok = ret == MDOC_VERIFIER_SUCCESS;
  result.message = result.ok
                       ? "ok"
                       : ("delegated mdoc verification failed with code " +
                          std::to_string(ret));
  return result;
}

}  // namespace proofs
