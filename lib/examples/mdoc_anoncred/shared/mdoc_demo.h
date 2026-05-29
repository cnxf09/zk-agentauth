#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_MDOC_DEMO_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_MDOC_DEMO_H_

#include <string>
#include <vector>

#include "examples/mdoc_anoncred/shared/types.h"

namespace proofs {

bool MaterializeMdocExample(uint32_t example_id, HolderMdoc* holder,
                            MdocIssuerPublicBundle* issuer_public,
                            std::string* err);

bool BuildReaderClaim(const std::string& claim_alias, ReaderClaim* claim,
                      std::string* err);

bool BuildReaderClaimForIssuer(const MdocIssuerPublicBundle& issuer_public,
                               const std::string& claim_alias, ReaderClaim* claim,
                               std::string* err);

bool BuildReaderRequest(const MdocIssuerPublicBundle& issuer_public,
                        const std::vector<std::string>& claim_aliases,
                        ReaderRequest* request, std::string* err);

bool BuildDelegatedReaderRequest(const MdocIssuerPublicBundle& issuer_public,
                                 const std::vector<std::string>& claim_aliases,
                                 ReaderRequest* request, std::string* err);

bool ProveMdocPresentation(const HolderMdoc& holder,
                           const MdocIssuerPublicBundle& issuer_public,
                           const ReaderRequest& request,
                           MdocPresentation* presentation,
                           std::string* err);

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
    MdocPresentation* presentation, std::string* err);

MdocVerificationResult VerifyMdocPresentation(
    const MdocIssuerPublicBundle& issuer_public, const ReaderRequest& request,
    const MdocPresentation& presentation);

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
    uint8_t revocation_revoked);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_MDOC_DEMO_H_
