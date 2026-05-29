#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_REQUEST_CODEC_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_REQUEST_CODEC_H_

#include <string>
#include <vector>

#include "examples/mdoc_anoncred/shared/types.h"

namespace proofs {

bool GenerateOpenId4VpSessionTranscript(std::vector<uint8_t>* transcript,
                                        std::string* nonce_hex,
                                        std::string* err);

std::string BuildOpenId4VpRequestJson(const ReaderRequest& request);

bool EncodeReaderRequestCbor(const ReaderRequest& request,
                             std::vector<uint8_t>* out, std::string* err);

bool DecodeReaderRequestCbor(const std::vector<uint8_t>& encoded,
                             ReaderRequest* request, std::string* err);

bool ComputeDeviceAuthenticationDigest(const std::vector<uint8_t>& transcript,
                                       const std::string& doc_type,
                                       std::vector<uint8_t>* digest,
                                       std::string* err);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_REQUEST_CODEC_H_
