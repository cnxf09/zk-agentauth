#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_CBOR_ENCODE_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_CBOR_ENCODE_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace proofs {

void CborAppendUnsigned(std::vector<uint8_t>* out, uint64_t value);
void CborAppendNegative(std::vector<uint8_t>* out, int64_t value);
void CborAppendBytes(std::vector<uint8_t>* out,
                     const std::vector<uint8_t>& bytes);
void CborAppendText(std::vector<uint8_t>* out, const std::string& text);
void CborAppendBool(std::vector<uint8_t>* out, bool value);
void CborAppendNull(std::vector<uint8_t>* out);
void CborAppendTag(std::vector<uint8_t>* out, uint64_t tag);
void CborBeginArray(std::vector<uint8_t>* out, size_t count);
void CborBeginMap(std::vector<uint8_t>* out, size_t count);
void CborAppendTaggedBytes(std::vector<uint8_t>* out, uint64_t tag,
                           const std::vector<uint8_t>& payload);
void CborAppendTaggedDateText(std::vector<uint8_t>* out,
                              const std::string& yyyy_mm_dd);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_BUILDER_CBOR_ENCODE_H_
