#ifndef PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_CRYPTO_H_
#define PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_CRYPTO_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace proofs {

bool GenerateP256KeyPair(std::string* sk_hex, std::string* pkx_hex,
                         std::string* pky_hex, std::string* err);

bool SignSha256DigestP256(const std::string& sk_hex,
                          const std::vector<uint8_t>& digest,
                          std::vector<uint8_t>* sig_rs, std::string* err);

bool Sha256Digest(const uint8_t* data, size_t len, std::vector<uint8_t>* digest);

bool HexToBytes(const std::string& hex, std::vector<uint8_t>* out,
                std::string* err);

std::string HexPrefixed(const uint8_t* bytes, size_t n);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_EXAMPLES_MDOC_ANONCRED_SHARED_CRYPTO_H_
