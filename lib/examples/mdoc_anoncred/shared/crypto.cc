#include "examples/mdoc_anoncred/shared/crypto.h"

#include <array>
#include <vector>

#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "util/crypto.h"

namespace proofs {
namespace {

bool SerializePublicKey(EC_GROUP* group, const EC_POINT* pub_key,
                        std::string* pkx_hex, std::string* pky_hex,
                        std::string* err) {
  uint8_t pub[65];
  if (EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, pub,
                         sizeof(pub), nullptr) != sizeof(pub)) {
    if (err != nullptr) {
      *err = "failed to serialize public key";
    }
    return false;
  }
  *pkx_hex = HexPrefixed(&pub[1], 32);
  *pky_hex = HexPrefixed(&pub[33], 32);
  return true;
}

bool BuildEcKeyFromPrivateKey(const std::string& sk_hex, EC_KEY** eckey,
                              EC_GROUP** group, std::string* err) {
  *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (*eckey == nullptr || *group == nullptr) {
    if (err != nullptr) {
      *err = "failed to initialize EC key";
    }
    if (*eckey != nullptr) EC_KEY_free(*eckey);
    if (*group != nullptr) EC_GROUP_free(*group);
    return false;
  }

  std::vector<uint8_t> sk_bytes;
  if (!HexToBytes(sk_hex, &sk_bytes, err)) {
    EC_KEY_free(*eckey);
    EC_GROUP_free(*group);
    return false;
  }
  BIGNUM* priv = BN_bin2bn(sk_bytes.data(), static_cast<int>(sk_bytes.size()),
                          nullptr);
  EC_POINT* pub = EC_POINT_new(*group);
  if (priv == nullptr || pub == nullptr) {
    if (err != nullptr) {
      *err = "failed to allocate EC key components";
    }
    if (priv != nullptr) BN_free(priv);
    if (pub != nullptr) EC_POINT_free(pub);
    EC_KEY_free(*eckey);
    EC_GROUP_free(*group);
    return false;
  }
  bool ok = false;
  do {
    if (EC_KEY_set_private_key(*eckey, priv) != 1 ||
        EC_POINT_mul(*group, pub, priv, nullptr, nullptr, nullptr) != 1 ||
        EC_KEY_set_public_key(*eckey, pub) != 1) {
      if (err != nullptr) {
        *err = "failed to reconstruct EC key";
      }
      break;
    }
    ok = true;
  } while (false);

  BN_free(priv);
  EC_POINT_free(pub);
  if (!ok) {
    EC_KEY_free(*eckey);
    EC_GROUP_free(*group);
  }
  return ok;
}

}  // namespace

std::string HexPrefixed(const uint8_t* bytes, size_t n) {
  std::vector<char> buf(2 * n + 3, '\0');
  buf[0] = '0';
  buf[1] = 'x';
  hex_to_str(buf.data() + 2, bytes, n);
  return std::string(buf.data());
}

bool HexToBytes(const std::string& hex, std::vector<uint8_t>* out,
                std::string* err) {
  const size_t prefix = hex.rfind("0x", 0) == 0 ? 2 : 0;
  const size_t n = hex.size() - prefix;
  if (n == 0 || (n % 2) != 0) {
    if (err != nullptr) {
      *err = "invalid hex string";
    }
    return false;
  }
  out->resize(n / 2);
  for (size_t i = 0; i < out->size(); ++i) {
    auto nibble = [&](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int hi = nibble(hex[prefix + 2 * i]);
    int lo = nibble(hex[prefix + 2 * i + 1]);
    if (hi < 0 || lo < 0) {
      if (err != nullptr) {
        *err = "invalid hex string";
      }
      return false;
    }
    (*out)[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

bool GenerateP256KeyPair(std::string* sk_hex, std::string* pkx_hex,
                         std::string* pky_hex, std::string* err) {
  EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (eckey == nullptr || group == nullptr) {
    if (err != nullptr) {
      *err = "failed to initialize EC key";
    }
    if (eckey != nullptr) EC_KEY_free(eckey);
    if (group != nullptr) EC_GROUP_free(group);
    return false;
  }
  bool ok = false;
  do {
    if (!EC_KEY_generate_key(eckey)) {
      if (err != nullptr) {
        *err = "failed to generate EC key";
      }
      break;
    }
    const BIGNUM* priv = EC_KEY_get0_private_key(eckey);
    const EC_POINT* pub = EC_KEY_get0_public_key(eckey);
    std::array<uint8_t, 32> sk_bytes{};
    if (BN_bn2binpad(priv, sk_bytes.data(), sk_bytes.size()) !=
        static_cast<int>(sk_bytes.size())) {
      if (err != nullptr) {
        *err = "failed to serialize private key";
      }
      break;
    }
    if (!SerializePublicKey(group, pub, pkx_hex, pky_hex, err)) {
      break;
    }
    *sk_hex = HexPrefixed(sk_bytes.data(), sk_bytes.size());
    ok = true;
  } while (false);
  EC_KEY_free(eckey);
  EC_GROUP_free(group);
  return ok;
}

bool Sha256Digest(const uint8_t* data, size_t len, std::vector<uint8_t>* digest) {
  digest->resize(kSHA256DigestSize);
  SHA256 sha;
  sha.Update(data, len);
  sha.DigestData(digest->data());
  return true;
}

bool SignSha256DigestP256(const std::string& sk_hex,
                          const std::vector<uint8_t>& digest,
                          std::vector<uint8_t>* sig_rs, std::string* err) {
  if (digest.size() != kSHA256DigestSize) {
    if (err != nullptr) {
      *err = "unexpected digest length";
    }
    return false;
  }
  EC_KEY* eckey = nullptr;
  EC_GROUP* group = nullptr;
  if (!BuildEcKeyFromPrivateKey(sk_hex, &eckey, &group, err)) {
    return false;
  }
  bool ok = false;
  do {
    ECDSA_SIG* sig = ECDSA_do_sign(digest.data(), digest.size(), eckey);
    if (sig == nullptr) {
      if (err != nullptr) {
        *err = "failed to sign digest";
      }
      break;
    }
    const BIGNUM* br = ECDSA_SIG_get0_r(sig);
    const BIGNUM* bs = ECDSA_SIG_get0_s(sig);
    sig_rs->assign(64, 0);
    if (BN_bn2binpad(br, sig_rs->data(), 32) != 32 ||
        BN_bn2binpad(bs, sig_rs->data() + 32, 32) != 32) {
      if (err != nullptr) {
        *err = "failed to serialize signature";
      }
      ECDSA_SIG_free(sig);
      break;
    }
    ECDSA_SIG_free(sig);
    ok = true;
  } while (false);
  EC_KEY_free(eckey);
  EC_GROUP_free(group);
  return ok;
}

}  // namespace proofs
