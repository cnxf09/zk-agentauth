#ifndef EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_REVOCATION_H_
#define EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_REVOCATION_H_

#include <cstdint>
#include <filesystem>
#include <string>

namespace proofs {

struct DelegationRevocationStatus {
  std::string delegation_id_hex;
  uint64_t epoch = 0;
  std::string expires;
  bool revoked = false;
  std::string sig_hex;
};

bool ComputeDelegationIdHex(const std::string& delegation_msg_hex,
                            std::string* delegation_id_hex,
                            std::string* err);

bool CreateDelegationRevocationStatus(
    const std::string& device_sk_hex,
    const std::string& delegation_msg_hex,
    uint64_t epoch,
    const std::string& expires,
    bool revoked,
    DelegationRevocationStatus* status,
    std::string* err);

bool VerifyDelegationRevocationStatus(
    const DelegationRevocationStatus& status,
    const std::string& device_pkx_hex,
    const std::string& device_pky_hex,
    const std::string& delegation_msg_hex,
    const std::string& now_iso8601,
    std::string* err);

bool WriteDelegationRevocationStatusJson(
    const std::filesystem::path& path,
    const DelegationRevocationStatus& status,
    std::string* err);

bool WritePublicDelegationRevocationStatusJson(
    const std::filesystem::path& path,
    const DelegationRevocationStatus& status,
    std::string* err);

bool ReadDelegationRevocationStatusJson(
    const std::filesystem::path& path,
    DelegationRevocationStatus* status,
    std::string* err);

}  // namespace proofs

#endif  // EXAMPLES_DELEGATION_DEMO_SHARED_DELEGATION_REVOCATION_H_
