#include "examples/delegation_demo/shared/delegation_crypto.h"

#include <iostream>
#include <string>
#include <vector>

#include "examples/delegation_demo/shared/delegation_revocation.h"
#include "examples/mdoc_anoncred/shared/crypto.h"

namespace proofs {
namespace {

bool Expect(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << "\n";
    return false;
  }
  std::cout << "PASS: " << message << "\n";
  return true;
}

bool Run() {
  bool ok = true;
  std::string err;

  const std::string abc = "abc";
  std::vector<uint8_t> digest;
  ok &= Expect(Sm3Digest(reinterpret_cast<const uint8_t*>(abc.data()),
                         abc.size(), &digest),
               "SM3 digest computes");
  ok &= Expect(
      HexPrefixed(digest.data(), digest.size()) ==
          "0x66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
      "SM3 abc test vector");

  std::string sk, pkx, pky;
  ok &= Expect(GenerateSM2KeyPair(&sk, &pkx, &pky, &err),
               "SM2 key generation");
  if (!ok) {
    std::cerr << err << "\n";
    return false;
  }

  const std::string msg = "delegation message";
  ok &= Expect(Sm3Digest(reinterpret_cast<const uint8_t*>(msg.data()),
                         msg.size(), &digest),
               "SM3 delegation digest computes");
  const std::string digest_hex = HexPrefixed(digest.data(), digest.size());
  const std::string msg_hex =
      HexPrefixed(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());

  std::string sig_hex;
  ok &= Expect(SignDelegationSm2(sk, msg_hex, &sig_hex, &err),
               "SM2 signs message with fixed device id");
  ok &= Expect(VerifyDelegationSigSm2(pkx, pky, msg_hex, sig_hex, &err),
               "SM2 verifies valid message signature");

  std::string tampered = msg_hex;
  tampered[tampered.size() - 1] = tampered.back() == '0' ? '1' : '0';
  ok &= Expect(!VerifyDelegationSigSm2(pkx, pky, tampered, sig_hex, &err),
               "SM2 rejects tampered message");

  std::string tampered_sig = sig_hex;
  tampered_sig[tampered_sig.size() - 1] =
      tampered_sig.back() == '0' ? '1' : '0';
  ok &= Expect(!VerifyDelegationSigSm2(pkx, pky, msg_hex, tampered_sig, &err),
               "SM2 rejects tampered signature");

  std::string other_sk, other_pkx, other_pky;
  ok &= Expect(GenerateSM2KeyPair(&other_sk, &other_pkx, &other_pky, &err),
               "SM2 second key generation");
  ok &= Expect(!VerifyDelegationSigSm2(other_pkx, other_pky, msg_hex, sig_hex,
                                       &err),
               "SM2 rejects wrong public key");
  std::vector<uint8_t> transcript = {0x83, 0x40, 0x40, 0x40};
  std::vector<uint8_t> auth_digest;
  ok &= Expect(ComputeDeviceAuthenticationDigestSm3(
                   transcript, "org.iso.18013.5.1.mDL", &auth_digest, &err) &&
                   auth_digest.size() == 32,
               "SM3 device authentication digest computes");

  Policy policy;
  policy.allowed_claims = {"age_over_18"};
  policy.expires = "2027-01-01T00:00:00Z";
  policy.agent_id = "tripgo-agent";
  policy.created = "2026-06-03T00:00:00Z";

  std::string agent_sk, agent_pkx, agent_pky;
  ok &= Expect(GenerateSM2KeyPair(&agent_sk, &agent_pkx, &agent_pky, &err),
               "SM2 agent key generation");
  std::string delegation_msg;
  ok &= Expect(ComputeDelegationMsgSm3(agent_pkx, agent_pky, policy,
                                       &delegation_msg, &err),
               "SM3 delegation message computes");

  DelegationRevocationStatus status;
  ok &= Expect(CreateDelegationRevocationStatusSm2(
                   sk, delegation_msg, 7, "2027-01-01T00:00:00Z", false,
                   &status, &err),
               "SM2 revocation status signs");
  ok &= Expect(VerifyDelegationRevocationStatusSm2(
                   status, pkx, pky, delegation_msg,
                   "2026-06-03T00:00:00Z", &err),
               "SM2 revocation status verifies");

  status.revoked = true;
  ok &= Expect(!VerifyDelegationRevocationStatusSm2(
                   status, pkx, pky, delegation_msg,
                   "2026-06-03T00:00:00Z", &err),
               "SM2 revocation status rejects revoked");

  status.revoked = false;
  status.epoch ^= 1;
  ok &= Expect(!VerifyDelegationRevocationStatusSm2(
                   status, pkx, pky, delegation_msg,
                   "2026-06-03T00:00:00Z", &err),
               "SM2 revocation status rejects tampered epoch");

  return ok;
}

}  // namespace
}  // namespace proofs

int main() { return proofs::Run() ? 0 : 1; }
