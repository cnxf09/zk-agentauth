#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

#include "circuits/mdoc/mdoc_witness.h"
#include "examples/mdoc_anoncred/builder/cbor_encode.h"
#include "examples/mdoc_anoncred/builder/input.h"
#include "examples/mdoc_anoncred/builder/issue_custom.h"
#include "examples/mdoc_anoncred/holder/prove.h"
#include "examples/mdoc_anoncred/issuer/issue.h"
#include "examples/mdoc_anoncred/shared/files.h"
#include "examples/mdoc_anoncred/shared/mdoc_demo.h"
#include "examples/mdoc_anoncred/verifier/verify.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

std::filesystem::path MakeTempDir(const char* suffix) {
  auto dir = std::filesystem::temp_directory_path() /
             (std::string("mdoc_anoncred_demo_") + suffix + "_" +
              std::to_string(::getpid()));
  std::filesystem::create_directories(dir);
  return dir;
}

TEST(MdocAnoncredDemo, RoundTripAgeOver18) {
  std::string err;
  auto root = MakeTempDir("age18");
  auto issue_dir = root / "issue";
  auto request_dir = root / "request";
  auto presentation_dir = root / "presentation";

  ASSERT_TRUE(RunMdocIssueCommand(3, issue_dir, &err)) << err;
  ASSERT_TRUE(RunMdocRequestCommand(issue_dir / "issuer_public", {"age_over_18"},
                                    request_dir, &err))
      << err;
  ASSERT_TRUE(RunMdocProveCommand(issue_dir / "holder", issue_dir / "issuer_public",
                                  request_dir, presentation_dir, &err))
      << err;
  bool verified = false;
  ASSERT_TRUE(RunMdocVerifyCommand(issue_dir / "issuer_public", request_dir,
                                   presentation_dir, &verified, &err))
      << err;
  EXPECT_TRUE(verified) << err;
}

TEST(MdocAnoncredDemo, RoundTripTwoClaims) {
  std::string err;
  auto root = MakeTempDir("two_claims");
  auto issue_dir = root / "issue";
  auto request_dir = root / "request";
  auto presentation_dir = root / "presentation";

  ASSERT_TRUE(RunMdocIssueCommand(3, issue_dir, &err)) << err;
  ASSERT_TRUE(RunMdocRequestCommand(issue_dir / "issuer_public",
                                    {"age_over_18", "family_name_mustermann"},
                                    request_dir, &err))
      << err;
  ASSERT_TRUE(RunMdocProveCommand(issue_dir / "holder", issue_dir / "issuer_public",
                                  request_dir, presentation_dir, &err))
      << err;
  bool verified = false;
  ASSERT_TRUE(RunMdocVerifyCommand(issue_dir / "issuer_public", request_dir,
                                   presentation_dir, &verified, &err))
      << err;
  EXPECT_TRUE(verified) << err;
}

TEST(MdocAnoncredDemo, TamperedProofFails) {
  std::string err;
  auto root = MakeTempDir("tamper");
  auto issue_dir = root / "issue";
  auto request_dir = root / "request";
  auto presentation_dir = root / "presentation";

  ASSERT_TRUE(RunMdocIssueCommand(3, issue_dir, &err)) << err;
  ASSERT_TRUE(RunMdocRequestCommand(issue_dir / "issuer_public", {"age_over_18"},
                                    request_dir, &err))
      << err;
  ASSERT_TRUE(RunMdocProveCommand(issue_dir / "holder", issue_dir / "issuer_public",
                                  request_dir, presentation_dir, &err))
      << err;

  MdocPresentation presentation;
  ASSERT_TRUE(ReadMdocPresentationDir(presentation_dir, &presentation, &err)) << err;
  ASSERT_FALSE(presentation.proof_bytes.empty());
  presentation.proof_bytes[0] ^= 0x01;
  ASSERT_TRUE(WriteMdocPresentationDir(presentation_dir, presentation, &err)) << err;

  bool verified = false;
  ASSERT_TRUE(RunMdocVerifyCommand(issue_dir / "issuer_public", request_dir,
                                   presentation_dir, &verified, &err))
      << err;
  EXPECT_FALSE(verified);
}

TEST(MdocAnoncredDemo, RequestTranscriptIsFresh) {
  std::string err;
  auto root = MakeTempDir("fresh_request");
  auto issue_dir = root / "issue";
  auto request1_dir = root / "request1";
  auto request2_dir = root / "request2";

  ASSERT_TRUE(RunMdocIssueCommand(3, issue_dir, &err)) << err;
  ASSERT_TRUE(RunMdocRequestCommand(issue_dir / "issuer_public", {"age_over_18"},
                                    request1_dir, &err))
      << err;
  ASSERT_TRUE(RunMdocRequestCommand(issue_dir / "issuer_public", {"age_over_18"},
                                    request2_dir, &err))
      << err;

  ReaderRequest request1;
  ReaderRequest request2;
  ASSERT_TRUE(ReadReaderRequestDir(request1_dir, &request1, &err)) << err;
  ASSERT_TRUE(ReadReaderRequestDir(request2_dir, &request2, &err)) << err;
  EXPECT_NE(request1.transcript_bytes, request2.transcript_bytes);
  EXPECT_NE(request1.nonce_hex, request2.nonce_hex);
}

TEST(MdocAnoncredDemo, PresentationCannotBeReplayedAcrossRequests) {
  std::string err;
  auto root = MakeTempDir("replay");
  auto issue_dir = root / "issue";
  auto request1_dir = root / "request1";
  auto request2_dir = root / "request2";
  auto presentation_dir = root / "presentation";

  ASSERT_TRUE(RunMdocIssueCommand(3, issue_dir, &err)) << err;
  ASSERT_TRUE(RunMdocRequestCommand(issue_dir / "issuer_public", {"age_over_18"},
                                    request1_dir, &err))
      << err;
  ASSERT_TRUE(RunMdocRequestCommand(issue_dir / "issuer_public", {"age_over_18"},
                                    request2_dir, &err))
      << err;
  ASSERT_TRUE(RunMdocProveCommand(issue_dir / "holder", issue_dir / "issuer_public",
                                  request1_dir, presentation_dir, &err))
      << err;

  bool verified = false;
  ASSERT_TRUE(RunMdocVerifyCommand(issue_dir / "issuer_public", request2_dir,
                                   presentation_dir, &verified, &err))
      << err;
  EXPECT_FALSE(verified);
}

TEST(MdocAnoncredDemo, CborTaggedDateEncoding) {
  std::vector<uint8_t> encoded;
  CborAppendTaggedDateText(&encoded, "1971-09-01");
  const std::vector<uint8_t> expected = {
      0xd9, 0x03, 0xec, 0x6a, '1', '9', '7', '1', '-', '0', '9', '-', '0', '1'};
  EXPECT_EQ(encoded, expected);
}

TEST(MdocAnoncredDemo, CustomIssuedMdocParses) {
  IssuedMdocInput input;
  input.family_name = "Researcher";
  input.given_name = "Alice";
  input.birth_date = "1999-12-31";
  input.issue_date = "2024-01-01";
  input.expiry_date = "2030-01-01";
  input.issuing_country = "US";
  input.age_over_18 = true;

  HolderMdoc holder;
  MdocIssuerPublicBundle issuer_public;
  std::string err;
  ASSERT_TRUE(BuildCustomMdoc(input, &holder, &issuer_public, &err)) << err;

  ParsedMdoc parsed;
  EXPECT_EQ(parsed.parse_device_response(holder.device_response_cbor.size(),
                                         holder.device_response_cbor.data()),
            MDOC_PROVER_SUCCESS);
  EXPECT_EQ(issuer_public.supported_claim_aliases.size(), 7u);
}

TEST(MdocAnoncredDemo, CustomIssueRoundTrip) {
  IssuedMdocInput input;
  input.family_name = "Researcher";
  input.given_name = "Alice";
  input.birth_date = "1999-12-31";
  input.issue_date = "2024-01-01";
  input.expiry_date = "2030-01-01";
  input.issuing_country = "US";
  input.age_over_18 = true;

  HolderMdoc holder;
  MdocIssuerPublicBundle issuer_public;
  std::string err;
  ASSERT_TRUE(BuildCustomMdoc(input, &holder, &issuer_public, &err)) << err;

  auto root = MakeTempDir("custom_issue");
  auto issue_dir = root / "issue";
  auto request_dir = root / "request";
  auto presentation_dir = root / "presentation";
  ASSERT_TRUE(WriteHolderMdocDir(issue_dir / "holder", holder, &err)) << err;
  ASSERT_TRUE(WriteMdocIssuerPublicDir(issue_dir / "issuer_public", issuer_public,
                                       &err))
      << err;

  ASSERT_TRUE(RunMdocRequestCommand(issue_dir / "issuer_public",
                                    {"given_name", "issuing_country"},
                                    request_dir,
                                    &err))
      << err;
  ASSERT_TRUE(RunMdocProveCommand(issue_dir / "holder", issue_dir / "issuer_public",
                                  request_dir, presentation_dir, &err))
      << err;

  bool verified = false;
  ASSERT_TRUE(RunMdocVerifyCommand(issue_dir / "issuer_public", request_dir,
                                   presentation_dir, &verified, &err))
      << err;
  EXPECT_TRUE(verified) << err;

  MdocPresentation presentation;
  ASSERT_TRUE(ReadMdocPresentationDir(presentation_dir, &presentation, &err)) << err;
  ASSERT_EQ(presentation.disclosed_claims.size(), 2u);
  EXPECT_EQ(presentation.disclosed_claims[0].alias, "given_name");
  EXPECT_EQ(presentation.disclosed_claims[1].alias, "issuing_country");
}

}  // namespace
}  // namespace proofs
