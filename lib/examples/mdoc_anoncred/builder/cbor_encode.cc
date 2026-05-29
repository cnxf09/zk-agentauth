#include "examples/mdoc_anoncred/builder/cbor_encode.h"

namespace proofs {
namespace {

void AppendMajorAndCount(std::vector<uint8_t>* out, uint8_t major,
                         uint64_t count) {
  if (count < 24) {
    out->push_back(static_cast<uint8_t>((major << 5) | count));
    return;
  }
  if (count <= 0xff) {
    out->push_back(static_cast<uint8_t>((major << 5) | 24));
    out->push_back(static_cast<uint8_t>(count));
    return;
  }
  if (count <= 0xffff) {
    out->push_back(static_cast<uint8_t>((major << 5) | 25));
    out->push_back(static_cast<uint8_t>((count >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>(count & 0xff));
    return;
  }
  if (count <= 0xffffffffULL) {
    out->push_back(static_cast<uint8_t>((major << 5) | 26));
    out->push_back(static_cast<uint8_t>((count >> 24) & 0xff));
    out->push_back(static_cast<uint8_t>((count >> 16) & 0xff));
    out->push_back(static_cast<uint8_t>((count >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>(count & 0xff));
    return;
  }
  out->push_back(static_cast<uint8_t>((major << 5) | 27));
  for (int shift = 56; shift >= 0; shift -= 8) {
    out->push_back(static_cast<uint8_t>((count >> shift) & 0xff));
  }
}

}  // namespace

void CborAppendUnsigned(std::vector<uint8_t>* out, uint64_t value) {
  AppendMajorAndCount(out, 0, value);
}

void CborAppendNegative(std::vector<uint8_t>* out, int64_t value) {
  // Match the repository's host_decoder negative-number convention, which
  // treats 0x21 as -1 and 0x22 as -2.
  const uint64_t encoded = static_cast<uint64_t>(-value);
  AppendMajorAndCount(out, 1, encoded);
}

void CborAppendBytes(std::vector<uint8_t>* out,
                     const std::vector<uint8_t>& bytes) {
  AppendMajorAndCount(out, 2, bytes.size());
  out->insert(out->end(), bytes.begin(), bytes.end());
}

void CborAppendText(std::vector<uint8_t>* out, const std::string& text) {
  AppendMajorAndCount(out, 3, text.size());
  out->insert(out->end(), text.begin(), text.end());
}

void CborAppendBool(std::vector<uint8_t>* out, bool value) {
  out->push_back(value ? 0xf5 : 0xf4);
}

void CborAppendNull(std::vector<uint8_t>* out) { out->push_back(0xf6); }

void CborAppendTag(std::vector<uint8_t>* out, uint64_t tag) {
  AppendMajorAndCount(out, 6, tag);
}

void CborBeginArray(std::vector<uint8_t>* out, size_t count) {
  AppendMajorAndCount(out, 4, count);
}

void CborBeginMap(std::vector<uint8_t>* out, size_t count) {
  AppendMajorAndCount(out, 5, count);
}

void CborAppendTaggedBytes(std::vector<uint8_t>* out, uint64_t tag,
                           const std::vector<uint8_t>& payload) {
  CborAppendTag(out, tag);
  CborAppendBytes(out, payload);
}

void CborAppendTaggedDateText(std::vector<uint8_t>* out,
                              const std::string& yyyy_mm_dd) {
  CborAppendTag(out, 1004);
  CborAppendText(out, yyyy_mm_dd);
}

}  // namespace proofs
