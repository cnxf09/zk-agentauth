#ifndef PRIVACY_PROOFS_ZK_LIB_ZSTD_COMPAT_H_
#define PRIVACY_PROOFS_ZK_LIB_ZSTD_COMPAT_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t ZSTD_compress(void* dst, size_t dstCapacity, const void* src,
                     size_t srcSize, int compressionLevel);
size_t ZSTD_decompress(void* dst, size_t dstCapacity, const void* src,
                       size_t compressedSize);
unsigned ZSTD_isError(size_t code);
const char* ZSTD_getErrorName(size_t code);

#ifdef __cplusplus
}
#endif

#endif  // PRIVACY_PROOFS_ZK_LIB_ZSTD_COMPAT_H_
