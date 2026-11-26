// Copyright (c) 2026 The Sugarchain En developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CRYPTO_YESPOWER_SHA256_DISPATCH_H
#define BITCOIN_CRYPTO_YESPOWER_SHA256_DISPATCH_H

#if defined(_WIN32) && (defined(__x86_64__) || defined(_M_X64)) && defined(ENABLE_SSE41) && defined(ENABLE_X86_SHANI)
#define YESPOWER_WINDOWS_SHA_NI

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Uses the detected hardware compressor. Returns false without changing state on fallback. */
bool YespowerSHA256TryCompress(uint32_t state[8], const uint8_t block[64]);

#ifdef __cplusplus
}
#endif

#endif // Windows x86-64 SHA-NI build
#endif // BITCOIN_CRYPTO_YESPOWER_SHA256_DISPATCH_H
