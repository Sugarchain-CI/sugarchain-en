#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void reference_SHA256_Init(SHA256_CTX *);
extern void reference_SHA256_Update(SHA256_CTX *, const void *, size_t);
extern void reference_SHA256_Final(uint8_t[32], SHA256_CTX *);
extern void reference_SHA256_Buf(const void *, size_t, uint8_t[32]);
extern void reference_HMAC_SHA256_Init(HMAC_SHA256_CTX *, const void *, size_t);
extern void reference_HMAC_SHA256_Update(HMAC_SHA256_CTX *, const void *, size_t);
extern void reference_HMAC_SHA256_Final(uint8_t[32], HMAC_SHA256_CTX *);
extern void reference_HMAC_SHA256_Buf(const void *, size_t, const void *, size_t, uint8_t[32]);
extern void reference_PBKDF2_SHA256(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t, uint8_t *, size_t);

static size_t checks;
static void equal(const char *label, const uint8_t *a, const uint8_t *b, size_t length)
{
    if (memcmp(a, b, length)) {
        fprintf(stderr, "FAIL %s at check %zu\n", label, checks);
        exit(1);
    }
    ++checks;
}

int main(void)
{
    static const size_t lengths[] = {0, 1, 31, 32, 51, 52, 55, 56, 63, 64, 65, 79, 80, 127, 128, 255, 256, 1024};
    static const uint8_t abc_hash[32] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t storage[1027], ref[96], got[96], streamed[96];
    for (size_t i = 0; i < sizeof(storage); ++i) storage[i] = (uint8_t)(i * 73 + 19);
    SHA256_Buf("abc", 3, got);
    equal("known SHA256 abc", abc_hash, got, 32);
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t n = lengths[i];
        const uint8_t *input = storage + 1;
        reference_SHA256_Buf(input, n, ref);
        SHA256_Buf(input, n, got);
        equal("SHA256 buffer", ref, got, 32);
        for (size_t split = 0; split <= n; split += n > 64 ? 17 : 1) {
            SHA256_CTX ctx, reference;
            SHA256_Init(&ctx);
            reference_SHA256_Init(&reference);
            SHA256_Update(&ctx, input, split);
            SHA256_Update(&ctx, input + split, n - split);
            reference_SHA256_Update(&reference, input, split);
            reference_SHA256_Update(&reference, input + split, n - split);
            SHA256_Final(streamed, &ctx);
            equal("SHA256 streaming", ref, streamed, 32);
            reference_SHA256_Final(streamed, &reference);
            equal("reference SHA256 streaming", ref, streamed, 32);
        }
        for (size_t k = 0; k <= 80; k += k == 0 ? 1 : k == 1 ? 62 : 1) {
            reference_HMAC_SHA256_Buf(storage + 2, k, input, n, ref);
            HMAC_SHA256_Buf(storage + 2, k, input, n, got);
            equal("HMAC buffer", ref, got, 32);
            HMAC_SHA256_CTX ctx, reference;
            HMAC_SHA256_Init(&ctx, storage + 2, k);
            reference_HMAC_SHA256_Init(&reference, storage + 2, k);
            HMAC_SHA256_Update(&ctx, input, n / 2);
            HMAC_SHA256_Update(&ctx, input + n / 2, n - n / 2);
            reference_HMAC_SHA256_Update(&reference, input, n / 2);
            reference_HMAC_SHA256_Update(&reference, input + n / 2, n - n / 2);
            HMAC_SHA256_Final(streamed, &ctx);
            equal("HMAC streaming", ref, streamed, 32);
            reference_HMAC_SHA256_Final(streamed, &reference);
            equal("reference HMAC streaming", ref, streamed, 32);
            for (uint64_t c = 1; c <= 2; ++c) {
                for (size_t out = 31; out <= 65; ++out) {
                    reference_PBKDF2_SHA256(storage + 2, k, input, n, c, ref, out);
                    PBKDF2_SHA256(storage + 2, k, input, n, c, got, out);
                    equal("PBKDF2 boundary", ref, got, out);
                }
            }
        }
    }
    printf("PASS: %zu SHA256, HMAC and PBKDF2 boundary checks\n", checks);
    return 0;
}
