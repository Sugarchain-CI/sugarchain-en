#define _POSIX_C_SOURCE 200809L
#include "yespower.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern int reference_yespower_init_local(yespower_local_t *);
extern int reference_yespower_free_local(yespower_local_t *);
extern int reference_yespower(yespower_local_t *, const uint8_t *, size_t,
    const yespower_params_t *, yespower_binary_t *);
extern int reference_yespower_tls(const uint8_t *, size_t, const yespower_params_t *, yespower_binary_t *);

static const uint8_t sugar[] = "Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote";
static const uint8_t personal[] = {0, 1, 255, 128, 19};
static size_t checked;
static yespower_local_t reference_local, candidate_local;

static void fail(const char *label, const char *reason)
{
    fprintf(stderr, "%s: %s\n", label, reason);
    exit(1);
}

static size_t unhex(const char *hex, uint8_t *out)
{
    const size_t n = strlen(hex);
    if (n & 1) fail("input", "odd hex length");
    for (size_t i = 0; i < n / 2; ++i) {
        unsigned b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) fail("input", "invalid hex");
        out[i] = (uint8_t)b;
    }
    return n / 2;
}

static void check(const char *label, const uint8_t *input, size_t length,
    const yespower_params_t *params, const uint8_t *expected)
{
    yespower_binary_t ref, got, tls_ref, tls_got;
    errno = 0;
    int a = reference_yespower(&reference_local, input, length, params, &ref), ea = errno;
    errno = 0;
    int b = yespower(&candidate_local, input, length, params, &got), eb = errno;
    if (a != b || (a && ea != eb)) fail(label, "return code or errno differs");
    if (a) fail(label, "valid vector failed");
    if (memcmp(ref.uc, got.uc, 32)) fail(label, "baseline and candidate hashes differ");
    if (expected && memcmp(expected, got.uc, 32)) fail(label, "known hash differs");
    if ((checked % 16) == 0) {
        if (reference_yespower_tls(input, length, params, &tls_ref) ||
            yespower_tls(input, length, params, &tls_got)) fail(label, "TLS failed");
        if (memcmp(tls_ref.uc, ref.uc, 32) || memcmp(tls_got.uc, ref.uc, 32)) fail(label, "TLS differs");
    }
    ++checked;
}

static double now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) fail("clock", "clock_gettime");
    return t.tv_sec + t.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    if (argc != 2) fail("usage", "yespower-differential headers.txt");
    if (reference_yespower_init_local(&reference_local) || yespower_init_local(&candidate_local)) fail("init", "failed");
    FILE *f = fopen(argv[1], "r");
    if (!f) fail("fixture", "cannot open");
    uint8_t headers[104][80];
    size_t count = 0;
    char label[96], hex[161], expected_hex[65];
    const yespower_params_t sugar_params = {YESPOWER_1_0, 2048, 32, sugar, sizeof(sugar) - 1};
    while (fscanf(f, "%95s %160s %64s", label, hex, expected_hex) == 3) {
        uint8_t expected[32];
        if (count >= 104 || unhex(hex, headers[count]) != 80) fail("fixture", "wrong header count or size");
        const int known = strcmp(expected_hex, "-") != 0;
        if (known && unhex(expected_hex, expected) != 32) fail("fixture", "wrong digest size");
        check(label, headers[count++], 80, &sugar_params, known ? expected : NULL);
    }
    fclose(f);
    if (count != 104) fail("fixture", "missing headers");

    static const size_t lengths[] = {0, 1, 31, 32, 63, 64, 79, 80, 81, 128, 255, 256};
    uint8_t storage[260];
    uint32_t random = 0x6217055;
    for (size_t i = 0; i < sizeof(storage); ++i) {
        random ^= random << 13; random ^= random >> 17; random ^= random << 5;
        storage[i] = (uint8_t)random;
    }
    for (int version = 0; version < 2; ++version) {
        for (unsigned n = 1024; n <= 4096; n *= 2) {
            for (unsigned r = 8; r <= 32; r += 8) {
                for (unsigned p = 0; p < 3; ++p) {
                    yespower_params_t params = {version ? YESPOWER_1_0 : YESPOWER_0_5, n, r,
                        p == 0 ? NULL : p == 1 ? personal : sugar,
                        p == 0 ? 0 : p == 1 ? sizeof(personal) : sizeof(sugar) - 1};
                    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
                        snprintf(label, sizeof(label), "v%d-N%u-r%u-p%u-len%zu", params.version, n, r, p, lengths[i]);
                        check(label, storage + (i % 3), lengths[i], &params, NULL);
                    }
                }
            }
        }
    }
    printf("PASS: %zu vectors, both versions, N1024..4096, r8..32, personalization and unaligned lengths, TLS reuse\n", checked);

    volatile uint8_t sink = 0;
    for (unsigned repeat = 0; repeat < 3; ++repeat) {
        for (unsigned pass = 0; pass < 2; ++pass) {
            const unsigned candidate = pass ^ (repeat & 1);
            yespower_binary_t hash;
            double start = now();
            for (size_t i = 2; i < count; ++i) {
                int rc = candidate ? yespower(&candidate_local, headers[i], 80, &sugar_params, &hash) :
                    reference_yespower(&reference_local, headers[i], 80, &sugar_params, &hash);
                if (rc) fail("timing", "hash failed");
                sink ^= hash.uc[0];
            }
            printf("TIMING repeat=%u implementation=%s headers=102 seconds=%.9f\n", repeat + 1, candidate ? "candidate" : "reference", now() - start);
        }
    }
    if (reference_yespower_free_local(&reference_local) || yespower_free_local(&candidate_local)) fail("free", "failed");
    printf("DONE sink=%u\n", sink);
    return 0;
}
