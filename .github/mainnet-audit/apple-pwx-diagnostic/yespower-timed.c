#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include "yespower.h"

static double seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) exit(2);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    FILE *input = fopen(argv[1], "rb");
    if (!input) return 2;
    uint8_t headers[256][80];
    if (fread(headers, sizeof(headers), 1, input) != 1 || fgetc(input) != EOF) return 2;
    fclose(input);
    static const uint8_t personalization[] =
        "Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote";
    const yespower_params_t params = {YESPOWER_1_0, 2048, 32, personalization, sizeof(personalization) - 1};
    yespower_binary_t reference[256], hashes[256];
    printf("{\"headers\":256,\"samples\":[");
    for (int repeat = 0; repeat < 1; ++repeat) {
        yespower_local_t local;
        if (yespower_init_local(&local)) return 2;
        struct rusage before, after;
        if (getrusage(RUSAGE_SELF, &before)) return 2;
        const double start = seconds();
        for (size_t i = 0; i < 256; ++i) {
            if (yespower(&local, headers[i], 80, &params, &hashes[i])) return 2;
        }
        const double elapsed = seconds() - start;
        if (getrusage(RUSAGE_SELF, &after)) return 2;
        const double cpu = (after.ru_utime.tv_sec - before.ru_utime.tv_sec) +
            (after.ru_utime.tv_usec - before.ru_utime.tv_usec) * 1e-6 +
            (after.ru_stime.tv_sec - before.ru_stime.tv_sec) +
            (after.ru_stime.tv_usec - before.ru_stime.tv_usec) * 1e-6;
        if (yespower_free_local(&local)) return 2;
        if (!repeat) memcpy(reference, hashes, sizeof(reference));
        else if (memcmp(reference, hashes, sizeof(reference))) return 2;
        printf("%s{\"wall\":%.9f,\"cpu\":%.9f}", repeat ? "," : "", elapsed, cpu);
        fflush(stdout);
    }
    printf("]}\n");
    FILE *output = fopen(argv[2], "wb");
    if (!output || fwrite(reference, sizeof(reference), 1, output) != 1 || fclose(output)) return 2;
    return 0;
}
