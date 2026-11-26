#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>

#include "yespower.h"

enum { WORKERS = 8, HEADERS = 8192, HEADER_BYTES = 80 };

static uint8_t headers[HEADERS][HEADER_BYTES];
static yespower_binary_t proofs[HEADERS];
static const uint8_t personalization[] =
    "Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote";
static const yespower_params_t params = {
    YESPOWER_1_0, 2048, 32, personalization, sizeof(personalization) - 1,
};

static double seconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) exit(2);
    return now.tv_sec + now.tv_nsec * 1e-9;
}

static double cpu_seconds(const struct rusage *usage)
{
    return usage->ru_utime.tv_sec + usage->ru_utime.tv_usec * 1e-6 +
        usage->ru_stime.tv_sec + usage->ru_stime.tv_usec * 1e-6;
}

static void *worker(void *argument)
{
    unsigned position = *(const unsigned *)argument;
    yespower_local_t local;
    if (yespower_init_local(&local)) exit(2);
    for (unsigned i = position; i < HEADERS; i += WORKERS) {
        if (yespower(&local, headers[i], HEADER_BYTES, &params, &proofs[i])) exit(2);
    }
    if (yespower_free_local(&local)) exit(2);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    FILE *input = fopen(argv[1], "rb");
    if (!input || fread(headers, sizeof(headers), 1, input) != 1 || fgetc(input) != EOF ||
        fclose(input)) return 2;

    pthread_t children[WORKERS - 1];
    unsigned positions[WORKERS];
    struct rusage before, after;
    if (getrusage(RUSAGE_SELF, &before)) return 2;
    const double start = seconds();
    for (unsigned index = 0; index < WORKERS - 1; ++index) {
        positions[index] = index;
        if (pthread_create(&children[index], NULL, worker, &positions[index])) return 2;
    }
    positions[WORKERS - 1] = WORKERS - 1;
    worker(&positions[WORKERS - 1]);
    for (unsigned index = 0; index < WORKERS - 1; ++index) {
        if (pthread_join(children[index], NULL)) return 2;
    }
    const double wall = seconds() - start;
    if (getrusage(RUSAGE_SELF, &after)) return 2;
    const double cpu = cpu_seconds(&after) - cpu_seconds(&before);
    printf("{\"headers\":%d,\"workers\":%d,\"wall\":%.9f,\"cpu\":%.9f}\n", HEADERS, WORKERS, wall, cpu);

    FILE *output = fopen(argv[2], "wb");
    if (!output || fwrite(proofs, sizeof(proofs), 1, output) != 1 || fclose(output)) return 2;
    return 0;
}
