#include "paired-probe.h"
#include "sha256.h"
#include "sugar-params.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_HEADERS 32768
#define MAX_WORKERS 8
#define MAX_REPEATS 6
#define CHECK_AUTHENTIC_LIMIT 256

enum arm { SINGLE, ALTERNATING, PAIRED, PAIRED_HINT };
static const char *const arm_names[] = {"single", "alternating", "paired", "paired-hint"};

static void fail(const char *reason)
{
    fprintf(stderr, "%s\n", reason);
    exit(1);
}

static void require(int condition, const char *reason)
{
    if (!condition)
        fail(reason);
}

static uint8_t *read_headers(const char *path, size_t *count)
{
    FILE *file = fopen(path, "rb");
    require(file != NULL && fseek(file, 0, SEEK_END) == 0, "Could not open raw header fixture");
    long length = ftell(file);
    require(length > 0 && length <= MAX_HEADERS * PROBE_HEADER_BYTES && length % (2 * PROBE_HEADER_BYTES) == 0,
        "Expected an even positive count of 80-byte headers within the fixture cap");
    require(fseek(file, 0, SEEK_SET) == 0, "Could not rewind header fixture");
    uint8_t *headers = malloc((size_t)length);
    require(headers != NULL && fread(headers, 1, (size_t)length, file) == (size_t)length && fgetc(file) == EOF && !ferror(file),
        "Could not read exact fixture bytes");
    require(fclose(file) == 0, "Could not close fixture");
    *count = (size_t)length / PROBE_HEADER_BYTES;
    return headers;
}

static int valid_mainnet_proof(const uint8_t *header, const yespower_binary_t *proof)
{
    uint8_t target[32] = {0};
    const uint32_t mantissa = (uint32_t)header[72] | (uint32_t)header[73] << 8 | (uint32_t)(header[74] & 0x7f) << 16;
    const uint8_t exponent = header[75];
    if ((header[74] & 0x80) || !mantissa || exponent < 3 || exponent > sizeof(target))
        return 0;
    for (size_t i = 0; i < 3; ++i)
        target[exponent - 3 + i] = (uint8_t)(mantissa >> (8 * i));
    for (size_t i = sizeof(target); i > 0; --i) {
        if (proof->uc[i - 1] != target[i - 1])
            return proof->uc[i - 1] < target[i - 1];
    }
    return 1;
}

static void init_pair(yespower_local_t locals[2])
{
    require(yespower_init_local(&locals[0]) == 0 && yespower_init_local(&locals[1]) == 0, "Could not initialize scratch contexts");
}

static void leave_pair(yespower_local_t locals[2])
{
    require(yespower_free_local(&locals[0]) == 0 && yespower_free_local(&locals[1]) == 0, "Could not release owned scratch contexts");
}

static void differential(yespower_local_t controls[2], yespower_local_t experiments[2], const uint8_t *headers,
    const yespower_params_t *params0, const yespower_params_t *params1, int authentic)
{
    paired_probe_lane oracle[2] = {
        {.local = &controls[0], .header = headers, .header_bytes = PROBE_HEADER_BYTES, .params = params0},
        {.local = &controls[1], .header = headers + PROBE_HEADER_BYTES, .header_bytes = PROBE_HEADER_BYTES, .params = params1},
    };
    for (size_t i = 0; i < 2; ++i) {
        paired_probe_lane *lane = &oracle[i];
        lane->result = yespower(lane->local, lane->header, lane->header_bytes, lane->params, &lane->proof);
        lane->error_number = lane->result ? errno : 0;
        if (authentic)
            require(lane->result == 0 && valid_mainnet_proof(lane->header, &lane->proof), "Authentic reference proof exceeds claimed target");
    }
    for (int hints = 0; hints <= 1; ++hints) {
        paired_probe_lane actual[2] = {oracle[0], oracle[1]};
        for (size_t i = 0; i < 2; ++i) {
            actual[i].local = &experiments[i];
            actual[i].result = 999;
            actual[i].error_number = 999;
            memset(&actual[i].proof, 0, sizeof(actual[i].proof));
        }
        paired_probe_hash(actual, hints);
        for (size_t i = 0; i < 2; ++i)
            require(actual[i].result == oracle[i].result && actual[i].error_number == oracle[i].error_number &&
                memcmp(actual[i].proof.uc, oracle[i].proof.uc, sizeof(actual[i].proof.uc)) == 0, "Independent lane differs from production oracle");
    }
}

static void run_checks(const uint8_t *headers, size_t count)
{
    yespower_local_t controls[2], experiments[2];
    init_pair(controls);
    init_pair(experiments);
    const size_t authentic = count < CHECK_AUTHENTIC_LIMIT ? count : CHECK_AUTHENTIC_LIMIT;
    for (size_t i = 0; i < authentic; i += 2)
        differential(controls, experiments, headers + i * PROBE_HEADER_BYTES, &probe_params, &probe_params, 1);
    uint32_t random = UINT32_C(0xbb67ae85);
    uint8_t vector[2 * PROBE_HEADER_BYTES];
    for (size_t pair = 0; pair < 16; ++pair) {
        for (size_t i = 0; i < sizeof(vector); ++i) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            vector[i] = (uint8_t)random;
        }
        differential(controls, experiments, vector, &probe_params, &probe_params, 0);
    }
    yespower_params_t invalid[] = {probe_params, probe_params, probe_params, probe_params};
    invalid[0].version = (yespower_version_t)0;
    invalid[1].N = 3;
    invalid[2].r = 5;
    invalid[3].pers = NULL;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        differential(controls, experiments, headers, &invalid[i], &probe_params, 0);
        differential(controls, experiments, headers, &probe_params, &invalid[i], 0);
    }
    leave_pair(controls);
    leave_pair(experiments);
    printf("{\"status\":\"verified\",\"authentic_headers\":%zu,\"deterministic_headers\":32,\"individual_error_cases\":8}\n", authentic);
}

struct worker {
    const uint8_t *headers;
    yespower_binary_t *proofs;
    size_t begin, end;
    int repeats;
    enum arm arm;
};

static void *run_worker(void *pointer)
{
    const struct worker *const task = pointer;
    yespower_local_t locals[2];
    init_pair(locals);
    for (int pass = 0; pass < task->repeats; ++pass) {
        for (size_t i = task->begin; i < task->end; i += 2) {
            const uint8_t *const raw = task->headers + i * PROBE_HEADER_BYTES;
            if (task->arm >= PAIRED) {
                paired_probe_lane lanes[2] = {
                    {.local = &locals[0], .header = raw, .header_bytes = PROBE_HEADER_BYTES, .params = &probe_params},
                    {.local = &locals[1], .header = raw + PROBE_HEADER_BYTES, .header_bytes = PROBE_HEADER_BYTES, .params = &probe_params},
                };
                paired_probe_hash(lanes, task->arm == PAIRED_HINT);
                for (size_t lane = 0; lane < 2; ++lane) {
                    require(lanes[lane].result == 0, "Paired benchmark proof failed");
                    task->proofs[i + lane] = lanes[lane].proof;
                }
            } else {
                for (size_t lane = 0; lane < 2; ++lane) {
                    yespower_local_t *const local = &locals[task->arm == SINGLE ? 0 : lane];
                    require(yespower(local, raw + lane * PROBE_HEADER_BYTES, PROBE_HEADER_BYTES,
                        &probe_params, &task->proofs[i + lane]) == 0, "Production benchmark proof failed");
                }
            }
        }
    }
    leave_pair(locals);
    return NULL;
}

static double clock_seconds(clockid_t clock)
{
    struct timespec now;
    require(clock_gettime(clock, &now) == 0, "Could not sample benchmark clock");
    return (double)now.tv_sec + (double)now.tv_nsec * 1e-9;
}

static void run_benchmark(enum arm arm, const uint8_t *headers, size_t count, int repeats, int workers)
{
    pthread_t threads[MAX_WORKERS];
    struct worker tasks[MAX_WORKERS];
    yespower_binary_t *proofs = malloc(count * sizeof(*proofs));
    require(proofs != NULL && count / 2 >= (size_t)workers, "Insufficient headers or benchmark memory");
    const size_t pairs = count / 2;
    double start_wall = clock_seconds(CLOCK_MONOTONIC);
    double start_cpu = clock_seconds(CLOCK_PROCESS_CPUTIME_ID);
    for (int i = 0; i < workers; ++i) {
        tasks[i] = (struct worker){.headers = headers, .proofs = proofs,
            .begin = 2 * (pairs * (size_t)i / (size_t)workers),
            .end = 2 * (pairs * (size_t)(i + 1) / (size_t)workers), .repeats = repeats, .arm = arm};
        require(pthread_create(&threads[i], NULL, run_worker, &tasks[i]) == 0, "Could not create owned benchmark worker");
    }
    for (int i = 0; i < workers; ++i)
        require(pthread_join(threads[i], NULL) == 0, "Could not join owned benchmark worker");
    double cpu = clock_seconds(CLOCK_PROCESS_CPUTIME_ID) - start_cpu;
    double wall = clock_seconds(CLOCK_MONOTONIC) - start_wall;
    require(cpu > 0 && wall > 0, "Invalid benchmark timing");
    uint8_t digest[32];
    SHA256_Buf(proofs, count * sizeof(*proofs), digest);
    printf("{\"arm\":\"%s\",\"workers\":%d,\"headers\":%zu,\"repeats\":%d,\"cpu_seconds\":%.9f,\"wall_seconds\":%.9f,\"proof_digest\":\"",
        arm_names[arm], workers, count, repeats, cpu, wall);
    for (size_t i = 0; i < sizeof(digest); ++i)
        printf("%02x", digest[i]);
    printf("\"}\n");
    free(proofs);
}

static int bounded_number(const char *argument, int limit)
{
    char *end = NULL;
    errno = 0;
    long value = strtol(argument, &end, 10);
    require(!errno && *argument && *end == '\0' && value > 0 && value <= limit, "Out-of-range benchmark option");
    return (int)value;
}

int main(int argc, char **argv)
{
    size_t count;
    if (argc == 3 && strcmp(argv[1], "check") == 0) {
        uint8_t *headers = read_headers(argv[2], &count);
        run_checks(headers, count);
        free(headers);
        return 0;
    }
    if ((argc == 5 || argc == 6) && strcmp(argv[1], "bench") == 0) {
        for (int arm = SINGLE; arm <= PAIRED_HINT; ++arm) {
            if (strcmp(argv[2], arm_names[arm]) != 0)
                continue;
            uint8_t *headers = read_headers(argv[3], &count);
            run_benchmark(arm, headers, count, bounded_number(argv[4], MAX_REPEATS), argc == 6 ? bounded_number(argv[5], MAX_WORKERS) : 1);
            free(headers);
            return 0;
        }
    }
    fail("Usage: paired_yespower_probe check HEADERS | bench single|alternating|paired|paired-hint HEADERS REPEATS [WORKERS]");
}
