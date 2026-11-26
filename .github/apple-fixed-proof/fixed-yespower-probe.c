#include "fixed-probe.h"
#include "probe-clock.h"
#include "sha256.h"
#include "sugar-params.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_HEADERS 32768
#define MAX_WORKERS 8
#define MAX_REPEATS 6
#define CHECK_AUTHENTIC_LIMIT 256

enum arm { GENERIC, FIXED };
static const char *const arm_names[] = {"generic", "fixed"};

typedef int (*proof_function)(yespower_local_t *, const uint8_t *, size_t, const yespower_params_t *, yespower_binary_t *);
/* One identical indirect call in both arms. The address is read before timing,
 * and the production C reference is never marked noinline or modified. */
static proof_function volatile entries[] = {yespower, fixed_sugar_probe};

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

static void differential(yespower_local_t locals[2], const uint8_t *header, size_t bytes,
    const yespower_params_t *params, int expected_code, int authentic)
{
    yespower_binary_t result[2];
    int condition[2], errors[2];
    for (size_t arm = GENERIC; arm <= FIXED; ++arm) {
        errno = 0;
        memset(&result[arm], 0, sizeof(result[arm]));
        condition[arm] = entries[arm](&locals[arm], header, bytes, params, &result[arm]);
        errors[arm] = condition[arm] ? errno : 0;
        require(condition[arm] == expected_code, "Incorrect generic or fixed proof return value");
    }
    require(errors[GENERIC] == errors[FIXED] &&
        memcmp(result[GENERIC].uc, result[FIXED].uc, sizeof(result[GENERIC].uc)) == 0,
        "Fixed proof differs from runtime-parameter production oracle");
    if (expected_code == -1) {
        require(errors[GENERIC] == EINVAL, "Malformed parameters did not produce EINVAL");
        for (size_t i = 0; i < sizeof(result[GENERIC].uc); ++i)
            require(result[GENERIC].uc[i] == 0xff, "Malformed parameters did not produce the failure sentinel");
    }
    if (authentic)
        require(valid_mainnet_proof(header, &result[GENERIC]), "Authentic production proof exceeds claimed target");
}

static void run_checks(const uint8_t *headers, size_t count)
{
    yespower_local_t locals[2];
    require(yespower_init_local(&locals[GENERIC]) == 0 && yespower_init_local(&locals[FIXED]) == 0,
        "Could not initialize scratch contexts");
    const size_t authentic = count < CHECK_AUTHENTIC_LIMIT ? count : CHECK_AUTHENTIC_LIMIT;
    for (size_t i = 0; i < authentic; ++i)
        differential(locals, headers + i * PROBE_HEADER_BYTES, PROBE_HEADER_BYTES, &probe_params, 0, 1);
    uint32_t random = UINT32_C(0xbb67ae85);
    uint8_t vector[PROBE_HEADER_BYTES];
    for (size_t example = 0; example < 32; ++example) {
        for (size_t i = 0; i < sizeof(vector); ++i) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            vector[i] = (uint8_t)random;
        }
        differential(locals, vector, sizeof(vector), &probe_params, 0, 0);
    }
    yespower_params_t invalid[] = {probe_params, probe_params, probe_params, probe_params};
    invalid[0].version = (yespower_version_t)0;
    invalid[1].N = 3;
    invalid[2].r = 5;
    invalid[3].pers = NULL;
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        differential(locals, headers, PROBE_HEADER_BYTES, &invalid[i], -1, 0);

    // Valid non-Sugar inputs must retain the existing generic API behavior.
    yespower_params_t other = probe_params;
    const uint8_t salt[] = "independent fallback salt";
    other.pers = salt;
    other.perslen = sizeof(salt) - 1;
    differential(locals, headers, PROBE_HEADER_BYTES, &other, 0, 0);
    differential(locals, headers, PROBE_HEADER_BYTES - 1, &probe_params, 0, 0);
    other.version = YESPOWER_0_5;
    other.N = 1024;
    other.r = 8;
    differential(locals, headers, PROBE_HEADER_BYTES, &other, 0, 0);
    require(yespower_free_local(&locals[GENERIC]) == 0 && yespower_free_local(&locals[FIXED]) == 0,
        "Could not release owned scratch contexts");
    printf("{\"status\":\"verified\",\"authentic_headers\":%zu,\"deterministic_headers\":32,\"individual_error_cases\":4,\"valid_fallback_cases\":3}\n", authentic);
}

struct worker {
    const uint8_t *headers;
    yespower_binary_t *proofs;
    size_t begin, end;
    int repeats;
    proof_function call;
    uint64_t cpu_ns;
};

static uint64_t clock_ns(clockid_t clock)
{
    uint64_t sample;
    require(probe_clock_ns(clock, &sample), "Could not sample benchmark clock");
    return sample;
}

static uint64_t clock_delta(clockid_t clock, uint64_t start)
{
    const uint64_t end = clock_ns(clock);
    require(end >= start, "Benchmark clock ran backwards");
    return end - start;
}

static void *run_worker(void *pointer)
{
    struct worker *const task = pointer;
    yespower_local_t local;
    require(yespower_init_local(&local) == 0, "Could not initialize owned proof scratch");
    const uint64_t start = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    for (int pass = 0; pass < task->repeats; ++pass) {
        for (size_t i = task->begin; i < task->end; ++i) {
            require(task->call(&local, task->headers + i * PROBE_HEADER_BYTES, PROBE_HEADER_BYTES,
                &probe_params, &task->proofs[i]) == 0, "Benchmark proof failed");
        }
    }
    task->cpu_ns = clock_delta(CLOCK_THREAD_CPUTIME_ID, start);
    require(yespower_free_local(&local) == 0, "Could not release owned proof scratch");
    return NULL;
}

static void run_benchmark(enum arm arm, const uint8_t *headers, size_t count, int repeats, int workers)
{
    pthread_t threads[MAX_WORKERS];
    struct worker tasks[MAX_WORKERS];
    yespower_binary_t *proofs = malloc(count * sizeof(*proofs));
    require(proofs != NULL && count >= (size_t)workers, "Insufficient headers or benchmark memory");
    const proof_function entry = entries[arm];
    for (int i = 0; i < workers; ++i) {
        tasks[i] = (struct worker){.headers = headers, .proofs = proofs,
            .begin = count * (size_t)i / (size_t)workers, .end = count * (size_t)(i + 1) / (size_t)workers,
            .repeats = repeats, .call = entry};
    }
    uint64_t thread_resolution, wall_resolution;
    require(probe_clock_resolution_ns(CLOCK_THREAD_CPUTIME_ID, &thread_resolution) &&
        probe_clock_resolution_ns(CLOCK_MONOTONIC, &wall_resolution), "Could not get benchmark clock resolution");
    const uint64_t start_wall = clock_ns(CLOCK_MONOTONIC);
    const uint64_t start_main_cpu = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    uint64_t start_process_cpu = 0, end_process_cpu = 0;
    const bool have_process_cpu = probe_clock_ns(CLOCK_PROCESS_CPUTIME_ID, &start_process_cpu);
    for (int i = 0; i < workers; ++i)
        require(pthread_create(&threads[i], NULL, run_worker, &tasks[i]) == 0, "Could not create owned benchmark worker");
    for (int i = 0; i < workers; ++i)
        require(pthread_join(threads[i], NULL) == 0, "Could not join owned benchmark worker");
    const uint64_t main_cpu = clock_delta(CLOCK_THREAD_CPUTIME_ID, start_main_cpu);
    const bool have_process_delta = have_process_cpu && probe_clock_ns(CLOCK_PROCESS_CPUTIME_ID, &end_process_cpu) &&
        start_process_cpu <= INT64_MAX && end_process_cpu <= INT64_MAX;
    const uint64_t wall = clock_delta(CLOCK_MONOTONIC, start_wall);
    uint64_t worker_total = 0;
    for (int i = 0; i < workers; ++i) {
        require(tasks[i].cpu_ns <= UINT64_MAX - worker_total, "Worker CPU total overflow");
        worker_total += tasks[i].cpu_ns;
    }
    uint8_t digest[32];
    SHA256_Buf(proofs, count * sizeof(*proofs), digest);
    printf("{\"arm\":\"%s\",\"workers\":%d,\"headers\":%zu,\"repeats\":%d,\"wall_ns\":%" PRIu64
        ",\"thread_clock_resolution_ns\":%" PRIu64 ",\"wall_clock_resolution_ns\":%" PRIu64
        ",\"main_thread_cpu_ns\":%" PRIu64 ",\"worker_cpu_total_ns\":%" PRIu64 ",\"worker_cpu_ns\":[",
        arm_names[arm], workers, count, repeats, wall, thread_resolution, wall_resolution, main_cpu, worker_total);
    for (int i = 0; i < workers; ++i)
        printf("%s%" PRIu64, i ? "," : "", tasks[i].cpu_ns);
    printf("],\"diagnostic_process_cpu_ns\":");
    if (have_process_delta)
        printf("%" PRId64, (int64_t)end_process_cpu - (int64_t)start_process_cpu);
    else
        printf("null");
    printf(",\"proof_digest\":\"");
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
        for (int arm = GENERIC; arm <= FIXED; ++arm) {
            if (strcmp(argv[2], arm_names[arm]) != 0)
                continue;
            uint8_t *headers = read_headers(argv[3], &count);
            run_benchmark(arm, headers, count, bounded_number(argv[4], MAX_REPEATS), argc == 6 ? bounded_number(argv[5], MAX_WORKERS) : 1);
            free(headers);
            return 0;
        }
    }
    fail("Usage: fixed_yespower_probe check HEADERS | bench generic|fixed HEADERS REPEATS [WORKERS]");
}
