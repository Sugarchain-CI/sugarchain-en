#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { RECORD_BYTES = 256, RECORDS = 10000, ROUNDS = 5 };
typedef enum { WRITE_REOPEN, WRITE_RETAIN, READ_REOPEN, READ_RETAIN, MODE_COUNT } Mode;

static void check(int condition, const char *operation)
{
    if (condition) return;
    perror(operation);
    exit(EXIT_FAILURE);
}

static double seconds(void)
{
    struct timespec time;
    check(clock_gettime(CLOCK_MONOTONIC, &time) == 0, "clock_gettime");
    return (double)time.tv_sec + (double)time.tv_nsec * 1e-9;
}

static FILE *open_file(const char *path, const char *mode)
{
    FILE *stream = fopen(path, mode);
    check(stream != NULL, "fopen");
    return stream;
}

static double measure(const char *path, Mode mode, unsigned char *buffer)
{
    const int write = mode == WRITE_REOPEN || mode == WRITE_RETAIN;
    const int retain = mode == WRITE_RETAIN || mode == READ_RETAIN;
    const char *file_mode = write ? "rb+" : "rb";
    double start = seconds();
    FILE *stream = retain ? open_file(path, file_mode) : NULL;
    for (int i = 0; i < RECORDS; ++i) {
        if (!retain) stream = open_file(path, file_mode);
        check(fseek(stream, (long)i * RECORD_BYTES, SEEK_SET) == 0, "fseek");
        check(ftell(stream) == (long)i * RECORD_BYTES, "ftell");
        if (write) {
            check(fwrite(buffer, 1, RECORD_BYTES, stream) == RECORD_BYTES, "fwrite");
            if (retain) check(fflush(stream) == 0, "fflush");
        } else {
            check(fread(buffer, 1, RECORD_BYTES, stream) == RECORD_BYTES, "fread");
        }
        if (!retain) check(fclose(stream) == 0, "fclose");
    }
    if (retain) check(fclose(stream) == 0, "fclose");
    return (seconds() - start) * 1e6 / RECORDS;
}

int main(int argc, char **argv)
{
    if (argc != 2) return EXIT_FAILURE;
    unsigned char buffer[RECORD_BYTES];
    memset(buffer, 0xe3, sizeof(buffer));
    FILE *stream = open_file(argv[1], "wb");
    for (int i = 0; i < RECORDS; ++i) {
        check(fwrite(buffer, 1, RECORD_BYTES, stream) == RECORD_BYTES, "initialize fixture");
    }
    check(fclose(stream) == 0, "close fixture");

    const char *names[MODE_COUNT] = {"write_reopen", "write_retain", "read_reopen", "read_retain"};
    puts("round,mode,records,us_per_record");
    for (int round = 0; round < ROUNDS; ++round) {
        for (unsigned i = 0; i < MODE_COUNT; ++i) {
            const Mode mode = (Mode)((i + (unsigned)round) % MODE_COUNT);
            const double result = measure(argv[1], mode, buffer);
            printf("%d,%s,%d,%.6f\n", round + 1, names[mode], RECORDS, result);
        }
    }
    check(remove(argv[1]) == 0, "remove fixture");
    return EXIT_SUCCESS;
}
