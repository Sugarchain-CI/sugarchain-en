#ifndef SUGARCHAIN_PROBE_CLOCK_H
#define SUGARCHAIN_PROBE_CLOCK_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

static inline bool probe_timespec_ns(const struct timespec *value, uint64_t *out)
{
    const uint64_t second = UINT64_C(1000000000);
    if (value->tv_sec < 0 || value->tv_nsec < 0 || value->tv_nsec >= (long)second)
        return false;
    const uint64_t nanoseconds = (uint64_t)value->tv_nsec;
    if ((uintmax_t)value->tv_sec > (UINT64_MAX - nanoseconds) / second)
        return false;
    *out = (uint64_t)value->tv_sec * second + nanoseconds;
    return true;
}

static inline bool probe_clock_ns(clockid_t clock, uint64_t *out)
{
    struct timespec value;
    return clock_gettime(clock, &value) == 0 && probe_timespec_ns(&value, out);
}

static inline bool probe_clock_resolution_ns(clockid_t clock, uint64_t *out)
{
    struct timespec value;
    return clock_getres(clock, &value) == 0 && probe_timespec_ns(&value, out) && *out > 0;
}

#endif
