#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct page_probe_stats {
    uint64_t frequency;
    uint64_t alloc_ticks;
    size_t base_size;
    int calls;
    int hint_attempts;
    int hint_successes;
    int hint_fallbacks;
    uint32_t hint_error;
};

struct page_probe_api {
    const char *module;
    uint32_t kernel32_lookup_error;
    uint32_t kernelbase_lookup_error;
    int lookup_attempted;
    int available;
};

int page_probe_configure(int allocator);
void page_probe_get_stats(struct page_probe_stats *result);
void page_probe_get_api(struct page_probe_api *result);

#ifdef __cplusplus
}
#endif
