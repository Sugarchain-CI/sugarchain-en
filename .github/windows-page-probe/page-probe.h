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
    int hint_successes;
    int hint_fallbacks;
};

int page_probe_configure(int allocator);
void page_probe_get_stats(struct page_probe_stats *result);

#ifdef __cplusplus
}
#endif
