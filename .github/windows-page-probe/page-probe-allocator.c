/* Standalone Windows diagnostic allocator, substituted only in private probes. */
#include <windows.h>
#include "page-probe.h"

#ifndef MEM_64K_PAGES
#define MEM_64K_PAGES 0x20400000
#endif

typedef PVOID (WINAPI *virtual_alloc2_fn)(HANDLE, PVOID, SIZE_T, ULONG, ULONG,
                                         MEM_EXTENDED_PARAMETER *, ULONG);

static int probe_allocator;
static virtual_alloc2_fn alloc2;
static uint64_t counter_frequency;
static __thread struct page_probe_stats thread_stats;
static struct page_probe_api api;

static FARPROC lookup_virtual_alloc2(const wchar_t *library, uint32_t *error)
{
    SetLastError(ERROR_SUCCESS);
    HMODULE module = GetModuleHandleW(library);
    FARPROC symbol = module ? GetProcAddress(module, "VirtualAlloc2") : NULL;
    if (!symbol) *error = GetLastError();
    return symbol;
}

int page_probe_configure(int allocator)
{
    LARGE_INTEGER frequency;
    if (allocator < 0 || allocator > 3 || !QueryPerformanceFrequency(&frequency))
        return -1;
    probe_allocator = allocator;
    counter_frequency = frequency.QuadPart;
    if (allocator == 2) {
        api.lookup_attempted = 1;
        FARPROC symbol = lookup_virtual_alloc2(L"kernel32.dll", &api.kernel32_lookup_error);
        if (symbol) {
            api.module = "kernel32.dll";
        } else {
            symbol = lookup_virtual_alloc2(L"kernelbase.dll", &api.kernelbase_lookup_error);
            if (symbol) api.module = "kernelbase.dll";
        }
        api.available = symbol != NULL;
        _Static_assert(sizeof(symbol) == sizeof(alloc2), "Unexpected Win32 function pointer size");
        memcpy(&alloc2, &symbol, sizeof(alloc2));
    }
    return 0;
}

void page_probe_get_stats(struct page_probe_stats *result)
{
    *result = thread_stats;
}

void page_probe_get_api(struct page_probe_api *result)
{
    *result = api;
}

static void init_region(yespower_region_t *region)
{
    region->base = region->aligned = NULL;
    region->base_size = region->aligned_size = 0;
}

static void *alloc_region(yespower_region_t *region, size_t size)
{
    const size_t alignment = 65536;
    const int is_virtual = probe_allocator != 0;
    const size_t extra = is_virtual ? alignment - 1 : 63;
    init_region(region);
    if (size > SIZE_MAX - extra) {
        errno = ENOMEM;
        return NULL;
    }
    const size_t base_size = is_virtual ? (size + extra) & ~extra : size + extra;
    LARGE_INTEGER begin, end;
    QueryPerformanceCounter(&begin);
    uint8_t *base = NULL;
    if (probe_allocator >= 2) {
        if (alloc2) {
            HANDLE process = GetCurrentProcess();
            thread_stats.hint_attempts++;
            SetLastError(ERROR_SUCCESS);
            base = alloc2(process, NULL, base_size,
                          MEM_RESERVE | MEM_COMMIT | MEM_64K_PAGES, PAGE_READWRITE, NULL, 0);
            if (!base) thread_stats.hint_error = GetLastError();
        }
        if (base)
            thread_stats.hint_successes++;
        else
            thread_stats.hint_fallbacks++;
    }
    if (!base) {
        base = is_virtual ? VirtualAlloc(NULL, base_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
                          : malloc(base_size);
    }
    QueryPerformanceCounter(&end);
    thread_stats.frequency = counter_frequency;
    thread_stats.alloc_ticks += end.QuadPart - begin.QuadPart;
    thread_stats.base_size = base_size;
    thread_stats.calls++;
    if (!base) {
        errno = ENOMEM;
        return NULL;
    }
    region->base = base;
    region->aligned = is_virtual ? base : (void *)(((uintptr_t)base + 63) & ~(uintptr_t)63);
    region->base_size = base_size;
    region->aligned_size = size;
    return region->aligned;
}

static int free_region(yespower_region_t *region)
{
    if (region->base) {
        if (probe_allocator != 0) {
            if (!VirtualFree(region->base, 0, MEM_RELEASE)) return -1;
        } else {
            free(region->base);
        }
    }
    init_region(region);
    return 0;
}
