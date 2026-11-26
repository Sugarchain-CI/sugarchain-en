#include "yespower.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <latch>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#ifdef SC_PAGE_PROBE
#include "page-probe.h"
#endif

using Clock = std::chrono::steady_clock;
using Seconds = std::chrono::duration<double>;
using Header = std::array<uint8_t, 80>;

struct WorkerResult {
    Clock::time_point end;
    double first_proof{};
    uint64_t allocation_ticks{};
    uint64_t allocation_frequency{};
    size_t allocation_size{};
    int allocation_calls{};
    int hint_attempts{};
    int hint_successes{};
    int hint_fallbacks{};
    uint32_t hint_error{};
    bool passed{};
};

int main(int argc, char** argv) try
{
    if (argc != 5) throw std::runtime_error("Usage: proof-probe <headers.bin> <digests.bin> <workers> <mode>");
    const std::string_view workers_arg{argv[3]};
    int workers{};
    const auto parsed{std::from_chars(workers_arg.begin(), workers_arg.end(), workers)};
    if (parsed.ec != std::errc{} || parsed.ptr != workers_arg.end() || workers < 1 || workers > 16) {
        throw std::runtime_error("Expected a worker count from 1 to 16");
    }
    const std::string_view mode{argv[4]};
#ifdef SC_PAGE_PROBE
    const int allocator{mode == "malloc" ? 0 : mode == "pages" ? 1 : mode == "page64" ? 2 : mode == "page64-fallback" ? 3 : -1};
    if (allocator < 0 || page_probe_configure(allocator)) throw std::runtime_error("Invalid allocator mode");
#else
    if (mode != "as-built") throw std::runtime_error("Expected as-built mode");
#endif
    const auto bytes{std::filesystem::file_size(argv[1])};
    if (bytes == 0 || bytes % 80 || bytes / 80 < size_t(workers) || bytes / 80 > 100'000) {
        throw std::runtime_error("Expected a bounded, aligned fixture with enough headers for all workers");
    }
    std::vector<Header> headers(bytes / 80);
    std::vector<yespower_binary_t> digests(headers.size());
    std::ifstream input{argv[1], std::ios::binary};
    if (!input.read(reinterpret_cast<char*>(headers.data()), bytes)) throw std::runtime_error("Unable to read the fixture");

    static constexpr uint8_t personal[]{"Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote"};
    constexpr yespower_params_t params{YESPOWER_1_0, 2048, 32, personal, sizeof(personal) - 1};
    std::vector<WorkerResult> results(workers);
    std::latch ready{workers};
    std::latch start{1};
    std::vector<std::thread> pool;
    pool.reserve(workers);
    for (int worker = 0; worker < workers; ++worker) {
        pool.emplace_back([&, worker] {
            auto& result{results[worker]};
            yespower_local_t local{};
            yespower_binary_t discard{};
            const auto warm_begin{Clock::now()};
            const bool initialised{yespower_init_local(&local) == 0};
            result.passed = initialised && yespower(&local, headers[worker].data(), 80, &params, &discard) == 0;
            result.first_proof = Seconds{Clock::now() - warm_begin}.count();
            ready.count_down();
            start.wait();
            for (size_t i = worker; i < headers.size() && result.passed; i += workers) {
                result.passed = yespower(&local, headers[i].data(), 80, &params, &digests[i]) == 0;
            }
            result.end = Clock::now();
#ifdef SC_PAGE_PROBE
            page_probe_stats stats{};
            page_probe_get_stats(&stats);
            result.allocation_frequency = stats.frequency;
            result.allocation_ticks = stats.alloc_ticks;
            result.allocation_size = stats.base_size;
            result.allocation_calls = stats.calls;
            result.hint_attempts = stats.hint_attempts;
            result.hint_successes = stats.hint_successes;
            result.hint_fallbacks = stats.hint_fallbacks;
            result.hint_error = stats.hint_error;
#endif
            if (initialised && yespower_free_local(&local)) result.passed = false;
        });
    }
    ready.wait();
    const auto begin{Clock::now()};
    start.count_down();
    for (auto& worker : pool) worker.join();
    const auto last = std::max_element(results.begin(), results.end(), [](const auto& a, const auto& b) {
        return a.end < b.end;
    });
    const double elapsed{Seconds{last->end - begin}.count()};
    if (elapsed <= 0 || std::any_of(results.begin(), results.end(), [](const auto& row) { return !row.passed; })) {
        throw std::runtime_error("A proof, allocation or cleanup failed");
    }
    std::ofstream output{argv[2], std::ios::binary};
    output.write(reinterpret_cast<const char*>(digests.data()), digests.size() * sizeof(digests[0]));
    output.close();
    if (!output) throw std::runtime_error("Unable to persist ordered proof digests");
    std::cout << std::fixed << std::setprecision(8)
              << "{\"mode\":\"" << mode << "\",\"workers\":" << workers << ",\"proofs\":" << headers.size()
              << ",\"seconds\":" << elapsed << ",\"proofs_per_second\":" << headers.size() / elapsed;
#ifdef SC_PAGE_PROBE
    page_probe_api api{};
    page_probe_get_api(&api);
    std::cout << ",\"virtualalloc2\":{\"lookup_attempted\":" << (api.lookup_attempted ? "true" : "false")
              << ",\"available\":" << (api.available ? "true" : "false") << ",\"module\":";
    if (api.module) {
        std::cout << '\"' << api.module << '\"';
    } else {
        std::cout << "null";
    }
    std::cout << ",\"kernel32_lookup_error\":" << api.kernel32_lookup_error
              << ",\"kernelbase_lookup_error\":" << api.kernelbase_lookup_error << '}';
#endif
    std::cout << ",\"scratch\":[";
    for (const auto& row : results) {
        if (&row != &results.front()) std::cout << ',';
        const double allocation_seconds{row.allocation_frequency ? double(row.allocation_ticks) / row.allocation_frequency : 0};
        std::cout << "{\"first_proof_seconds\":" << row.first_proof << ",\"allocation_seconds\":" << allocation_seconds
                  << ",\"base_size\":" << row.allocation_size << ",\"allocation_calls\":" << row.allocation_calls
                  << ",\"hint_attempts\":" << row.hint_attempts << ",\"hint_successes\":" << row.hint_successes
                  << ",\"hint_fallbacks\":" << row.hint_fallbacks << ",\"hint_error\":" << row.hint_error << '}';
    }
    std::cout << "]}\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
}
