// Copyright (c) 2026 The Sugarchain En developers
// Distributed under the MIT software license, see the accompanying file COPYING.

#include "single-cv.h"
#include "split-cv.h"
#include "yespower.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/resource.h>
#endif

namespace {
constexpr size_t HEADER_COUNT{8192};
constexpr size_t PARTICIPANTS{8};
constexpr size_t HEADER_BYTES{80};
constexpr unsigned char PERSONALIZATION[]{
    "Satoshi Nakamoto 31/Oct/2008 Proof-of-work is essentially one-CPU-one-vote"};
constexpr yespower_params_t POW_PARAMS{YESPOWER_1_0, 2048, 32, PERSONALIZATION, sizeof(PERSONALIZATION) - 1};
using Header = std::array<uint8_t, HEADER_BYTES>;
using JobResult = std::optional<std::exception_ptr>;
using Clock = std::chrono::steady_clock;
static_assert(sizeof(Header) == HEADER_BYTES);
static_assert(sizeof(yespower_binary_t) == 32);

class Scratch
{
public:
    yespower_local_t memory;
    Scratch()
    {
        if (yespower_init_local(&memory)) throw std::runtime_error("Scratch initialization failed");
    }
    ~Scratch() { yespower_free_local(&memory); }
    Scratch(const Scratch&) = delete;
    Scratch& operator=(const Scratch&) = delete;
};

void Proof(const Header& header, yespower_binary_t& result)
{
    thread_local Scratch scratch;
    if (yespower(&scratch.memory, header.data(), header.size(), &POW_PARAMS, &result)) {
        throw std::runtime_error("Proof computation failed");
    }
}

double CpuSeconds()
{
#ifdef _WIN32
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) {
        throw std::runtime_error("GetProcessTimes failed");
    }
    const auto ticks = [](const FILETIME& value) {
        return (uint64_t{value.dwHighDateTime} << 32) | value.dwLowDateTime;
    };
    return (ticks(kernel) + ticks(user)) * 1e-7;
#else
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage)) throw std::runtime_error("getrusage failed");
    return usage.ru_utime.tv_sec + usage.ru_utime.tv_usec * 1e-6 +
        usage.ru_stime.tv_sec + usage.ru_stime.tv_usec * 1e-6;
#endif
}

struct Measurements {
    double wall_seconds;
    double cpu_seconds;
    double serial_wall_seconds;
    size_t caller_parallel_proofs;
};

struct Work {
    const std::vector<Header>& headers;
    std::vector<yespower_binary_t>& proofs;
    const std::thread::id caller{std::this_thread::get_id()};
    std::vector<std::atomic_uint> visits = std::vector<std::atomic_uint>(HEADER_COUNT);
    size_t caller_parallel_proofs{0};
};

struct CheckJob {
    Work& work;
    size_t index;

    JobResult operator()() const
    {
        if (work.visits[index].fetch_add(1, std::memory_order_relaxed) != 0) {
            throw std::runtime_error("The queue ran a proof more than once");
        }
        if (std::this_thread::get_id() == work.caller) ++work.caller_parallel_proofs;
        Proof(work.headers[index], work.proofs[index]);
        return std::nullopt;
    }
};

template <typename Queue>
Measurements Measure(Work& work)
{
    std::atomic_size_t created{0};
    Measurements measurements{};
    {
        Queue queue(PARTICIPANTS, [&](size_t) { created.fetch_add(1, std::memory_order_relaxed); });
        const auto cpu_start{CpuSeconds()};
        const auto wall_start{Clock::now()};
        Proof(work.headers.front(), work.proofs.front());
        work.visits.front().store(1, std::memory_order_relaxed);
        measurements.serial_wall_seconds = std::chrono::duration<double>(Clock::now() - wall_start).count();

        size_t next_index{1};
        if (!queue.Run([&]() -> std::optional<CheckJob> {
                if (next_index == HEADER_COUNT) return std::nullopt;
                return CheckJob{work, next_index++};
            })) {
            throw std::runtime_error("The queue rejected an authentic proof workload");
        }
        measurements.wall_seconds = std::chrono::duration<double>(Clock::now() - wall_start).count();
        measurements.cpu_seconds = CpuSeconds() - cpu_start;
        measurements.caller_parallel_proofs = work.caller_parallel_proofs;
    }
    for (const auto& count : work.visits) {
        if (count.load(std::memory_order_relaxed) != 1) throw std::runtime_error("A proof was skipped");
    }
    if (created.load(std::memory_order_relaxed) != PARTICIPANTS - 1 || measurements.caller_parallel_proofs == 0) {
        throw std::runtime_error("The requested participant configuration did not execute");
    }
    return measurements;
}
} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc != 4) throw std::runtime_error("Usage: queue-proofs single|split HEADERS OUTPUT");
        const std::string_view variant{argv[1]};
        if (variant != "single" && variant != "split") throw std::runtime_error("Unknown queue variant");

        std::vector<Header> headers(HEADER_COUNT);
        std::ifstream input(argv[2], std::ios::binary);
        if (!input.read(reinterpret_cast<char*>(headers.data()), headers.size() * sizeof(Header)) ||
            input.peek() != std::char_traits<char>::eof()) throw std::runtime_error("Unexpected fixture length");

        std::vector<yespower_binary_t> proofs(HEADER_COUNT);
        Work work{headers, proofs};
        const Measurements result = variant == "single"
            ? Measure<single_cv::OrderedCheckWindow<CheckJob, PARTICIPANTS>>(work)
            : Measure<split_cv::OrderedCheckWindow<CheckJob, PARTICIPANTS>>(work);

        std::ofstream output(argv[3], std::ios::binary);
        output.write(reinterpret_cast<const char*>(proofs.data()), proofs.size() * sizeof(yespower_binary_t));
        output.close();
        if (!output) throw std::runtime_error("Could not write the proof output");
        std::cout << std::fixed << std::setprecision(9) << "{\"variant\":\"" << variant
                  << "\",\"headers\":" << HEADER_COUNT << ",\"participants\":" << PARTICIPANTS
                  << ",\"pending_limit\":" << PARTICIPANTS << ",\"wall_seconds\":" << result.wall_seconds
                  << ",\"cpu_seconds\":" << result.cpu_seconds << ",\"serial_wall_seconds\":" << result.serial_wall_seconds
                  << ",\"caller_parallel_proofs\":" << result.caller_parallel_proofs << "}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
