// Copyright (c) 2026 The Sugarchain En developers
// Distributed under the MIT software license, see the accompanying file COPYING.

#ifndef BITCOIN_UTIL_ORDERED_CHECK_WINDOW_H
#define BITCOIN_UTIL_ORDERED_CHECK_WINDOW_H

#include <algorithm>
#include <array>
#include <cassert>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace util {

/** A bounded ordered stream of checks. The caller participates as a worker.
 * Next supplies jobs in order, under the queue mutex. An empty result ends the
 * stream. Each job returns no value on success, a null exception pointer for
 * failed validation, or a real exception pointer for a local failure.
 */
template <typename Job, size_t Capacity>
class OrderedCheckWindow
{
    static_assert(Capacity > 0);
    static_assert(std::is_nothrow_move_constructible_v<Job> && std::is_nothrow_destructible_v<Job>);

    struct Slot {
        std::optional<Job> job;
        bool passed{false};
    };

    using Next = std::function<std::optional<Job>()>;
    using Result = std::optional<std::exception_ptr>;
    using Lock = std::unique_lock<std::mutex>;

    const size_t m_pending_limit;
    std::mutex m_call_mutex;
    std::mutex m_mutex;
    std::condition_variable m_changed;
    std::array<Slot, Capacity> m_slots;
    std::vector<std::thread> m_workers;
    Next m_next;
    size_t m_retired{0};
    size_t m_started{0};
    size_t m_admitted{0};
    size_t m_active{0};
    size_t m_waiters{0};
    Result m_failure;
    bool m_exhausted{true};
    bool m_shutdown{false};

    bool HasWork() const { return !m_failure && m_started < m_admitted; }
    bool Complete() const { return (m_exhausted || m_failure) && !HasWork() && m_active == 0; }

    void Wake()
    {
        if (m_waiters != 0) m_changed.notify_all();
    }

    void Wait(Lock& lock)
    {
        ++m_waiters;
        m_changed.wait(lock);
        --m_waiters;
    }

    void Fail(std::exception_ptr error)
    {
        // Never turn a local error from a started job into peer misbehavior.
        if (!m_failure || (!*m_failure && error)) m_failure.emplace(std::move(error));
    }

    void Refill()
    {
        // Only the contiguous successful prefix frees capacity. An unresolved
        // check at k leaves at most m_pending_limit - 1 later jobs admitted.
        while (!m_exhausted && !m_failure && m_admitted - m_retired < m_pending_limit) {
            try {
                auto job{m_next()};
                if (!job) {
                    m_exhausted = true;
                    break;
                }
                auto& slot{m_slots[m_admitted % Capacity]};
                assert(!slot.job && !slot.passed);
                slot.job.emplace(std::move(*job));
                ++m_admitted;
            } catch (...) {
                Fail(std::current_exception());
            }
        }
    }

    void CheckOne(Lock& lock)
    {
        const size_t index{m_started++};
        auto& slot{m_slots[index % Capacity]};
        assert(slot.job && !slot.passed);
        Job job{std::move(*slot.job)};
        slot.job.reset();
        ++m_active;
        lock.unlock();
        Result result;
        try {
            result = job();
        } catch (...) {
            result.emplace(std::current_exception());
        }
        lock.lock();
        --m_active;

        if (result) Fail(std::move(*result));
        if (!m_failure) {
            slot.passed = true;
            while (m_retired < m_admitted && m_slots[m_retired % Capacity].passed) {
                m_slots[m_retired % Capacity].passed = false;
                ++m_retired;
            }
            Refill();
        }
        if (HasWork() || Complete()) Wake();
    }

    void WorkerLoop()
    {
        Lock lock{m_mutex};
        while (!m_shutdown) {
            if (HasWork()) CheckOne(lock);
            else Wait(lock);
        }
    }

    void StopWorkers()
    {
        {
            Lock lock{m_mutex};
            m_shutdown = true;
            Wake();
        }
        for (auto& worker : m_workers) worker.join();
    }

public:
    /** The pending limit counts every check outside the verified prefix. */
    OrderedCheckWindow(size_t participants, size_t pending_limit, const std::function<void(size_t)>& name_worker = {})
        : m_pending_limit{std::clamp(pending_limit, size_t{1}, Capacity)}
    {
        const size_t worker_count{std::clamp(participants, size_t{1}, m_pending_limit) - 1};
        m_workers.reserve(worker_count);
        try {
            for (size_t i{0}; i < worker_count; ++i) {
                m_workers.emplace_back([this, name_worker, i] {
                    try {
                        if (name_worker) name_worker(i);
                    } catch (...) {
                        // Diagnostic naming must not prevent a worker from running.
                    }
                    WorkerLoop();
                });
            }
        } catch (...) {
            StopWorkers();
            throw;
        }
    }

    ~OrderedCheckWindow() { StopWorkers(); }

    /** All started work finishes before the input and its references are released. */
    bool Run(Next next)
    {
        const std::lock_guard call{m_call_mutex};
        Lock lock{m_mutex};
        assert(m_active == 0 && !m_next && next);
        m_next = std::move(next);
        m_exhausted = false;
        Refill();
        Wake();
        while (!Complete()) {
            if (HasWork()) CheckOne(lock);
            else Wait(lock);
        }

        auto failure{std::exchange(m_failure, std::nullopt)};
        for (auto& slot : m_slots) {
            slot.job.reset();
            slot.passed = false;
        }
        m_retired = m_started = m_admitted = 0;
        m_exhausted = true;
        m_next = {};
        if (failure && *failure) std::rethrow_exception(*failure);
        return !failure;
    }
};

} // namespace util

#endif // BITCOIN_UTIL_ORDERED_CHECK_WINDOW_H
