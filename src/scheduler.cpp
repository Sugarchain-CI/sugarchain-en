// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <scheduler.h>

#include <sync.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <functional>
#include <utility>

CScheduler::CScheduler() = default;

CScheduler::~CScheduler()
{
    assert(nThreadsServicingQueue == 0);
    if (stopWhenEmpty) assert(taskQueue.empty());
}


void CScheduler::serviceQueue()
{
    WAIT_LOCK(newTaskMutex, lock);
    ++nThreadsServicingQueue;
#if defined(__APPLE__) && defined(__x86_64__)
    bool waiting{false};
#endif

    // newTaskMutex is locked throughout this loop EXCEPT
    // when the thread is waiting or when the user's function
    // is called.
    while (!shouldStop()) {
        try {
            while (!shouldStop() && taskQueue.empty()) {
                // Wait until there is something to do.
#if defined(__APPLE__) && defined(__x86_64__)
                ++m_waiting_threads;
                waiting = true;
#endif
                newTaskScheduled.wait(lock);
#if defined(__APPLE__) && defined(__x86_64__)
                --m_waiting_threads;
                waiting = false;
#endif
            }

            // Wait until either there is a new task, or until
            // the time of the first item on the queue:

            while (!shouldStop() && !taskQueue.empty()) {
                std::chrono::steady_clock::time_point timeToWaitFor = taskQueue.begin()->first;
#if defined(WIN32) || (defined(__APPLE__) && defined(__x86_64__))
                // Avoid timed-wait overhead for tasks whose deadline has passed.
                // MinGW can also wait an entire Windows timer tick in this case.
                if (timeToWaitFor <= std::chrono::steady_clock::now()) break;
#endif
#if defined(__APPLE__) && defined(__x86_64__)
                ++m_waiting_threads;
                waiting = true;
#endif
                const auto status{newTaskScheduled.wait_until(lock, timeToWaitFor)};
#if defined(__APPLE__) && defined(__x86_64__)
                --m_waiting_threads;
                waiting = false;
#endif
                if (status == std::cv_status::timeout) {
                    break; // Exit loop after timeout, it means we reached the time of the event
                }
            }

            // If there are multiple threads, the queue can empty while we're waiting (another
            // thread may service the task we were waiting on).
            if (shouldStop() || taskQueue.empty())
                continue;

            Function f = taskQueue.begin()->second;
            taskQueue.erase(taskQueue.begin());

            {
                // Unlock before calling f, so it can reschedule itself or another task
                // without deadlocking:
                REVERSE_LOCK(lock, newTaskMutex);
                f();
            }
        } catch (...) {
#if defined(__APPLE__) && defined(__x86_64__)
            if (waiting) --m_waiting_threads;
#endif
            --nThreadsServicingQueue;
            throw;
        }
    }
    --nThreadsServicingQueue;
    newTaskScheduled.notify_one();
}

void CScheduler::schedule(CScheduler::Function f, std::chrono::steady_clock::time_point t)
{
#if defined(__APPLE__) && defined(__x86_64__)
    bool wake;
#endif
    {
        LOCK(newTaskMutex);
        taskQueue.insert(std::make_pair(t, f));
#if defined(__APPLE__) && defined(__x86_64__)
        // A running worker will inspect this queue before waiting. Notify only
        // workers that are already waiting, using the same lock as the queue.
        wake = m_waiting_threads != 0;
#endif
    }
#if defined(__APPLE__) && defined(__x86_64__)
    if (wake) newTaskScheduled.notify_one();
#else
    newTaskScheduled.notify_one();
#endif
}

void CScheduler::MockForward(std::chrono::seconds delta_seconds)
{
    assert(delta_seconds > 0s && delta_seconds <= 1h);

    {
        LOCK(newTaskMutex);

        // use temp_queue to maintain updated schedule
        std::multimap<std::chrono::steady_clock::time_point, Function> temp_queue;

        for (const auto& element : taskQueue) {
            temp_queue.emplace_hint(temp_queue.cend(), element.first - delta_seconds, element.second);
        }

        // point taskQueue to temp_queue
        taskQueue = std::move(temp_queue);
    }

    // notify that the taskQueue needs to be processed
    newTaskScheduled.notify_one();
}

static void Repeat(CScheduler& s, CScheduler::Function f, std::chrono::milliseconds delta)
{
    f();
    s.scheduleFromNow([=, &s] { Repeat(s, f, delta); }, delta);
}

void CScheduler::scheduleEvery(CScheduler::Function f, std::chrono::milliseconds delta)
{
    scheduleFromNow([this, f, delta] { Repeat(*this, f, delta); }, delta);
}

size_t CScheduler::getQueueInfo(std::chrono::steady_clock::time_point& first,
                                std::chrono::steady_clock::time_point& last) const
{
    LOCK(newTaskMutex);
    size_t result = taskQueue.size();
    if (!taskQueue.empty()) {
        first = taskQueue.begin()->first;
        last = taskQueue.rbegin()->first;
    }
    return result;
}

bool CScheduler::AreThreadsServicingQueue() const
{
    LOCK(newTaskMutex);
    return nThreadsServicingQueue;
}


void SerialTaskRunner::MaybeScheduleProcessQueue()
{
    {
        LOCK(m_callbacks_mutex);
        if (m_are_callbacks_running) return;
        if (m_callbacks_pending.empty()) return;
#ifdef __APPLE__
        if (m_process_queue_scheduled) return;
        m_process_queue_scheduled = true;
#endif
    }
#if defined(__APPLE__) && defined(__x86_64__)
    ScheduleProcessQueue();
#else
#ifdef __APPLE__
    try {
#endif
        m_scheduler.schedule([this] { this->ProcessQueue(); }, std::chrono::steady_clock::now());
#ifdef __APPLE__
    } catch (...) {
        LOCK(m_callbacks_mutex);
        m_process_queue_scheduled = false;
        throw;
    }
#endif
#endif
}

#if defined(__APPLE__) && defined(__x86_64__)
void SerialTaskRunner::ScheduleProcessQueue()
{
    try {
        m_scheduler.schedule([this] { this->ProcessQueue(); }, std::chrono::steady_clock::now());
    } catch (...) {
        LOCK(m_callbacks_mutex);
        m_process_queue_scheduled = false;
        throw;
    }
}
#endif

#ifdef __APPLE__
#ifdef __x86_64__
void SerialTaskRunner::PopCallback(std::list<std::function<void()>>& ready)
#else
std::function<void()> SerialTaskRunner::PopCallback()
#endif
{
    AssertLockHeld(m_callbacks_mutex);
#ifdef __x86_64__
    ready.splice(ready.end(), m_callbacks_pending, m_callbacks_pending.begin());
    m_pending_count.store(m_callbacks_pending.size(), std::memory_order_relaxed);
#else
    auto callback{std::move(m_callbacks_pending.front())};
    m_callbacks_pending.pop_front();
#endif
    if (m_capacity_waiters && m_callbacks_pending.size() <= m_capacity_wait_limit) {
        m_capacity.notify_all();
    }
#ifndef __x86_64__
    return callback;
#endif
}
#endif

void SerialTaskRunner::ProcessQueue()
{
#if defined(__APPLE__) && defined(__x86_64__)
    std::list<std::function<void()>> ready;
#else
    std::function<void()> callback;
#endif
    {
        LOCK(m_callbacks_mutex);
#ifdef __APPLE__
        m_process_queue_scheduled = false;
#endif
        if (m_are_callbacks_running) return;
        if (m_callbacks_pending.empty()) return;
        m_are_callbacks_running = true;

#if defined(__APPLE__) && defined(__x86_64__)
        PopCallback(ready);
#elif defined(__APPLE__)
        callback = PopCallback();
#else
        callback = std::move(m_callbacks_pending.front());
        m_callbacks_pending.pop_front();
#endif
    }

    // RAII the setting of fCallbacksRunning and calling MaybeScheduleProcessQueue
    // to ensure both happen safely even if callback() throws.
    struct RAIICallbacksRunning {
        SerialTaskRunner* instance;
        explicit RAIICallbacksRunning(SerialTaskRunner* _instance) : instance(_instance) {}
        ~RAIICallbacksRunning()
        {
            {
                LOCK(instance->m_callbacks_mutex);
                instance->m_are_callbacks_running = false;
            }
            instance->MaybeScheduleProcessQueue();
        }
    } raiicallbacksrunning(this);

#if defined(__APPLE__) && defined(__x86_64__)
    const auto deadline{std::chrono::steady_clock::now() + 1ms};
    ready.front()();
    ready.pop_front();
    // Share each scheduler turn among ready callbacks without starving other tasks.
    for (size_t processed{1}; processed < 8; ++processed) {
        if (std::chrono::steady_clock::now() >= deadline || m_scheduler.StopRequested()) break;
        std::list<std::function<void()>> next;
        {
            LOCK(m_callbacks_mutex);
            if (m_callbacks_pending.empty()) break;
            PopCallback(next);
        }
        next.front()();
    }
#else
    callback();
#endif
}

void SerialTaskRunner::insert(std::function<void()> func)
{
#if defined(__APPLE__) && defined(__x86_64__)
    // Allocate the callback node before taking the queue lock.
    std::list<std::function<void()>> ready;
    ready.emplace_back(std::move(func));
#endif
    {
        LOCK(m_callbacks_mutex);
#if defined(__APPLE__) && defined(__x86_64__)
        m_callbacks_pending.splice(m_callbacks_pending.end(), ready);
        m_pending_count.store(m_callbacks_pending.size(), std::memory_order_relaxed);
        // Enqueue and reserve the scheduler turn in one critical section.
        // The running consumer or the reserved turn will observe this callback.
        if (m_are_callbacks_running || m_process_queue_scheduled) return;
        m_process_queue_scheduled = true;
#else
        m_callbacks_pending.emplace_back(std::move(func));
#endif
    }
#if defined(__APPLE__) && defined(__x86_64__)
    ScheduleProcessQueue();
#else
    MaybeScheduleProcessQueue();
#endif
}

void SerialTaskRunner::flush()
{
    assert(!m_scheduler.AreThreadsServicingQueue());
    bool should_continue = true;
    while (should_continue) {
        ProcessQueue();
        LOCK(m_callbacks_mutex);
        should_continue = !m_callbacks_pending.empty();
    }
}

size_t SerialTaskRunner::size()
{
#if defined(__APPLE__) && defined(__x86_64__)
    return m_pending_count.load(std::memory_order_relaxed);
#else
    LOCK(m_callbacks_mutex);
    return m_callbacks_pending.size();
#endif
}

#ifdef __APPLE__
bool SerialTaskRunner::waitForPendingAtMost(size_t limit)
{
    WAIT_LOCK(m_callbacks_mutex, lock);
    if (m_callbacks_pending.size() <= limit) return true;

    ++m_capacity_waiters;
    m_capacity_wait_limit = std::max(m_capacity_wait_limit, limit);
    m_capacity.wait(lock, [this, limit]() EXCLUSIVE_LOCKS_REQUIRED(m_callbacks_mutex) {
        return m_callbacks_pending.size() <= limit;
    });
    if (--m_capacity_waiters == 0) m_capacity_wait_limit = 0;
    return true;
}
#endif

#if defined(__APPLE__) && defined(__aarch64__)
ValidationTaskRunner::ValidationTaskRunner() : m_worker{[this] { Run(/*drain=*/false); }} {}

ValidationTaskRunner::~ValidationTaskRunner()
{
    stop();
}

void ValidationTaskRunner::Run(bool drain)
{
    WAIT_LOCK(m_mutex, lock);
    while (drain || !m_stopped) {
        if (m_pending.empty()) {
            if (drain) return;
            m_available.wait(lock);
            continue;
        }

        auto callback{std::move(m_pending.front())};
        m_pending.pop_front();
        if (m_capacity_waiters != 0 && m_pending.size() <= m_capacity_wait_limit) {
            m_capacity.notify_all();
        }
        {
            REVERSE_LOCK(lock, m_mutex);
            auto task{std::move(callback)};
            task();
        }
    }
}

void ValidationTaskRunner::insert(std::function<void()> func)
{
    bool wake;
    {
        LOCK(m_mutex);
        wake = m_pending.empty() && !m_stopped;
        m_pending.emplace_back(std::move(func));
    }
    if (wake) m_available.notify_one();
}

void ValidationTaskRunner::stop()
{
    {
        LOCK(m_mutex);
        m_stopped = true;
    }
    m_available.notify_one();
    m_capacity.notify_all();
    if (m_worker.joinable()) m_worker.join();
}

void ValidationTaskRunner::flush()
{
    assert(!m_worker.joinable());
    Run(/*drain=*/true);
}

size_t ValidationTaskRunner::size()
{
    LOCK(m_mutex);
    return m_pending.size();
}

bool ValidationTaskRunner::waitForPendingAtMost(size_t limit)
{
    WAIT_LOCK(m_mutex, lock);
    if (m_stopped || m_pending.size() <= limit) return true;

    ++m_capacity_waiters;
    m_capacity_wait_limit = std::max(m_capacity_wait_limit, limit);
    m_capacity.wait(lock, [this, limit]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) {
        return m_stopped || m_pending.size() <= limit;
    });
    if (--m_capacity_waiters == 0) m_capacity_wait_limit = 0;
    return true;
}
#endif
