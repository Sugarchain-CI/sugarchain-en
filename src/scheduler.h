// Copyright (c) 2015-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCHEDULER_H
#define BITCOIN_SCHEDULER_H

#include <attributes.h>
#include <sync.h>
#include <threadsafety.h>
#include <util/task_runner.h>

#if defined(__APPLE__) && defined(__x86_64__)
#include <atomic>
#endif
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <list>
#include <map>
#include <thread>
#include <utility>

/**
 * Simple class for background tasks that should be run
 * periodically or once "after a while"
 *
 * Usage:
 *
 * CScheduler* s = new CScheduler();
 * s->scheduleFromNow(doSomething, std::chrono::milliseconds{11}); // Assuming a: void doSomething() { }
 * s->scheduleFromNow([=] { this->func(argument); }, std::chrono::milliseconds{3});
 * std::thread* t = new std::thread([&] { s->serviceQueue(); });
 *
 * ... then at program shutdown, make sure to call stop() to clean up the thread(s) running serviceQueue:
 * s->stop();
 * t->join();
 * delete t;
 * delete s; // Must be done after thread is interrupted/joined.
 */
class CScheduler
{
public:
    CScheduler();
    ~CScheduler();

    std::thread m_service_thread;

    typedef std::function<void()> Function;

    /** Call func at/after time t */
    void schedule(Function f, std::chrono::steady_clock::time_point t) EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex);

    /** Call f once after the delta has passed */
    void scheduleFromNow(Function f, std::chrono::milliseconds delta) EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex)
    {
        schedule(std::move(f), std::chrono::steady_clock::now() + delta);
    }

    /**
     * Repeat f until the scheduler is stopped. First run is after delta has passed once.
     *
     * The timing is not exact: Every time f is finished, it is rescheduled to run again after delta. If you need more
     * accurate scheduling, don't use this method.
     */
    void scheduleEvery(Function f, std::chrono::milliseconds delta) EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex);

    /**
     * Mock the scheduler to fast forward in time.
     * Iterates through items on taskQueue and reschedules them
     * to be delta_seconds sooner.
     */
    void MockForward(std::chrono::seconds delta_seconds) EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex);

    /**
     * Services the queue 'forever'. Should be run in a thread.
     */
    void serviceQueue() EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex);

    /** Tell any threads running serviceQueue to stop as soon as the current task is done */
    void stop() EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex)
    {
        WITH_LOCK(newTaskMutex, stopRequested = true);
        newTaskScheduled.notify_all();
        if (m_service_thread.joinable()) m_service_thread.join();
    }
    /** Tell any threads running serviceQueue to stop when there is no work left to be done */
    void StopWhenDrained() EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex)
    {
        WITH_LOCK(newTaskMutex, stopWhenEmpty = true);
        newTaskScheduled.notify_all();
        if (m_service_thread.joinable()) m_service_thread.join();
    }

    /**
     * Returns number of tasks waiting to be serviced,
     * and first and last task times
     */
    size_t getQueueInfo(std::chrono::steady_clock::time_point& first,
                        std::chrono::steady_clock::time_point& last) const
        EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex);

    /** Returns true if there are threads actively running in serviceQueue() */
    bool AreThreadsServicingQueue() const EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex);

private:
#if defined(__APPLE__) && defined(__x86_64__)
    friend class SerialTaskRunner;
    friend struct SchedulerWaiterTestAccess;

    bool StopRequested() const EXCLUSIVE_LOCKS_REQUIRED(!newTaskMutex)
    {
        return WITH_LOCK(newTaskMutex, return stopRequested);
    }
#endif
    mutable Mutex newTaskMutex;
    std::condition_variable newTaskScheduled;
    std::multimap<std::chrono::steady_clock::time_point, Function> taskQueue GUARDED_BY(newTaskMutex);
    int nThreadsServicingQueue GUARDED_BY(newTaskMutex){0};
#if defined(__APPLE__) && defined(__x86_64__)
    //! Count waits until their lock is reacquired, including exceptional exits.
    size_t m_waiting_threads GUARDED_BY(newTaskMutex){0};
#endif
    bool stopRequested GUARDED_BY(newTaskMutex){false};
    bool stopWhenEmpty GUARDED_BY(newTaskMutex){false};
    bool shouldStop() const EXCLUSIVE_LOCKS_REQUIRED(newTaskMutex) { return stopRequested || (stopWhenEmpty && taskQueue.empty()); }
};

/**
 * Class used by CScheduler clients which may schedule multiple jobs
 * which are required to be run serially. Jobs may not be run on the
 * same thread, but no two jobs will be executed
 * at the same time and memory will be release-acquire consistent
 * (the scheduler will internally do an acquire before invoking a callback
 * as well as a release at the end). In practice this means that a callback
 * B() will be able to observe all of the effects of callback A() which executed
 * before it.
 */
class SerialTaskRunner : public util::TaskRunnerInterface
{
private:
#if defined(__APPLE__) && defined(__x86_64__)
    friend struct SchedulerWaiterTestAccess;
#endif
    CScheduler& m_scheduler;

    Mutex m_callbacks_mutex;

    // We are not allowed to assume the scheduler only runs in one thread,
    // but must ensure all callbacks happen in-order, so we end up creating
    // our own queue here :(
    std::list<std::function<void()>> m_callbacks_pending GUARDED_BY(m_callbacks_mutex);
#if defined(__APPLE__) && defined(__x86_64__)
    // Published under m_callbacks_mutex. Capacity waiters use the queue itself.
    std::atomic<size_t> m_pending_count{0};
#endif
    bool m_are_callbacks_running GUARDED_BY(m_callbacks_mutex) = false;
#ifdef __APPLE__
    bool m_process_queue_scheduled GUARDED_BY(m_callbacks_mutex){false};
    std::condition_variable m_capacity;
    size_t m_capacity_waiters GUARDED_BY(m_callbacks_mutex){0};
    size_t m_capacity_wait_limit GUARDED_BY(m_callbacks_mutex){0};
#endif

    void MaybeScheduleProcessQueue() EXCLUSIVE_LOCKS_REQUIRED(!m_callbacks_mutex);
#if defined(__APPLE__) && defined(__x86_64__)
    void ScheduleProcessQueue() EXCLUSIVE_LOCKS_REQUIRED(!m_callbacks_mutex);
    void PopCallback(std::list<std::function<void()>>& ready) EXCLUSIVE_LOCKS_REQUIRED(m_callbacks_mutex);
#elif defined(__APPLE__)
    std::function<void()> PopCallback() EXCLUSIVE_LOCKS_REQUIRED(m_callbacks_mutex);
#endif
    void ProcessQueue() EXCLUSIVE_LOCKS_REQUIRED(!m_callbacks_mutex);

public:
    explicit SerialTaskRunner(CScheduler& scheduler LIFETIMEBOUND) : m_scheduler{scheduler} {}

    /**
     * Add a callback to be executed. Callbacks are executed serially
     * and memory is release-acquire consistent between callback executions.
     * Practically, this means that callbacks can behave as if they are executed
     * in order by a single thread.
     */
    void insert(std::function<void()> func) override EXCLUSIVE_LOCKS_REQUIRED(!m_callbacks_mutex);

    /**
     * Processes all remaining queue members on the calling thread, blocking until queue is empty
     * Must be called after the CScheduler has no remaining processing threads!
     */
    void flush() override EXCLUSIVE_LOCKS_REQUIRED(!m_callbacks_mutex);

    size_t size() override EXCLUSIVE_LOCKS_REQUIRED(!m_callbacks_mutex);
#ifdef __APPLE__
    bool waitForPendingAtMost(size_t limit) override EXCLUSIVE_LOCKS_REQUIRED(!m_callbacks_mutex);
#endif
};

#if defined(__APPLE__) && defined(__aarch64__)
/** A single background worker for the ordered validation callback queue. */
class ValidationTaskRunner final : public util::TaskRunnerInterface
{
    Mutex m_mutex;
    std::condition_variable m_available;
    std::condition_variable m_capacity;
    size_t m_capacity_waiters GUARDED_BY(m_mutex){0};
    size_t m_capacity_wait_limit GUARDED_BY(m_mutex){0};
    std::list<std::function<void()>> m_pending GUARDED_BY(m_mutex);
    bool m_stopped GUARDED_BY(m_mutex){false};
    std::thread m_worker;

    void Run(bool drain) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

public:
    ValidationTaskRunner();
    ~ValidationTaskRunner() override;

    void insert(std::function<void()> func) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void stop() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    void flush() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    size_t size() override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    bool waitForPendingAtMost(size_t limit) override EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
};
#endif

#endif // BITCOIN_SCHEDULER_H
