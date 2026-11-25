#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <initializer_list>
#include <mutex>

int main()
{
    using Clock = std::chrono::steady_clock;
    std::condition_variable wake;
    std::mutex mutex;
    std::unique_lock lock{mutex};
    for (bool skip : {false, true, true, false}) {
        const auto start = Clock::now();
        for (int i = 0; i < 1000; ++i) {
            const auto ready = Clock::now();
            if (!skip || ready > Clock::now()) wake.wait_until(lock, ready);
        }
        const auto elapsed = std::chrono::duration<double, std::micro>(Clock::now() - start).count();
        std::printf("%s %.3f us per due callback\n", skip ? "ready-check" : "expired-wait", elapsed / 1000);
    }
}
