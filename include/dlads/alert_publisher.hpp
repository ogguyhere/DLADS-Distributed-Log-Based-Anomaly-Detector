#pragma once

#include "dlads/alert_event.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

namespace dlads {

class AlertPublisher {
public:
    static constexpr std::size_t kMaxQueueDepth = 1024;

    explicit AlertPublisher(std::string endpoint);
    ~AlertPublisher();

    AlertPublisher(const AlertPublisher&)            = delete;
    AlertPublisher& operator=(const AlertPublisher&) = delete;
    AlertPublisher(AlertPublisher&&)                 = delete;
    AlertPublisher& operator=(AlertPublisher&&)      = delete;

    void     start();
    void     stop();
    bool     running() const noexcept { return running_.load(std::memory_order_acquire); }
    void     publish(const AlertEvent& ev);
    uint64_t dropped_count() const noexcept { return dropped_.load(std::memory_order_relaxed); }

private:
    void send_loop();

    std::string           endpoint_;
    std::atomic<bool>     stop_   { false };
    std::atomic<bool>     running_{ false };
    std::atomic<uint64_t> dropped_{ 0 };
    std::thread           thread_;

    void* zmq_ctx_  { nullptr };
    void* zmq_sock_ { nullptr };

    std::mutex              queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<std::string> queue_;
};

}  // namespace dlads
