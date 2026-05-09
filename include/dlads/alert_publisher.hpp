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

/**
 * Non-blocking ZeroMQ PUB socket that ships serialized AlertEvent JSON.
 *
 * Two modes controlled by the endpoint prefix:
 *   "tcp://*:PORT"           → zmq_bind  (standalone agent, no coordinator)
 *   "tcp://HOST:PORT"        → zmq_connect (agent → coordinator, normal mode)
 *
 * The coordinator does sub.bind("tcp://*:5555") so agents must connect to it.
 * Pass "tcp://127.0.0.1:5555" (or real coordinator IP) for production use.
 * Pass "tcp://*:5555" only for standalone testing with your own subscriber.
 */
class AlertPublisher {
public:
    static constexpr std::size_t QUEUE_CAPACITY = 1024;

    explicit AlertPublisher(std::string endpoint);
    ~AlertPublisher();

    AlertPublisher(const AlertPublisher&)            = delete;
    AlertPublisher& operator=(const AlertPublisher&) = delete;
    AlertPublisher(AlertPublisher&&)                 = delete;
    AlertPublisher& operator=(AlertPublisher&&)      = delete;

    void     start();
    void     stop();
    void     publish(const AlertEvent& ev);

    uint64_t dropped_count() const noexcept;
    uint64_t sent_count()    const noexcept;
    bool     running()       const noexcept;

private:
    void send_loop();

    // Returns true if endpoint should use bind rather than connect.
    // Bind endpoints contain "://*:" — e.g. "tcp://*:5555".
    static bool should_bind(const std::string& ep) {
        return ep.find("://*:") != std::string::npos;
    }

    std::string              endpoint_;
    void*                    zmq_ctx_{ nullptr };
    void*                    zmq_sock_{ nullptr };

    std::queue<std::string>  queue_;
    mutable std::mutex       queue_mtx_;
    std::condition_variable  queue_cv_;

    std::thread              send_thread_;
    std::atomic<bool>        running_{ false };
    std::atomic<bool>        stop_flag_{ false };
    std::atomic<uint64_t>    dropped_{ 0 };
    std::atomic<uint64_t>    sent_{ 0 };
};

}  // namespace dlads