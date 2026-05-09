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
 * Non-blocking ZeroMQ PUB socket that ships serialized AlertEvent JSON
 * to any connected subscriber (e.g. Partner B's coordinator).
 *
 * Design contract:
 *   - publish() is O(1) and never blocks the detection thread.
 *   - A dedicated send thread drains the internal queue and calls zmq_send.
 *   - When the queue is full (>= QUEUE_CAPACITY), the incoming alert is
 *     silently dropped and dropped_count() is incremented.
 *   - Topic frame is always "alerts" so subscribers can filter with
 *     zmq_setsockopt(ZMQ_SUBSCRIBE, "alerts", 6).
 *
 * Typical use:
 *   AlertPublisher pub("tcp://*:5555");
 *   pub.start();
 *   pub.publish(alert_ev);   // called from detection thread, never blocks
 *   pub.stop();              // drains queue then closes socket
 *
 * Thread safety: publish() is safe to call from any thread after start().
 */
class AlertPublisher {
public:
    static constexpr std::size_t QUEUE_CAPACITY = 1024;
    // static constexpr const char* TOPIC          = "alerts";

    /**
     * @param endpoint  ZMQ endpoint string, e.g. "tcp://*:5555".
     *                  Passed verbatim to zmq_bind().
     */
    explicit AlertPublisher(std::string endpoint);

    /**
     * Destructor — calls stop() if still running.
     */
    ~AlertPublisher();

    // Non-copyable, non-movable (owns a live socket and thread).
    AlertPublisher(const AlertPublisher&)            = delete;
    AlertPublisher& operator=(const AlertPublisher&) = delete;
    AlertPublisher(AlertPublisher&&)                 = delete;
    AlertPublisher& operator=(AlertPublisher&&)      = delete;

    /**
     * Bind the ZMQ PUB socket and start the background send thread.
     * Must be called exactly once before publish().
     * Throws std::runtime_error if zmq_bind fails.
     */
    void start();

    /**
     * Signal the send thread to stop, drain remaining queued alerts
     * (up to a short timeout), then close the socket.
     * Safe to call multiple times.
     */
    void stop();

    /**
     * Enqueue an alert for sending.  Non-blocking.
     *
     * If the internal queue is already at QUEUE_CAPACITY the alert is
     * dropped and dropped_count() is incremented.
     *
     * Safe to call from any thread after start().
     */
    void publish(const AlertEvent& ev);

    /**
     * Total number of alerts dropped because the queue was full.
     * Monotonically increasing; never resets.
     */
    uint64_t dropped_count() const noexcept;

    /**
     * Total number of alerts successfully sent on the wire.
     */
    uint64_t sent_count() const noexcept;

    /**
     * True between a successful start() and stop().
     */
    bool running() const noexcept;

private:
    void send_loop();   // runs on send_thread_

    std::string            endpoint_;

    // ZMQ handles — void* to avoid pulling zmq.h into every translation unit.
    void*                  zmq_ctx_{ nullptr };
    void*                  zmq_sock_{ nullptr };

    // Internal queue — protected by queue_mtx_.
    std::queue<std::string>  queue_;          // pre-serialized JSON strings
    mutable std::mutex       queue_mtx_;
    std::condition_variable  queue_cv_;

    std::thread              send_thread_;
    std::atomic<bool>        running_{ false };
    std::atomic<bool>        stop_flag_{ false };

    std::atomic<uint64_t>    dropped_{ 0 };
    std::atomic<uint64_t>    sent_{ 0 };
};

}  // namespace dlads