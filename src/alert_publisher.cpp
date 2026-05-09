#include "dlads/alert_publisher.hpp"
#include "dlads/alert_event.hpp"

#include <zmq.h>

#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>

namespace dlads {

// ── Construction / destruction ────────────────────────────────────────────────

AlertPublisher::AlertPublisher(std::string endpoint)
    : endpoint_(std::move(endpoint))
{}

AlertPublisher::~AlertPublisher() {
    stop();
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void AlertPublisher::start() {
    if (running_.load()) return;

    zmq_ctx_ = zmq_ctx_new();
    if (!zmq_ctx_)
        throw std::runtime_error("[AlertPublisher] zmq_ctx_new() failed");

    zmq_sock_ = zmq_socket(zmq_ctx_, ZMQ_PUB);
    if (!zmq_sock_) {
        zmq_ctx_destroy(zmq_ctx_);
        zmq_ctx_ = nullptr;
        throw std::runtime_error("[AlertPublisher] zmq_socket() failed");
    }

    int hwm = static_cast<int>(QUEUE_CAPACITY);
    zmq_setsockopt(zmq_sock_, ZMQ_SNDHWM, &hwm, sizeof(hwm));

    int linger = 500;
    zmq_setsockopt(zmq_sock_, ZMQ_LINGER, &linger, sizeof(linger));

    if (zmq_bind(zmq_sock_, endpoint_.c_str()) != 0) {
        zmq_close(zmq_sock_);
        zmq_ctx_destroy(zmq_ctx_);
        zmq_sock_ = nullptr;
        zmq_ctx_  = nullptr;
        throw std::runtime_error(
            std::string("[AlertPublisher] zmq_bind failed on ") + endpoint_
            + ": " + zmq_strerror(errno));
    }

    stop_flag_.store(false);
    running_.store(true);
    send_thread_ = std::thread(&AlertPublisher::send_loop, this);
}

void AlertPublisher::stop() {
    if (!running_.load()) return;

    {
        std::lock_guard<std::mutex> lk(queue_mtx_);
        stop_flag_.store(true);
    }
    queue_cv_.notify_all();

    if (send_thread_.joinable())
        send_thread_.join();

    if (zmq_sock_) { zmq_close(zmq_sock_);      zmq_sock_ = nullptr; }
    if (zmq_ctx_)  { zmq_ctx_destroy(zmq_ctx_); zmq_ctx_  = nullptr; }

    running_.store(false);
}

// ── publish() ─────────────────────────────────────────────────────────────────

void AlertPublisher::publish(const AlertEvent& ev) {
    std::string json = serialize(ev);

    std::lock_guard<std::mutex> lk(queue_mtx_);
    if (queue_.size() >= QUEUE_CAPACITY) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    queue_.push(std::move(json));
    queue_cv_.notify_one();
}

// ── Accessors ─────────────────────────────────────────────────────────────────

uint64_t AlertPublisher::dropped_count() const noexcept {
    return dropped_.load(std::memory_order_relaxed);
}

uint64_t AlertPublisher::sent_count() const noexcept {
    return sent_.load(std::memory_order_relaxed);
}

bool AlertPublisher::running() const noexcept {
    return running_.load(std::memory_order_relaxed);
}

// ── send_loop() ───────────────────────────────────────────────────────────────

void AlertPublisher::send_loop() {
    // Single-frame send: the entire message is the JSON payload.
    // Partner B subscribes with ZMQ_SUBSCRIBE "" (accept all) so no topic
    // frame is needed, and recv_n() can treat every frame as a JSON string.
    while (true) {
        std::string json;

        {
            std::unique_lock<std::mutex> lk(queue_mtx_);
            queue_cv_.wait(lk, [this] {
                return !queue_.empty() || stop_flag_.load();
            });

            if (queue_.empty())
                break;  // stop_flag_ set and queue drained

            json = std::move(queue_.front());
            queue_.pop();
        }

        if (zmq_send(zmq_sock_, json.data(), json.size(), 0) < 0)
            break;  // socket closed or interrupted

        sent_.fetch_add(1, std::memory_order_relaxed);
    }
}

}  // namespace dlads