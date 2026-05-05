#include "dlads/alert_publisher.hpp"
#include "dlads/alert_event.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <vector>

#include <zmq.h>

namespace dlads {

AlertPublisher::AlertPublisher(std::string endpoint)
    : endpoint_(std::move(endpoint))
{}

AlertPublisher::~AlertPublisher() {
    stop();
}

void AlertPublisher::start() {
    if (running_.load(std::memory_order_acquire)) return;

    zmq_ctx_ = zmq_ctx_new();
    if (!zmq_ctx_) {
        std::cerr << "[AlertPublisher] zmq_ctx_new failed\n";
        return;
    }

    zmq_sock_ = zmq_socket(zmq_ctx_, ZMQ_PUB);
    if (!zmq_sock_) {
        std::cerr << "[AlertPublisher] zmq_socket failed\n";
        zmq_ctx_destroy(zmq_ctx_);
        zmq_ctx_ = nullptr;
        return;
    }

    int hwm = 1000000;
    zmq_setsockopt(zmq_sock_, ZMQ_SNDHWM, &hwm, sizeof(hwm));

    int linger = 500;
    zmq_setsockopt(zmq_sock_, ZMQ_LINGER, &linger, sizeof(linger));

    if (zmq_bind(zmq_sock_, endpoint_.c_str()) != 0) {
        std::cerr << "[AlertPublisher] zmq_bind(" << endpoint_
                  << ") failed: " << zmq_strerror(errno) << "\n";
        zmq_close(zmq_sock_);
        zmq_ctx_destroy(zmq_ctx_);
        zmq_sock_ = nullptr;
        zmq_ctx_  = nullptr;
        return;
    }

    stop_.store(false, std::memory_order_release);
    thread_ = std::thread(&AlertPublisher::send_loop, this);
}

void AlertPublisher::stop() {
    {
        std::lock_guard<std::mutex> lk(queue_mutex_);
        stop_.store(true, std::memory_order_release);
    }
    queue_cv_.notify_one();
    if (thread_.joinable()) thread_.join();
}

void AlertPublisher::publish(const AlertEvent& ev) {
    std::string json = serialize(ev);
    {
        std::lock_guard<std::mutex> lk(queue_mutex_);
        if (queue_.size() >= kMaxQueueDepth) {
            queue_.pop();
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
        queue_.push(std::move(json));
    }
    queue_cv_.notify_one();
}

void AlertPublisher::send_loop() {
    running_.store(true, std::memory_order_release);
    std::cout << "[AlertPublisher] send thread started, bound to "
              << endpoint_ << "\n";

    while (true) {
        std::vector<std::string> batch;
        {
            std::unique_lock<std::mutex> lk(queue_mutex_);
            queue_cv_.wait(lk, [this] {
                return !queue_.empty()
                    || stop_.load(std::memory_order_acquire);
            });
            if (queue_.empty()) break;
            while (!queue_.empty()) {
                batch.push_back(std::move(queue_.front()));
                queue_.pop();
            }
        }
        for (const auto& json : batch) {
            while (zmq_send(zmq_sock_,
                            json.data(),
                            static_cast<int>(json.size()),
                            0) < 0) {
                if (errno == EINTR) continue;
                std::cerr << "[AlertPublisher] zmq_send error: "
                          << zmq_strerror(errno) << "\n";
                break;
            }
        }
    }

    zmq_close(zmq_sock_);
    zmq_ctx_destroy(zmq_ctx_);
    zmq_sock_ = nullptr;
    zmq_ctx_  = nullptr;
    running_.store(false, std::memory_order_release);
}

}  // namespace dlads
