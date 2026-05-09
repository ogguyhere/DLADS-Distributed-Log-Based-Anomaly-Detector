#include "dlads/alert_publisher.hpp"
#include "dlads/alert_event.hpp"

#include <zmq.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace dlads;
using namespace std::chrono_literals;

// ── Helpers ───────────────────────────────────────────────────────────────────

static AlertEvent make_alert(const std::string& id = "test-001",
                             Severity sev          = Severity::HIGH) {
    AlertEvent ev;
    ev.alert_id      = id;
    ev.source_host   = "agent-test-01";
    ev.rule_id       = "SSH_BRUTE_FORCE_001";
    ev.severity      = sev;
    ev.anomaly_score = 0.85f;
    ev.description   = "Test brute force alert";
    ev.timestamp     = std::chrono::system_clock::now();
    ev.metadata["src_ip"] = "192.168.1.100";
    ev.metadata["count"]  = "7";
    return ev;
}

// Receive up to `expected` single-frame JSON messages from a SUB socket.
// Returns count of messages received within timeout.
static int recv_n(void* sock, int expected,
                  std::chrono::milliseconds timeout = 2000ms) {
    int count = 0;
    auto deadline = std::chrono::steady_clock::now() + timeout;

    while (count < expected && std::chrono::steady_clock::now() < deadline) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);
        // Non-blocking poll so we can respect the deadline.
        int rc = zmq_msg_recv(&msg, sock, ZMQ_DONTWAIT);
        if (rc >= 0) {
            ++count;
        } else {
            std::this_thread::sleep_for(5ms);
        }
        zmq_msg_close(&msg);
    }
    return count;
}

// Receive one message and return its contents as a string.
static std::string recv_one(void* sock,
                            std::chrono::milliseconds timeout = 2000ms) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);
        int rc = zmq_msg_recv(&msg, sock, ZMQ_DONTWAIT);
        if (rc >= 0) {
            std::string out(static_cast<const char*>(zmq_msg_data(&msg)),
                            zmq_msg_size(&msg));
            zmq_msg_close(&msg);
            return out;
        }
        zmq_msg_close(&msg);
        std::this_thread::sleep_for(5ms);
    }
    return {};
}

// Create a SUB socket subscribed to everything (empty filter = accept all).
// Single-frame mode: no topic prefix, just raw JSON.
static void* make_sub(void* ctx, const std::string& endpoint) {
    void* sock = zmq_socket(ctx, ZMQ_SUB);
    // Empty string filter = accept ALL messages regardless of content.
    zmq_setsockopt(sock, ZMQ_SUBSCRIBE, "", 0);
    int linger = 0;
    zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_connect(sock, endpoint.c_str());
    return sock;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

TEST(AlertPublisher, StartStop) {
    AlertPublisher pub("tcp://*:5601");
    EXPECT_FALSE(pub.running());
    pub.start();
    EXPECT_TRUE(pub.running());
    pub.stop();
    EXPECT_FALSE(pub.running());
}

TEST(AlertPublisher, StopBeforeStartIsNoop) {
    AlertPublisher pub("tcp://*:5602");
    EXPECT_NO_THROW(pub.stop());
}

TEST(AlertPublisher, DoubleStartIsNoop) {
    AlertPublisher pub("tcp://*:5603");
    pub.start();
    EXPECT_NO_THROW(pub.start());
    pub.stop();
}

TEST(AlertPublisher, DestructorStops) {
    {
        AlertPublisher pub("tcp://*:5604");
        pub.start();
        pub.publish(make_alert());
    }
    SUCCEED();
}

TEST(AlertPublisher, SingleAlertIsReceived) {
    // PUB must bind before SUB connects, then we wait for the handshake.
    AlertPublisher pub("tcp://*:5605");
    pub.start();

    void* ctx  = zmq_ctx_new();
    void* sock = make_sub(ctx, "tcp://127.0.0.1:5605");
    std::this_thread::sleep_for(300ms);  // wait for PUB/SUB handshake

    pub.publish(make_alert("a-001"));

    int count = recv_n(sock, 1, 2000ms);

    pub.stop();
    zmq_close(sock);
    zmq_ctx_destroy(ctx);

    EXPECT_EQ(count, 1);
    EXPECT_EQ(pub.sent_count(), 1u);
    EXPECT_EQ(pub.dropped_count(), 0u);
}

TEST(AlertPublisher, MultipleAlertsAllReceived) {
    AlertPublisher pub("tcp://*:5606");
    pub.start();

    void* ctx  = zmq_ctx_new();
    void* sock = make_sub(ctx, "tcp://127.0.0.1:5606");
    std::this_thread::sleep_for(300ms);

    const int N = 10;
    for (int i = 0; i < N; ++i)
        pub.publish(make_alert("m-" + std::to_string(i)));

    int count = recv_n(sock, N, 3000ms);

    pub.stop();
    zmq_close(sock);
    zmq_ctx_destroy(ctx);

    EXPECT_EQ(count, N);
    EXPECT_EQ(pub.sent_count(), static_cast<uint64_t>(N));
    EXPECT_EQ(pub.dropped_count(), 0u);
}

TEST(AlertPublisher, DropsWhenQueueFull) {
    // Do NOT call start() — no send thread means nothing drains the queue.
    // publish() still works; it just fills the queue until QUEUE_CAPACITY.
    AlertPublisher pub("tcp://*:5607");

    const std::size_t over = AlertPublisher::QUEUE_CAPACITY + 200;
    for (std::size_t i = 0; i < over; ++i)
        pub.publish(make_alert("d-" + std::to_string(i)));

    EXPECT_GT(pub.dropped_count(), 0u);
    EXPECT_EQ(pub.dropped_count(), 200u);
}

TEST(AlertPublisher, ConcurrentPublishIsSafe) {
    AlertPublisher pub("tcp://*:5608");
    pub.start();

    const int THREADS = 4;
    const int PER     = 50;
    std::vector<std::thread> workers;
    workers.reserve(THREADS);

    for (int t = 0; t < THREADS; ++t) {
        workers.emplace_back([&, t]{
            for (int i = 0; i < PER; ++i)
                pub.publish(make_alert("c-" + std::to_string(t * 1000 + i)));
        });
    }
    for (auto& w : workers) w.join();

    pub.stop();

    EXPECT_EQ(pub.sent_count() + pub.dropped_count(),
              static_cast<uint64_t>(THREADS * PER));
}

TEST(AlertPublisher, SerializedPayloadRoundtrips) {
    AlertPublisher pub("tcp://*:5609");
    pub.start();

    void* ctx  = zmq_ctx_new();
    void* sock = make_sub(ctx, "tcp://127.0.0.1:5609");
    std::this_thread::sleep_for(300ms);  // wait for PUB/SUB handshake

    AlertEvent original = make_alert("rt-001", Severity::CRITICAL);
    pub.publish(original);

    std::string json = recv_one(sock, 2000ms);

    pub.stop();
    zmq_close(sock);
    zmq_ctx_destroy(ctx);

    ASSERT_FALSE(json.empty());
    auto maybe = deserialize(json);
    ASSERT_TRUE(maybe.has_value());
    EXPECT_EQ(maybe->alert_id,    original.alert_id);
    EXPECT_EQ(maybe->source_host, original.source_host);
    EXPECT_EQ(maybe->severity,    original.severity);
    EXPECT_EQ(maybe->rule_id,     original.rule_id);
}