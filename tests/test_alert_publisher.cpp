#include "dlads/alert_publisher.hpp"
#include "dlads/alert_event.hpp"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <zmq.h>
#include <gtest/gtest.h>

using namespace dlads;
using namespace std::chrono_literals;

// ── Helpers ───────────────────────────────────────────────────────────────────

static AlertEvent make_alert(const std::string& rule = "TEST_RULE") {
    AlertEvent ev;
    ev.alert_id    = AlertEvent::next_id();
    ev.timestamp   = std::chrono::system_clock::now();
    ev.source_host = "testhost";
    ev.rule_id     = rule;
    ev.severity    = Severity::HIGH;
    ev.anomaly_score = 0.75f;
    ev.description = "test alert";
    ev.metadata["src_ip"] = "10.0.0.1";
    return ev;
}

// Pick a port unlikely to be in use.
static std::string pub_endpoint(int port) {
    return "tcp://127.0.0.1:" + std::to_string(port);
}
static std::string sub_endpoint(int port) {
    return "tcp://127.0.0.1:" + std::to_string(port);
}

// Receive up to `count` messages from a SUB socket within `timeout`.
// Returns the received JSON strings.
static std::vector<std::string> recv_n(void* sock, int count,
                                        std::chrono::milliseconds timeout) {
    std::vector<std::string> out;
    auto deadline = std::chrono::steady_clock::now() + timeout;

    while (static_cast<int>(out.size()) < count &&
           std::chrono::steady_clock::now() < deadline) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);
        int rc = zmq_msg_recv(&msg, sock, ZMQ_DONTWAIT);
        if (rc > 0) {
            out.emplace_back(static_cast<char*>(zmq_msg_data(&msg)),
                             zmq_msg_size(&msg));
            zmq_msg_close(&msg);
        } else {
            zmq_msg_close(&msg);
            std::this_thread::sleep_for(10ms);
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture: spins up a ZMQ SUB socket for each test
// ─────────────────────────────────────────────────────────────────────────────
class PublisherTest : public ::testing::Test {
protected:
    void SetUp() override {
        ctx_  = zmq_ctx_new();
        sock_ = zmq_socket(ctx_, ZMQ_SUB);

        int linger = 0;
        zmq_setsockopt(sock_, ZMQ_LINGER, &linger, sizeof(linger));
        // Subscribe to all messages.
        zmq_setsockopt(sock_, ZMQ_SUBSCRIBE, "", 0);

        // Assign a unique port per test to avoid cross-test interference.
        port_ = 15000 + (test_counter_++ % 100);
        zmq_connect(sock_, sub_endpoint(port_).c_str());
    }

    void TearDown() override {
        zmq_close(sock_);
        zmq_ctx_destroy(ctx_);
    }

    void* ctx_  = nullptr;
    void* sock_ = nullptr;
    int   port_ = 0;
    static inline std::atomic<int> test_counter_{ 0 };
};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Basic delivery
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(PublisherTest, DeliversSingleAlert) {
    AlertPublisher pub(pub_endpoint(port_));
    pub.start();
    std::this_thread::sleep_for(50ms);  // let socket bind + SUB connect

    pub.publish(make_alert());

    auto msgs = recv_n(sock_, 1, 2000ms);
    pub.stop();

    ASSERT_EQ(msgs.size(), 1u);
    auto ev = deserialize(msgs[0]);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->rule_id, "TEST_RULE");
}

TEST_F(PublisherTest, Delivers1000Alerts) {
    AlertPublisher pub(pub_endpoint(port_));
    pub.start();
    std::this_thread::sleep_for(50ms);

    constexpr int N = 1000;
    for (int i = 0; i < N; ++i)
        pub.publish(make_alert("RULE_" + std::to_string(i % 10)));

    auto msgs = recv_n(sock_, N, 5000ms);
    pub.stop();

    EXPECT_EQ(msgs.size(), static_cast<std::size_t>(N));
    // Every received message must deserialize cleanly.
    for (auto& m : msgs) {
        EXPECT_TRUE(deserialize(m).has_value());
    }
}

TEST_F(PublisherTest, AlertContentSurvivesWire) {
    AlertPublisher pub(pub_endpoint(port_));
    pub.start();
    std::this_thread::sleep_for(50ms);

    auto original = make_alert("WIRE_CHECK");
    original.severity      = Severity::CRITICAL;
    original.anomaly_score = 0.99f;
    original.metadata["src_ip"] = "192.168.1.55";
    pub.publish(original);

    auto msgs = recv_n(sock_, 1, 2000ms);
    pub.stop();

    ASSERT_EQ(msgs.size(), 1u);
    auto ev = deserialize(msgs[0]);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->rule_id,              "WIRE_CHECK");
    EXPECT_EQ(ev->severity,             Severity::CRITICAL);
    EXPECT_NEAR(ev->anomaly_score,      0.99f, 1e-4f);
    EXPECT_EQ(ev->metadata.at("src_ip"),"192.168.1.55");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Non-blocking guarantee
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(PublisherTest, PublishNeverBlocksWhenNoReceiver) {
    // Use a port with NO subscriber connected.
    AlertPublisher pub("tcp://127.0.0.1:19999");
    pub.start();
    std::this_thread::sleep_for(50ms);

    constexpr int N = 2000;
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < N; ++i)
        pub.publish(make_alert());
    auto elapsed = std::chrono::steady_clock::now() - t0;
    pub.stop();

    // 2000 publish() calls must complete in well under 1 second total.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(),
              1000)
        << "publish() appears to be blocking";
}

TEST_F(PublisherTest, DroppedCountReflectsQueueOverflow) {
    // Fill more than queue capacity (1024) without a receiver draining it.
    // Use a port with no subscriber so the send thread can't drain fast enough
    // to race with our push.
    AlertPublisher pub("tcp://127.0.0.1:19998");
    pub.start();

    // Push 1200 alerts immediately — 176 should overflow the 1024 queue.
    for (int i = 0; i < 1200; ++i)
        pub.publish(make_alert());

    pub.stop();
    EXPECT_GT(pub.dropped_count(), 0u);
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(PublisherTest, StopReturnsQuickly) {
    AlertPublisher pub(pub_endpoint(port_));
    pub.start();
    std::this_thread::sleep_for(50ms);
    EXPECT_TRUE(pub.running());

    auto t0 = std::chrono::steady_clock::now();
    pub.stop();
    auto elapsed = std::chrono::steady_clock::now() - t0;

    EXPECT_FALSE(pub.running());
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(),
              500);
}

TEST_F(PublisherTest, StopWithoutStartIsNoop) {
    AlertPublisher pub(pub_endpoint(port_));
    pub.stop();  // must not crash
    EXPECT_FALSE(pub.running());
}

TEST_F(PublisherTest, DestructorStopsSendThread) {
    {
        AlertPublisher pub(pub_endpoint(port_));
        pub.start();
        std::this_thread::sleep_for(30ms);
    }  // destructor here — must not hang
    SUCCEED();
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Latency smoke test
// ─────────────────────────────────────────────────────────────────────────────

TEST_F(PublisherTest, MedianLatencyUnder5ms) {
    AlertPublisher pub(pub_endpoint(port_));
    pub.start();
    std::this_thread::sleep_for(100ms);  // let SUB fully connect

    constexpr int N = 50;
    std::vector<long long> latencies;
    latencies.reserve(N);

    for (int i = 0; i < N; ++i) {
        auto sent = std::chrono::steady_clock::now();
        pub.publish(make_alert());
        auto msgs = recv_n(sock_, 1, 500ms);
        if (!msgs.empty()) {
            auto recv_time = std::chrono::steady_clock::now();
            latencies.push_back(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    recv_time - sent).count());
        }
        std::this_thread::sleep_for(5ms);
    }
    pub.stop();

    ASSERT_FALSE(latencies.empty());
    std::sort(latencies.begin(), latencies.end());
    long long median = latencies[latencies.size() / 2];
    std::cout << "[LATENCY] median=" << median << " us  "
              << "p95=" << latencies[latencies.size() * 95 / 100] << " us\n";

    // 5ms = 5000us on loopback. ASan adds overhead so we use a generous bound.
    EXPECT_LT(median, 5000)
        << "Median latency " << median << "us exceeds 5ms target";
}