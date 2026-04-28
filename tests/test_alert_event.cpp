#include "dlads/alert_event.hpp"

#include <chrono>
#include <cmath>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

using namespace dlads;
using namespace std::chrono_literals;

// ── Helpers ───────────────────────────────────────────────────────────────────

static AlertEvent make_full() {
    AlertEvent ev;
    ev.alert_id    = "alert-42";
    ev.timestamp   = std::chrono::system_clock::time_point{
                         std::chrono::seconds{1704196800} }; // 2024-01-02 12:00:00 UTC
    ev.source_host = "webserver01";
    ev.rule_id     = "SSH_BRUTE_FORCE_001";
    ev.severity    = Severity::HIGH;
    ev.anomaly_score = 0.87f;
    ev.description = "Repeated failed SSH logins from single source";
    ev.contributing_log_ids = {"log-1", "log-2", "log-3"};
    ev.metadata = {
        {"src_ip", "192.168.1.100"},
        {"attempt_count", "25"},
        {"username", "root"},
    };
    return ev;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Severity helpers
// ─────────────────────────────────────────────────────────────────────────────

TEST(SeverityTest, ToStringRoundTrip) {
    for (auto s : { Severity::LOW, Severity::MEDIUM,
                    Severity::HIGH, Severity::CRITICAL }) {
        auto str = to_string(s);
        auto back = severity_from_string(str);
        ASSERT_TRUE(back.has_value()) << "failed for: " << str;
        EXPECT_EQ(*back, s);
    }
}

TEST(SeverityTest, FromStringUnknownReturnsNullopt) {
    EXPECT_FALSE(severity_from_string("").has_value());
    EXPECT_FALSE(severity_from_string("low").has_value());   // case sensitive
    EXPECT_FALSE(severity_from_string("EXTREME").has_value());
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. next_id
// ─────────────────────────────────────────────────────────────────────────────

TEST(AlertEventId, IdsAreUnique) {
    constexpr int N = 1000;
    std::set<std::string> ids;
    for (int i = 0; i < N; ++i)
        ids.insert(AlertEvent::next_id());
    EXPECT_EQ(ids.size(), static_cast<std::size_t>(N));
}

TEST(AlertEventId, IdsAreMonotonic) {
    // IDs are "alert-N" — successive calls must produce increasing N.
    auto a = AlertEvent::next_id();
    auto b = AlertEvent::next_id();
    // Extract the numeric suffix and compare.
    auto num = [](const std::string& id) {
        return std::stoull(id.substr(id.find('-') + 1));
    };
    EXPECT_LT(num(a), num(b));
}

TEST(AlertEventId, ThreadSafeUniqueness) {
    constexpr int THREADS = 8;
    constexpr int PER_THREAD = 500;
    std::vector<std::vector<std::string>> buckets(THREADS);

    std::vector<std::thread> threads;
    threads.reserve(THREADS);
    for (int t = 0; t < THREADS; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < PER_THREAD; ++i)
                buckets[t].push_back(AlertEvent::next_id());
        });
    }
    for (auto& th : threads) th.join();

    std::set<std::string> all;
    for (auto& b : buckets)
        for (auto& id : b) all.insert(id);

    EXPECT_EQ(all.size(), static_cast<std::size_t>(THREADS * PER_THREAD));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Round-trip serialization
// ─────────────────────────────────────────────────────────────────────────────

TEST(AlertEventSerde, FullRoundTrip) {
    auto original = make_full();
    auto json_str = serialize(original);
    auto restored = deserialize(json_str);

    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->alert_id,    original.alert_id);
    EXPECT_EQ(restored->source_host, original.source_host);
    EXPECT_EQ(restored->rule_id,     original.rule_id);
    EXPECT_EQ(restored->severity,    original.severity);
    EXPECT_EQ(restored->description, original.description);

    // Timestamp round-trips at second precision.
    auto orig_sec = std::chrono::duration_cast<std::chrono::seconds>(
        original.timestamp.time_since_epoch()).count();
    auto rest_sec = std::chrono::duration_cast<std::chrono::seconds>(
        restored->timestamp.time_since_epoch()).count();
    EXPECT_EQ(orig_sec, rest_sec);

    // anomaly_score: round-trip may have float quantization; allow 1e-4 delta.
    EXPECT_NEAR(restored->anomaly_score, original.anomaly_score, 1e-4f);
}

TEST(AlertEventSerde, ContributingLogIdsRoundTrip) {
    auto original = make_full();
    auto restored = deserialize(serialize(original));
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->contributing_log_ids, original.contributing_log_ids);
}

TEST(AlertEventSerde, MetadataRoundTrip) {
    auto original = make_full();
    auto restored = deserialize(serialize(original));
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->metadata, original.metadata);
}

TEST(AlertEventSerde, AllSeverityLevelsRoundTrip) {
    for (auto s : { Severity::LOW, Severity::MEDIUM,
                    Severity::HIGH, Severity::CRITICAL }) {
        AlertEvent ev;
        ev.alert_id    = "x";
        ev.source_host = "h";
        ev.rule_id     = "r";
        ev.severity    = s;
        ev.timestamp   = std::chrono::system_clock::now();

        auto restored = deserialize(serialize(ev));
        ASSERT_TRUE(restored.has_value());
        EXPECT_EQ(restored->severity, s);
    }
}

TEST(AlertEventSerde, EmptyCollectionsRoundTrip) {
    AlertEvent ev;
    ev.alert_id    = "alert-1";
    ev.source_host = "host";
    ev.rule_id     = "RULE";
    ev.severity    = Severity::LOW;
    ev.timestamp   = std::chrono::system_clock::now();
    // contributing_log_ids and metadata are empty.

    auto restored = deserialize(serialize(ev));
    ASSERT_TRUE(restored.has_value());
    EXPECT_TRUE(restored->contributing_log_ids.empty());
    EXPECT_TRUE(restored->metadata.empty());
}

TEST(AlertEventSerde, MassRoundTrip) {
    // 100 events with randomised scores, all must survive the round-trip.
    for (int i = 0; i < 100; ++i) {
        AlertEvent ev;
        ev.alert_id      = AlertEvent::next_id();
        ev.source_host   = "host-" + std::to_string(i % 10);
        ev.rule_id       = "RULE_" + std::to_string(i % 5);
        ev.severity      = static_cast<Severity>((i % 4) + 1);
        ev.anomaly_score = static_cast<float>(i) / 100.0f;
        ev.description   = "alert " + std::to_string(i);
        ev.timestamp     = std::chrono::system_clock::now();
        ev.metadata      = {{"idx", std::to_string(i)}};

        auto restored = deserialize(serialize(ev));
        ASSERT_TRUE(restored.has_value()) << "failed at i=" << i;
        EXPECT_EQ(restored->alert_id, ev.alert_id);
        EXPECT_NEAR(restored->anomaly_score, ev.anomaly_score, 1e-4f);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. deserialize rejects invalid input
// ─────────────────────────────────────────────────────────────────────────────

TEST(AlertEventDeserialize, EmptyStringReturnsNullopt) {
    EXPECT_FALSE(deserialize("").has_value());
}

TEST(AlertEventDeserialize, NotJsonReturnsNullopt) {
    EXPECT_FALSE(deserialize("not json at all !!").has_value());
}

TEST(AlertEventDeserialize, JsonArrayReturnsNullopt) {
    EXPECT_FALSE(deserialize("[1,2,3]").has_value());
}

TEST(AlertEventDeserialize, MissingAlertIdReturnsNullopt) {
    // Build a valid JSON but remove alert_id.
    auto j = R"({"source_host":"h","rule_id":"r","severity":"LOW",)"
             R"("timestamp":1000,"anomaly_score":0.0,"description":""})";
    EXPECT_FALSE(deserialize(j).has_value());
}

TEST(AlertEventDeserialize, MissingRuleIdReturnsNullopt) {
    auto j = R"({"alert_id":"a","source_host":"h","severity":"LOW",)"
             R"("timestamp":1000,"anomaly_score":0.0,"description":""})";
    EXPECT_FALSE(deserialize(j).has_value());
}

TEST(AlertEventDeserialize, MissingSourceHostReturnsNullopt) {
    auto j = R"({"alert_id":"a","rule_id":"r","severity":"LOW",)"
             R"("timestamp":1000,"anomaly_score":0.0,"description":""})";
    EXPECT_FALSE(deserialize(j).has_value());
}

TEST(AlertEventDeserialize, UnknownSeverityReturnsNullopt) {
    auto j = R"({"alert_id":"a","source_host":"h","rule_id":"r",)"
             R"("severity":"EXTREME","timestamp":1000})";
    EXPECT_FALSE(deserialize(j).has_value());
}

TEST(AlertEventDeserialize, MissingTimestampReturnsNullopt) {
    auto j = R"({"alert_id":"a","source_host":"h","rule_id":"r","severity":"LOW"})";
    EXPECT_FALSE(deserialize(j).has_value());
}

TEST(AlertEventDeserialize, WrongTypeForAlertIdReturnsNullopt) {
    auto j = R"({"alert_id":123,"source_host":"h","rule_id":"r",)"
             R"("severity":"LOW","timestamp":1000})";
    EXPECT_FALSE(deserialize(j).has_value());
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Anomaly score clamping
// ─────────────────────────────────────────────────────────────────────────────

TEST(AlertEventSerde, AnomalyScoreClampedAboveOne) {
    AlertEvent ev;
    ev.alert_id = "a"; ev.source_host = "h"; ev.rule_id = "r";
    ev.severity = Severity::LOW; ev.timestamp = std::chrono::system_clock::now();
    ev.anomaly_score = 99.9f;   // way out of range

    auto restored = deserialize(serialize(ev));
    ASSERT_TRUE(restored.has_value());
    EXPECT_LE(restored->anomaly_score, 1.0f);
}

TEST(AlertEventSerde, AnomalyScoreClampedBelowZero) {
    AlertEvent ev;
    ev.alert_id = "a"; ev.source_host = "h"; ev.rule_id = "r";
    ev.severity = Severity::LOW; ev.timestamp = std::chrono::system_clock::now();
    ev.anomaly_score = -5.0f;

    auto restored = deserialize(serialize(ev));
    ASSERT_TRUE(restored.has_value());
    EXPECT_GE(restored->anomaly_score, 0.0f);
}

TEST(AlertEventSerde, NanAnomalyScoreBecomesZero) {
    AlertEvent ev;
    ev.alert_id = "a"; ev.source_host = "h"; ev.rule_id = "r";
    ev.severity = Severity::LOW; ev.timestamp = std::chrono::system_clock::now();
    ev.anomaly_score = std::numeric_limits<float>::quiet_NaN();

    auto restored = deserialize(serialize(ev));
    ASSERT_TRUE(restored.has_value());
    EXPECT_FLOAT_EQ(restored->anomaly_score, 0.0f);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Serialized size budget
// ─────────────────────────────────────────────────────────────────────────────

TEST(AlertEventSerde, SerializedSizeUnder512Bytes) {
    auto ev = make_full();
    auto json_str = serialize(ev);
    EXPECT_LT(json_str.size(), 512u)
        << "Serialized size " << json_str.size()
        << " exceeds 512-byte budget.\nJSON: " << json_str;
}

TEST(AlertEventSerde, SerializedOutputIsValidUtf8Json) {
    auto ev = make_full();
    auto json_str = serialize(ev);

    // Must not be empty and must start/end with braces.
    ASSERT_FALSE(json_str.empty());
    EXPECT_EQ(json_str.front(), '{');
    EXPECT_EQ(json_str.back(),  '}');

    // Must be parseable back without throwing.
    EXPECT_NO_THROW(deserialize(json_str));
}