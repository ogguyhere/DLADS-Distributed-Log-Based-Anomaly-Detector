#include "dlads/zscore_detector.hpp"
#include <gtest/gtest.h>

using namespace dlads;

TEST(ZScoreDetector, NoAlertDuringNormalTraffic) {
    ZScoreDetector detector(3.0);

    // Feed 50 normal observations — should produce no alerts
    for (int i = 0; i < 50; i++) {
        auto result = detector.update("node-1", 5.0 + (i % 3 - 1));
        EXPECT_FALSE(result.has_value());
    }
}

TEST(ZScoreDetector, AlertOnSpike) {
    ZScoreDetector detector(3.0);

    // Establish baseline
    for (int i = 0; i < 50; i++)
        detector.update("node-1", 5.0 + (i % 3 - 1));

    // Inject spike
    auto result = detector.update("node-1", 95.0);
    ASSERT_TRUE(result.has_value());

    const auto& alert = result.value();
    EXPECT_EQ(alert.source_host, "node-1");
    EXPECT_EQ(alert.rule_id, "RULE-ZSCORE-ANOMALY");
    EXPECT_EQ(alert.severity, Severity::CRITICAL);
    EXPECT_GT(alert.anomaly_score, 0.5f);
    EXPECT_FALSE(alert.alert_id.empty());
}

TEST(ZScoreDetector, MetadataPopulated) {
    ZScoreDetector detector(3.0);

    for (int i = 0; i < 50; i++)
        detector.update("node-2", 5.0, "192.168.1.50");

    auto result = detector.update("node-2", 95.0, "192.168.1.50", "log-999");
    ASSERT_TRUE(result.has_value());

    const auto& alert = result.value();
    EXPECT_EQ(alert.metadata.at("source_ip"), "192.168.1.50");
    EXPECT_EQ(alert.contributing_log_ids[0], "log-999");
    EXPECT_TRUE(alert.metadata.count("z_score"));
}

TEST(ZScoreDetector, SeparateStatePerHost) {
    ZScoreDetector detector(3.0);

    // node-1 builds normal baseline
    for (int i = 0; i < 50; i++)
        detector.update("node-1", 5.0);

    // node-2 has no baseline yet — should not alert even on high value
    auto result = detector.update("node-2", 95.0);
    EXPECT_FALSE(result.has_value()); // only 1 sample, no variance yet
}

TEST(ZScoreDetector, SerializeRoundTrip) {
    ZScoreDetector detector(3.0);

    for (int i = 0; i < 50; i++)
        detector.update("node-3", 5.0);

    auto result = detector.update("node-3", 95.0);
    ASSERT_TRUE(result.has_value());

    // Serialize and deserialize — must survive the round trip
    std::string json = dlads::serialize(result.value());
    auto recovered   = dlads::deserialize(json);

    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(recovered->alert_id,    result->alert_id);
    EXPECT_EQ(recovered->source_host, result->source_host);
    EXPECT_EQ(recovered->severity,    result->severity);
    EXPECT_EQ(recovered->rule_id,     result->rule_id);
}