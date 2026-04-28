#pragma once

#include "dlads/alert_event.hpp"
#include <chrono>
#include <cmath>
#include <optional>
#include <string>
#include <unordered_map>

namespace dlads {

class ZScoreDetector {
public:
    explicit ZScoreDetector(double threshold = 3.0)
        : threshold_(threshold) {}

    // Feed a new event rate observation for a source_host.
    // Returns a filled AlertEvent if anomaly detected, nullopt otherwise.
    std::optional<AlertEvent> update(
        const std::string& source_host,
        double             current_rate,
        const std::string& source_ip      = "",
        const std::string& log_id         = "")
    {
        auto& s = states_[source_host];
        s.count++;

        // Welford online update
        double delta  = current_rate - s.mean;
        s.mean       += delta / s.count;
        double delta2 = current_rate - s.mean;
        s.M2         += delta * delta2;

        // Need at least 2 samples to compute variance
        if (s.count < 2) return std::nullopt;

        double variance = s.M2 / (s.count - 1);
        double stddev   = std::sqrt(variance);
        if (stddev < 1e-9) return std::nullopt;

        double z = std::abs(current_rate - s.mean) / stddev;
        if (z < threshold_) return std::nullopt;

        // Build AlertEvent using their exact struct + helpers
        AlertEvent alert;
        alert.alert_id    = AlertEvent::next_id();
        alert.timestamp   = std::chrono::system_clock::now();
        alert.source_host = source_host;
        alert.rule_id     = "RULE-ZSCORE-ANOMALY";

        // Map Z-score to severity
        if      (z > 6.0) alert.severity = Severity::CRITICAL;
        else if (z > 4.5) alert.severity = Severity::HIGH;
        else if (z > 3.0) alert.severity = Severity::MEDIUM;
        else              alert.severity = Severity::LOW;

        // Clamp anomaly_score to [0, 1]
        alert.anomaly_score = static_cast<float>(std::min(1.0, z / 10.0));

        alert.description = "Statistical anomaly detected: event rate deviated "
                          + std::to_string(z).substr(0, 4)
                          + " standard deviations from baseline";

        if (!log_id.empty())
            alert.contributing_log_ids.push_back(log_id);

        if (!source_ip.empty())
            alert.metadata["source_ip"] = source_ip;

        alert.metadata["z_score"]       = std::to_string(z).substr(0, 5);
        alert.metadata["current_rate"]  = std::to_string(current_rate).substr(0, 5);
        alert.metadata["baseline_mean"] = std::to_string(s.mean).substr(0, 5);

        return alert;
    }

    // Reset state for a specific host (useful in tests)
    void reset(const std::string& source_host) {
        states_.erase(source_host);
    }

private:
    struct WelfordState {
        int    count = 0;
        double mean  = 0.0;
        double M2    = 0.0;
    };

    double threshold_;
    std::unordered_map<std::string, WelfordState> states_;
};

} // namespace dlads