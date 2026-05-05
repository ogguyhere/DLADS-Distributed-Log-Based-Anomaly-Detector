#pragma once

#include "dlads/alert_event.hpp"
#include <algorithm>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

namespace dlads {

struct CorrelatedThreat {
    std::string              threat_id;
    std::string              source_ip;
    std::string              rule_id;
    Severity                 severity;
    std::vector<std::string> confirmed_by_nodes;
    std::string              evidence;
    std::chrono::system_clock::time_point timestamp;
};

class CorrelationEngine {
public:
    // correlation_window_sec: how long to keep alerts in memory
    // consensus_threshold: how many distinct nodes must agree
    explicit CorrelationEngine(
        int correlation_window_sec = 120,
        int consensus_threshold    = 2)
        : window_sec_(correlation_window_sec)
        , threshold_(consensus_threshold) {}

    // Called when a new alert arrives from any agent node.
    // Returns a CorrelatedThreat if consensus is reached, nullopt otherwise.
    std::optional<CorrelatedThreat> ingest(const AlertEvent& alert) {
        std::lock_guard<std::mutex> lock(mutex_);

        // Extract source_ip from metadata if present, else use source_host
        std::string source_ip = alert.source_host;
        if (alert.metadata.count("source_ip"))
            source_ip = alert.metadata.at("source_ip");

        // Key is (source_ip, rule_id)
        std::string key = source_ip + "|" + alert.rule_id;

        auto  now     = std::chrono::system_clock::now();
        auto& entries = index_[key];

        // Evict old entries outside the correlation window
        entries.erase(
            std::remove_if(entries.begin(), entries.end(),
                [&](const Entry& e) {
                    return std::chrono::duration_cast<std::chrono::seconds>(
                        now - e.timestamp).count() > window_sec_;
                }),
            entries.end());

        // Add this alert if this node hasn't already contributed
        bool already_present = false;
        for (const auto& e : entries)
            if (e.node_id == alert.source_host)
                already_present = true;

        if (!already_present)
            entries.push_back({ alert.source_host, alert.severity, now });

        // Check consensus
        if ((int)entries.size() < threshold_)
            return std::nullopt;

        // Build correlated threat
        CorrelatedThreat threat;
        threat.threat_id  = "threat-" + std::to_string(threat_counter_++);
        threat.source_ip  = source_ip;
        threat.rule_id    = alert.rule_id;
        threat.timestamp  = now;

        // Escalate severity — take the highest among all confirming nodes
        Severity max_sev = Severity::LOW;
        for (const auto& e : entries) {
            threat.confirmed_by_nodes.push_back(e.node_id);
            if (static_cast<uint8_t>(e.severity) > static_cast<uint8_t>(max_sev))
                max_sev = e.severity;
        }

        // Always escalate one level above highest individual severity
        threat.severity =
            (max_sev == Severity::CRITICAL) ? Severity::CRITICAL :
            (max_sev == Severity::HIGH)     ? Severity::CRITICAL :
            (max_sev == Severity::MEDIUM)   ? Severity::HIGH     :
                                              Severity::MEDIUM;

        threat.evidence = "Confirmed by " + std::to_string(entries.size())
                        + " nodes within " + std::to_string(window_sec_)
                        + "s — rule: " + alert.rule_id
                        + " from IP: " + source_ip;

        // Clear this key so we don't keep re-firing for same attack
        index_.erase(key);

        return threat;
    }

private:
    struct Entry {
        std::string                           node_id;
        Severity                              severity;
        std::chrono::system_clock::time_point timestamp;
    };

    int window_sec_;
    int threshold_;
    int threat_counter_ = 1;
    std::mutex mutex_;
    std::unordered_map<std::string, std::vector<Entry>> index_;
};

} // namespace dlads