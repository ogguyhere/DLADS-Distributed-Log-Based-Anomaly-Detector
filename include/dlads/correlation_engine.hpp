#pragma once

#include "dlads/alert_event.hpp"
#include <algorithm>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace dlads {

struct CorrelatedThreat {
    std::string              threat_id;
    std::string              source_ip;
    std::string              rule_id;          // rule that triggered consensus
    Severity                 severity;
    std::vector<std::string> confirmed_by_nodes;
    std::string              evidence;
    std::chrono::system_clock::time_point timestamp;
};

class CorrelationEngine {
public:
    explicit CorrelationEngine(
        int correlation_window_sec = 120,
        int consensus_threshold    = 2)
        : window_sec_(correlation_window_sec)
        , threshold_(consensus_threshold) {}

    std::optional<CorrelatedThreat> ingest(const AlertEvent& alert) {
        std::lock_guard<std::mutex> lock(mutex_);

        // FIX 1: check "src_ip" first (your rule engine stores it under src_ip),
        // then "source_ip" for compatibility, then fall back to source_host.
        std::string source_ip = alert.source_host;
        if (alert.metadata.count("src_ip"))
            source_ip = alert.metadata.at("src_ip");
        else if (alert.metadata.count("source_ip"))
            source_ip = alert.metadata.at("source_ip");

        // FIX 2: key on source_ip only — a distributed attack from one IP
        // using different techniques on different nodes is ONE threat.
        // Keying on (ip + rule_id) means SSH on node-1 and PortScan on node-2
        // never correlate because their rule_ids differ.
        std::string key = source_ip;

        auto  now     = std::chrono::system_clock::now();
        auto& entries = index_[key];

        // Evict entries outside the correlation window.
        entries.erase(
            std::remove_if(entries.begin(), entries.end(),
                [&](const Entry& e) {
                    return std::chrono::duration_cast<std::chrono::seconds>(
                        now - e.timestamp).count() > window_sec_;
                }),
            entries.end());

        // Add this alert if this node hasn't already contributed.
        bool already_present = false;
        for (const auto& e : entries)
            if (e.node_id == alert.source_host)
                already_present = true;

        if (!already_present)
            entries.push_back({ alert.source_host, alert.rule_id,
                                 alert.severity, now });

        if ((int)entries.size() < threshold_)
            return std::nullopt;

        // ── Build correlated threat ───────────────────────────────────────────
        CorrelatedThreat threat;
        threat.threat_id = "threat-" + std::to_string(threat_counter_++);
        threat.source_ip = source_ip;
        threat.timestamp = now;

        // Collect all rule_ids seen — list them in evidence.
        std::string rules_seen;
        Severity max_sev = Severity::LOW;
        for (const auto& e : entries) {
            threat.confirmed_by_nodes.push_back(e.node_id);
            if (!rules_seen.empty()) rules_seen += ',';
            rules_seen += e.rule_id;
            if (static_cast<uint8_t>(e.severity) > static_cast<uint8_t>(max_sev))
                max_sev = e.severity;
        }

        // Use the triggering alert's rule_id as the primary rule.
        threat.rule_id = alert.rule_id;

        // Escalate one level above the highest individual severity.
        threat.severity =
            (max_sev == Severity::CRITICAL) ? Severity::CRITICAL :
            (max_sev == Severity::HIGH)     ? Severity::CRITICAL :
            (max_sev == Severity::MEDIUM)   ? Severity::HIGH     :
                                              Severity::MEDIUM;

        threat.evidence = "Confirmed by " + std::to_string(entries.size())
                        + " nodes within " + std::to_string(window_sec_)
                        + "s — rules: [" + rules_seen + "]"
                        + " from IP: " + source_ip;

        // Clear so the same attack doesn't keep re-firing.
        index_.erase(key);

        return threat;
    }

private:
    struct Entry {
        std::string                           node_id;
        std::string                           rule_id;
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