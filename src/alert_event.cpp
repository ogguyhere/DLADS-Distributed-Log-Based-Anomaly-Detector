#include "dlads/alert_event.hpp"

#include <atomic>
#include <chrono>
#include <cmath>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

namespace dlads {

using json = nlohmann::json;

// ── AlertEvent::next_id ───────────────────────────────────────────────────────

std::string AlertEvent::next_id() {
    static std::atomic<uint64_t> counter{ 1 };
    return "alert-" + std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

// ── serialize ─────────────────────────────────────────────────────────────────

std::string serialize(const AlertEvent& ev) {
    // Encode timestamp as integer Unix epoch seconds.
    auto epoch_sec = std::chrono::duration_cast<std::chrono::seconds>(
        ev.timestamp.time_since_epoch()).count();

    // Clamp anomaly_score to [0, 1] and reject NaN / inf.
    float score = ev.anomaly_score;
    if (!std::isfinite(score)) score = 0.0f;
    score = std::max(0.0f, std::min(1.0f, score));

    json j;
    j["alert_id"]             = ev.alert_id;
    j["timestamp"]            = epoch_sec;
    j["source_host"]          = ev.source_host;
    j["rule_id"]              = ev.rule_id;
    j["severity"]             = to_string(ev.severity);
    j["anomaly_score"]        = score;
    j["description"]          = ev.description;
    j["contributing_log_ids"] = ev.contributing_log_ids;
    j["metadata"]             = ev.metadata;

    return j.dump();
}

// ── deserialize ───────────────────────────────────────────────────────────────

std::optional<AlertEvent> deserialize(std::string_view json_sv) {
    if (json_sv.empty()) return std::nullopt;

    json j;
    try {
        j = json::parse(json_sv.begin(), json_sv.end());
    } catch (...) {
        return std::nullopt;
    }

    if (!j.is_object()) return std::nullopt;

    // ── Required string fields ────────────────────────────────────────────────
    auto get_str = [&](const char* key) -> std::optional<std::string> {
        auto it = j.find(key);
        if (it == j.end() || !it->is_string()) return std::nullopt;
        return it->get<std::string>();
    };

    auto alert_id   = get_str("alert_id");
    auto rule_id    = get_str("rule_id");
    auto source_host = get_str("source_host");
    auto sev_str    = get_str("severity");

    if (!alert_id || !rule_id || !source_host || !sev_str)
        return std::nullopt;

    auto sev = severity_from_string(*sev_str);
    if (!sev) return std::nullopt;

    // ── Required timestamp ────────────────────────────────────────────────────
    auto ts_it = j.find("timestamp");
    if (ts_it == j.end() || !ts_it->is_number_integer())
        return std::nullopt;

    AlertEvent ev;
    ev.alert_id    = std::move(*alert_id);
    ev.rule_id     = std::move(*rule_id);
    ev.source_host = std::move(*source_host);
    ev.severity    = *sev;

    int64_t epoch_sec = ts_it->get<int64_t>();
    ev.timestamp = std::chrono::system_clock::time_point{
        std::chrono::seconds{ epoch_sec }
    };

    // ── Optional numeric field ────────────────────────────────────────────────
    if (auto it = j.find("anomaly_score"); it != j.end() && it->is_number()) {
        float s = it->get<float>();
        if (std::isfinite(s))
            ev.anomaly_score = std::max(0.0f, std::min(1.0f, s));
    }

    // ── Optional string fields ────────────────────────────────────────────────
    if (auto desc = get_str("description")) ev.description = std::move(*desc);

    // ── Optional array: contributing_log_ids ─────────────────────────────────
    if (auto it = j.find("contributing_log_ids"); it != j.end() && it->is_array()) {
        for (const auto& el : *it) {
            if (el.is_string())
                ev.contributing_log_ids.push_back(el.get<std::string>());
        }
    }

    // ── Optional object: metadata ─────────────────────────────────────────────
    if (auto it = j.find("metadata"); it != j.end() && it->is_object()) {
        for (auto& [k, v] : it->items()) {
            if (v.is_string())
                ev.metadata.emplace(k, v.get<std::string>());
        }
    }

    return ev;
}

}  // namespace dlads