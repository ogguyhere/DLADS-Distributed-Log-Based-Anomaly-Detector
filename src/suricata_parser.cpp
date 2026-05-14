#include "dlads/suricata_parser.hpp"
#include "dlads/alert_event.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <string>

namespace dlads {

using json = nlohmann::json;

// Suricata severity is 1–4, inverted (1 = most critical).
Severity SuricataParser::severity_from_suricata(int level) noexcept {
    switch (level) {
        case 1:  return Severity::CRITICAL;
        case 2:  return Severity::HIGH;
        case 3:  return Severity::MEDIUM;
        default: return Severity::LOW;
    }
}

std::optional<AlertEvent> SuricataParser::parse(
        std::string_view line,
        const std::string& node_id) const
{
    if (line.empty()) return std::nullopt;

    json j;
    try {
        j = json::parse(line);
    } catch (...) {
        return std::nullopt;
    }

    // Only process alert events — skip flow, dns, tls, stats, etc.
    if (!j.contains("event_type") || j["event_type"] != "alert")
        return std::nullopt;

    // alert sub-object is required.
    if (!j.contains("alert") || !j["alert"].is_object())
        return std::nullopt;

    const auto& a = j["alert"];

    AlertEvent ev;
    ev.alert_id    = node_id + "-" + AlertEvent::next_id();
    ev.source_host = node_id;
    ev.timestamp   = std::chrono::system_clock::now();

    // rule_id: "SID-<signature_id>" so coordinator can correlate by rule family.
    int sid = a.value("signature_id", 0);
    ev.rule_id = "SURICATA-SID-" + std::to_string(sid);

    // Severity — Suricata 1=critical, 4=low (inverted from our scale).
    int sev_int = a.value("severity", 4);
    ev.severity = severity_from_suricata(sev_int);

    // anomaly_score: map Suricata severity to [0,1].
    ev.anomaly_score = 1.0f - ((sev_int - 1) / 3.0f);

    // Human-readable description from signature + category.
    std::string sig = a.value("signature", "unknown");
    std::string cat = a.value("category",  "");
    ev.description = sig;
    if (!cat.empty()) ev.description += " [" + cat + "]";

    // Evidence metadata — all top-level fields the coordinator may need.
    if (j.contains("src_ip"))   ev.metadata["src_ip"]   = j["src_ip"];
    if (j.contains("dest_ip"))  ev.metadata["dest_ip"]  = j["dest_ip"];
    if (j.contains("proto"))    ev.metadata["proto"]    = j["proto"];
    if (j.contains("app_proto"))ev.metadata["app_proto"]= j["app_proto"];

    if (j.contains("dest_port") && j["dest_port"].is_number())
        ev.metadata["dest_port"] = std::to_string(j["dest_port"].get<int>());
    if (j.contains("src_port") && j["src_port"].is_number())
        ev.metadata["src_port"]  = std::to_string(j["src_port"].get<int>());

    ev.metadata["signature_id"] = std::to_string(sid);
    ev.metadata["action"]       = a.value("action", "");
    if (!cat.empty()) ev.metadata["category"] = cat;

    // TLS SNI if present — useful for identifying the target service.
    if (j.contains("tls") && j["tls"].contains("sni"))
        ev.metadata["tls_sni"] = j["tls"]["sni"];

    return ev;
}

}  // namespace dlads