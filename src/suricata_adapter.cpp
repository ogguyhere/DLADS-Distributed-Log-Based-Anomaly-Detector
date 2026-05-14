#include "dlads/suricata_adapter.hpp"
#include "dlads/alert_event.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

namespace dlads {

using json = nlohmann::json;

// ── Constructor / Destructor ──────────────────────────────────────────────────

SuricataAdapter::SuricataAdapter(std::string   eve_json_path,
                                 AlertCallback cb,
                                 std::string   source_host)
    : eve_path_(std::move(eve_json_path))
    , cb_(std::move(cb))
    , source_host_(std::move(source_host))
{}

SuricataAdapter::~SuricataAdapter() { stop(); }

// ── Public API ────────────────────────────────────────────────────────────────

void SuricataAdapter::start() {
    if (running_.load(std::memory_order_acquire)) return;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread(&SuricataAdapter::run, this);
}

void SuricataAdapter::stop() {
    stop_.store(true, std::memory_order_release);
    if (thread_.joinable()) thread_.join();
    running_.store(false, std::memory_order_release);
}

// ── Tail loop ─────────────────────────────────────────────────────────────────
// Mimics `tail -f`: opens the file, seeks to end, then reads new lines as
// Suricata appends them. Polls every 100 ms when no new data is available.

void SuricataAdapter::run() {
    running_.store(true, std::memory_order_release);

    std::ifstream file(eve_path_, std::ios::in);
    if (!file.is_open()) {
        std::cerr << "[SuricataAdapter] ERROR: cannot open " << eve_path_ << "\n";
        running_.store(false, std::memory_order_release);
        return;
    }

    // Seek to end so we only process new events from this point forward.
    file.seekg(0, std::ios::end);

    std::string line;
    while (!stop_.load(std::memory_order_acquire)) {
        if (std::getline(file, line)) {
            if (line.empty()) continue;
            lines_processed_.fetch_add(1, std::memory_order_relaxed);

            AlertEvent alert;
            if (parse_eve_line(line, alert)) {
                alerts_converted_.fetch_add(1, std::memory_order_relaxed);
                cb_(std::move(alert));
            }
        } else {
            // No new data yet — clear EOF flag and wait.
            file.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    running_.store(false, std::memory_order_release);
}

// ── Eve.json line parser ──────────────────────────────────────────────────────
// Only processes lines where event_type == "alert". Silently skips all other
// event types (dns, flow, http, etc.) which make up the majority of eve.json.

bool SuricataAdapter::parse_eve_line(const std::string& line,
                                     AlertEvent&        out) const {
    json j;
    try {
        j = json::parse(line);
    } catch (...) {
        return false;  // malformed JSON — skip
    }

    // Only handle alert events.
    auto et = j.find("event_type");
    if (et == j.end() || et->get<std::string>() != "alert")
        return false;

    auto alert_obj = j.find("alert");
    if (alert_obj == j.end() || !alert_obj->is_object())
        return false;

    // ── Build AlertEvent ──────────────────────────────────────────────────────

    out.alert_id    = AlertEvent::next_id();
    out.source_host = source_host_;

    // Timestamp: parse ISO-8601 string from Suricata.
    // e.g. "2024-01-15T12:34:56.789+0000"
    // We extract the epoch seconds portion by using system_clock::now() as
    // fallback when parsing fails (avoids pulling in a full date library).
    if (auto ts_it = j.find("timestamp"); ts_it != j.end() && ts_it->is_string()) {
        // strptime is POSIX — available on Linux where Suricata runs.
        std::string ts_str = ts_it->get<std::string>();
        struct tm tm{};
        // Handle both "+0000" and "Z" suffixes.
        const char* fmt = "%Y-%m-%dT%H:%M:%S";
        char* res = strptime(ts_str.c_str(), fmt, &tm);
        if (res) {
            time_t t = timegm(&tm);  // UTC, not local — timegm is POSIX/Linux
            out.timestamp = std::chrono::system_clock::from_time_t(t);
        } else {
            out.timestamp = std::chrono::system_clock::now();
        }
    } else {
        out.timestamp = std::chrono::system_clock::now();
    }

    // Severity: Suricata uses 1 (high) → 4 (low), we map to dlads Severity.
    int suricata_sev = 3;  // default: medium
    if (auto sev_it = alert_obj->find("severity");
        sev_it != alert_obj->end() && sev_it->is_number_integer()) {
        suricata_sev = sev_it->get<int>();
    }
    out.severity = map_severity(suricata_sev);

    // Rule ID from Suricata signature_id (e.g. 2001219 → "suricata-2001219").
    if (auto sid_it = alert_obj->find("signature_id");
        sid_it != alert_obj->end() && sid_it->is_number_integer()) {
        out.rule_id = "suricata-" + std::to_string(sid_it->get<int>());
    } else {
        out.rule_id = "suricata-unknown";
    }

    // Human-readable description from signature name.
    if (auto sig_it = alert_obj->find("signature");
        sig_it != alert_obj->end() && sig_it->is_string()) {
        out.description = sig_it->get<std::string>();
    }

    // Category → metadata (useful for coordinator-side filtering).
    if (auto cat_it = alert_obj->find("category");
        cat_it != alert_obj->end() && cat_it->is_string()) {
        out.metadata["category"] = cat_it->get<std::string>();
    }

    // Network context stored in metadata (no fixed top-level fields).
    auto get_str_field = [&](const char* key) -> std::string {
        auto it = j.find(key);
        if (it != j.end() && it->is_string()) return it->get<std::string>();
        return {};
    };
    auto get_int_field = [&](const char* key) -> std::string {
        auto it = j.find(key);
        if (it != j.end() && it->is_number_integer())
            return std::to_string(it->get<int>());
        return {};
    };

    if (auto v = get_str_field("src_ip");   !v.empty()) out.metadata["src_ip"]   = v;
    if (auto v = get_str_field("dest_ip");  !v.empty()) out.metadata["dest_ip"]  = v;
    if (auto v = get_int_field("src_port"); !v.empty()) out.metadata["src_port"] = v;
    if (auto v = get_int_field("dest_port");!v.empty()) out.metadata["dest_port"]= v;
    if (auto v = get_str_field("proto");    !v.empty()) out.metadata["proto"]    = v;

    // Mark the alert source so coordinator/dashboard can distinguish.
    out.metadata["ids_source"] = "suricata";

    // anomaly_score: derive from severity (Suricata doesn't provide one).
    // 1→1.0, 2→0.75, 3→0.5, 4→0.25
    out.anomaly_score = std::max(0.0f, 1.0f - (suricata_sev - 1) * 0.25f);

    return true;
}

// ── Severity mapping ──────────────────────────────────────────────────────────

Severity SuricataAdapter::map_severity(int s) noexcept {
    switch (s) {
        case 1:  return Severity::CRITICAL;
        case 2:  return Severity::HIGH;
        case 3:  return Severity::MEDIUM;
        default: return Severity::LOW;
    }
}

}  // namespace dlads