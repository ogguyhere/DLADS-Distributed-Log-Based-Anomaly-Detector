#include "dlads/rule_engine.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>

namespace dlads {

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// Case-insensitive substring search.
bool icontains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(),   needle.end(),
        [](unsigned char a, unsigned char b){
            return std::tolower(a) == std::tolower(b);
        });
    return it != haystack.end();
}

// Extract "from <ip>" pattern — sshd log format.
// Returns empty on failure.
std::string parse_from_ip(std::string_view msg) {
    static constexpr std::string_view FROM = "from ";
    auto pos = msg.find(FROM);
    if (pos == std::string_view::npos) return {};
    std::string_view rest = msg.substr(pos + FROM.size());
    // IP ends at first whitespace.
    auto end = rest.find(' ');
    if (end == std::string_view::npos) end = rest.size();
    return std::string(rest.substr(0, end));
}

// Extract "DPT=<port>" from iptables log lines.
// Returns -1 on failure.
int parse_dpt(std::string_view msg) {
    static constexpr std::string_view DPT = "DPT=";
    auto pos = msg.find(DPT);
    if (pos == std::string_view::npos) return -1;
    std::string_view rest = msg.substr(pos + DPT.size());
    int v = -1;
    std::from_chars(rest.data(), rest.data() + rest.size(), v);
    return v;
}

// Extract username from "for user root by <username>" (sudo log).
std::string parse_sudo_user(std::string_view msg) {
    static constexpr std::string_view BY = " by ";
    auto pos = msg.rfind(BY);
    if (pos == std::string_view::npos) return {};
    std::string_view rest = msg.substr(pos + BY.size());
    // Username ends at first whitespace or end-of-string.
    auto end = rest.find_first_of(" \t(");
    if (end == std::string_view::npos) end = rest.size();
    return std::string(rest.substr(0, end));
}

// Lightweight YAML key=value parser (handles "  key: value" lines only).
std::unordered_map<std::string, std::string> parse_flat_yaml(
        const std::string& path) {
    std::unordered_map<std::string, std::string> out;
    std::ifstream f(path);
    if (!f.is_open()) return out;
    std::string line;
    while (std::getline(f, line)) {
        // Strip comments.
        auto hash = line.find('#');
        if (hash != std::string::npos) line.resize(hash);
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
        // Trim whitespace from both.
        auto trim = [](std::string& s) {
            auto b = s.find_first_not_of(" \t");
            auto e = s.find_last_not_of(" \t\r\n");
            s = (b == std::string::npos) ? "" : s.substr(b, e - b + 1);
        };
        trim(key); trim(val);
        if (!key.empty()) out[key] = val;
    }
    return out;
}

int to_int(const std::unordered_map<std::string,std::string>& m,
           const std::string& key, int def) {
    auto it = m.find(key);
    if (it == m.end()) return def;
    int v = def;
    std::from_chars(it->second.data(),
                    it->second.data() + it->second.size(), v);
    return v;
}

}  // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// extract_src_ip  (free helper, also used by tests)
// ─────────────────────────────────────────────────────────────────────────────

std::string extract_src_ip(const LogEvent& ev) {
    // 1. Explicit field wins.
    if (auto it = ev.fields.find("src_ip"); it != ev.fields.end())
        return it->second;
    if (auto it = ev.fields.find("client"); it != ev.fields.end())
        return it->second;
    // 2. Try "from <ip>" pattern in the message.
    return parse_from_ip(ev.message);
}

// ─────────────────────────────────────────────────────────────────────────────
// RuleConfig
// ─────────────────────────────────────────────────────────────────────────────

RuleConfig RuleConfig::from_yaml(const std::string& path) {
    auto m = parse_flat_yaml(path);
    RuleConfig c;
    c.ssh_window_seconds    = to_int(m, "window_seconds",    c.ssh_window_seconds);
    c.ssh_threshold         = to_int(m, "threshold",         c.ssh_threshold);
    c.ssh_cooldown_seconds  = to_int(m, "cooldown_seconds",  c.ssh_cooldown_seconds);
    c.scan_window_seconds   = to_int(m, "scan_window_seconds",  c.scan_window_seconds);
    c.scan_threshold        = to_int(m, "scan_threshold",       c.scan_threshold);
    c.scan_cooldown_seconds = to_int(m, "scan_cooldown_seconds",c.scan_cooldown_seconds);
    c.priv_history_hours    = to_int(m, "priv_history_hours",   c.priv_history_hours);
    c.priv_cooldown_seconds = to_int(m, "priv_cooldown_seconds",c.priv_cooldown_seconds);
    c.multi_window_seconds  = to_int(m, "multi_window_seconds", c.multi_window_seconds);
    c.multi_min_services    = to_int(m, "multi_min_services",   c.multi_min_services);
    c.multi_cooldown_seconds= to_int(m, "multi_cooldown_seconds",c.multi_cooldown_seconds);
    return c;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule 1 — SSH Brute Force
// ─────────────────────────────────────────────────────────────────────────────

class SshBruteForceRule final : public Rule {
public:
    std::string_view rule_id() const override { return "SSH_BRUTE_FORCE_001"; }

    std::chrono::seconds cooldown(const RuleConfig& cfg) const override {
        return std::chrono::seconds(cfg.ssh_cooldown_seconds);
    }

    std::optional<AlertEvent> evaluate(
            const LogEvent&              event,
            const std::vector<LogEvent>& /*snapshot*/,
            const EventIndex&            index,
            const RuleConfig&            cfg) override
    {
        // Only care about sshd events with failed-login messages.
        if (event.log_source != "sshd") return std::nullopt;
        if (!icontains(event.message, "Failed password") &&
            !icontains(event.message, "Invalid user"))
            return std::nullopt;

        std::string src_ip = extract_src_ip(event);
        if (src_ip.empty()) return std::nullopt;

        // Count failed logins from this IP within the window.
        auto window = std::chrono::seconds(cfg.ssh_window_seconds);
        auto cutoff = event.timestamp - window;

        auto it = index.by_ip.find(src_ip);
        if (it == index.by_ip.end()) return std::nullopt;

        // Start count at 1 to include the trigger event itself
        // (it is not yet in the snapshot when evaluate() is called).
        int count = 1;
        for (const LogEvent* ev : it->second) {
            if (ev->log_source != "sshd")            continue;
            if (ev->timestamp < cutoff)               continue;
            if (!icontains(ev->message, "Failed password") &&
                !icontains(ev->message, "Invalid user")) continue;
            ++count;
        }

        if (count < cfg.ssh_threshold) return std::nullopt;

        AlertEvent alert;
        alert.alert_id    = AlertEvent::next_id();
        alert.timestamp   = event.timestamp;
        alert.source_host = event.source_host;
        alert.rule_id     = std::string(rule_id());
        alert.severity    = Severity::HIGH;
        alert.anomaly_score = std::min(1.0f,
            static_cast<float>(count) / static_cast<float>(cfg.ssh_threshold * 2));
        alert.description = "SSH brute force: " + std::to_string(count) +
                            " failed logins from " + src_ip +
                            " in " + std::to_string(cfg.ssh_window_seconds) + "s";
        alert.metadata["src_ip"]        = src_ip;
        alert.metadata["attempt_count"] = std::to_string(count);
        return alert;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Rule 2 — Port Scan
// ─────────────────────────────────────────────────────────────────────────────

class PortScanRule final : public Rule {
public:
    std::string_view rule_id() const override { return "PORT_SCAN_001"; }

    std::chrono::seconds cooldown(const RuleConfig& cfg) const override {
        return std::chrono::seconds(cfg.scan_cooldown_seconds);
    }

    std::optional<AlertEvent> evaluate(
            const LogEvent&              event,
            const std::vector<LogEvent>& /*snapshot*/,
            const EventIndex&            index,
            const RuleConfig&            cfg) override
    {
        // Look for iptables REJECT or connection-refused events.
        bool is_reject = (event.log_source == "kernel" &&
                          (icontains(event.message, "REJECT") ||
                           icontains(event.message, "DPT=")));
        bool is_refused = icontains(event.message, "Connection refused") ||
                          icontains(event.message, "connection refused");
        if (!is_reject && !is_refused) return std::nullopt;

        std::string src_ip = extract_src_ip(event);
        // For iptables lines, SRC= field may be used instead.
        if (src_ip.empty()) {
            if (auto it = event.fields.find("src"); it != event.fields.end())
                src_ip = it->second;
        }
        if (src_ip.empty()) return std::nullopt;

        auto window = std::chrono::seconds(cfg.scan_window_seconds);
        auto cutoff = event.timestamp - window;

        // Count distinct destination ports from this IP in the window.
        std::set<int> ports_seen;
        auto it = index.by_ip.find(src_ip);
        if (it != index.by_ip.end()) {
            for (const LogEvent* ev : it->second) {
                if (ev->timestamp < cutoff) continue;
                int dpt = parse_dpt(ev->message);
                if (dpt > 0) ports_seen.insert(dpt);
            }
        }
        // Also check by_source for connection-refused entries.
        for (const LogEvent* ev : index.last_60s) {
            if (ev->timestamp < cutoff)    continue;
            if (extract_src_ip(*ev) != src_ip) continue;
            if (!icontains(ev->message, "refused")) continue;
            int dpt = parse_dpt(ev->message);
            if (dpt > 0) ports_seen.insert(dpt);
        }

        int distinct = static_cast<int>(ports_seen.size());
        if (distinct < cfg.scan_threshold) return std::nullopt;

        AlertEvent alert;
        alert.alert_id    = AlertEvent::next_id();
        alert.timestamp   = event.timestamp;
        alert.source_host = event.source_host;
        alert.rule_id     = std::string(rule_id());
        alert.severity    = Severity::HIGH;
        alert.anomaly_score = std::min(1.0f,
            static_cast<float>(distinct) / 50.0f);
        alert.description = "Port scan: " + src_ip + " hit " +
                            std::to_string(distinct) + " distinct ports in " +
                            std::to_string(cfg.scan_window_seconds) + "s";
        alert.metadata["src_ip"]       = src_ip;
        alert.metadata["port_count"]   = std::to_string(distinct);
        return alert;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Rule 3 — Privilege Escalation
// ─────────────────────────────────────────────────────────────────────────────

class PrivEscRule final : public Rule {
public:
    std::string_view rule_id() const override { return "PRIV_ESC_001"; }

    std::chrono::seconds cooldown(const RuleConfig& cfg) const override {
        return std::chrono::seconds(cfg.priv_cooldown_seconds);
    }

    std::optional<AlertEvent> evaluate(
            const LogEvent&              event,
            const std::vector<LogEvent>& /*snapshot*/,
            const EventIndex&            index,
            const RuleConfig&            cfg) override
    {
        // Only sudo session-opened events.
        if (event.log_source != "sudo") return std::nullopt;
        if (!icontains(event.message, "session opened")) return std::nullopt;

        std::string username = parse_sudo_user(event.message);
        if (username.empty()) return std::nullopt;

        // Scan history: has this user done a sudo before?
        auto window  = std::chrono::hours(cfg.priv_history_hours);
        auto cutoff  = event.timestamp - window;

        bool seen_before = false;
        auto sit = index.by_source.find("sudo");
        if (sit != index.by_source.end()) {
            for (const LogEvent* ev : sit->second) {
                if (ev->timestamp < cutoff)    continue;
                if (!icontains(ev->message, username)) continue;
                // Any prior sudo event for this user counts.
                seen_before = true;
                break;
            }
        }

        if (seen_before) return std::nullopt;

        AlertEvent alert;
        alert.alert_id    = AlertEvent::next_id();
        alert.timestamp   = event.timestamp;
        alert.source_host = event.source_host;
        alert.rule_id     = std::string(rule_id());
        alert.severity    = Severity::CRITICAL;
        alert.anomaly_score = 0.9f;
        alert.description = "Privilege escalation: first-time sudo session "
                            "opened by user '" + username + "'";
        alert.metadata["username"] = username;
        return alert;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Rule 4 — Multi-Service Auth Failure
// ─────────────────────────────────────────────────────────────────────────────

class MultiServiceAuthRule final : public Rule {
public:
    std::string_view rule_id() const override { return "MULTI_SERVICE_AUTH_001"; }

    std::chrono::seconds cooldown(const RuleConfig& cfg) const override {
        return std::chrono::seconds(cfg.multi_cooldown_seconds);
    }

    std::optional<AlertEvent> evaluate(
            const LogEvent&              event,
            const std::vector<LogEvent>& /*snapshot*/,
            const EventIndex&            index,
            const RuleConfig&            cfg) override
    {
        // Must be an auth failure event.
        bool is_fail = icontains(event.message, "authentication failure") ||
                       icontains(event.message, "Failed password")        ||
                       icontains(event.message, "auth error")             ||
                       icontains(event.message, "Invalid user");
        if (!is_fail) return std::nullopt;

        std::string src_ip = extract_src_ip(event);
        if (src_ip.empty()) return std::nullopt;

        auto window = std::chrono::seconds(cfg.multi_window_seconds);
        auto cutoff = event.timestamp - window;

        // Count distinct services this IP has failed auth on.
        std::set<std::string> services_hit;
        // Include the current event's service.
        if (!event.log_source.empty()) services_hit.insert(event.log_source);

        auto it = index.by_ip.find(src_ip);
        if (it != index.by_ip.end()) {
            for (const LogEvent* ev : it->second) {
                if (ev->timestamp < cutoff) continue;
                bool fail = icontains(ev->message, "authentication failure") ||
                            icontains(ev->message, "Failed password")        ||
                            icontains(ev->message, "auth error")             ||
                            icontains(ev->message, "Invalid user");
                if (!fail) continue;
                if (!ev->log_source.empty())
                    services_hit.insert(ev->log_source);
            }
        }

        int distinct = static_cast<int>(services_hit.size());
        if (distinct < cfg.multi_min_services) return std::nullopt;

        // Build a comma-separated service list for the alert.
        std::string svc_list;
        for (const auto& s : services_hit) {
            if (!svc_list.empty()) svc_list += ',';
            svc_list += s;
        }

        AlertEvent alert;
        alert.alert_id    = AlertEvent::next_id();
        alert.timestamp   = event.timestamp;
        alert.source_host = event.source_host;
        alert.rule_id     = std::string(rule_id());
        alert.severity    = Severity::CRITICAL;
        alert.anomaly_score = std::min(1.0f,
            static_cast<float>(distinct) / 4.0f);
        alert.description = "Multi-service auth failure: " + src_ip +
                            " failed on services [" + svc_list + "]";
        alert.metadata["src_ip"]   = src_ip;
        alert.metadata["services"] = svc_list;
        alert.metadata["service_count"] = std::to_string(distinct);
        return alert;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// RuleEngine
// ─────────────────────────────────────────────────────────────────────────────

RuleEngine::RuleEngine(RuleConfig cfg)
    : cfg_(std::move(cfg))
{
    rules_.push_back(std::make_unique<SshBruteForceRule>());
    rules_.push_back(std::make_unique<PortScanRule>());
    rules_.push_back(std::make_unique<PrivEscRule>());
    rules_.push_back(std::make_unique<MultiServiceAuthRule>());
}

void RuleEngine::set_config(RuleConfig cfg) {
    cfg_ = std::move(cfg);
}

// ── Index building ────────────────────────────────────────────────────────────

EventIndex RuleEngine::build_index(
        const std::vector<LogEvent>& snapshot,
        std::chrono::system_clock::time_point now)
{
    EventIndex idx;
    auto cutoff_60s  = now - std::chrono::seconds(60);
    auto cutoff_300s = now - std::chrono::seconds(300);
    // Pre-filter uses 24 h — the longest rule window (priv-esc history).
    // Events older than this cannot contribute to any rule decision.
    auto cutoff_max  = now - std::chrono::hours(24);

    for (const LogEvent& ev : snapshot) {
        if (ev.timestamp < cutoff_max) continue;  // discard truly stale events

        // IP index (O(1) amortised per event).
        std::string ip = extract_src_ip(ev);
        idx.by_ip[ip].push_back(&ev);

        // Source index — includes all events within 24 h (needed by priv-esc).
        idx.by_source[ev.log_source].push_back(&ev);

        // Time-filtered views for short-window rules.
        if (ev.timestamp >= cutoff_300s) {
            idx.last_300s.push_back(&ev);
            if (ev.timestamp >= cutoff_60s)
                idx.last_60s.push_back(&ev);
        }
    }
    return idx;
}

// ── Cooldown helpers ──────────────────────────────────────────────────────────

bool RuleEngine::in_cooldown(const std::string& key) const {
    auto it = cooldown_map_.find(key);
    if (it == cooldown_map_.end()) return false;
    return std::chrono::system_clock::now() < it->second;
}

void RuleEngine::set_cooldown(const std::string& key,
                              std::chrono::seconds duration) {
    cooldown_map_[key] = std::chrono::system_clock::now() + duration;
}

// ── process ───────────────────────────────────────────────────────────────────

std::vector<AlertEvent> RuleEngine::process(
        const LogEvent&              event,
        const std::vector<LogEvent>& snapshot)
{
    // Use the incoming event's timestamp as "now" so that tests using
    // fixed historical timestamps are not wiped out by the 300s pre-filter.
    auto now = event.timestamp;
    EventIndex index = build_index(snapshot, now);

    std::vector<AlertEvent> results;

    for (auto& rule : rules_) {
        auto maybe = rule->evaluate(event, snapshot, index, cfg_);
        if (!maybe) continue;

        // Build the dedup key: "RULE_ID:src_ip"
        std::string src_ip = maybe->metadata.count("src_ip")
                             ? maybe->metadata.at("src_ip")
                             : maybe->source_host;
        std::string dedup_key = std::string(rule->rule_id()) + ":" + src_ip;

        if (in_cooldown(dedup_key)) continue;

        set_cooldown(dedup_key, rule->cooldown(cfg_));
        results.push_back(std::move(*maybe));
    }

    return results;
}

}  // namespace dlads