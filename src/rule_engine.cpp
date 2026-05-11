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

std::string parse_from_ip(std::string_view msg) {
    static constexpr std::string_view FROM = "from ";
    auto pos = msg.find(FROM);
    if (pos == std::string_view::npos) return {};
    std::string_view rest = msg.substr(pos + FROM.size());
    auto end = rest.find(' ');
    if (end == std::string_view::npos) end = rest.size();
    return std::string(rest.substr(0, end));
}

// Extract "KEY=<value>" from a message — handles iptables SRC=, DPT= etc.
std::string parse_kv_field(std::string_view msg, std::string_view key) {
    auto pos = msg.find(key);
    if (pos == std::string_view::npos) return {};
    std::string_view rest = msg.substr(pos + key.size());
    auto end = rest.find_first_of(" \t\r\n");
    if (end == std::string_view::npos) end = rest.size();
    return std::string(rest.substr(0, end));
}

int parse_dpt(std::string_view msg) {
    std::string val = parse_kv_field(msg, "DPT=");
    if (val.empty()) return -1;
    int v = -1;
    std::from_chars(val.data(), val.data() + val.size(), v);
    return v;
}

std::string parse_sudo_user(std::string_view msg) {
    static constexpr std::string_view BY = " by ";
    auto pos = msg.rfind(BY);
    if (pos == std::string_view::npos) return {};
    std::string_view rest = msg.substr(pos + BY.size());
    auto end = rest.find_first_of(" \t(");
    if (end == std::string_view::npos) end = rest.size();
    return std::string(rest.substr(0, end));
}

std::unordered_map<std::string, std::string> parse_flat_yaml(
        const std::string& path) {
    std::unordered_map<std::string, std::string> out;
    std::ifstream f(path);
    if (!f.is_open()) return out;
    std::string line;
    while (std::getline(f, line)) {
        auto hash = line.find('#');
        if (hash != std::string::npos) line.resize(hash);
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = line.substr(0, colon);
        std::string val = line.substr(colon + 1);
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
// extract_src_ip
// ─────────────────────────────────────────────────────────────────────────────

std::string extract_src_ip(const LogEvent& ev) {
    // 1. Explicit fields (set by KV parser).
    if (auto it = ev.fields.find("src_ip"); it != ev.fields.end())
        return it->second;
    if (auto it = ev.fields.find("client"); it != ev.fields.end())
        return it->second;
    if (auto it = ev.fields.find("src"); it != ev.fields.end())
        return it->second;

    // 2. "SRC=<ip>" in message — iptables logs (kernel lines parsed as syslog,
    //    fields map is empty, so we must scan the raw message).
    std::string src = parse_kv_field(ev.message, "SRC=");
    if (!src.empty()) return src;

    // 3. "from <ip>" pattern — sshd, sudo, etc.
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
        if (event.log_source != "sshd" && event.log_source != "sshd-session") return std::nullopt;
        if (!icontains(event.message, "Failed password") &&
            !icontains(event.message, "Invalid user"))
            return std::nullopt;

        std::string src_ip = extract_src_ip(event);
        if (src_ip.empty()) return std::nullopt;

        auto cutoff = event.timestamp - std::chrono::seconds(cfg.ssh_window_seconds);

        auto it = index.by_ip.find(src_ip);
        int count = 1;  // include current event
        if (it != index.by_ip.end()) {
            for (const LogEvent* ev : it->second) {
                if (ev->log_source != "sshd" && ev->log_source != "sshd-session") continue;
                if (ev->timestamp < cutoff)         continue;
                if (!icontains(ev->message, "Failed password") &&
                    !icontains(ev->message, "Invalid user"))   continue;
                ++count;
            }
        }

        if (count < cfg.ssh_threshold) return std::nullopt;

        AlertEvent alert;
        alert.alert_id      = AlertEvent::next_id();
        alert.timestamp     = event.timestamp;
        alert.source_host   = event.source_host;
        alert.rule_id       = std::string(rule_id());
        alert.severity      = Severity::HIGH;
        alert.anomaly_score = std::min(1.0f,
            static_cast<float>(count) / static_cast<float>(cfg.ssh_threshold * 2));
        alert.description   = "SSH brute force: " + std::to_string(count) +
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
        // Match kernel iptables REJECT lines.
        if (event.log_source != "kernel") return std::nullopt;
        if (!icontains(event.message, "REJECT") &&
            !icontains(event.message, "DPT="))
            return std::nullopt;

        // extract_src_ip now handles SRC= via parse_kv_field.
        std::string src_ip = extract_src_ip(event);
        if (src_ip.empty()) return std::nullopt;

        auto cutoff = event.timestamp - std::chrono::seconds(cfg.scan_window_seconds);

        // Count distinct destination ports from this IP within the window.
        std::set<int> ports_seen;

        // Include current event's port.
        int cur_dpt = parse_dpt(event.message);
        if (cur_dpt > 0) ports_seen.insert(cur_dpt);

        auto it = index.by_ip.find(src_ip);
        if (it != index.by_ip.end()) {
            for (const LogEvent* ev : it->second) {
                if (ev->timestamp < cutoff)           continue;
                if (ev->log_source != "kernel")       continue;
                if (!icontains(ev->message, "DPT="))  continue;
                int dpt = parse_dpt(ev->message);
                if (dpt > 0) ports_seen.insert(dpt);
            }
        }

        int distinct = static_cast<int>(ports_seen.size());
        if (distinct < cfg.scan_threshold) return std::nullopt;

        AlertEvent alert;
        alert.alert_id      = AlertEvent::next_id();
        alert.timestamp     = event.timestamp;
        alert.source_host   = event.source_host;
        alert.rule_id       = std::string(rule_id());
        alert.severity      = Severity::HIGH;
        alert.anomaly_score = std::min(1.0f, static_cast<float>(distinct) / 50.0f);
        alert.description   = "Port scan: " + src_ip + " hit " +
                              std::to_string(distinct) + " distinct ports in " +
                              std::to_string(cfg.scan_window_seconds) + "s";
        alert.metadata["src_ip"]     = src_ip;
        alert.metadata["port_count"] = std::to_string(distinct);
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
        if (event.log_source != "sudo") return std::nullopt;
        if (!icontains(event.message, "session opened")) return std::nullopt;

        std::string username = parse_sudo_user(event.message);
        if (username.empty()) return std::nullopt;

        auto cutoff = event.timestamp - std::chrono::hours(cfg.priv_history_hours);

        // Check if this user has a PRIOR sudo session in history.
        // Exclude events at the exact same timestamp as the trigger event
        // to avoid the current event matching itself in the snapshot.
        bool seen_before = false;
        auto sit = index.by_source.find("sudo");
        if (sit != index.by_source.end()) {
            for (const LogEvent* ev : sit->second) {
                if (ev->timestamp < cutoff)              continue;
                if (ev->timestamp >= event.timestamp)    continue;  // not prior
                if (!icontains(ev->message, "session opened")) continue;
                if (!icontains(ev->message, username))   continue;
                seen_before = true;
                break;
            }
        }

        if (seen_before) return std::nullopt;

        AlertEvent alert;
        alert.alert_id      = AlertEvent::next_id();
        alert.timestamp     = event.timestamp;
        alert.source_host   = event.source_host;
        alert.rule_id       = std::string(rule_id());
        alert.severity      = Severity::CRITICAL;
        alert.anomaly_score = 0.9f;
        alert.description   = "Privilege escalation: first-time sudo session "
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
        bool is_fail = icontains(event.message, "authentication failure") ||
                       icontains(event.message, "Failed password")        ||
                       icontains(event.message, "auth error")             ||
                       icontains(event.message, "Invalid user");
        if (!is_fail) return std::nullopt;

        std::string src_ip = extract_src_ip(event);
        if (src_ip.empty()) return std::nullopt;

        auto cutoff = event.timestamp - std::chrono::seconds(cfg.multi_window_seconds);

        std::set<std::string> services_hit;
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

        std::string svc_list;
        for (const auto& s : services_hit) {
            if (!svc_list.empty()) svc_list += ',';
            svc_list += s;
        }

        AlertEvent alert;
        alert.alert_id      = AlertEvent::next_id();
        alert.timestamp     = event.timestamp;
        alert.source_host   = event.source_host;
        alert.rule_id       = std::string(rule_id());
        alert.severity      = Severity::CRITICAL;
        alert.anomaly_score = std::min(1.0f, static_cast<float>(distinct) / 4.0f);
        alert.description   = "Multi-service auth failure: " + src_ip +
                              " failed on services [" + svc_list + "]";
        alert.metadata["src_ip"]        = src_ip;
        alert.metadata["services"]      = svc_list;
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

EventIndex RuleEngine::build_index(
        const std::vector<LogEvent>& snapshot,
        std::chrono::system_clock::time_point now)
{
    EventIndex idx;
    auto cutoff_60s  = now - std::chrono::seconds(60);
    auto cutoff_300s = now - std::chrono::seconds(300);
    auto cutoff_max  = now - std::chrono::hours(24);

    for (const LogEvent& ev : snapshot) {
        if (ev.timestamp < cutoff_max) continue;

        std::string ip = extract_src_ip(ev);
        idx.by_ip[ip].push_back(&ev);
        idx.by_source[ev.log_source].push_back(&ev);

        if (ev.timestamp >= cutoff_300s) {
            idx.last_300s.push_back(&ev);
            if (ev.timestamp >= cutoff_60s)
                idx.last_60s.push_back(&ev);
        }
    }
    return idx;
}

bool RuleEngine::in_cooldown(const std::string& key) const {
    auto it = cooldown_map_.find(key);
    if (it == cooldown_map_.end()) return false;
    return std::chrono::system_clock::now() < it->second;
}

void RuleEngine::set_cooldown(const std::string& key,
                              std::chrono::seconds duration) {
    cooldown_map_[key] = std::chrono::system_clock::now() + duration;
}

std::vector<AlertEvent> RuleEngine::process(
        const LogEvent&              event,
        const std::vector<LogEvent>& snapshot)
{
    auto now = event.timestamp;
    EventIndex index = build_index(snapshot, now);

    std::vector<AlertEvent> results;

    for (auto& rule : rules_) {
        auto maybe = rule->evaluate(event, snapshot, index, cfg_);
        if (!maybe) continue;

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