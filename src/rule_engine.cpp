#include "dlads/rule_engine.hpp"
#include "dlads/alert_event.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>

namespace dlads {

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

namespace {

// Returns the "src_ip" field from a LogEvent metadata map, or "".
const std::string& src_ip(const LogEvent& ev) {
    static const std::string empty;
    auto it = ev.fields.find("src_ip");
    return it != ev.fields.end() ? it->second : empty;
}

// Does the message body contain any of the given substrings?
bool msg_contains(const LogEvent& ev, std::initializer_list<const char*> needles) {
    for (const char* n : needles) {
        if (ev.message.find(n) != std::string::npos) return true;
    }
    return false;
}

using Clock     = std::chrono::system_clock;
using TimePoint = Clock::time_point;
using Seconds   = std::chrono::seconds;

TimePoint now_tp() { return Clock::now(); }

double age_seconds(const LogEvent& ev) {
    return std::chrono::duration<double>(now_tp() - ev.timestamp).count();
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════════════
// SshBruteForceRule
// ═══════════════════════════════════════════════════════════════════════════════

SshBruteForceRule::SshBruteForceRule(int threshold, int window_seconds)
    : threshold_(threshold), window_seconds_(window_seconds) {}

std::optional<AlertEvent> SshBruteForceRule::evaluate(
    const LogEvent&              event,
    const std::vector<LogEvent>& recent_history)
{
    // Only interested in sshd failures on the current event.
    if (event.log_source.find("sshd") == std::string::npos) return std::nullopt;

    const bool is_failure = msg_contains(event, {
        "Failed password",
        "Invalid user",
        "authentication failure",
        "FAILED LOGIN"
    });
    if (!is_failure) return std::nullopt;

    const std::string& attacker = src_ip(event);
    if (attacker.empty()) return std::nullopt;

    // Count failures from the same IP within the window.
    int count = 0;
    const double window = static_cast<double>(window_seconds_);

    for (const auto& ev : recent_history) {
        if (age_seconds(ev) > window)                           continue;
        if (ev.log_source.find("sshd") == std::string::npos)   continue;
        if (src_ip(ev) != attacker)                             continue;
        if (!msg_contains(ev, {"Failed password", "Invalid user",
                                "authentication failure", "FAILED LOGIN"}))
            continue;
        ++count;
    }

    if (count < threshold_) return std::nullopt;

    AlertEvent alert;
    alert.alert_id       = AlertEvent::next_id();
    alert.timestamp      = now_tp();
    alert.source_host    = event.source_host;
    alert.rule_id        = rule_id();
    alert.severity       = Severity::HIGH;
    alert.anomaly_score  = std::min(1.0f, static_cast<float>(count) /
                                          static_cast<float>(threshold_ * 3));
    alert.description    = "SSH brute-force detected from " + attacker +
                           " (" + std::to_string(count) + " failures in " +
                           std::to_string(window_seconds_) + "s)";
    alert.metadata["src_ip"]         = attacker;
    alert.metadata["failure_count"]  = std::to_string(count);
    alert.metadata["window_seconds"] = std::to_string(window_seconds_);
    return alert;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PrivilegeEscalationRule
// ═══════════════════════════════════════════════════════════════════════════════

PrivilegeEscalationRule::PrivilegeEscalationRule(int lookback_seconds)
    : lookback_seconds_(lookback_seconds) {}

std::optional<AlertEvent> PrivilegeEscalationRule::evaluate(
    const LogEvent&              event,
    const std::vector<LogEvent>& recent_history)
{
    // Trigger on "sudo session opened".
    if (event.log_source.find("sudo") == std::string::npos &&
        event.message.find("sudo") == std::string::npos)
        return std::nullopt;

    if (!msg_contains(event, {"session opened", "COMMAND="})) return std::nullopt;

    // Extract the user who ran sudo.
    std::string user;
    {
        auto it = event.fields.find("user");
        if (it != event.fields.end()) {
            user = it->second;
        } else {
            // Fallback: scan message for "for USER by"
            const std::string& m = event.message;
            auto pos = m.find("for ");
            if (pos != std::string::npos) {
                pos += 4;
                auto end = m.find(' ', pos);
                user = m.substr(pos, end == std::string::npos ? end : end - pos);
            }
        }
    }
    if (user.empty()) return std::nullopt;

    // Check whether this user had a prior SUCCESSFUL sudo in the lookback window.
    const double lookback = static_cast<double>(lookback_seconds_);
    for (const auto& ev : recent_history) {
        if (age_seconds(ev) > lookback) continue;
        if (ev.log_source.find("sudo") == std::string::npos &&
            ev.message.find("sudo") == std::string::npos) continue;
        if (!msg_contains(ev, {"session opened", "COMMAND="})) continue;

        std::string ev_user;
        auto it = ev.fields.find("user");
        if (it != ev.fields.end()) ev_user = it->second;

        if (ev_user == user) return std::nullopt; // Prior sudo found → not suspicious.
    }

    AlertEvent alert;
    alert.alert_id      = AlertEvent::next_id();
    alert.timestamp     = now_tp();
    alert.source_host   = event.source_host;
    alert.rule_id       = rule_id();
    alert.severity      = Severity::CRITICAL;
    alert.anomaly_score = 0.85f;
    alert.description   = "Privilege escalation: user '" + user +
                          "' opened sudo session with no prior sudo history";
    alert.metadata["user"]            = user;
    alert.metadata["lookback_seconds"]= std::to_string(lookback_seconds_);
    return alert;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PortScanRule
// ═══════════════════════════════════════════════════════════════════════════════

PortScanRule::PortScanRule(int distinct_port_threshold, int window_seconds)
    : distinct_port_threshold_(distinct_port_threshold),
      window_seconds_(window_seconds) {}

std::optional<AlertEvent> PortScanRule::evaluate(
    const LogEvent&              event,
    const std::vector<LogEvent>& recent_history)
{
    // Connection-refused pattern: kernel/firewall log or "connection refused"
    if (!msg_contains(event, {"Connection refused", "connection refused",
                               "REJECT", "DPT=", "refused connect"}))
        return std::nullopt;

    const std::string& attacker = src_ip(event);
    if (attacker.empty()) return std::nullopt;

    std::set<std::string> distinct_ports;
    const double window = static_cast<double>(window_seconds_);

    auto collect_port = [&](const LogEvent& ev) {
        auto it = ev.fields.find("dst_port");
        if (it == ev.fields.end()) it = ev.fields.find("port");
        if (it != ev.fields.end() && !it->second.empty())
            distinct_ports.insert(it->second);
    };

    for (const auto& ev : recent_history) {
        if (age_seconds(ev) > window) continue;
        if (src_ip(ev) != attacker)   continue;
        if (!msg_contains(ev, {"Connection refused", "connection refused",
                                "REJECT", "DPT=", "refused connect"})) continue;
        collect_port(ev);
    }
    collect_port(event);

    if (static_cast<int>(distinct_ports.size()) < distinct_port_threshold_)
        return std::nullopt;

    AlertEvent alert;
    alert.alert_id      = AlertEvent::next_id();
    alert.timestamp     = now_tp();
    alert.source_host   = event.source_host;
    alert.rule_id       = rule_id();
    alert.severity      = Severity::HIGH;
    alert.anomaly_score = std::min(1.0f,
        static_cast<float>(distinct_ports.size()) /
        static_cast<float>(distinct_port_threshold_ * 2));
    alert.description   = "Port scan detected from " + attacker +
                          " (" + std::to_string(distinct_ports.size()) +
                          " distinct ports in " +
                          std::to_string(window_seconds_) + "s)";
    alert.metadata["src_ip"]              = attacker;
    alert.metadata["distinct_port_count"] = std::to_string(distinct_ports.size());
    alert.metadata["window_seconds"]      = std::to_string(window_seconds_);
    return alert;
}

// ═══════════════════════════════════════════════════════════════════════════════
// RuleEngine — config loader
// ═══════════════════════════════════════════════════════════════════════════════

RuleEngine::ThresholdConfig RuleEngine::load_config(const std::string& path) {
    ThresholdConfig cfg;
    if (path.empty()) return cfg;

    std::ifstream f(path);
    if (!f.is_open()) {
        // File missing → silently use defaults.
        return cfg;
    }

    // Minimal INI parser: key = value  (# comments, blank lines ignored).
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#' || line[0] == '[') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key   = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        // Trim whitespace.
        auto trim = [](std::string& s) {
            s.erase(0, s.find_first_not_of(" \t\r\n"));
            s.erase(s.find_last_not_of(" \t\r\n") + 1);
        };
        trim(key); trim(value);

        try {
            int v = std::stoi(value);
            if      (key == "ssh_threshold")    cfg.ssh_threshold   = v;
            else if (key == "ssh_window_s")     cfg.ssh_window_s    = v;
            else if (key == "priv_lookback_s")  cfg.priv_lookback_s = v;
            else if (key == "port_threshold")   cfg.port_threshold  = v;
            else if (key == "port_window_s")    cfg.port_window_s   = v;
            else if (key == "cooldown_s")       cfg.cooldown_s      = v;
        } catch (...) { /* malformed value — skip */ }
    }
    return cfg;
}

// ═══════════════════════════════════════════════════════════════════════════════
// RuleEngine — construction & rule management
// ═══════════════════════════════════════════════════════════════════════════════

RuleEngine::RuleEngine(const std::string& config_path, int cooldown_seconds)
    : cfg_(load_config(config_path)),
      cooldown_seconds_(config_path.empty() ? cooldown_seconds : cfg_.cooldown_s)
{
    // Register built-in rules with config-loaded thresholds.
    rules_.push_back(std::make_unique<SshBruteForceRule>(
        cfg_.ssh_threshold, cfg_.ssh_window_s));
    rules_.push_back(std::make_unique<PrivilegeEscalationRule>(
        cfg_.priv_lookback_s));
    rules_.push_back(std::make_unique<PortScanRule>(
        cfg_.port_threshold, cfg_.port_window_s));
}

void RuleEngine::add_rule(std::unique_ptr<Rule> rule) {
    rules_.push_back(std::move(rule));
}

void RuleEngine::reset_dedup() {
    dedup_table_.clear();
}

// ═══════════════════════════════════════════════════════════════════════════════
// RuleEngine — deduplication
// ═══════════════════════════════════════════════════════════════════════════════

bool RuleEngine::is_suppressed(const std::string& rid,
                                const std::string& source_ip)
{
    std::string key = rid + "|" + source_ip;
    auto it = dedup_table_.find(key);
    if (it == dedup_table_.end()) return false;
    auto elapsed = std::chrono::duration_cast<Seconds>(now_tp() - it->second).count();
    return elapsed < cooldown_seconds_;
}

void RuleEngine::record_firing(const std::string& rid,
                                const std::string& source_ip)
{
    dedup_table_[rid + "|" + source_ip] = now_tp();
}

// ═══════════════════════════════════════════════════════════════════════════════
// RuleEngine — main evaluation loop
// ═══════════════════════════════════════════════════════════════════════════════

std::vector<AlertEvent> RuleEngine::process(
    const LogEvent&              event,
    const std::vector<LogEvent>& recent_history)
{
    std::vector<AlertEvent> results;

    for (auto& rule : rules_) {
        auto maybe = rule->evaluate(event, recent_history);
        if (!maybe) continue;

        // Determine source IP for dedup key.
        std::string ip;
        auto it = maybe->metadata.find("src_ip");
        if (it != maybe->metadata.end()) ip = it->second;
        else {
            auto it2 = event.fields.find("src_ip");
            if (it2 != event.fields.end()) ip = it2->second;
            else ip = event.source_host;
        }

        if (is_suppressed(rule->rule_id(), ip)) continue;

        record_firing(rule->rule_id(), ip);
        results.push_back(std::move(*maybe));
    }

    return results;
}

}  // namespace dlads