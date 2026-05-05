#include "dlads/rule_engine.hpp"
#include "dlads/log_event.hpp"
#include "dlads/alert_event.hpp"

#include <chrono>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using namespace dlads;
using namespace std::chrono_literals;

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::chrono::system_clock::time_point base_time() {
    // 2024-01-15 12:00:00 UTC
    return std::chrono::system_clock::time_point{
        std::chrono::seconds{1705316400}};
}

// Build a minimal sshd failed-login event.
static LogEvent make_ssh_fail(const std::string& src_ip,
                               std::chrono::system_clock::time_point ts,
                               const std::string& host = "testhost") {
    LogEvent ev;
    ev.timestamp   = ts;
    ev.source_host = host;
    ev.log_source  = "sshd";
    ev.message     = "Failed password for root from " + src_ip + " port 54321 ssh2";
    ev.fields["src_ip"] = src_ip;
    ev.format      = LogFormat::SYSLOG;
    ev.level       = LogLevel::INFO;
    return ev;
}

static LogEvent make_ssh_invalid(const std::string& src_ip,
                                  std::chrono::system_clock::time_point ts) {
    LogEvent ev;
    ev.timestamp   = ts;
    ev.source_host = "testhost";
    ev.log_source  = "sshd";
    ev.message     = "Invalid user admin from " + src_ip + " port 12345";
    ev.fields["src_ip"] = src_ip;
    ev.format      = LogFormat::SYSLOG;
    ev.level       = LogLevel::INFO;
    return ev;
}

static LogEvent make_port_scan(const std::string& src_ip, int dport,
                                std::chrono::system_clock::time_point ts) {
    LogEvent ev;
    ev.timestamp   = ts;
    ev.source_host = "testhost";
    ev.log_source  = "kernel";
    ev.message     = "iptables REJECT IN=eth0 SRC=" + src_ip +
                     " DST=10.0.0.1 DPT=" + std::to_string(dport);
    ev.fields["src_ip"] = src_ip;
    ev.format      = LogFormat::SYSLOG;
    ev.level       = LogLevel::WARN;
    return ev;
}

static LogEvent make_sudo_session(const std::string& username,
                                   std::chrono::system_clock::time_point ts) {
    LogEvent ev;
    ev.timestamp   = ts;
    ev.source_host = "testhost";
    ev.log_source  = "sudo";
    ev.message     = "pam_unix(sudo:session): session opened for user root by "
                     + username + "(uid=1001)";
    ev.format      = LogFormat::SYSLOG;
    ev.level       = LogLevel::INFO;
    return ev;
}

static LogEvent make_auth_fail(const std::string& src_ip,
                                const std::string& service,
                                std::chrono::system_clock::time_point ts) {
    LogEvent ev;
    ev.timestamp   = ts;
    ev.source_host = "testhost";
    ev.log_source  = service;
    ev.message     = "authentication failure from " + src_ip;
    ev.fields["src_ip"] = src_ip;
    ev.format      = LogFormat::SYSLOG;
    ev.level       = LogLevel::WARN;
    return ev;
}

// Build a snapshot of N ssh-fail events from the same IP, all within
// `window_seconds` of `base`.
static std::vector<LogEvent> make_ssh_history(
        const std::string& ip, int count,
        std::chrono::system_clock::time_point base,
        int spread_seconds = 50) {
    std::vector<LogEvent> h;
    for (int i = 0; i < count; ++i) {
        auto ts = base - std::chrono::seconds(spread_seconds) +
                  std::chrono::seconds(i * (spread_seconds / std::max(count, 1)));
        h.push_back(make_ssh_fail(ip, ts));
    }
    return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. SSH Brute Force
// ─────────────────────────────────────────────────────────────────────────────

TEST(SshBruteForce, FiresAtThreshold) {
    RuleConfig cfg;
    cfg.ssh_threshold       = 10;
    cfg.ssh_window_seconds  = 60;
    cfg.ssh_cooldown_seconds = 3600; // long cooldown so it doesn't interfere
    RuleEngine engine(cfg);

    auto base = base_time();
    // 10 prior events in history + the triggering event = 11 total seen.
    auto history = make_ssh_history("192.168.1.50", 10, base);
    auto trigger = make_ssh_fail("192.168.1.50", base);

    auto alerts = engine.process(trigger, history);
    ASSERT_EQ(alerts.size(), 1u);
    EXPECT_EQ(alerts[0].rule_id, "SSH_BRUTE_FORCE_001");
    EXPECT_EQ(alerts[0].severity, Severity::HIGH);
    EXPECT_EQ(alerts[0].metadata.at("src_ip"), "192.168.1.50");
}

TEST(SshBruteForce, DoesNotFireBelowThreshold) {
    RuleConfig cfg;
    cfg.ssh_threshold = 10;
    RuleEngine engine(cfg);

    auto base    = base_time();
    auto history = make_ssh_history("192.168.1.50", 5, base);
    auto trigger = make_ssh_fail("192.168.1.50", base);

    auto alerts = engine.process(trigger, history);
    // Should produce 0 SSH brute force alerts (other rules may not fire either).
    bool ssh_fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "SSH_BRUTE_FORCE_001") ssh_fired = true;
    EXPECT_FALSE(ssh_fired);
}

TEST(SshBruteForce, DoesNotFireForDifferentIPs) {
    RuleConfig cfg;
    cfg.ssh_threshold = 3;
    RuleEngine engine(cfg);

    auto base = base_time();
    // 3 events, each from a different IP.
    std::vector<LogEvent> history = {
        make_ssh_fail("10.0.0.1", base - 30s),
        make_ssh_fail("10.0.0.2", base - 20s),
        make_ssh_fail("10.0.0.3", base - 10s),
    };
    auto trigger = make_ssh_fail("10.0.0.4", base);

    auto alerts = engine.process(trigger, history);
    bool ssh_fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "SSH_BRUTE_FORCE_001") ssh_fired = true;
    EXPECT_FALSE(ssh_fired);
}

TEST(SshBruteForce, IgnoresEventsOutsideWindow) {
    RuleConfig cfg;
    cfg.ssh_threshold      = 3;
    cfg.ssh_window_seconds = 30;
    RuleEngine engine(cfg);

    auto base = base_time();
    // 5 events — but all older than 30s window.
    std::vector<LogEvent> history;
    for (int i = 0; i < 5; ++i)
        history.push_back(make_ssh_fail("10.0.0.1", base - 120s - std::chrono::seconds(i)));

    auto trigger = make_ssh_fail("10.0.0.1", base);

    auto alerts = engine.process(trigger, history);
    bool ssh_fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "SSH_BRUTE_FORCE_001") ssh_fired = true;
    EXPECT_FALSE(ssh_fired);
}

TEST(SshBruteForce, WorksWithInvalidUserMessages) {
    RuleConfig cfg;
    cfg.ssh_threshold = 3;
    RuleEngine engine(cfg);

    auto base = base_time();
    std::vector<LogEvent> history = {
        make_ssh_invalid("10.0.0.99", base - 20s),
        make_ssh_invalid("10.0.0.99", base - 10s),
    };
    auto trigger = make_ssh_invalid("10.0.0.99", base);

    auto alerts = engine.process(trigger, history);
    bool ssh_fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "SSH_BRUTE_FORCE_001") ssh_fired = true;
    EXPECT_TRUE(ssh_fired);
}

TEST(SshBruteForce, AnomalyScoreClamped) {
    RuleConfig cfg;
    cfg.ssh_threshold = 2;
    RuleEngine engine(cfg);

    auto base    = base_time();
    // Flood with 100 events.
    auto history = make_ssh_history("10.0.0.1", 100, base, 59);
    auto trigger = make_ssh_fail("10.0.0.1", base);

    auto alerts = engine.process(trigger, history);
    bool found = false;
    for (auto& a : alerts) {
        if (a.rule_id == "SSH_BRUTE_FORCE_001") {
            EXPECT_LE(a.anomaly_score, 1.0f);
            EXPECT_GE(a.anomaly_score, 0.0f);
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Port Scan
// ─────────────────────────────────────────────────────────────────────────────

TEST(PortScan, FiresAtThreshold) {
    RuleConfig cfg;
    cfg.scan_threshold      = 5;
    cfg.scan_window_seconds = 30;
    cfg.scan_cooldown_seconds = 3600;
    RuleEngine engine(cfg);

    auto base = base_time();
    std::vector<LogEvent> history;
    for (int port = 80; port < 85; ++port)
        history.push_back(make_port_scan("10.0.0.5", port, base - std::chrono::seconds(port - 79)));

    auto trigger = make_port_scan("10.0.0.5", 8080, base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "PORT_SCAN_001") fired = true;
    EXPECT_TRUE(fired);
}

TEST(PortScan, DoesNotFireBelowThreshold) {
    RuleConfig cfg;
    cfg.scan_threshold = 15;
    RuleEngine engine(cfg);

    auto base = base_time();
    std::vector<LogEvent> history;
    for (int port = 80; port < 89; ++port)
        history.push_back(make_port_scan("10.0.0.5", port, base - 5s));

    auto trigger = make_port_scan("10.0.0.5", 443, base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "PORT_SCAN_001") fired = true;
    EXPECT_FALSE(fired);
}

TEST(PortScan, DuplicatePortsCountOnce) {
    RuleConfig cfg;
    cfg.scan_threshold = 3;
    RuleEngine engine(cfg);

    auto base = base_time();
    // Same port 80 repeated 10 times — should count as 1 distinct port.
    std::vector<LogEvent> history;
    for (int i = 0; i < 10; ++i)
        history.push_back(make_port_scan("10.0.0.5", 80, base - std::chrono::seconds(i)));

    auto trigger = make_port_scan("10.0.0.5", 80, base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "PORT_SCAN_001") fired = true;
    EXPECT_FALSE(fired);  // only 1 distinct port, below threshold of 3
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Privilege Escalation
// ─────────────────────────────────────────────────────────────────────────────

TEST(PrivEsc, FiresForFirstTimeSudoUser) {
    RuleConfig cfg;
    cfg.priv_history_hours   = 24;
    cfg.priv_cooldown_seconds = 3600;
    RuleEngine engine(cfg);

    auto base    = base_time();
    // Empty history — no prior sudo events.
    std::vector<LogEvent> history;
    auto trigger = make_sudo_session("alice", base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts) {
        if (a.rule_id == "PRIV_ESC_001") {
            fired = true;
            EXPECT_EQ(a.severity, Severity::CRITICAL);
            EXPECT_EQ(a.metadata.at("username"), "alice");
        }
    }
    EXPECT_TRUE(fired);
}

TEST(PrivEsc, DoesNotFireForKnownSudoUser) {
    RuleConfig cfg;
    cfg.priv_history_hours = 24;
    RuleEngine engine(cfg);

    auto base = base_time();
    // alice has prior sudo history.
    std::vector<LogEvent> history = {
        make_sudo_session("alice", base - 2h),
        make_sudo_session("alice", base - 1h),
    };
    auto trigger = make_sudo_session("alice", base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "PRIV_ESC_001") fired = true;
    EXPECT_FALSE(fired);
}

TEST(PrivEsc, DoesNotFireForDifferentUserInHistory) {
    RuleConfig cfg;
    RuleEngine engine(cfg);

    auto base = base_time();
    // bob has history, but alice does not.
    std::vector<LogEvent> history = {
        make_sudo_session("bob", base - 1h),
    };
    auto trigger = make_sudo_session("alice", base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "PRIV_ESC_001") fired = true;
    EXPECT_TRUE(fired);  // alice still unknown
}

TEST(PrivEsc, IgnoresHistoryOutsideWindow) {
    RuleConfig cfg;
    cfg.priv_history_hours = 1;  // only look back 1 hour
    RuleEngine engine(cfg);

    auto base = base_time();
    // alice's prior sudo is 2 hours ago — outside the 1h window.
    std::vector<LogEvent> history = {
        make_sudo_session("alice", base - 2h),
    };
    auto trigger = make_sudo_session("alice", base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "PRIV_ESC_001") fired = true;
    EXPECT_TRUE(fired);  // history too old, alice treated as first-timer
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Multi-Service Auth Failure
// ─────────────────────────────────────────────────────────────────────────────

TEST(MultiServiceAuth, FiresAcrossTwoServices) {
    RuleConfig cfg;
    cfg.multi_min_services    = 2;
    cfg.multi_window_seconds  = 300;
    cfg.multi_cooldown_seconds = 3600;
    RuleEngine engine(cfg);

    auto base = base_time();
    std::vector<LogEvent> history = {
        make_auth_fail("10.0.0.99", "sshd",  base - 60s),
    };
    auto trigger = make_auth_fail("10.0.0.99", "sudo", base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts) {
        if (a.rule_id == "MULTI_SERVICE_AUTH_001") {
            fired = true;
            EXPECT_EQ(a.severity, Severity::CRITICAL);
            EXPECT_NE(a.metadata.at("services").find("sshd"), std::string::npos);
            EXPECT_NE(a.metadata.at("services").find("sudo"), std::string::npos);
        }
    }
    EXPECT_TRUE(fired);
}

TEST(MultiServiceAuth, DoesNotFireSingleService) {
    RuleConfig cfg;
    cfg.multi_min_services = 2;
    RuleEngine engine(cfg);

    auto base = base_time();
    std::vector<LogEvent> history = {
        make_auth_fail("10.0.0.99", "sshd", base - 30s),
        make_auth_fail("10.0.0.99", "sshd", base - 10s),
    };
    auto trigger = make_auth_fail("10.0.0.99", "sshd", base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "MULTI_SERVICE_AUTH_001") fired = true;
    EXPECT_FALSE(fired);
}

TEST(MultiServiceAuth, FiresAcrossThreeServices) {
    RuleConfig cfg;
    cfg.multi_min_services = 2;
    RuleEngine engine(cfg);

    auto base = base_time();
    std::vector<LogEvent> history = {
        make_auth_fail("172.16.0.1", "sshd",  base - 120s),
        make_auth_fail("172.16.0.1", "sudo",  base - 60s),
    };
    auto trigger = make_auth_fail("172.16.0.1", "nginx", base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts) {
        if (a.rule_id == "MULTI_SERVICE_AUTH_001") {
            fired = true;
            EXPECT_EQ(a.metadata.at("service_count"), "3");
        }
    }
    EXPECT_TRUE(fired);
}

TEST(MultiServiceAuth, DoesNotCrossContaminateIPs) {
    RuleConfig cfg;
    cfg.multi_min_services = 2;
    RuleEngine engine(cfg);

    auto base = base_time();
    // Different IPs failing on different services.
    std::vector<LogEvent> history = {
        make_auth_fail("10.0.0.1", "sshd",  base - 30s),
        make_auth_fail("10.0.0.2", "nginx", base - 20s),
    };
    auto trigger = make_auth_fail("10.0.0.1", "sshd", base);

    auto alerts = engine.process(trigger, history);
    bool fired = false;
    for (auto& a : alerts)
        if (a.rule_id == "MULTI_SERVICE_AUTH_001") fired = true;
    EXPECT_FALSE(fired);  // 10.0.0.1 only hit sshd
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Cooldown / deduplication
// ─────────────────────────────────────────────────────────────────────────────

TEST(Cooldown, SecondAlertSuppressedWithinWindow) {
    RuleConfig cfg;
    cfg.ssh_threshold        = 3;
    cfg.ssh_cooldown_seconds = 3600;  // 1 hour
    RuleEngine engine(cfg);

    auto base    = base_time();
    auto history = make_ssh_history("10.0.0.1", 3, base, 50);
    auto trigger = make_ssh_fail("10.0.0.1", base);

    // First call — should fire.
    auto first = engine.process(trigger, history);
    bool fired_first = false;
    for (auto& a : first)
        if (a.rule_id == "SSH_BRUTE_FORCE_001") fired_first = true;
    EXPECT_TRUE(fired_first);

    // Second call immediately after — cooldown should suppress it.
    auto second = engine.process(trigger, history);
    bool fired_second = false;
    for (auto& a : second)
        if (a.rule_id == "SSH_BRUTE_FORCE_001") fired_second = true;
    EXPECT_FALSE(fired_second);
}

TEST(Cooldown, DifferentIPsNotAffectedByEachOthersCooldown) {
    RuleConfig cfg;
    cfg.ssh_threshold        = 3;
    cfg.ssh_cooldown_seconds = 3600;
    RuleEngine engine(cfg);

    auto base = base_time();

    // Fire rule for IP A.
    auto hist_a = make_ssh_history("10.0.0.1", 3, base, 50);
    auto trig_a = make_ssh_fail("10.0.0.1", base);
    engine.process(trig_a, hist_a);

    // IP B should still be able to fire.
    auto hist_b = make_ssh_history("10.0.0.2", 3, base, 50);
    auto trig_b = make_ssh_fail("10.0.0.2", base);
    auto alerts_b = engine.process(trig_b, hist_b);

    bool fired_b = false;
    for (auto& a : alerts_b)
        if (a.rule_id == "SSH_BRUTE_FORCE_001") fired_b = true;
    EXPECT_TRUE(fired_b);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. extract_src_ip helper
// ─────────────────────────────────────────────────────────────────────────────

TEST(ExtractSrcIp, FromFieldsMap) {
    LogEvent ev;
    ev.fields["src_ip"] = "192.168.1.1";
    EXPECT_EQ(extract_src_ip(ev), "192.168.1.1");
}

TEST(ExtractSrcIp, FromMessageFromPattern) {
    LogEvent ev;
    ev.message = "Failed password for root from 10.0.0.5 port 22 ssh2";
    EXPECT_EQ(extract_src_ip(ev), "10.0.0.5");
}

TEST(ExtractSrcIp, FieldTakesPriorityOverMessage) {
    LogEvent ev;
    ev.fields["src_ip"] = "1.2.3.4";
    ev.message = "Failed password for root from 9.9.9.9 port 22 ssh2";
    EXPECT_EQ(extract_src_ip(ev), "1.2.3.4");
}

TEST(ExtractSrcIp, ReturnsEmptyWhenNotFound) {
    LogEvent ev;
    ev.message = "some log line with no IP";
    EXPECT_TRUE(extract_src_ip(ev).empty());
}