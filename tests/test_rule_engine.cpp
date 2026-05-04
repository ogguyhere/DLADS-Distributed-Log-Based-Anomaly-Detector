#include <gtest/gtest.h>
#include "dlads/rule_engine.hpp"
#include "dlads/log_event.hpp"

#include <chrono>
#include <vector>

using namespace dlads;

// FIX: avoid conflict with C std::clock_t
using Clock = std::chrono::system_clock;

// ---------------- helper ----------------

static LogEvent make_event(
    std::string source,
    std::string message,
    std::string src_ip,
    int seconds_ago)
{
    LogEvent e;
    e.log_source = std::move(source);
    e.message = std::move(message);
    e.source_host = "test_host";
    e.fields["src_ip"] = std::move(src_ip);

    e.timestamp = Clock::now() - std::chrono::seconds(seconds_ago);
    return e;
}

// ---------------- tests ----------------

TEST(RuleEngine, SSHBruteforceTriggers)
{
    RuleConfig cfg;
    cfg.ssh_threshold = 3;
    cfg.ssh_window_seconds = 60;

    RuleEngine engine(cfg);

    std::vector<LogEvent> snap = {
        make_event("sshd", "Failed password for root", "1.1.1.1", 10),
        make_event("sshd", "Failed password for root", "1.1.1.1", 20),
        make_event("sshd", "Failed password for root", "1.1.1.1", 30),
    };

    auto alerts = engine.process(snap.back(), snap);
    ASSERT_FALSE(alerts.empty());
}

TEST(RuleEngine, SSHBruteforceNoTrigger)
{
    RuleConfig cfg;
    cfg.ssh_threshold = 5;

    RuleEngine engine(cfg);

    std::vector<LogEvent> snap = {
        make_event("sshd", "Failed password", "2.2.2.2", 10),
        make_event("sshd", "Failed password", "2.2.2.2", 20),
    };

    auto alerts = engine.process(snap.back(), snap);
    ASSERT_TRUE(alerts.empty());
}

TEST(RuleEngine, PortScanTriggers)
{
    RuleConfig cfg;
    cfg.scan_threshold = 3;

    RuleEngine engine(cfg);

    std::vector<LogEvent> snap = {
        make_event("kernel", "REJECT DPT=22 SRC=3.3.3.3", "3.3.3.3", 5),
        make_event("kernel", "REJECT DPT=80 SRC=3.3.3.3", "3.3.3.3", 6),
        make_event("kernel", "REJECT DPT=443 SRC=3.3.3.3", "3.3.3.3", 7),
    };

    auto alerts = engine.process(snap.back(), snap);
    ASSERT_FALSE(alerts.empty());
}

TEST(RuleEngine, MultiServiceAuth)
{
    RuleConfig cfg;
    cfg.multi_min_services = 2;

    RuleEngine engine(cfg);

    std::vector<LogEvent> snap = {
        make_event("ssh", "authentication failure", "4.4.4.4", 5),
        make_event("sudo", "authentication failure", "4.4.4.4", 10),
    };

    auto alerts = engine.process(snap.back(), snap);
    ASSERT_FALSE(alerts.empty());
}

TEST(RuleEngine, NoFalsePositive)
{
    RuleConfig cfg;
    RuleEngine engine(cfg);

    std::vector<LogEvent> snap = {
        make_event("sshd", "Accepted password", "5.5.5.5", 10),
        make_event("sudo", "session opened", "5.5.5.5", 20),
    };

    auto alerts = engine.process(snap.back(), snap);
    ASSERT_TRUE(alerts.empty());
}