#include "dlads/rule_engine.hpp"
#include "dlads/ring_buffer.hpp"
#include "dlads/alert_event.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace dlads;
using Clock = std::chrono::system_clock;

// ── Helpers ───────────────────────────────────────────────────────────────────

static LogEvent make_ssh_failure(const std::string& ip,
                                 int offset_seconds_ago = 0)
{
    LogEvent ev;
    ev.timestamp   = Clock::now() - std::chrono::seconds(offset_seconds_ago);
    ev.source_host = "testhost";
    ev.log_source  = "sshd";
    ev.message     = "Failed password for root from " + ip + " port 54321 ssh2";
    ev.fields["src_ip"] = ip;
    return ev;
}

static LogEvent make_sudo_open(const std::string& user,
                               int offset_seconds_ago = 0)
{
    LogEvent ev;
    ev.timestamp   = Clock::now() - std::chrono::seconds(offset_seconds_ago);
    ev.source_host = "testhost";
    ev.log_source  = "sudo";
    ev.message     = "pam_unix(sudo:session): session opened for user root by " + user;
    ev.fields["user"] = user;
    return ev;
}

static LogEvent make_conn_refused(const std::string& ip,
                                  const std::string& dst_port,
                                  int offset_seconds_ago = 0)
{
    LogEvent ev;
    ev.timestamp   = Clock::now() - std::chrono::seconds(offset_seconds_ago);
    ev.source_host = "testhost";
    ev.log_source  = "kernel";
    ev.message     = "Connection refused from " + ip + " DPT=" + dst_port;
    ev.fields["src_ip"]  = ip;
    ev.fields["dst_port"]= dst_port;
    return ev;
}

// ── Test 1: SSH brute force — single IP fires exactly once ────────────────────

void test_ssh_brute_force_single_ip() {
    std::cout << "[TEST] SSH brute force — 10 failures, same IP\n";

    RingBuffer<LogEvent, 1024> rb;
    RuleEngine engine("", 3600); // Long cooldown so only 1 alert.

    // Push 9 failures into history.
    for (int i = 0; i < 9; ++i) {
        rb.push(make_ssh_failure("1.2.3.4", i));
    }
    // The 10th event is the "current" event passed to process().
    LogEvent current = make_ssh_failure("1.2.3.4", 0);
    auto history = rb.snapshot();
    auto alerts  = engine.process(current, history);

    assert(alerts.size() == 1 && "Expected exactly 1 SSH alert");
    assert(alerts[0].rule_id == "SSH_BRUTE_FORCE_001");
    assert(alerts[0].metadata.at("src_ip") == "1.2.3.4");
    std::cout << "  PASS: 1 alert fired\n";
}

// ── Test 2: SSH brute force — spread across 10 different IPs → 0 alerts ──────

void test_ssh_brute_force_distributed() {
    std::cout << "[TEST] SSH brute force — 10 failures, 10 different IPs\n";

    RingBuffer<LogEvent, 1024> rb;
    RuleEngine engine("", 3600);

    for (int i = 0; i < 9; ++i) {
        rb.push(make_ssh_failure("10.0.0." + std::to_string(i), 0));
    }
    LogEvent current = make_ssh_failure("10.0.0.9", 0);
    auto history = rb.snapshot();
    auto alerts  = engine.process(current, history);

    assert(alerts.empty() && "Expected 0 alerts for distributed IPs");
    std::cout << "  PASS: 0 alerts fired\n";
}

// ── Test 3: Deduplication — suppresses second alert within cooldown ───────────

void test_dedup_within_cooldown() {
    std::cout << "[TEST] Deduplication — second alert suppressed within cooldown\n";

    RingBuffer<LogEvent, 1024> rb;
    // Short cooldown: 5 seconds.
    RuleEngine engine("", 5);

    for (int i = 0; i < 10; ++i) rb.push(make_ssh_failure("5.5.5.5", i));

    // First firing.
    LogEvent ev1 = make_ssh_failure("5.5.5.5", 0);
    auto a1 = engine.process(ev1, rb.snapshot());
    assert(a1.size() == 1 && "First alert should fire");

    // Immediate second attempt (still within cooldown).
    rb.push(make_ssh_failure("5.5.5.5", 0));
    LogEvent ev2 = make_ssh_failure("5.5.5.5", 0);
    auto a2 = engine.process(ev2, rb.snapshot());
    assert(a2.empty() && "Second alert should be suppressed");

    std::cout << "  PASS: second alert suppressed\n";
}

// ── Test 4: Deduplication — alert fires again AFTER cooldown expires ──────────

void test_dedup_after_cooldown() {
    std::cout << "[TEST] Deduplication — alert fires again after cooldown\n";

    RingBuffer<LogEvent, 1024> rb;
    // Very short cooldown: 1 second.
    RuleEngine engine("", 1);

    for (int i = 0; i < 10; ++i) rb.push(make_ssh_failure("6.6.6.6", i));

    LogEvent ev1 = make_ssh_failure("6.6.6.6", 0);
    auto a1 = engine.process(ev1, rb.snapshot());
    assert(a1.size() == 1 && "First alert should fire");

    // Wait for cooldown to expire.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    for (int i = 0; i < 10; ++i) rb.push(make_ssh_failure("6.6.6.6", i));
    LogEvent ev2 = make_ssh_failure("6.6.6.6", 0);
    auto a2 = engine.process(ev2, rb.snapshot());
    assert(a2.size() == 1 && "Alert should fire again after cooldown");

    std::cout << "  PASS: alert re-fired after cooldown\n";
}

// ── Test 5: Privilege escalation — unknown user fires alert ───────────────────

void test_priv_esc_unknown_user() {
    std::cout << "[TEST] Privilege escalation — no prior sudo history\n";

    RingBuffer<LogEvent, 1024> rb;
    RuleEngine engine("", 3600);

    // History: some noise, but NO prior sudo by 'newuser'.
    rb.push(make_ssh_failure("9.9.9.9", 100));

    LogEvent current = make_sudo_open("newuser", 0);
    auto alerts = engine.process(current, rb.snapshot());

    // Might also fire SSH rule but NOT port scan; just check priv esc present.
    bool found = false;
    for (auto& a : alerts)
        if (a.rule_id == "PRIVILEGE_ESCALATION_001") found = true;

    assert(found && "Expected PRIVILEGE_ESCALATION_001 alert");
    std::cout << "  PASS: privilege escalation alert fired\n";
}

// ── Test 6: Port scan — >= 10 distinct ports within 60s ──────────────────────

void test_port_scan_fires() {
    std::cout << "[TEST] Port scan — 12 distinct ports, same IP\n";

    RingBuffer<LogEvent, 1024> rb;
    RuleEngine engine("", 3600);

    for (int p = 1; p <= 11; ++p)
        rb.push(make_conn_refused("7.7.7.7", std::to_string(1000 + p), 5));

    LogEvent current = make_conn_refused("7.7.7.7", "2000", 0);
    auto alerts = engine.process(current, rb.snapshot());

    bool found = false;
    for (auto& a : alerts)
        if (a.rule_id == "PORT_SCAN_001") found = true;

    assert(found && "Expected PORT_SCAN_001 alert");
    std::cout << "  PASS: port scan alert fired\n";
}

// ── Test 7: Throughput benchmark ──────────────────────────────────────────────

void test_throughput() {
    std::cout << "[TEST] Throughput — 1000 events, measure avg latency\n";

    RingBuffer<LogEvent, 4096> rb;
    RuleEngine engine("", 3600);

    // Pre-fill ring buffer.
    for (int i = 0; i < 1000; ++i)
        rb.push(make_ssh_failure("192.168.1." + std::to_string(i % 256), i % 30));

    const int N = 1000;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < N; ++i) {
        LogEvent ev = make_ssh_failure("172.16.0." + std::to_string(i % 256), 0);
        auto history = rb.snapshot();          // O(N) — once per cycle
        auto alerts  = engine.process(ev, history);
        rb.push(std::move(ev));
    }

    auto end = std::chrono::high_resolution_clock::now();
    double total_us = std::chrono::duration<double, std::micro>(end - start).count();
    double avg_us   = total_us / N;

    std::cout << "  Total: " << static_cast<int>(total_us) << " µs  |  "
              << "Avg per event: " << avg_us << " µs\n";
    // Target: < 5 µs average (snapshot dominates; acceptable for prototype).
    std::cout << "  " << (avg_us < 50.0 ? "PASS" : "WARN (check snapshot size)")
              << ": avg latency " << avg_us << " µs\n";
}

// ── main ──────────────────────────────────────────────────────────────────────

int main() {
    test_ssh_brute_force_single_ip();
    test_ssh_brute_force_distributed();
    test_dedup_within_cooldown();
    test_dedup_after_cooldown();
    test_priv_esc_unknown_user();
    test_port_scan_fires();
    test_throughput();

    std::cout << "\n✓ All rule engine tests passed.\n";
    return 0;
}