#include "dlads/alert_event.hpp"
#include "dlads/alert_publisher.hpp"
#include "dlads/log_parser.hpp"
#include "dlads/log_tailer.hpp"
#include "dlads/ring_buffer.hpp"
#include "dlads/rule_engine.hpp"

#include <atomic>
#include <csignal>
#include <iostream>
#include <mutex>
#include <string>

using namespace dlads;

// ── Graceful shutdown ─────────────────────────────────────────────────────────
static std::atomic<bool> g_stop{ false };
static void on_signal(int) { g_stop.store(true); }

int main(int argc, char* argv[]) {
    // Config — use defaults or accept path as first arg.
    std::string cfg_path = (argc > 1) ? argv[1] : "config/agent.yaml";
    std::string watch    = "/var/log/auth.log";
    std::string endpoint = "tcp://*:5555";

    // Load rule config.
    RuleConfig cfg = RuleConfig::from_yaml(cfg_path);

    // ── Core pipeline objects ─────────────────────────────────────────────────
    RingBuffer<LogEvent, 4096> ring;
    LogParser                  parser;
    RuleEngine                 engine(cfg);
    AlertPublisher             publisher(endpoint);

    std::mutex ring_mtx;  // guards ring + engine (single detection thread)

    // ── Log tailer callback ───────────────────────────────────────────────────
    LogTailer tailer(watch, [&](std::string_view line) {
        auto ev = parser.parse(line);
        if (!ev) return;

        std::lock_guard<std::mutex> lk(ring_mtx);
        ring.push(*ev);
        auto snap   = ring.snapshot();
        auto alerts = engine.process(*ev, snap);

        for (auto& alert : alerts) {
            std::cout << "[ALERT] " << serialize(alert) << "\n";
            publisher.publish(alert);
        }
    });

    // ── Start ─────────────────────────────────────────────────────────────────
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    publisher.start();
    tailer.start();

    std::cout << "[dlads] agent started — watching " << watch
              << "  publishing to " << endpoint << "\n";

    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cout << "[dlads] shutting down\n";
    tailer.stop();
    publisher.stop();
    return 0;
}