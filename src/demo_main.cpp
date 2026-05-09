// demo_main.cpp
// DLADS Full Demo — single binary, no networking required.
//
// Launches:
//   - LogSimulator   (writes fake attack logs to /tmp/dlads_agentN.log)
//   - N LogTailers   (one per simulated agent)
//   - RuleEngine     (local detection per agent)
//   - Coordinator    (in-memory shared state + analytics + HTTP on :8080)
//
// Then run the dashboard separately:
//   ./dlads_dashboard http://localhost:8080

#include "dlads/alert_event.hpp"
#include "dlads/coordinator.hpp"
#include "dlads/log_parser.hpp"
#include "dlads/log_tailer.hpp"
#include "dlads/log_simulator.hpp"
#include "dlads/ring_buffer.hpp"
#include "dlads/rule_engine.hpp"

#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace dlads;

static std::atomic<bool> g_stop{ false };
static void on_signal(int) { g_stop.store(true); }

// ── Per-agent pipeline ────────────────────────────────────────────────────────

struct AgentPipeline {
    std::string                        name;
    std::unique_ptr<RingBuffer<LogEvent, 4096>> ring;
    std::unique_ptr<LogParser>         parser;
    std::unique_ptr<RuleEngine>        engine;
    std::unique_ptr<LogTailer>         tailer;
    std::mutex                         mtx;
};

int main() {
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    // ── Coordinator (shared state + HTTP + analytics) ─────────────────────────
    Coordinator coordinator;
    coordinator.start();

    // ── Simulated agents ──────────────────────────────────────────────────────
    // Two agents simulating two different hosts under attack.
    std::vector<AgentConfig> sim_configs = {
        { "webserver-01", "/tmp/dlads_agent1.log", "10.10.1.", 200 },
        { "dbserver-01",  "/tmp/dlads_agent2.log", "10.10.2.", 250 },
    };

    // Register nodes with coordinator before simulation starts
    coordinator.registerNode("webserver-01", "192.168.0.101");
    coordinator.registerNode("dbserver-01",  "192.168.0.102");

    // Start log simulator
    LogSimulator simulator(sim_configs);
    simulator.start();

    // Give simulator a moment to create the files
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // ── Build one pipeline per agent ──────────────────────────────────────────
    RuleConfig rule_cfg;
    rule_cfg.ssh_threshold        = 8;   // lower for demo — fires faster
    rule_cfg.ssh_window_seconds   = 30;
    rule_cfg.ssh_cooldown_seconds = 20;
    rule_cfg.scan_threshold       = 10;
    rule_cfg.scan_window_seconds  = 20;
    rule_cfg.scan_cooldown_seconds= 15;
    rule_cfg.priv_history_hours   = 1;
    rule_cfg.priv_cooldown_seconds= 30;
    rule_cfg.multi_min_services   = 2;
    rule_cfg.multi_window_seconds = 60;
    rule_cfg.multi_cooldown_seconds=30;

    std::vector<std::unique_ptr<AgentPipeline>> pipelines;

    for (auto& ac : sim_configs) {
        auto p   = std::make_unique<AgentPipeline>();
        p->name  = ac.host;
        p->ring  = std::make_unique<RingBuffer<LogEvent, 4096>>();
        p->parser= std::make_unique<LogParser>();
        p->engine= std::make_unique<RuleEngine>(rule_cfg);

        // Capture raw pointers for the lambda (pipelines owns unique_ptrs)
        AgentPipeline* pp = p.get();
        std::string    host = ac.host;
        Coordinator*   coord = &coordinator;

        p->tailer = std::make_unique<LogTailer>(
            ac.log_path,
            [pp, host, coord](std::string_view line) {
                auto ev = pp->parser->parse(line);
                if (!ev) return;

                std::lock_guard<std::mutex> lk(pp->mtx);
                pp->ring->push(*ev);

                // Snapshot for rule evaluation
                auto snap   = pp->ring->snapshot();
                auto alerts = pp->engine->process(*ev, snap);

                for (auto& alert : alerts) {
                    alert.source_host = host;
                    std::cout << "[" << host << "] ALERT "
                              << alert.rule_id << " from "
                              << (alert.metadata.count("src_ip")
                                  ? alert.metadata.at("src_ip") : "?")
                              << "\n";
                    // ── Directly inject into coordinator ──────────────────
                    coord->ingestAlert(alert);
                    // (ZeroMQ publisher commented out — using shared queue)
                    // publisher.publish(alert);
                }
            },
            50  // poll every 50ms for snappy demo
        );

        pipelines.push_back(std::move(p));
    }

    // ── Start all tailers ─────────────────────────────────────────────────────
    for (auto& p : pipelines)
        p->tailer->start();

    std::cout << "\n"
              << "╔══════════════════════════════════════════════╗\n"
              << "║   DLADS Demo running                         ║\n"
              << "║   Dashboard: ./dlads_dashboard               ║\n"
              << "║   HTTP API:  http://localhost:8080            ║\n"
              << "║   Press Ctrl+C to stop                       ║\n"
              << "╚══════════════════════════════════════════════╝\n\n";

    // ── Heartbeat loop ────────────────────────────────────────────────────────
    int tick = 0;
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        // Send heartbeat for each node so dashboard shows ALIVE
        coordinator.nodeHeartbeat("webserver-01");
        coordinator.nodeHeartbeat("dbserver-01");

        if (++tick % 10 == 0) {
            // Print a brief status every 10s
            std::cout << "[Demo] tick=" << tick
                      << "  " << coordinator.getStatsJson() << "\n";
        }
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────
    std::cout << "[Demo] shutting down...\n";
    for (auto& p : pipelines) p->tailer->stop();
    simulator.stop();
    coordinator.stop();
    std::cout << "[Demo] done.\n";
    return 0;
}