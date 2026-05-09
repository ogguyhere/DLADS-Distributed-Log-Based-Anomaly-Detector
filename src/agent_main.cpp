#include "dlads/alert_event.hpp"
#include "dlads/alert_publisher.hpp"
#include "dlads/heartbeat.hpp"
#include "dlads/log_parser.hpp"
#include "dlads/log_tailer.hpp"
#include "dlads/ring_buffer.hpp"
#include "dlads/rule_engine.hpp"

#include <zmq.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

using namespace dlads;

// ── Graceful shutdown ─────────────────────────────────────────────────────────
static std::atomic<bool> g_stop{ false };
static void on_signal(int) { g_stop.store(true); }

// ── Logging ───────────────────────────────────────────────────────────────────
static std::mutex g_log_mtx;

static std::string now_str() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                   now.time_since_epoch()).count() % 1000;
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&tt));
    std::snprintf(buf + 8, sizeof(buf) - 8, ".%03lld", static_cast<long long>(ms));
    return buf;
}

#define LOG_INFO(stage, msg) \
    do { \
        std::lock_guard<std::mutex> _lg(g_log_mtx); \
        std::cout << "[" << now_str() << "] [" << (stage) << "] " \
                  << msg << "\n" << std::flush; \
    } while(0)

#define LOG_ERR(stage, msg) \
    do { \
        std::lock_guard<std::mutex> _lg(g_log_mtx); \
        std::cerr << "***************\n" \
                  << "[" << now_str() << "] [" << (stage) << "] ERROR: " \
                  << msg << "\n" \
                  << "***************\n" << std::flush; \
    } while(0)

// ── Stats ─────────────────────────────────────────────────────────────────────
static std::atomic<uint64_t> g_lines_seen{ 0 };
static std::atomic<uint64_t> g_lines_parsed{ 0 };
static std::atomic<uint64_t> g_parse_failures{ 0 };
static std::atomic<uint64_t> g_alerts_fired{ 0 };

static void stats_loop(const AlertPublisher& pub) {
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        LOG_INFO("STATS",
            "lines_seen="    << g_lines_seen.load()     <<
            "  parsed="      << g_lines_parsed.load()   <<
            "  parse_fail="  << g_parse_failures.load() <<
            "  alerts="      << g_alerts_fired.load()   <<
            "  zmq_sent="    << pub.sent_count()         <<
            "  zmq_dropped=" << pub.dropped_count());
    }
}

// ── Heartbeat thread ──────────────────────────────────────────────────────────
// Coordinator binds PULL on tcp://*:5556 — we connect as PUSH.
// Sends every 10 seconds so coordinator marks us ALIVE (dead threshold = 30s).
static void heartbeat_loop(
    const std::string& node_id,
    const std::string& coordinator_ip,
    const AlertPublisher& pub)
{
    void* ctx  = zmq_ctx_new();
    void* sock = zmq_socket(ctx, ZMQ_PUSH);

    int linger = 500;
    zmq_setsockopt(sock, ZMQ_LINGER, &linger, sizeof(linger));

    std::string endpoint = "tcp://" + coordinator_ip + ":5556";
    if (zmq_connect(sock, endpoint.c_str()) != 0) {
        LOG_ERR("HEARTBEAT", "zmq_connect failed: " << endpoint);
        zmq_close(sock);
        zmq_ctx_destroy(ctx);
        return;
    }
    LOG_INFO("HEARTBEAT", "connected to " << endpoint);

    while (!g_stop.load()) {
        HeartbeatMessage hb;
        hb.node_id     = node_id;
        hb.alerts_sent = static_cast<int>(pub.sent_count());
        hb.status      = "ALIVE";
        hb.timestamp   = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch()
                         ).count();

        std::string json = hb.toJSON();
        zmq_send(sock, json.data(), json.size(), ZMQ_DONTWAIT);
        LOG_INFO("HEARTBEAT", "ping sent node=" << node_id
                 << " alerts_sent=" << hb.alerts_sent);

        // 10s sleep, checking stop every 200ms for fast shutdown.
        for (int i = 0; i < 50 && !g_stop.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    zmq_close(sock);
    zmq_ctx_destroy(ctx);
    LOG_INFO("HEARTBEAT", "stopped");
}

// ── Main ──────────────────────────────────────────────────────────────────────
// Usage: dlads_agent [config] [watch_file] [alert_endpoint] [node_id] [coordinator_ip]
//
// Examples (two agents on same machine):
//   ./dlads_agent config/agent.yaml /tmp/agent1.log "tcp://*:5557" agent-01 127.0.0.1
//   ./dlads_agent config/agent.yaml /tmp/agent2.log "tcp://*:5558" agent-02 127.0.0.1
//
// Coordinator (Partner B) binds:
//   SUB tcp://*:5555  <-- BUT we PUB to specific ports above, so coordinator
//                         must connect (not bind) to agent ports, OR we all
//                         publish to the coordinator's single SUB port 5555.
//
// !! See note in heartbeat_loop — coordinator SUB binds 5555, agents PUB
//    connect to 5555. This is the correct ZMQ PUB/SUB topology when there
//    is one known coordinator and N unknown agents.
int main(int argc, char* argv[]) {
    std::string cfg_path       = (argc > 1) ? argv[1] : "config/agent.yaml";
    std::string watch          = (argc > 2) ? argv[2] : "/var/log/auth.log";
    std::string alert_endpoint = (argc > 3) ? argv[3] : "tcp://127.0.0.1:5555";
    std::string node_id        = (argc > 4) ? argv[4] : "agent-01";
    std::string coordinator_ip = (argc > 5) ? argv[5] : "127.0.0.1";

    LOG_INFO("INIT", "dlads agent starting");
    LOG_INFO("INIT", "node_id        = " << node_id);
    LOG_INFO("INIT", "config         = " << cfg_path);
    LOG_INFO("INIT", "watching       = " << watch);
    LOG_INFO("INIT", "alert_endpoint = " << alert_endpoint);
    LOG_INFO("INIT", "coordinator    = " << coordinator_ip);

    RuleConfig cfg = RuleConfig::from_yaml(cfg_path);
    LOG_INFO("INIT", "rule config loaded");

    RingBuffer<LogEvent, 4096> ring;
    LogParser                  parser;
    RuleEngine                 engine(cfg);

    // ── ZMQ topology note ─────────────────────────────────────────────────────
    // Coordinator's zmq_alert_receiver does: sub.bind("tcp://*:5555")
    // So WE must connect (not bind) to it.
    // AlertPublisher currently calls zmq_bind. We need zmq_connect instead
    // when talking to a coordinator that binds. Simplest fix without changing
    // AlertPublisher: use a raw PUSH socket here and coordinator uses PULL,
    // OR change coordinator to connect to agents (less scalable).
    //
    // Looking at coordinator.cpp: it uses ZMQ_SUB and binds. So agents must
    // use ZMQ_PUB and CONNECT to coordinator. AlertPublisher uses zmq_bind
    // which is wrong for this topology.
    //
    // Fix: AlertPublisher gets the endpoint as-is. For multi-agent demo,
    // pass "tcp://127.0.0.1:5555" (connect) not "tcp://*:5555" (bind).
    // AlertPublisher needs a connect mode. We handle it by detecting prefix.
    AlertPublisher publisher(alert_endpoint);
    std::mutex     detection_mtx;

    LOG_INFO("INIT", "pipeline objects constructed");

    // ── Tailer callback ───────────────────────────────────────────────────────
    LogTailer tailer(watch, [&](std::string_view line) {
        g_lines_seen.fetch_add(1, std::memory_order_relaxed);
        LOG_INFO("TAILER", "raw line: " << line);

        auto ev = parser.parse(line);
        if (!ev) {
            g_parse_failures.fetch_add(1, std::memory_order_relaxed);
            LOG_ERR("PARSER", "failed to parse: " << line);
            return;
        }

        // Always force node_id into source_host — overrides whatever hostname
        // the parser extracted from the log line. Coordinator uses source_host
        // for node identity and cross-node correlation. Must match heartbeat.
        ev->source_host = node_id;
        g_lines_parsed.fetch_add(1, std::memory_order_relaxed);
        LOG_INFO("PARSER", "parsed OK — source=" << ev->log_source
                 << " level=" << to_string(ev->level)
                 << " stamped_node=" << node_id);

        std::lock_guard<std::mutex> lk(detection_mtx);
        ring.push(*ev);
        LOG_INFO("RINGBUF", "ring size=" << ring.size());

        auto snap   = ring.snapshot();
        auto alerts = engine.process(*ev, snap);

        if (alerts.empty()) {
            LOG_INFO("RULES", "no rules fired");
            return;
        }

        for (auto& alert : alerts) {
            g_alerts_fired.fetch_add(1, std::memory_order_relaxed);
            // Force source_host and prefix alert_id with node_id so IDs are
            // globally unique across agents (each agent's counter starts at 1).
            alert.source_host = node_id;
            alert.alert_id    = node_id + "-" + alert.alert_id;
            LOG_INFO("RULES",
                "ALERT FIRED rule=" << alert.rule_id <<
                " severity="        << to_string(alert.severity) <<
                " desc="            << alert.description);
            publisher.publish(alert);

            if (publisher.dropped_count() > 0)
                LOG_ERR("PUBLISHER", "queue full — total dropped: "
                        << publisher.dropped_count());
        }
    });

    // ── Start ─────────────────────────────────────────────────────────────────
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    try {
        publisher.start();
        LOG_INFO("PUBLISHER", "ZMQ PUB started → " << alert_endpoint);
    } catch (const std::exception& e) {
        LOG_ERR("PUBLISHER", "failed: " << e.what());
        return 1;
    }

    try {
        tailer.start();
        LOG_INFO("TAILER", "watching " << watch);
    } catch (const std::exception& e) {
        LOG_ERR("TAILER", "failed: " << e.what());
        publisher.stop();
        return 1;
    }

    std::thread stats_thread(stats_loop, std::cref(publisher));
    std::thread hb_thread(heartbeat_loop,
                          node_id, coordinator_ip, std::cref(publisher));

    LOG_INFO("INIT", "all systems running — Ctrl+C to stop");

    while (!g_stop.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    LOG_INFO("INIT", "shutdown signal received");
    g_stop.store(true);
    hb_thread.join();
    stats_thread.join();
    tailer.stop();
    LOG_INFO("TAILER", "stopped");
    publisher.stop();
    LOG_INFO("PUBLISHER", "stopped — sent=" << publisher.sent_count()
             << " dropped=" << publisher.dropped_count());
    LOG_INFO("STATS",
        "final — lines_seen=" << g_lines_seen.load()     <<
        " parsed="            << g_lines_parsed.load()   <<
        " parse_fail="        << g_parse_failures.load() <<
        " alerts="            << g_alerts_fired.load());
    return 0;
}