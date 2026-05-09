#include "dlads/alert_event.hpp"
#include "dlads/alert_publisher.hpp"
#include "dlads/log_parser.hpp"
#include "dlads/log_tailer.hpp"
#include "dlads/ring_buffer.hpp"
#include "dlads/rule_engine.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

using namespace dlads;

// ── Graceful shutdown ─────────────────────────────────────────────────────────
static std::atomic<bool> g_stop{ false };
static void on_signal(int) { g_stop.store(true); }

// ── Logging helpers ───────────────────────────────────────────────────────────
static std::mutex g_log_mtx;

static std::string now_str() {
    auto now  = std::chrono::system_clock::now();
    auto tt   = std::chrono::system_clock::to_time_t(now);
    auto ms   = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()).count() % 1000;
    char buf[32];
    std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&tt));
    std::snprintf(buf + 8, sizeof(buf) - 8, ".%03lld", static_cast<long long>(ms));
    return buf;
}

// Normal info log — [HH:MM:SS.mmm] [STAGE] message
#define LOG_INFO(stage, msg) \
    do { \
        std::lock_guard<std::mutex> _lg(g_log_mtx); \
        std::cout << "[" << now_str() << "] [" << (stage) << "] " \
                  << msg << "\n" << std::flush; \
    } while(0)

// Error log — starts with *************** so it's impossible to miss
#define LOG_ERR(stage, msg) \
    do { \
        std::lock_guard<std::mutex> _lg(g_log_mtx); \
        std::cerr << "***************\n" \
                  << "[" << now_str() << "] [" << (stage) << "] ERROR: " \
                  << msg << "\n" \
                  << "***************\n" << std::flush; \
    } while(0)

// ── Pipeline stats (printed every 10s) ───────────────────────────────────────
static std::atomic<uint64_t> g_lines_seen{ 0 };
static std::atomic<uint64_t> g_lines_parsed{ 0 };
static std::atomic<uint64_t> g_parse_failures{ 0 };
static std::atomic<uint64_t> g_alerts_fired{ 0 };

static void stats_loop(const AlertPublisher& pub) {
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        LOG_INFO("STATS",
            "lines_seen="    << g_lines_seen.load()    <<
            "  parsed="      << g_lines_parsed.load()  <<
            "  parse_fail="  << g_parse_failures.load() <<
            "  alerts="      << g_alerts_fired.load()  <<
            "  zmq_sent="    << pub.sent_count()        <<
            "  zmq_dropped=" << pub.dropped_count());
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    // ── Config ────────────────────────────────────────────────────────────────
    std::string cfg_path = (argc > 1) ? argv[1] : "config/agent.yaml";
    std::string watch    = (argc > 2) ? argv[2] : "/var/log/auth.log";
    std::string endpoint = (argc > 3) ? argv[3] : "tcp://*:5555";

    LOG_INFO("INIT", "dlads agent starting");
    LOG_INFO("INIT", "config   = " << cfg_path);
    LOG_INFO("INIT", "watching = " << watch);
    LOG_INFO("INIT", "endpoint = " << endpoint);

    // ── Load rule config ──────────────────────────────────────────────────────
    RuleConfig cfg = RuleConfig::from_yaml(cfg_path);
    LOG_INFO("INIT", "rule config loaded from " << cfg_path);

    // ── Construct pipeline objects ────────────────────────────────────────────
    RingBuffer<LogEvent, 4096> ring;
    LogParser                  parser;
    RuleEngine                 engine(cfg);
    AlertPublisher             publisher(endpoint);

    // Single mutex guards ring + engine — both accessed only in the tailer
    // callback, which runs on one background thread.
    std::mutex detection_mtx;

    LOG_INFO("INIT", "pipeline objects constructed (ring=4096, engine ready)");

    // ── Tailer callback — this IS the hot path ────────────────────────────────
    LogTailer tailer(watch, [&](std::string_view line) {

        // ── Stage 1: raw line received ────────────────────────────────────────
        g_lines_seen.fetch_add(1, std::memory_order_relaxed);
        LOG_INFO("TAILER", "raw line: " << line);

        // ── Stage 2: parse ────────────────────────────────────────────────────
        auto ev = parser.parse(line);
        if (!ev) {
            g_parse_failures.fetch_add(1, std::memory_order_relaxed);
            LOG_ERR("PARSER", "failed to parse line: " << line);
            return;
        }
        g_lines_parsed.fetch_add(1, std::memory_order_relaxed);
        LOG_INFO("PARSER",
            "parsed OK — host=" << ev->source_host <<
            " source="          << ev->log_source  <<
            " level="           << to_string(ev->level));

        // ── Stage 3: ring buffer push ─────────────────────────────────────────
        std::lock_guard<std::mutex> lk(detection_mtx);
        ring.push(*ev);
        LOG_INFO("RINGBUF", "pushed event, ring size=" << ring.size());

        // ── Stage 4: rule engine ──────────────────────────────────────────────
        auto snap   = ring.snapshot();
        auto alerts = engine.process(*ev, snap);

        if (alerts.empty()) {
            LOG_INFO("RULES", "no rules fired");
            return;
        }

        // ── Stage 5: publish each alert ───────────────────────────────────────
        for (auto& alert : alerts) {
            g_alerts_fired.fetch_add(1, std::memory_order_relaxed);
            LOG_INFO("RULES",
                "ALERT FIRED rule=" << alert.rule_id <<
                " severity="        << to_string(alert.severity) <<
                " score="           << alert.anomaly_score <<
                " desc="            << alert.description);

            std::string json = serialize(alert);
            LOG_INFO("PUBLISHER", "publishing: " << json);

            publisher.publish(alert);

            if (publisher.dropped_count() > 0) {
                LOG_ERR("PUBLISHER",
                    "ZMQ queue full — total dropped so far: "
                    << publisher.dropped_count());
            }
        }
    });

    // ── Start everything ──────────────────────────────────────────────────────
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    // Start publisher first so the ZMQ socket is bound before the tailer
    // can fire any alerts.
    try {
        publisher.start();
        LOG_INFO("PUBLISHER", "ZMQ PUB socket bound on " << endpoint);
    } catch (const std::exception& e) {
        LOG_ERR("PUBLISHER", "failed to start: " << e.what());
        return 1;
    }

    try {
        tailer.start();
        LOG_INFO("TAILER", "watching " << watch);
    } catch (const std::exception& e) {
        LOG_ERR("TAILER", "failed to start: " << e.what());
        publisher.stop();
        return 1;
    }

    // Stats printer — runs on its own thread, never touches pipeline objects.
    std::thread stats_thread(stats_loop, std::cref(publisher));

    LOG_INFO("INIT", "pipeline running — press Ctrl+C to stop");

    // ── Main loop ─────────────────────────────────────────────────────────────
    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // ── Shutdown ──────────────────────────────────────────────────────────────
    LOG_INFO("INIT", "shutdown signal received");

    g_stop.store(true);
    stats_thread.join();

    tailer.stop();
    LOG_INFO("TAILER", "stopped");

    publisher.stop();
    LOG_INFO("PUBLISHER",
        "stopped — total sent=" << publisher.sent_count() <<
        " dropped="             << publisher.dropped_count());

    LOG_INFO("STATS",
        "final — lines_seen="  << g_lines_seen.load()    <<
        " parsed="             << g_lines_parsed.load()  <<
        " parse_fail="         << g_parse_failures.load() <<
        " alerts="             << g_alerts_fired.load());

    return 0;
}