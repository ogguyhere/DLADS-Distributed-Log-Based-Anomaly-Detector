#include "dlads/alert_event.hpp"
#include "dlads/alert_publisher.hpp"
#include "dlads/heartbeat.hpp"
#include "dlads/log_parser.hpp"
#include "dlads/log_tailer.hpp"
#include "dlads/ring_buffer.hpp"
#include "dlads/rule_engine.hpp"
#include "dlads/suricata_adapter.hpp"

#include <zmq.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <memory>

// POSIX sockets for status + config server
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>

using namespace dlads;

// ── Graceful shutdown ─────────────────────────────────────────────────────────
static std::atomic<bool> g_stop{ false };
static void on_signal(int) { g_stop.store(true); }

// ── Runtime state ─────────────────────────────────────────────────────────────
static std::string g_node_id;
static std::string g_watch_file;
static std::string g_coordinator_ip;
static std::string g_ids_mode;           // "builtin" | "suricata"
static std::string g_eve_json_path;
static std::string g_cfg_path;

static std::chrono::steady_clock::time_point g_start_time;

// ── Hot-swap state ────────────────────────────────────────────────────────────
// Protected by g_ids_swap_mtx.  Main IDS objects live here so the
// config-server thread can stop/start them without touching main().
static std::mutex                          g_ids_swap_mtx;
static std::unique_ptr<SuricataAdapter>    g_suricata_adapter;
static std::unique_ptr<LogTailer>          g_tailer;
static RingBuffer<LogEvent, 4096>          g_ring;
static LogParser                           g_parser;
static std::unique_ptr<RuleEngine>         g_engine;

// AlertPublisher pointer — set once in main, read everywhere
static AlertPublisher* g_publisher = nullptr;

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

        for (int i = 0; i < 50 && !g_stop.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    zmq_close(sock);
    zmq_ctx_destroy(ctx);
    LOG_INFO("HEARTBEAT", "stopped");
}

// ── Helpers ───────────────────────────────────────────────────────────────────
static bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}

// Read one field from the flat yaml (same logic as before)
static std::string read_yaml_field(const std::string& cfg_path,
                                    const std::string& key,
                                    const std::string& def = "") {
    std::ifstream f(cfg_path);
    if (!f.is_open()) return def;
    std::string line;
    while (std::getline(f, line)) {
        auto hash = line.find('#');
        if (hash != std::string::npos) line.resize(hash);
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string k = line.substr(0, colon);
        std::string v = line.substr(colon + 1);
        auto trim = [](std::string& s) {
            auto b = s.find_first_not_of(" \t");
            auto e = s.find_last_not_of(" \t\r\n");
            s = (b == std::string::npos) ? "" : s.substr(b, e - b + 1);
        };
        trim(k); trim(v);
        if (k == key) return v;
    }
    return def;
}

// Overwrite ONE key's value in the yaml file, preserving everything else.
static bool write_yaml_field(const std::string& cfg_path,
                              const std::string& key,
                              const std::string& value) {
    std::ifstream in(cfg_path);
    if (!in.is_open()) return false;

    std::vector<std::string> lines;
    std::string line;
    bool found = false;
    while (std::getline(in, line)) {
        // Check if this is the target key (skip comment lines)
        std::string stripped = line;
        auto hash = stripped.find('#');
        if (hash != std::string::npos) stripped.resize(hash);
        auto colon = stripped.find(':');
        if (colon != std::string::npos) {
            std::string k = stripped.substr(0, colon);
            auto b = k.find_first_not_of(" \t");
            auto e = k.find_last_not_of(" \t");
            if (b != std::string::npos) k = k.substr(b, e - b + 1);
            if (k == key) {
                line = key + ": " + value;
                found = true;
            }
        }
        lines.push_back(line);
    }
    in.close();

    if (!found) {
        // Key not present at all — append it
        lines.push_back(key + ": " + value);
    }

    std::ofstream out(cfg_path);
    if (!out.is_open()) return false;
    for (const auto& l : lines)
        out << l << "\n";
    return true;
}

// ── IDS hot-swap ──────────────────────────────────────────────────────────────
// Called from the HTTP config handler.  Switches the active IDS engine
// without restarting the process.
static std::string do_ids_swap(const std::string& new_mode) {
    if (new_mode != "builtin" && new_mode != "suricata")
        return "invalid mode";

    if (new_mode == g_ids_mode)
        return "already in " + new_mode + " mode";

    LOG_INFO("CONFIG", "hot-swap requested: " << g_ids_mode << " → " << new_mode);

    std::lock_guard<std::mutex> lk(g_ids_swap_mtx);

    // ── Tear down current IDS ─────────────────────────────────────────────────
    if (g_suricata_adapter) {
        g_suricata_adapter->stop();
        g_suricata_adapter.reset();
        LOG_INFO("CONFIG", "SuricataAdapter stopped");
    }
    if (g_tailer) {
        g_tailer->stop();
        g_tailer.reset();
        LOG_INFO("CONFIG", "LogTailer stopped");
    }

    // ── Persist to yaml ───────────────────────────────────────────────────────
    if (!write_yaml_field(g_cfg_path, "ids_mode", new_mode)) {
        LOG_ERR("CONFIG", "failed to write agent.yaml");
        return "yaml write failed";
    }
    LOG_INFO("CONFIG", "agent.yaml updated: ids_mode=" << new_mode);

    // ── Start new IDS ─────────────────────────────────────────────────────────
    if (new_mode == "suricata") {
        if (!file_exists(g_eve_json_path)) {
            // Roll back yaml
            write_yaml_field(g_cfg_path, "ids_mode", "builtin");
            LOG_ERR("CONFIG", "eve.json not found at " << g_eve_json_path
                    << " — swap aborted, staying on builtin");
            return "eve.json not found at " + g_eve_json_path;
        }

        // Update watch_file to eve.json path
        g_watch_file = g_eve_json_path;

        g_suricata_adapter = std::make_unique<SuricataAdapter>(
            g_eve_json_path,
            [](AlertEvent alert) {
                g_alerts_fired.fetch_add(1, std::memory_order_relaxed);
                alert.source_host = g_node_id;
                alert.alert_id    = g_node_id + "-" + alert.alert_id;
                LOG_INFO("SURICATA",
                    "ALERT FIRED rule=" << alert.rule_id <<
                    " severity="        << to_string(alert.severity) <<
                    " desc="            << alert.description);
                if (g_publisher) {
                    g_publisher->publish(alert);
                    if (g_publisher->dropped_count() > 0)
                        LOG_ERR("PUBLISHER", "queue full — total dropped: "
                                << g_publisher->dropped_count());
                }
            },
            g_node_id
        );
        try {
            g_suricata_adapter->start();
            g_ids_mode = "suricata";
            LOG_INFO("CONFIG", "SuricataAdapter started on " << g_eve_json_path);
        } catch (const std::exception& e) {
            g_suricata_adapter.reset();
            write_yaml_field(g_cfg_path, "ids_mode", "builtin");
            LOG_ERR("CONFIG", "SuricataAdapter start failed: " << e.what());
            return std::string("suricata start failed: ") + e.what();
        }

    } else {
        // builtin

        g_watch_file = g_watch_file;

        RuleConfig cfg = RuleConfig::from_yaml(g_cfg_path);
        g_engine = std::make_unique<RuleEngine>(cfg);

        g_tailer = std::make_unique<LogTailer>(g_watch_file, [](std::string_view line) {
            g_lines_seen.fetch_add(1, std::memory_order_relaxed);
            LOG_INFO("TAILER", "raw line: " << line);

            auto ev = g_parser.parse(line);
            if (!ev) {
                g_parse_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_ERR("PARSER", "failed to parse: " << line);
                return;
            }

            ev->source_host = g_node_id;
            g_lines_parsed.fetch_add(1, std::memory_order_relaxed);

            std::lock_guard<std::mutex> lk2(g_ids_swap_mtx);
            g_ring.push(*ev);

            if (!g_engine) return;
            auto snap   = g_ring.snapshot();
            auto alerts = g_engine->process(*ev, snap);

            for (auto& alert : alerts) {
                g_alerts_fired.fetch_add(1, std::memory_order_relaxed);
                alert.source_host = g_node_id;
                alert.alert_id    = g_node_id + "-" + alert.alert_id;
                LOG_INFO("RULES",
                    "ALERT FIRED rule=" << alert.rule_id <<
                    " severity="        << to_string(alert.severity) <<
                    " desc="            << alert.description);
                if (g_publisher) {
                    g_publisher->publish(alert);
                    if (g_publisher->dropped_count() > 0)
                        LOG_ERR("PUBLISHER", "queue full — total dropped: "
                                << g_publisher->dropped_count());
                }
            }
        });

        try {
            g_tailer->start();
            g_ids_mode = "builtin";
            LOG_INFO("CONFIG", "LogTailer started on " << g_watch_file);
        } catch (const std::exception& e) {
            g_tailer.reset();
            write_yaml_field(g_cfg_path, "ids_mode", "suricata");
            LOG_ERR("CONFIG", "LogTailer start failed: " << e.what());
            return std::string("builtin start failed: ") + e.what();
        }
    }

    return "ok";
}

// ── HTTP server: /status (GET) + /config (POST) on port 8081 ─────────────────
static void status_server_loop(const AlertPublisher& pub) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { LOG_ERR("STATUS", "socket() failed"); return; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(8081);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERR("STATUS", "bind() failed on port 8081");
        close(server_fd);
        return;
    }
    listen(server_fd, 8);
    LOG_INFO("STATUS", "agent HTTP server on port 8081  (GET /status  POST /config)");

    while (!g_stop.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        timeval tv{ 1, 0 };
        if (select(server_fd + 1, &fds, nullptr, nullptr, &tv) <= 0)
            continue;

        int client = accept(server_fd, nullptr, nullptr);
        if (client < 0) continue;

        // Read request
        char rbuf[4096] = {};
        int  rlen = recv(client, rbuf, sizeof(rbuf) - 1, 0);
        std::string request(rbuf, rlen > 0 ? rlen : 0);

        // ── CORS preflight ────────────────────────────────────────────────────
        if (request.rfind("OPTIONS", 0) == 0) {
            std::string pre =
                "HTTP/1.1 204 No Content\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n";
            send(client, pre.data(), pre.size(), 0);
            close(client);
            continue;
        }

        std::string body;
        int status_code = 200;

        // ── POST /config — IDS mode hot-swap ─────────────────────────────────
        if (request.rfind("POST /config", 0) == 0) {
            // Extract JSON body (everything after the blank line)
            auto sep = request.find("\r\n\r\n");
            std::string json_body = (sep != std::string::npos)
                                    ? request.substr(sep + 4) : "";

            // Very small manual parse: look for "ids_mode":"<value>"
            std::string new_mode;
            auto pos = json_body.find("\"ids_mode\"");
            if (pos != std::string::npos) {
                auto colon = json_body.find(':', pos);
                if (colon != std::string::npos) {
                    auto q1 = json_body.find('"', colon + 1);
                    auto q2 = (q1 != std::string::npos)
                              ? json_body.find('"', q1 + 1)
                              : std::string::npos;
                    if (q2 != std::string::npos)
                        new_mode = json_body.substr(q1 + 1, q2 - q1 - 1);
                }
            }

            if (new_mode.empty()) {
                body        = "{\"error\":\"missing ids_mode field\"}";
                status_code = 400;
            } else {
                std::string result = do_ids_swap(new_mode);
                if (result == "ok" || result.rfind("already", 0) == 0) {
                    body = "{\"ok\":true,\"ids_mode\":\"" + g_ids_mode + "\"}";
                } else {
                    body        = "{\"ok\":false,\"error\":\"" + result + "\"}";
                    status_code = 500;
                }
            }

        // ── GET /status ───────────────────────────────────────────────────────
        } else {
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - g_start_time).count();

            bool zmq_ok = pub.sent_count() > 0 || pub.dropped_count() == 0;

            body =
                "{\"node_id\":\""       + g_node_id        + "\","
                "\"watch_file\":\""     + g_watch_file      + "\","
                "\"coordinator_ip\":\"" + g_coordinator_ip  + "\","
                "\"ids_mode\":\""       + g_ids_mode        + "\","
                "\"eve_json_path\":\""  + g_eve_json_path   + "\","
                "\"uptime_sec\":"       + std::to_string(uptime) + ","
                "\"zmq_connected\":"    + (zmq_ok ? "true" : "false") + ","
                "\"alerts_fired\":"     + std::to_string(g_alerts_fired.load()) + ","
                "\"zmq_sent\":"         + std::to_string(pub.sent_count()) + "}";
        }

        std::string response =
            "HTTP/1.1 " + std::to_string(status_code) + " OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "Connection: close\r\n\r\n" + body;

        send(client, response.data(), response.size(), 0);
        close(client);
    }
    close(server_fd);
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::string cfg_path       = (argc > 1) ? argv[1] : "config/agent.yaml";
    std::string watch          = (argc > 2) ? argv[2] : "/var/log/auth.log";
    std::string alert_endpoint = (argc > 3) ? argv[3] : "tcp://127.0.0.1:5555";
    std::string node_id        = (argc > 4) ? argv[4] : "agent-01";
    std::string coordinator_ip = (argc > 5) ? argv[5] : "127.0.0.1";

    g_start_time      = std::chrono::steady_clock::now();
    g_node_id         = node_id;
    g_watch_file      = watch;
    g_coordinator_ip  = coordinator_ip;
    g_cfg_path        = cfg_path;

    LOG_INFO("INIT", "dlads agent starting");
    LOG_INFO("INIT", "node_id        = " << node_id);
    LOG_INFO("INIT", "config         = " << cfg_path);
    LOG_INFO("INIT", "watching       = " << watch);
    LOG_INFO("INIT", "alert_endpoint = " << alert_endpoint);
    LOG_INFO("INIT", "coordinator    = " << coordinator_ip);

    // ── Load config ───────────────────────────────────────────────────────────
    RuleConfig cfg = RuleConfig::from_yaml(cfg_path);

    std::string ids_mode      = read_yaml_field(cfg_path, "ids_mode",     "builtin");
    std::string eve_json_path = read_yaml_field(cfg_path, "eve_json_path",
                                                "/var/log/suricata/eve.json");

    if (ids_mode != "suricata") ids_mode = "builtin";

    g_ids_mode      = ids_mode;
    g_eve_json_path = eve_json_path;
    g_engine        = std::make_unique<RuleEngine>(cfg);

    LOG_INFO("INIT", "ids_mode       = " << ids_mode);
    if (ids_mode == "suricata")
        LOG_INFO("INIT", "eve_json_path  = " << eve_json_path);

    // ── Publisher ─────────────────────────────────────────────────────────────
    AlertPublisher publisher(alert_endpoint);
    g_publisher = &publisher;

    try {
        publisher.start();
        LOG_INFO("PUBLISHER", "ZMQ PUB started → " << alert_endpoint);
    } catch (const std::exception& e) {
        LOG_ERR("PUBLISHER", "failed: " << e.what());
        return 1;
    }

    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    // ── Start IDS (initial mode from yaml) ────────────────────────────────────
    if (ids_mode == "suricata") {
        if (!file_exists(eve_json_path)) {
            LOG_ERR("IDS", "eve.json not found at: " << eve_json_path
                    << " — falling back to builtin");
            write_yaml_field(cfg_path, "ids_mode", "builtin");
            g_ids_mode = "builtin (fallback — eve.json missing)";
            ids_mode   = "builtin";
        } else {
            g_suricata_adapter = std::make_unique<SuricataAdapter>(
                eve_json_path,
                [](AlertEvent alert) {
                    g_alerts_fired.fetch_add(1, std::memory_order_relaxed);
                    alert.source_host = g_node_id;
                    alert.alert_id    = g_node_id + "-" + alert.alert_id;
                    LOG_INFO("SURICATA",
                        "ALERT FIRED rule=" << alert.rule_id <<
                        " severity="        << to_string(alert.severity) <<
                        " desc="            << alert.description);
                    if (g_publisher) {
                        g_publisher->publish(alert);
                        if (g_publisher->dropped_count() > 0)
                            LOG_ERR("PUBLISHER", "queue full — total dropped: "
                                    << g_publisher->dropped_count());
                    }
                },
                node_id
            );
            try {
                g_suricata_adapter->start();
                LOG_INFO("IDS", "SuricataAdapter started, watching " << eve_json_path);
            } catch (const std::exception& e) {
                LOG_ERR("IDS", "SuricataAdapter start failed: " << e.what());
                publisher.stop();
                return 1;
            }
        }
    }

    if (ids_mode == "builtin") {
        LOG_INFO("IDS", "Built-in rule engine mode: watching " << watch);

        g_tailer = std::make_unique<LogTailer>(watch, [](std::string_view line) {
            g_lines_seen.fetch_add(1, std::memory_order_relaxed);
            LOG_INFO("TAILER", "raw line: " << line);

            auto ev = g_parser.parse(line);
            if (!ev) {
                g_parse_failures.fetch_add(1, std::memory_order_relaxed);
                LOG_ERR("PARSER", "failed to parse: " << line);
                return;
            }

            ev->source_host = g_node_id;
            g_lines_parsed.fetch_add(1, std::memory_order_relaxed);

            std::lock_guard<std::mutex> lk(g_ids_swap_mtx);
            g_ring.push(*ev);

            if (!g_engine) return;
            auto snap   = g_ring.snapshot();
            auto alerts = g_engine->process(*ev, snap);

            if (alerts.empty()) { LOG_INFO("RULES", "no rules fired"); return; }

            for (auto& alert : alerts) {
                g_alerts_fired.fetch_add(1, std::memory_order_relaxed);
                alert.source_host = g_node_id;
                alert.alert_id    = g_node_id + "-" + alert.alert_id;
                LOG_INFO("RULES",
                    "ALERT FIRED rule=" << alert.rule_id <<
                    " severity="        << to_string(alert.severity) <<
                    " desc="            << alert.description);
                if (g_publisher) {
                    g_publisher->publish(alert);
                    if (g_publisher->dropped_count() > 0)
                        LOG_ERR("PUBLISHER", "queue full — total dropped: "
                                << g_publisher->dropped_count());
                }
            }
        });

        try {
            g_tailer->start();
            LOG_INFO("TAILER", "watching " << watch);
        } catch (const std::exception& e) {
            LOG_ERR("TAILER", "failed: " << e.what());
            publisher.stop();
            return 1;
        }
    }

    // ── Background threads ────────────────────────────────────────────────────
    std::thread stats_thread(stats_loop, std::cref(publisher));
    std::thread hb_thread(heartbeat_loop,
                          node_id, coordinator_ip, std::cref(publisher));
    std::thread status_thread(status_server_loop, std::cref(publisher));

    LOG_INFO("INIT", "all systems running — Ctrl+C to stop");
    LOG_INFO("INIT", "IDS mode: " << g_ids_mode);
    LOG_INFO("INIT", "dashboard can hot-swap via POST http://localhost:8081/config");

    while (!g_stop.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

    LOG_INFO("INIT", "shutdown signal received");
    g_stop.store(true);

    {
        std::lock_guard<std::mutex> lk(g_ids_swap_mtx);
        if (g_suricata_adapter) g_suricata_adapter->stop();
        if (g_tailer)           g_tailer->stop();
    }

    hb_thread.join();
    stats_thread.join();
    status_thread.join();

    g_publisher = nullptr;
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