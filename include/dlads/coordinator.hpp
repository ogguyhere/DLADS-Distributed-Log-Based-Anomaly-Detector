#pragma once

#include "dlads/alert_event.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cmath>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace dlads {

// ── Threat (correlated alert group) ──────────────────────────────────────────
struct Threat {
    std::string threat_id;
    std::string source_ip;
    std::string rule_id;
    std::string severity;
    std::string evidence;
};

// ── Node registry entry ───────────────────────────────────────────────────────
struct NodeInfo {
    std::string node_id;
    std::string host_ip;
    std::string status;   // "ALIVE" / "DEAD"
    int         alerts_sent{ 0 };
    int64_t     last_seen{ 0 };  // unix seconds
};

// ─────────────────────────────────────────────────────────────────────────────
// Coordinator
//
// Single in-memory source of truth for the demo.
//
// Partner A calls:  ingestAlert(AlertEvent)
// Dashboard calls:  getStatsJson(), getNodesJson(),
//                   getAlertsJson(), getThreatsJson()
// Partner B thread: runs inside start() — reads from internal queue,
//                   performs Z-score + correlation, writes threats back.
// HTTP server:      tiny blocking server on port 8080, serves the four
//                   endpoints the dashboard already polls.
// ─────────────────────────────────────────────────────────────────────────────
class Coordinator {
public:
    Coordinator();
    ~Coordinator();

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    void start();   // launches analytics + HTTP threads
    void stop();

    // ── Partner A interface ───────────────────────────────────────────────────
    // Thread-safe. Called directly from the detection pipeline.
    void ingestAlert(const AlertEvent& ev);

    // ── Node registration (called by each simulated agent) ───────────────────
    void registerNode(const std::string& node_id,
                      const std::string& host_ip);
    void nodeHeartbeat(const std::string& node_id);

    // ── Dashboard / REST interface ────────────────────────────────────────────
    std::string getStatsJson()   const;
    std::string getNodesJson()   const;
    std::string getAlertsJson()  const;
    std::string getThreatsJson() const;

private:
    // ── Analytics (Partner B) ─────────────────────────────────────────────────
    void analytics_loop();   // Z-score + correlation thread
    void run_zscore(const AlertEvent& ev);
    void run_correlation();

    // ── Tiny HTTP server ──────────────────────────────────────────────────────
    void http_loop();
    void handle_client(int fd);

    // ── Internal state (all guarded by mtx_) ─────────────────────────────────
    mutable std::mutex mtx_;

    std::vector<AlertEvent>  alerts_;      // all ingested alerts, newest last
    std::vector<Threat>      threats_;     // correlated threats
    std::vector<NodeInfo>    nodes_;

    // Queue for analytics thread
    std::deque<AlertEvent>   queue_;
    std::condition_variable  cv_;

    // Z-score state: per-rule event-rate window (events per minute)
    struct ZState {
        std::deque<std::chrono::system_clock::time_point> times;
        double mean{ 0 }, m2{ 0 };
        int    n{ 0 };
    };
    std::unordered_map<std::string, ZState> zstate_;

    // Correlation: per-source-ip seen rules in last 5 minutes
    struct CorrelState {
        std::deque<std::pair<std::chrono::system_clock::time_point,
                             std::string>> rule_hits;  // (time, rule_id)
    };
    std::unordered_map<std::string, CorrelState> correl_;

    // Threat dedup: source_ip -> last threat time
    std::unordered_map<std::string,
        std::chrono::system_clock::time_point> threat_cooldown_;

    // ── Threads ───────────────────────────────────────────────────────────────
    std::thread analytics_thread_;
    std::thread http_thread_;
    std::atomic<bool> stop_{ false };

    int http_port_{ 8080 };
};

}  // namespace dlads