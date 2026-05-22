#include "dlads/alert_event.hpp"
#include "dlads/correlation_engine.hpp"
#include "dlads/alert_store.hpp"
#include "dlads/node_registry.hpp"
#include "httplib.h"
#include <ctime>
#include <zmq.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>

// ── ZMQ Alert Receiver ────────────────────────────────────────────────────────
void zmq_alert_receiver(
    dlads::CorrelationEngine &engine,
    dlads::AlertStore &store,
    dlads::NodeRegistry &registry)
{
    zmq::context_t ctx(1);
    zmq::socket_t sub(ctx, zmq::socket_type::sub);
    sub.bind("tcp://*:5555");
    sub.set(zmq::sockopt::subscribe, "");

    std::cout << "[coordinator] alert receiver bound to port 5555\n";

    while (true)
    {
        zmq::message_t msg;
        auto result = sub.recv(msg, zmq::recv_flags::none);
        if (!result)
            continue;

        std::string_view raw(static_cast<char *>(msg.data()), msg.size());
        auto alert_opt = dlads::deserialize(raw);

        if (!alert_opt.has_value())
        {
            std::cerr << "[warn] bad alert received, skipping\n";
            continue;
        }

        const auto &alert = alert_opt.value();

        // Update node registry
        registry.ping(alert.source_host);
        registry.record_alert(alert.source_host);

        // Persist raw alert
        store.save_alert(alert);

        std::cout << "[alert] from=" << alert.source_host
                  << " rule=" << alert.rule_id
                  << " severity=" << dlads::to_string(alert.severity)
                  << "\n";

        // Correlate
        auto threat_opt = engine.ingest(alert);
        if (threat_opt.has_value())
        {
            const auto &threat = threat_opt.value();
            store.save_threat(threat);

            std::cout << "\n[CORRELATED THREAT DETECTED]"
                      << "\n  id:       " << threat.threat_id
                      << "\n  ip:       " << threat.source_ip
                      << "\n  rule:     " << threat.rule_id
                      << "\n  severity: " << dlads::to_string(threat.severity)
                      << "\n  evidence: " << threat.evidence
                      << "\n  nodes:    ";
            for (const auto &n : threat.confirmed_by_nodes)
                std::cout << n << " ";
            std::cout << "\n\n";
        }
    }
}

// ── ZMQ Heartbeat Receiver ────────────────────────────────────────────────────
// Agents send a tiny ping JSON every 10 seconds on port 5556
// {"node_id":"node-1","host_ip":"192.168.1.10","uptime_sec":120}
// void zmq_heartbeat_receiver(dlads::NodeRegistry& registry) {
//     zmq::context_t ctx(1);
//     zmq::socket_t  pull(ctx, zmq::socket_type::pull);
//     pull.bind("tcp://*:5556");

//     std::cout << "[coordinator] heartbeat receiver bound to port 5556\n";

//     while (true) {
//         zmq::message_t msg;
//         auto result = pull.recv(msg, zmq::recv_flags::none);
//         if (!result) continue;

//         std::string raw(static_cast<char*>(msg.data()), msg.size());

//         // Parse minimal ping JSON manually — no heavy deps needed
//         // Expected: {"node_id":"...","host_ip":"..."}
//         auto extract = [&](const std::string& key) -> std::string {
//             std::string search = "\"" + key + "\":\"";
//             auto pos = raw.find(search);
//             if (pos == std::string::npos) return "";
//             pos += search.size();
//             auto end = raw.find("\"", pos);
//             if (end == std::string::npos) return "";
//             return raw.substr(pos, end - pos);
//         };

//         std::string node_id = extract("node_id");
//         std::string host_ip = extract("host_ip");

//         if (!node_id.empty()) {
//             registry.ping(node_id, host_ip);
//             std::cout << "[heartbeat] node=" << node_id
//                       << " ip=" << host_ip << "\n";
//         }
//     }
// }

void zmq_heartbeat_receiver(dlads::NodeRegistry &registry)
{
    zmq::context_t ctx(1);
    zmq::socket_t pull(ctx, zmq::socket_type::pull);

    // Use PULL bind — agents connect TO us
    pull.bind("tcp://*:5556");
    std::cout << "[coordinator] heartbeat receiver bound to port 5556\n";

    while (true)
    {
        zmq::message_t msg;
        zmq::recv_result_t result = pull.recv(msg, zmq::recv_flags::none);
        if (!result)
            continue;

        std::string raw(static_cast<char *>(msg.data()), msg.size());
        std::cout << "[heartbeat raw] " << raw << "\n";

        // auto extract = [&](const std::string& key) -> std::string {
        //     std::string search = "\"" + key + "\":\"";
        //     auto pos = raw.find(search);
        //     if (pos == std::string::npos) return "";
        //     pos += search.size();
        //     auto end = raw.find("\"", pos);
        //     if (end == std::string::npos) return "";
        //     return raw.substr(pos, end - pos);
        // };

        auto extract = [&](const std::string &key) -> std::string
        {
            // Try with space after colon first, then without
            for (const auto &sep : {"\": \"", "\":\""})
            {
                std::string search = "\"" + key + sep;
                auto pos = raw.find(search);
                if (pos == std::string::npos)
                    continue;
                pos += search.size();
                auto end = raw.find("\"", pos);
                if (end == std::string::npos)
                    continue;
                return raw.substr(pos, end - pos);
            }
            return "";
        };

        std::string node_id = extract("node_id");
        std::string host_ip = extract("host_ip");

        if (!node_id.empty())
        {
            registry.ping(node_id, host_ip);
            std::cout << "[heartbeat] node=" << node_id
                      << " ip=" << host_ip << "\n";
        }
        else
        {
            std::cerr << "[heartbeat warn] could not extract node_id from: "
                      << raw << "\n";
        }
    }
}

// ── Watchdog Thread ───────────────────────────────────────────────────────────
// Checks every 10 seconds if any node has gone silent
// void watchdog(dlads::NodeRegistry& registry) {
//     while (true) {
//         std::this_thread::sleep_for(std::chrono::seconds(10));
//         registry.check_dead_nodes();

//         auto nodes = registry.all_nodes();
//         for (const auto& n : nodes) {
//             if (n.status == dlads::NodeStatus::DEAD) {
//                 std::cout << "[DEAD NODE DETECTED] node=" << n.node_id
//                           << " last_seen=" << n.last_seen_sec << "\n";
//             }
//         }
//     }
// }

void watchdog(dlads::NodeRegistry &registry)
{
    // Track which nodes we have already reported as dead
    std::map<std::string, bool> reported_dead;

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        registry.check_dead_nodes();

        auto nodes = registry.all_nodes();
        for (const auto &n : nodes)
        {
            if (n.status == dlads::NodeStatus::DEAD)
            {
                if (!reported_dead[n.node_id])
                {
                    std::cout << "[DEAD NODE DETECTED] node=" << n.node_id
                              << " last_seen=" << n.last_seen_sec << "\n";
                    reported_dead[n.node_id] = true;
                }
            }
            else
            {
                // Node came back alive — reset so we report if it dies again
                reported_dead[n.node_id] = false;
            }
        }
    }
}

// ── REST API ──────────────────────────────────────────────────────────────────
void rest_api(
    dlads::AlertStore &store,
    dlads::NodeRegistry &registry)
{
    httplib::Server svr;

    svr.Get("/alerts", [&](const httplib::Request &, httplib::Response &res)
            {
        auto alerts = store.get_recent_alerts();
        std::string json = "[";
        for (size_t i = 0; i < alerts.size(); i++) {
            json += dlads::serialize(alerts[i]);
            if (i + 1 < alerts.size()) json += ",";
        }
        json += "]";
        res.set_content(json, "application/json"); });

    svr.Get("/threats", [&](const httplib::Request &, httplib::Response &res)
            {
        auto threats = store.get_recent_threats();
        std::string json = "[";
        for (size_t i = 0; i < threats.size(); i++) {
            const auto& t = threats[i];
            json += "{\"threat_id\":\"" + t.threat_id + "\","
                  + "\"source_ip\":\""  + t.source_ip  + "\","
                  + "\"rule_id\":\""    + t.rule_id    + "\","
                  + "\"severity\":\""   + std::string(dlads::to_string(t.severity)) + "\","
                  + "\"evidence\":\""   + t.evidence   + "\"}";
            if (i + 1 < threats.size()) json += ",";
        }
        json += "]";
        res.set_content(json, "application/json"); });

    svr.Get("/nodes", [&](const httplib::Request &, httplib::Response &res)
            {
        auto nodes = registry.all_nodes();
        std::string json = "[";
        for (size_t i = 0; i < nodes.size(); i++) {
            const auto& n = nodes[i];
            json += "{\"node_id\":\""    + n.node_id + "\","
                  + "\"host_ip\":\""     + n.host_ip + "\","
                  + "\"status\":\""      + (n.status == dlads::NodeStatus::ALIVE ? "ALIVE" : "DEAD") + "\","
                  + "\"last_seen\":"     + std::to_string(n.last_seen_sec) + ","
                  + "\"alerts_sent\":"   + std::to_string(n.alerts_sent) + "}";
            if (i + 1 < nodes.size()) json += ",";
        }
        json += "]";
        res.set_content(json, "application/json"); });

    svr.Get("/stats", [&](const httplib::Request &, httplib::Response &res)
            {
        std::string json =
            "{\"total_alerts\":"  + std::to_string(store.alert_count())   +
            ",\"total_threats\":" + std::to_string(store.threat_count())  +
            ",\"active_nodes\":"  + std::to_string(registry.alive_count()) + "}";
        res.set_content(json, "application/json"); });

    svr.Get("/status", [&](const httplib::Request &, httplib::Response &res)
    {
        auto nodes = registry.all_nodes();
        std::string node_id    = nodes.empty() ? "unknown" : nodes[0].node_id;
        std::string host_ip    = nodes.empty() ? "" : nodes[0].host_ip;
        bool zmq_connected     = !nodes.empty() && nodes[0].status == dlads::NodeStatus::ALIVE;
        std::string json =
            "{\"node_id\":\"" + node_id + "\","
            + "\"watch_file\":\"\","
            + "\"coordinator_ip\":\"" + host_ip + "\","
            + "\"ids_mode\":\"builtin\","
            + "\"uptime_sec\":0,"
            + "\"zmq_connected\":" + (zmq_connected ? "true" : "false") + "}";
        res.set_content(json, "application/json");
    });

    svr.Get("/feed", [&](const httplib::Request &, httplib::Response &res)
    {
        auto alerts = store.get_recent_alerts();
        std::string json = "[";
        for (size_t i = 0; i < alerts.size(); i++) {
            const auto& a = alerts[i];
            // Convert chrono timestamp to ISO string
            auto tt  = std::chrono::system_clock::to_time_t(a.timestamp);
            char tsbuf[32];
            std::strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%dT%H:%M:%S", std::localtime(&tt));
            // Pull attacker IP from metadata if present
            std::string src_ip = a.source_host;
            auto it = a.metadata.find("src_ip");
            if (it != a.metadata.end()) src_ip = it->second;
            json += std::string("{\"timestamp\":\"") + tsbuf + "\","
                  + "\"raw_line\":\"" + a.source_host + " — " + a.description + "\","
                  + "\"stage\":\"alert\","
                  + "\"detail\":\"" + a.rule_id + "\","
                  + "\"severity\":\"" + std::string(dlads::to_string(a.severity)) + "\"}";
            if (i + 1 < alerts.size()) json += ",";
        }
        json += "]";
        res.set_content(json, "application/json");
    });

    std::cout << "[coordinator] REST API listening on port 8080\n";
    svr.listen("0.0.0.0", 8080);
}

// ── Main ──────────────────────────────────────────────────────────────────────
int main()
{
    std::cout << "[dlads] coordinator starting...\n";

    dlads::CorrelationEngine engine(120, 2);
    dlads::AlertStore store("alerts.db");
    dlads::NodeRegistry registry(30); // 30s dead threshold

    std::thread alert_thread(zmq_alert_receiver,
                             std::ref(engine),
                             std::ref(store),
                             std::ref(registry));

    std::thread heartbeat_thread(zmq_heartbeat_receiver,
                                 std::ref(registry));

    std::thread watchdog_thread(watchdog,
                                std::ref(registry));

    std::thread api_thread(rest_api,
                           std::ref(store),
                           std::ref(registry));

    alert_thread.join();
    heartbeat_thread.join();
    watchdog_thread.join();
    api_thread.join();

    return 0;
}
