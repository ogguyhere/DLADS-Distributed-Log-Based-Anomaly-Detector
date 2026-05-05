#pragma once

#include <chrono>
#include <string>
#include <nlohmann/json.hpp>

namespace dlads {

// Lightweight ping sent by each agent every 10 seconds
struct HeartbeatMessage {
    std::string node_id;
    int64_t     timestamp;
    int         alerts_sent;    // how many alerts this node has published
    std::string status;         // "ALIVE" always from agent side

    std::string toJSON() const {
        nlohmann::json j;
        j["type"]        = "heartbeat";
        j["node_id"]     = node_id;
        j["timestamp"]   = timestamp;
        j["alerts_sent"] = alerts_sent;
        j["status"]      = status;
        return j.dump();
    }

    static std::optional<HeartbeatMessage> fromJSON(std::string_view raw) {
        try {
            auto j = nlohmann::json::parse(raw);
            if (!j.contains("type") || j["type"] != "heartbeat")
                return std::nullopt;
            HeartbeatMessage hb;
            hb.node_id     = j["node_id"].get<std::string>();
            hb.timestamp   = j["timestamp"].get<int64_t>();
            hb.alerts_sent = j.value("alerts_sent", 0);
            hb.status      = j.value("status", "ALIVE");
            return hb;
        } catch (...) {
            return std::nullopt;
        }
    }
};

// Node status as seen by the coordinator
enum class NodeStatus { ALIVE, DEGRADED, DEAD };

inline const char* to_string(NodeStatus s) {
    switch (s) {
        case NodeStatus::ALIVE:    return "ALIVE";
        case NodeStatus::DEGRADED: return "DEGRADED";
        case NodeStatus::DEAD:     return "DEAD";
        default:                   return "UNKNOWN";
    }
}

struct NodeInfo {
    std::string node_id;
    int64_t     last_seen      = 0;
    int         alerts_sent    = 0;
    NodeStatus  status         = NodeStatus::DEAD;
};

} // namespace dlads