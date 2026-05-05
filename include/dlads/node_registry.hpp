#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace dlads {

enum class NodeStatus { ALIVE, DEAD };

struct NodeInfo {
    std::string node_id;
    std::string host_ip;
    NodeStatus  status        = NodeStatus::ALIVE;
    int64_t     last_seen_sec = 0;
    int64_t     first_seen_sec = 0;
    int         alerts_sent   = 0;
};

class NodeRegistry {
public:
    explicit NodeRegistry(int dead_threshold_sec = 30)
        : dead_threshold_(dead_threshold_sec) {}

    // Called when a heartbeat ping arrives from a node
    void ping(const std::string& node_id, const std::string& host_ip = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = now_sec();
        auto it  = nodes_.find(node_id);
        if (it == nodes_.end()) {
            NodeInfo info;
            info.node_id        = node_id;
            info.host_ip        = host_ip;
            info.last_seen_sec  = now;
            info.first_seen_sec = now;
            info.status         = NodeStatus::ALIVE;
            nodes_[node_id]     = info;
            return;
        }
        it->second.last_seen_sec = now;
        it->second.status        = NodeStatus::ALIVE;
        if (!host_ip.empty())
            it->second.host_ip = host_ip;
    }

    // Called when an alert arrives — also counts alert activity per node
    void record_alert(const std::string& node_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (nodes_.count(node_id))
            nodes_[node_id].alerts_sent++;
    }

    // Called by watchdog thread — marks stale nodes as DEAD
    void check_dead_nodes() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = now_sec();
        for (auto& [id, info] : nodes_) {
            if (info.status == NodeStatus::ALIVE &&
                (now - info.last_seen_sec) > dead_threshold_) {
                info.status = NodeStatus::DEAD;
            }
        }
    }

    // Returns copy of all node info for REST API and dashboard
    std::vector<NodeInfo> all_nodes() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<NodeInfo> result;
        for (const auto& [id, info] : nodes_)
            result.push_back(info);
        return result;
    }

    int alive_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        int count = 0;
        for (const auto& [id, info] : nodes_)
            if (info.status == NodeStatus::ALIVE) count++;
        return count;
    }

private:
    static int64_t now_sec() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    int dead_threshold_;
    std::mutex mutex_;
    std::map<std::string, NodeInfo> nodes_;
};

} // namespace dlads