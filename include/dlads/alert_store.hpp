#pragma once

#include "dlads/alert_event.hpp"
#include "dlads/correlation_engine.hpp"
#include <sqlite3.h>
#include <mutex>
#include <vector>
#include <string>
#include <stdexcept>

namespace dlads {

class AlertStore {
public:
    explicit AlertStore(const std::string& db_path = "alerts.db") {
        if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK)
            throw std::runtime_error("Cannot open SQLite db: " + db_path);
        create_tables();
    }

    ~AlertStore() {
        if (db_) sqlite3_close(db_);
    }

    // Save a raw alert from an agent
    void save_alert(const AlertEvent& alert) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string source_ip = alert.source_host;
        if (alert.metadata.count("source_ip"))
            source_ip = alert.metadata.at("source_ip");

        const char* sql =
            "INSERT OR IGNORE INTO alerts "
            "(id, source_ip, source_host, rule_id, severity, anomaly_score, description, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?);";

        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, alert.alert_id.c_str(),    -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, source_ip.c_str(),         -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, alert.source_host.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, alert.rule_id.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, to_string(alert.severity), -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt, 6, alert.anomaly_score);
        sqlite3_bind_text(stmt, 7, alert.description.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 8,
            std::chrono::duration_cast<std::chrono::seconds>(
                alert.timestamp.time_since_epoch()).count());
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // Keep in-memory cache
        recent_alerts_.push_back(alert);
        if (recent_alerts_.size() > 100)
            recent_alerts_.erase(recent_alerts_.begin());
    }

    // Save a correlated threat
    void save_threat(const CorrelatedThreat& threat) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string nodes;
        for (const auto& n : threat.confirmed_by_nodes)
            nodes += n + ",";

        const char* sql =
            "INSERT OR IGNORE INTO threats "
            "(id, source_ip, rule_id, severity, confirmed_by, evidence, timestamp) "
            "VALUES (?,?,?,?,?,?,?);";

        sqlite3_stmt* stmt;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, threat.threat_id.c_str(),  -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, threat.source_ip.c_str(),  -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, threat.rule_id.c_str(),    -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, to_string(threat.severity),-1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, nodes.c_str(),             -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, threat.evidence.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 7,
            std::chrono::duration_cast<std::chrono::seconds>(
                threat.timestamp.time_since_epoch()).count());
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        recent_threats_.push_back(threat);
        if (recent_threats_.size() > 50)
            recent_threats_.erase(recent_threats_.begin());
    }

    // REST API reads these
    std::vector<AlertEvent>      get_recent_alerts()  { std::lock_guard<std::mutex> l(mutex_); return recent_alerts_; }
    std::vector<CorrelatedThreat> get_recent_threats() { std::lock_guard<std::mutex> l(mutex_); return recent_threats_; }

    int alert_count()  { std::lock_guard<std::mutex> l(mutex_); return (int)recent_alerts_.size(); }
    int threat_count() { std::lock_guard<std::mutex> l(mutex_); return (int)recent_threats_.size(); }

private:
    void create_tables() {
        const char* sql =
            "CREATE TABLE IF NOT EXISTS alerts ("
            "  id TEXT PRIMARY KEY,"
            "  source_ip TEXT,"
            "  source_host TEXT,"
            "  rule_id TEXT,"
            "  severity TEXT,"
            "  anomaly_score REAL,"
            "  description TEXT,"
            "  timestamp INTEGER"
            ");"
            "CREATE TABLE IF NOT EXISTS threats ("
            "  id TEXT PRIMARY KEY,"
            "  source_ip TEXT,"
            "  rule_id TEXT,"
            "  severity TEXT,"
            "  confirmed_by TEXT,"
            "  evidence TEXT,"
            "  timestamp INTEGER"
            ");";
        char* err = nullptr;
        sqlite3_exec(db_, sql, nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
    }

    sqlite3*                      db_ = nullptr;
    std::mutex                    mutex_;
    std::vector<AlertEvent>       recent_alerts_;
    std::vector<CorrelatedThreat> recent_threats_;
};

} // namespace dlads