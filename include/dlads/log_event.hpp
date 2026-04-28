#pragma once

#include <chrono>
#include <string>
#include <unordered_map>

namespace dlads {

// ── Log level ─────────────────────────────────────────────────────────────────

enum class LogLevel : uint8_t {
    UNKNOWN  = 0,
    DEBUG    = 1,
    INFO     = 2,
    NOTICE   = 3,
    WARN     = 4,
    ERROR    = 5,
    CRITICAL = 6,
    ALERT    = 7,
    EMERG    = 8,
};

inline const char* to_string(LogLevel l) noexcept {
    switch (l) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO";
        case LogLevel::NOTICE:   return "NOTICE";
        case LogLevel::WARN:     return "WARN";
        case LogLevel::ERROR:    return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        case LogLevel::ALERT:    return "ALERT";
        case LogLevel::EMERG:    return "EMERG";
        default:                 return "UNKNOWN";
    }
}

// ── LogFormat ─────────────────────────────────────────────────────────────────

enum class LogFormat : uint8_t {
    UNKNOWN   = 0,
    SYSLOG    = 1,   // RFC 3164: "Mon DD HH:MM:SS host proc[pid]: msg"
    KV_PAIRS  = 2,   // key=value ... (nginx error, fail2ban, custom apps)
};

// ── LogEvent ──────────────────────────────────────────────────────────────────

/**
 * A single structured log event produced by LogParser.
 *
 * All string fields are owned copies — no string_view borrows into a
 * transient buffer.  The `fields` map carries format-specific extracted
 * keys (pid, ip, port, …) so downstream rules never have to re-parse
 * the raw line.
 */
struct LogEvent {
    // Wall-clock time the event was emitted.  If the log line carries no
    // parseable timestamp this is set to the time parse() was called.
    std::chrono::system_clock::time_point timestamp;

    // Hostname field from the log line, or empty string if absent.
    std::string source_host;

    // Process / subsystem name: "sshd", "kernel", "nginx", …
    std::string log_source;

    // Numeric PID extracted from "proc[pid]:", or 0 if not present.
    int pid{ 0 };

    LogLevel  level{ LogLevel::UNKNOWN };
    LogFormat format{ LogFormat::UNKNOWN };

    // The complete original line, unmodified.
    std::string raw_line;

    // The message body (everything after "proc[pid]: ").
    std::string message;

    // Format-specific key=value pairs extracted from the message.
    // Examples: {"src_ip","192.168.1.1"}, {"port","22"}, {"user","root"}
    std::unordered_map<std::string, std::string> fields;
};

}  // namespace dlads