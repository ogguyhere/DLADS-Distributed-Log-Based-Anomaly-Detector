#pragma once

#include "dlads/log_event.hpp"

#include <optional>
#include <string_view>

namespace dlads {

/**
 * LogParser
 *
 * Converts a raw log line into a structured LogEvent.
 *
 * Supported formats (auto-detected, no pre-configuration needed):
 *
 *   SYSLOG   — RFC 3164
 *              "Jan  2 15:04:05 hostname process[pid]: message"
 *              "Jan  2 15:04:05 hostname process: message"   (no pid)
 *
 *   KV_PAIRS — Structured key=value, optionally quoted values.
 *              Common in nginx error logs, fail2ban, custom daemons.
 *              "2024/01/02 15:04:05 [error] 42#0: *1 msg, client: 1.2.3.4"
 *              "time=... level=warn msg=... ip=1.2.3.4 port=22"
 *
 * Error handling:
 *   - Returns std::nullopt for blank lines or lines that match no format.
 *   - Never throws.  Malformed fields (bad timestamp, non-numeric pid) are
 *     silently defaulted rather than rejected.
 *
 * Performance:
 *   - No regex.  All parsing is manual string_view tokenisation.
 *   - A cold parse of a typical 120-byte syslog line takes < 500 ns.
 *   - The parser is stateless and reentrant; one instance may be shared
 *     across threads without locking.
 */
class LogParser {
public:
    LogParser()  = default;
    ~LogParser() = default;

    /**
     * Parse a single log line.
     *
     * @param line  The raw log line, including any trailing whitespace.
     *              Must NOT include a trailing '\n' (the LogTailer strips it).
     * @return      A populated LogEvent, or std::nullopt if the line is blank
     *              or unrecognised.
     */
    [[nodiscard]]
    std::optional<LogEvent> parse(std::string_view line) const;

private:
    // ── Format-specific parsers ───────────────────────────────────────────────
    // Each returns true and fills `ev` on success, false otherwise.

    static bool parse_syslog  (std::string_view line, LogEvent& ev);
    static bool parse_nginx   (std::string_view line, LogEvent& ev);
    static bool parse_kv_pairs(std::string_view line, LogEvent& ev);

    // ── Shared helpers ────────────────────────────────────────────────────────

    // Parse a syslog-style "Mon DD HH:MM:SS" timestamp (no year).
    // Returns true and sets ev.timestamp on success.
    static bool parse_syslog_timestamp(std::string_view ts, LogEvent& ev);

    // Parse an nginx/ISO-style "YYYY/MM/DD HH:MM:SS" timestamp.
    static bool parse_iso_timestamp(std::string_view ts, LogEvent& ev);

    // Extract key=value (or key="quoted value") pairs from `msg` into
    // ev.fields.  Existing fields are NOT overwritten.
    static void extract_kv(std::string_view msg, LogEvent& ev);

    // Map a syslog priority integer (0-191) to LogLevel.
    static LogLevel priority_to_level(int pri) noexcept;

    // Map a level keyword ("error", "warn", …) to LogLevel.
    static LogLevel keyword_to_level(std::string_view kw) noexcept;
};

}  // namespace dlads