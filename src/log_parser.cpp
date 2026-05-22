#include "dlads/log_parser.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstring>
#include <ctime>

namespace dlads {

// ─────────────────────────────────────────────────────────────────────────────
// Internal utilities
// ─────────────────────────────────────────────────────────────────────────────

namespace {

// Trim leading whitespace (string_view, no allocation).
std::string_view ltrim(std::string_view s) noexcept {
    auto it = std::find_if(s.begin(), s.end(),
                           [](unsigned char c){ return !std::isspace(c); });
    return s.substr(static_cast<std::size_t>(it - s.begin()));
}

// Trim trailing whitespace.
std::string_view rtrim(std::string_view s) noexcept {
    auto it = std::find_if(s.rbegin(), s.rend(),
                           [](unsigned char c){ return !std::isspace(c); });
    return s.substr(0, static_cast<std::size_t>(s.rend() - it));
}

std::string_view trim(std::string_view s) noexcept {
    return rtrim(ltrim(s));
}

// Lowercase a single ASCII character.
inline char ascii_lower(char c) noexcept {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

// Case-insensitive equality for short strings (no locale).
bool iequal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
    return true;
}

// Parse a non-negative integer from sv using from_chars.
// Returns -1 on failure.
int parse_int(std::string_view sv) noexcept {
    sv = trim(sv);
    int v = 0;
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), v);
    return (ec == std::errc{} && v >= 0) ? v : -1;
}

// Current calendar year (used to fill in the year syslog RFC3164 omits).
int current_year() noexcept {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    return tm.tm_year + 1900;
}

// Three-letter month abbreviation → 0-based month index.
// Returns -1 on failure.
int month_from_abbr(std::string_view abbr) noexcept {
    static constexpr std::array<const char*, 12> months = {
        "jan","feb","mar","apr","may","jun",
        "jul","aug","sep","oct","nov","dec"
    };
    if (abbr.size() != 3) return -1;
    char lo[3] = { ascii_lower(abbr[0]),
                   ascii_lower(abbr[1]),
                   ascii_lower(abbr[2]) };
    for (int i = 0; i < 12; ++i)
        if (lo[0]==months[i][0] && lo[1]==months[i][1] && lo[2]==months[i][2])
            return i;
    return -1;
}

// Build a system_clock::time_point from broken-down UTC components.
// Returns the epoch on failure.
std::chrono::system_clock::time_point
make_timepoint(int year, int mon0, int mday,
               int hour, int min, int sec) noexcept {
    std::tm tm{};
    tm.tm_year = year - 1900;
    tm.tm_mon  = mon0;
    tm.tm_mday = mday;
    tm.tm_hour = hour;
    tm.tm_min  = min;
    tm.tm_sec  = sec;
    tm.tm_isdst = 0;
    std::time_t t = ::mktime(&tm);
    if (t == static_cast<std::time_t>(-1))
        return std::chrono::system_clock::time_point{};
    return std::chrono::system_clock::from_time_t(t);
}

// Split sv at the first occurrence of delim.
// Returns {before, after} where after does NOT include the delimiter.
// If delim is not found, after is empty.
std::pair<std::string_view, std::string_view>
split_once(std::string_view sv, char delim) noexcept {
    auto pos = sv.find(delim);
    if (pos == std::string_view::npos)
        return {sv, {}};
    return {sv.substr(0, pos), sv.substr(pos + 1)};
}

// Detect whether a line looks like KV-pair format.
// Heuristic: contains at least two "word=" tokens.
bool looks_like_kv(std::string_view line) noexcept {
    int count = 0;
    for (std::size_t i = 0; i + 1 < line.size(); ++i) {
        if (line[i] == '=' && i > 0 &&
            (std::isalnum(static_cast<unsigned char>(line[i-1])) ||
             line[i-1] == '_')) {
            ++count;
            if (count >= 2) return true;
        }
    }
    return false;
}

}  // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// LogParser::parse  (public entry point)
// ─────────────────────────────────────────────────────────────────────────────

std::optional<LogEvent> LogParser::parse(std::string_view line) const {
    line = trim(line);
    if (line.empty()) return std::nullopt;

    LogEvent ev;
    ev.raw_line = std::string(line);

    // Try syslog first (very common, distinctive timestamp prefix).
    if (parse_syslog(line, ev))   return ev;

    // Nginx-style: "YYYY/MM/DD HH:MM:SS [level] ..."
    if (line.size() >= 5 &&
        std::isdigit(static_cast<unsigned char>(line[0])) &&
        std::isdigit(static_cast<unsigned char>(line[1])) &&
        std::isdigit(static_cast<unsigned char>(line[2])) &&
        std::isdigit(static_cast<unsigned char>(line[3])) &&
        line[4] == '/') {
        if (parse_nginx(line, ev)) return ev;
    }

    if (parse_kv_pairs(line, ev)) return ev;

    return std::nullopt;
}

// ─────────────────────────────────────────────────────────────────────────────
// Syslog RFC 3164 parser
//
// Format: "Mon DD HH:MM:SS hostname process[pid]: message"
//    or   "Mon DD HH:MM:SS hostname process: message"
//    or   "<pri>Mon DD HH:MM:SS hostname process[pid]: message"
// ─────────────────────────────────────────────────────────────────────────────

bool LogParser::parse_syslog(std::string_view line, LogEvent& ev) {
    std::string_view rest = line;

    // ── Optional <priority> prefix ────────────────────────────────────────────
    if (!rest.empty() && rest[0] == '<') {
        auto close = rest.find('>');
        if (close == std::string_view::npos) return false;
        int pri = parse_int(rest.substr(1, close - 1));
        if (pri >= 0) ev.level = priority_to_level(pri);
        rest = rest.substr(close + 1);
    }

    rest = ltrim(rest);

    // ── Timestamp: "Mon DD HH:MM:SS" (15 chars, but day may be space-padded) ─
    // Minimum: "Jan  1 00:00:00 " = 16 chars
    if (rest.size() < 16) return false;

    // Month is always a 3-letter abbreviation.
    if (month_from_abbr(rest.substr(0, 3)) < 0) return false;

    // Find the end of the timestamp field: everything up to but not including
    // the fourth space token (i.e. the hostname).
    // Timestamp is exactly "Mmm DD HH:MM:SS" — positions 0-14.
    if (rest[3] != ' ') return false;
    // Day field: positions 4-5 (space-padded single digit or two digits).
    if (rest[6] != ' ') return false;
    // Time field starts at 7, is 8 chars "HH:MM:SS".
    if (rest.size() < 15) return false;
    if (rest[9] != ':' || rest[12] != ':') return false;

    std::string_view ts_field = rest.substr(0, 15);
    if (!parse_syslog_timestamp(ts_field, ev)) return false;
    rest = ltrim(rest.substr(15));

    // ── Hostname ───────────────────────────────────────────────────────────────
    auto [host, after_host] = split_once(rest, ' ');
    if (host.empty()) return false;
    ev.source_host = std::string(host);
    rest = ltrim(after_host);

    // ── Process[pid]: ─────────────────────────────────────────────────────────
    // Find the colon that ends the process field.
    auto colon_pos = rest.find(": ");
    if (colon_pos == std::string_view::npos) {
        // Try colon at end of string (no message body).
        colon_pos = rest.rfind(':');
        if (colon_pos == std::string_view::npos) return false;
    }

    std::string_view proc_field = rest.substr(0, colon_pos);
    std::string_view msg_field  =
        (colon_pos + 2 <= rest.size()) ? rest.substr(colon_pos + 2) : "";

    // proc_field is "process" or "process[pid]"
    auto bracket = proc_field.find('[');
    if (bracket != std::string_view::npos) {
        ev.log_source = std::string(proc_field.substr(0, bracket));
        auto close_b = proc_field.find(']', bracket);
        if (close_b != std::string_view::npos) {
            int pid = parse_int(proc_field.substr(bracket + 1,
                                                   close_b - bracket - 1));
            if (pid >= 0) ev.pid = pid;
        }
    } else {
        ev.log_source = std::string(proc_field);
    }

    ev.message = std::string(msg_field);
    ev.format  = LogFormat::SYSLOG;

    // Best-effort: pull level keyword from message if not set by priority.
    if (ev.level == LogLevel::UNKNOWN)
        ev.level = LogLevel::INFO;  // syslog lines without <pri> default to INFO

    // Extract any embedded key=value pairs from the message.
    extract_kv(msg_field, ev);

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Nginx error-log parser
//
// Format: "YYYY/MM/DD HH:MM:SS [level] pid#tid: *cid message"
// The message body may or may not contain key=value pairs; both are handled.
// ─────────────────────────────────────────────────────────────────────────────

bool LogParser::parse_nginx(std::string_view line, LogEvent& ev) {
    std::string_view rest = line;

    // Timestamp: first 19 chars "YYYY/MM/DD HH:MM:SS"
    if (rest.size() < 19) return false;
    if (!parse_iso_timestamp(rest.substr(0, 19), ev)) return false;
    rest = ltrim(rest.substr(19));

    // Optional [level] bracket.
    if (!rest.empty() && rest[0] == '[') {
        auto close = rest.find(']');
        if (close != std::string_view::npos) {
            ev.level = keyword_to_level(rest.substr(1, close - 1));
            rest = ltrim(rest.substr(close + 1));
        }
    } else {
        ev.level = LogLevel::INFO;
    }

    // Optional "pid#tid: " prefix — skip up to and including ": "
    auto colon_sp = rest.find(": ");
    if (colon_sp != std::string_view::npos && colon_sp < 30) {
        // Only skip if it looks like a pid field (all digits / '#' / digits).
        auto candidate = rest.substr(0, colon_sp);
        bool looks_like_pid = !candidate.empty() &&
            std::all_of(candidate.begin(), candidate.end(), [](unsigned char c){
                return std::isdigit(c) || c == '#';
            });
        if (looks_like_pid) rest = ltrim(rest.substr(colon_sp + 2));
    }

    ev.message    = std::string(rest);
    ev.log_source = "nginx";
    ev.format     = LogFormat::KV_PAIRS;  // reuse the KV format tag

    // Extract any embedded kv pairs from the message.
    extract_kv(rest, ev);

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// KV-pair parser
//
// Handles two sub-formats:
//   nginx error:  "YYYY/MM/DD HH:MM:SS [level] pid#tid: *cid message ..."
//   structured:   "time=... level=... msg=... key=value ..."
// ─────────────────────────────────────────────────────────────────────────────

bool LogParser::parse_kv_pairs(std::string_view line, LogEvent& ev) {
    if (!looks_like_kv(line)) return false;

    std::string_view rest = line;

    // ── Attempt nginx-style timestamp "YYYY/MM/DD HH:MM:SS" ──────────────────
    // Must start with 4 digits + '/'
    bool has_ts = (rest.size() >= 19 &&
                   std::isdigit(static_cast<unsigned char>(rest[0])) &&
                   std::isdigit(static_cast<unsigned char>(rest[1])) &&
                   std::isdigit(static_cast<unsigned char>(rest[2])) &&
                   std::isdigit(static_cast<unsigned char>(rest[3])) &&
                   rest[4] == '/');

    if (has_ts) {
        if (parse_iso_timestamp(rest.substr(0, 19), ev))
            rest = ltrim(rest.substr(19));
    }

    if (ev.timestamp == std::chrono::system_clock::time_point{})
        ev.timestamp = std::chrono::system_clock::now();

    // ── nginx [level] field ───────────────────────────────────────────────────
    rest = ltrim(rest);
    if (!rest.empty() && rest[0] == '[') {
        auto close = rest.find(']');
        if (close != std::string_view::npos) {
            ev.level = keyword_to_level(rest.substr(1, close - 1));
            rest = ltrim(rest.substr(close + 1));
        }
    }

    // ── Extract all key=value pairs ───────────────────────────────────────────
    extract_kv(rest, ev);

    // Pull well-known keys into first-class fields.
    if (auto it = ev.fields.find("level"); it != ev.fields.end())
        ev.level = keyword_to_level(it->second);
    if (auto it = ev.fields.find("msg"); it != ev.fields.end())
        ev.message = it->second;
    if (auto it = ev.fields.find("message"); it != ev.fields.end())
        if (ev.message.empty()) ev.message = it->second;
    if (auto it = ev.fields.find("host"); it != ev.fields.end())
        if (ev.source_host.empty()) ev.source_host = it->second;
    if (auto it = ev.fields.find("hostname"); it != ev.fields.end())
        if (ev.source_host.empty()) ev.source_host = it->second;
    if (auto it = ev.fields.find("app"); it != ev.fields.end())
        if (ev.log_source.empty()) ev.log_source = it->second;
    if (auto it = ev.fields.find("service"); it != ev.fields.end())
        if (ev.log_source.empty()) ev.log_source = it->second;

    if (ev.message.empty()) ev.message = std::string(rest);
    ev.format = LogFormat::KV_PAIRS;

    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Timestamp helpers
// ─────────────────────────────────────────────────────────────────────────────

bool LogParser::parse_syslog_timestamp(std::string_view ts, LogEvent& ev) {
    // "Jan  2 15:04:05"  or  "Jan 12 15:04:05"
    //  0123456789012345
    if (ts.size() < 15) return false;

    int mon = month_from_abbr(ts.substr(0, 3));
    if (mon < 0) return false;

    int mday = parse_int(ts.substr(4, 2));
    if (mday <= 0) return false;

    int hour = parse_int(ts.substr(7, 2));
    int min  = parse_int(ts.substr(10, 2));
    int sec  = parse_int(ts.substr(13, 2));
    if (hour < 0 || min < 0 || sec < 0) return false;

    // Syslog RFC 3164 omits the year.  Use the current year; if that would
    // put the timestamp in the future by more than a day, assume last year
    // (handles the Dec 31 → Jan 1 rollover edge case).
    int year = current_year();
    auto tp   = make_timepoint(year, mon, mday, hour, min, sec);
    auto now  = std::chrono::system_clock::now();
    if (tp > now + std::chrono::hours(24))
        tp = make_timepoint(year - 1, mon, mday, hour, min, sec);

    ev.timestamp = tp;
    return true;
}

bool LogParser::parse_iso_timestamp(std::string_view ts, LogEvent& ev) {
    // "YYYY/MM/DD HH:MM:SS"
    //  0123456789012345678
    if (ts.size() < 19) return false;
    if (ts[4] != '/' || ts[7] != '/' || ts[10] != ' ' ||
        ts[13] != ':' || ts[16] != ':') return false;

    int year = parse_int(ts.substr(0, 4));
    int mon  = parse_int(ts.substr(5, 2)) - 1;  // 0-based
    int mday = parse_int(ts.substr(8, 2));
    int hour = parse_int(ts.substr(11, 2));
    int min  = parse_int(ts.substr(14, 2));
    int sec  = parse_int(ts.substr(17, 2));

    if (year < 1970 || mon < 0 || mon > 11 || mday <= 0) return false;
    if (hour < 0 || min < 0 || sec < 0) return false;

    ev.timestamp = make_timepoint(year, mon, mday, hour, min, sec);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// KV extraction
// ─────────────────────────────────────────────────────────────────────────────

void LogParser::extract_kv(std::string_view msg, LogEvent& ev) {
    // Walk the string looking for "key=value" or "key="quoted value"" tokens.
    // Keys: [a-zA-Z0-9_-]+
    // Values: everything up to the next whitespace, OR a double-quoted string.

    std::size_t i = 0;
    while (i < msg.size()) {
        // Skip to the start of a potential key.
        while (i < msg.size() && !std::isalpha(static_cast<unsigned char>(msg[i]))
               && msg[i] != '_')
            ++i;
        if (i >= msg.size()) break;

        // Collect key characters.
        std::size_t key_start = i;
        while (i < msg.size() &&
               (std::isalnum(static_cast<unsigned char>(msg[i])) ||
                msg[i] == '_' || msg[i] == '-'))
            ++i;

        if (i >= msg.size() || msg[i] != '=') continue;  // not a kv pair
        std::string_view key = msg.substr(key_start, i - key_start);
        ++i;  // skip '='

        if (i >= msg.size()) break;

        std::string value;
        if (msg[i] == '"') {
            // Quoted value.
            ++i;
            std::size_t vstart = i;
            while (i < msg.size() && msg[i] != '"') ++i;
            value = std::string(msg.substr(vstart, i - vstart));
            if (i < msg.size()) ++i;  // skip closing '"'
        } else {
            // Unquoted: up to next whitespace or comma.
            std::size_t vstart = i;
            while (i < msg.size() && !std::isspace(static_cast<unsigned char>(msg[i]))
                   && msg[i] != ',')
                ++i;
            value = std::string(msg.substr(vstart, i - vstart));
        }

        // Lowercase the key for uniform lookup.
        std::string key_str(key);
        for (auto& c : key_str) c = ascii_lower(c);

        // Do not overwrite an already-extracted field.
        ev.fields.emplace(std::move(key_str), std::move(value));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Level mapping
// ─────────────────────────────────────────────────────────────────────────────

LogLevel LogParser::priority_to_level(int pri) noexcept {
    // RFC 3164: priority = facility*8 + severity (0=EMERG … 7=DEBUG)
    int severity = pri & 0x07;
    switch (severity) {
        case 0: return LogLevel::EMERG;
        case 1: return LogLevel::ALERT;
        case 2: return LogLevel::CRITICAL;
        case 3: return LogLevel::ERROR;
        case 4: return LogLevel::WARN;
        case 5: return LogLevel::NOTICE;
        case 6: return LogLevel::INFO;
        case 7: return LogLevel::DEBUG;
        default: return LogLevel::UNKNOWN;
    }
}

LogLevel LogParser::keyword_to_level(std::string_view kw) noexcept {
    // Build a lowercase copy (keywords are short — stack is fine).
    char buf[16]{};
    std::size_t len = std::min(kw.size(), sizeof(buf) - 1);
    for (std::size_t i = 0; i < len; ++i)
        buf[i] = ascii_lower(kw[i]);
    std::string_view lo(buf, len);

    if (lo == "debug")                      return LogLevel::DEBUG;
    if (lo == "info" || lo == "information")return LogLevel::INFO;
    if (lo == "notice")                     return LogLevel::NOTICE;
    if (lo == "warn" || lo == "warning")    return LogLevel::WARN;
    if (lo == "err"  || lo == "error")      return LogLevel::ERROR;
    if (lo == "crit" || lo == "critical")   return LogLevel::CRITICAL;
    if (lo == "alert")                      return LogLevel::ALERT;
    if (lo == "emerg" || lo == "emergency") return LogLevel::EMERG;
    return LogLevel::UNKNOWN;
}

}  // namespace dlads