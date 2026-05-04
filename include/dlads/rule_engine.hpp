#pragma once

#include "dlads/alert_event.hpp"
#include "dlads/log_event.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace dlads {

// ── Rule configuration ────────────────────────────────────────────────────────
// Loaded from config/agent.yaml.  All rules read from a single instance that
// is passed into RuleEngine at construction time.

struct RuleConfig {
    // SSH brute force
    int ssh_window_seconds   { 60  };
    int ssh_threshold        { 10  };
    int ssh_cooldown_seconds { 120 };

    // Port scan
    int scan_window_seconds   { 30 };
    int scan_threshold        { 15 };
    int scan_cooldown_seconds { 60 };

    // Privilege escalation
    int priv_history_hours     { 24  };
    int priv_cooldown_seconds  { 300 };

    // Multi-service auth failure
    int multi_window_seconds   { 300 };
    int multi_min_services     { 2   };
    int multi_cooldown_seconds { 180 };

    /** Parse a flat agent.yaml file.  Returns default config on any error. */
    static RuleConfig from_yaml(const std::string& path);
};

// ── Per-event index ───────────────────────────────────────────────────────────
// Built once per RuleEngine::process() call from the ring-buffer snapshot.
// Rules receive a const ref — they never rebuild it themselves.

struct EventIndex {
    // All events grouped by extracted source IP (from LogEvent::fields["src_ip"]
    // or parsed from the message).  Empty-string key holds events with no IP.
    std::unordered_map<std::string, std::vector<const LogEvent*>> by_ip;

    // All events grouped by log_source ("sshd", "sudo", "kernel", …).
    std::unordered_map<std::string, std::vector<const LogEvent*>> by_source;

    // Pre-filtered views (populated during build, pointers into snapshot).
    std::vector<const LogEvent*> last_60s;
    std::vector<const LogEvent*> last_300s;
};

// ── Rule interface ────────────────────────────────────────────────────────────

class Rule {
public:
    virtual ~Rule() = default;

    /**
     * Evaluate the incoming event against stored history.
     *
     * @param event    The newly arrived log event.
     * @param snapshot Full ring-buffer snapshot (oldest first).
     * @param index    Pre-built index over snapshot.
     * @param cfg      Thresholds / window sizes.
     * @return         An AlertEvent if the rule fires, std::nullopt otherwise.
     */
    virtual std::optional<AlertEvent> evaluate(
        const LogEvent&              event,
        const std::vector<LogEvent>& snapshot,
        const EventIndex&            index,
        const RuleConfig&            cfg) = 0;

    virtual std::string_view rule_id()           const = 0;
    virtual std::chrono::seconds cooldown(const RuleConfig&) const = 0;
};

// ── RuleEngine ────────────────────────────────────────────────────────────────

/**
 * Owns the rule set, maintains per-rule cooldown state, and drives evaluation.
 *
 * Thread safety: NOT thread-safe.  Call process() from a single thread only
 * (the detection thread that also owns the ring buffer).
 */
class RuleEngine {
public:
    explicit RuleEngine(RuleConfig cfg = {});
    ~RuleEngine() = default;

    // Non-copyable, movable.
    RuleEngine(const RuleEngine&)            = delete;
    RuleEngine& operator=(const RuleEngine&) = delete;
    RuleEngine(RuleEngine&&)                 = default;
    RuleEngine& operator=(RuleEngine&&)      = default;

    /**
     * Process one event against all rules.
     *
     * @param event    The newly arrived log event.
     * @param snapshot Current ring-buffer snapshot (taken by the caller once
     *                 per event; passed here by const ref to avoid a second
     *                 O(N) copy).
     * @return         Zero or more alerts produced this cycle.
     */
    std::vector<AlertEvent> process(
        const LogEvent&              event,
        const std::vector<LogEvent>& snapshot);

    /** Replace the current config (e.g. after a SIGHUP reload). */
    void set_config(RuleConfig cfg);

    const RuleConfig& config() const noexcept { return cfg_; }

private:
    // Build an EventIndex from a snapshot + the current wall-clock time.
    static EventIndex build_index(
        const std::vector<LogEvent>& snapshot,
        std::chrono::system_clock::time_point now);

    // Returns true if rule_key is still within its cooldown window.
    bool in_cooldown(const std::string& rule_key) const;

    // Record a cooldown entry for rule_key.
    void set_cooldown(const std::string& rule_key,
                      std::chrono::seconds duration);

    RuleConfig                         cfg_;
    std::vector<std::unique_ptr<Rule>> rules_;

    // Keyed by "RULE_ID:source_ip" — maps to the time the alert fired.
    std::unordered_map<std::string,
        std::chrono::system_clock::time_point> cooldown_map_;
};

// ── Free helper used by rules and tests ──────────────────────────────────────

/** Extract a source IP string from a log event.
 *  Checks fields["src_ip"] first, then scans the message for "from <ip>".
 *  Returns empty string if no IP found. */
std::string extract_src_ip(const LogEvent& ev);

}  // namespace dlads