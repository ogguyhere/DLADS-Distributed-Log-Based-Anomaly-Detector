#pragma once

#include "dlads/alert_event.hpp"
#include "dlads/log_event.hpp"
#include "dlads/ring_buffer.hpp"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace dlads {

// ── Rule interface ────────────────────────────────────────────────────────────

/**
 * Abstract base for all detection rules.
 *
 * evaluate() receives the event that just arrived PLUS a snapshot of recent
 * history (oldest→newest).  It must return an AlertEvent on a positive
 * detection, or std::nullopt otherwise.
 *
 * Rules are stateless with respect to history — all state lives in the shared
 * RingBuffer.  Rules MAY keep internal state (e.g. per-source counters) but
 * must be thread-safe if the engine is used from multiple threads.
 */
class Rule {
public:
    virtual std::optional<AlertEvent> evaluate(
        const LogEvent&                    event,
        const std::vector<LogEvent>&       recent_history) = 0;

    virtual std::string rule_id() const = 0;
    virtual ~Rule() = default;
};

// ── Concrete rules ────────────────────────────────────────────────────────────

/**
 * SSH_BRUTE_FORCE
 *
 * Fires when a single source IP accumulates >= threshold failed SSH
 * authentication attempts within window_seconds.
 */
class SshBruteForceRule final : public Rule {
public:
    explicit SshBruteForceRule(int threshold = 5, int window_seconds = 30);

    std::optional<AlertEvent> evaluate(
        const LogEvent&              event,
        const std::vector<LogEvent>& recent_history) override;

    std::string rule_id() const override { return "SSH_BRUTE_FORCE_001"; }

private:
    int threshold_;
    int window_seconds_;
};

/**
 * PRIVILEGE_ESCALATION
 *
 * Fires when a user opens a sudo session but has NO prior successful sudo
 * in the last 24 h of the ring-buffer window.
 */
class PrivilegeEscalationRule final : public Rule {
public:
    explicit PrivilegeEscalationRule(int lookback_seconds = 86400);

    std::optional<AlertEvent> evaluate(
        const LogEvent&              event,
        const std::vector<LogEvent>& recent_history) override;

    std::string rule_id() const override { return "PRIVILEGE_ESCALATION_001"; }

private:
    int lookback_seconds_;
};

/**
 * PORT_SCAN
 *
 * Fires when a single source IP triggers connection-refused entries on
 * >= distinct_port_threshold distinct destination ports within window_seconds.
 */
class PortScanRule final : public Rule {
public:
    explicit PortScanRule(int distinct_port_threshold = 10,
                          int window_seconds          = 60);

    std::optional<AlertEvent> evaluate(
        const LogEvent&              event,
        const std::vector<LogEvent>& recent_history) override;

    std::string rule_id() const override { return "PORT_SCAN_001"; }

private:
    int distinct_port_threshold_;
    int window_seconds_;
};

// ── RuleEngine ────────────────────────────────────────────────────────────────

/**
 * Holds all Rule instances and drives per-event evaluation.
 *
 * Usage:
 *   RuleEngine engine("config/rules.ini");
 *   engine.add_rule(std::make_unique<SshBruteForceRule>(...));
 *   ...
 *   auto alerts = engine.process(event, ring_buffer.snapshot());
 *
 * Deduplication:
 *   A rule+source_ip pair is suppressed for cooldown_seconds after its first
 *   firing.  This prevents alert storms from a sustained attack.
 */
class RuleEngine {
public:
    /**
     * @param config_path  Path to INI config file with rule thresholds.
     *                     Pass empty string to use compiled-in defaults.
     * @param cooldown_seconds  Minimum seconds between repeated alerts for
     *                          the same rule+source combination.
     */
    explicit RuleEngine(const std::string& config_path    = "",
                        int                cooldown_seconds = 60);

    /** Register an additional rule.  Rules fire in insertion order. */
    void add_rule(std::unique_ptr<Rule> rule);

    /**
     * Evaluate all rules against one new event.
     *
     * @param event           The event that just arrived.
     * @param recent_history  Snapshot from RingBuffer::snapshot() — call this
     *                        ONCE per cycle and pass the result here.
     * @return                Zero or more alerts (deduplication applied).
     */
    std::vector<AlertEvent> process(
        const LogEvent&              event,
        const std::vector<LogEvent>& recent_history);

    /** Clear the deduplication table (useful in tests). */
    void reset_dedup();

private:
    bool is_suppressed(const std::string& rule_id,
                       const std::string& source_ip);

    void record_firing(const std::string& rule_id,
                       const std::string& source_ip);

    struct ThresholdConfig {
        int ssh_threshold         = 5;
        int ssh_window_s          = 30;
        int priv_lookback_s       = 86400;
        int port_threshold        = 10;
        int port_window_s         = 60;
        int cooldown_s            = 60;
    };

    static ThresholdConfig load_config(const std::string& path);

    ThresholdConfig                                            cfg_;
    std::vector<std::unique_ptr<Rule>>                         rules_;
    // Key: rule_id + "|" + source_ip  →  last-fired time
    std::unordered_map<std::string,
        std::chrono::system_clock::time_point>                 dedup_table_;
    int                                                        cooldown_seconds_;
};

}  // namespace dlads