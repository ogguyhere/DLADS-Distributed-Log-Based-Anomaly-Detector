#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace dlads {

// ── Severity ──────────────────────────────────────────────────────────────────

enum class Severity : uint8_t {
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4,
};

inline const char* to_string(Severity s) noexcept {
    switch (s) {
        case Severity::LOW:      return "LOW";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::HIGH:     return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
        default:                 return "UNKNOWN";
    }
}

inline std::optional<Severity> severity_from_string(std::string_view s) noexcept {
    if (s == "LOW")      return Severity::LOW;
    if (s == "MEDIUM")   return Severity::MEDIUM;
    if (s == "HIGH")     return Severity::HIGH;
    if (s == "CRITICAL") return Severity::CRITICAL;
    return std::nullopt;
}

// ── AlertEvent ────────────────────────────────────────────────────────────────

/**
 * A detection result produced by the Rule Engine or Anomaly Scorer.
 *
 * Compact by design — the ZeroMQ publisher will ship these across the wire
 * to the coordinator.  Keep metadata strings short; raw log lines do NOT
 * belong here (they stay in the ring buffer on the agent side).
 *
 * Serialization contract (see alert_event.cpp):
 *   serialize()   → UTF-8 JSON string, always valid if the struct is valid.
 *   deserialize() → std::nullopt on any parse or validation error; never throws.
 *
 * Size budget: a typical AlertEvent serializes to < 512 bytes.
 */
struct AlertEvent {
    // ── Identity ──────────────────────────────────────────────────────────────

    // Unique identifier.  Use next_id() to generate monotonically increasing
    // string IDs, or supply a UUID from the coordinator side.
    std::string alert_id;

    // Wall-clock time the alert was generated (agent local time).
    std::chrono::system_clock::time_point timestamp;

    // Hostname / IP of the machine that produced the alert.
    std::string source_host;

    // ── Detection metadata ────────────────────────────────────────────────────

    // Rule or detector that fired, e.g. "SSH_BRUTE_FORCE_001".
    std::string rule_id;

    Severity severity{ Severity::LOW };

    // Statistical anomaly score in [0.0, 1.0].  0 = purely rule-based,
    // higher values indicate increasing statistical deviation.
    float anomaly_score{ 0.0f };

    // Human-readable summary for operators.
    std::string description;

    // ── Evidence ──────────────────────────────────────────────────────────────

    // IDs / hashes of the log lines that triggered this alert.
    // Keep short — max ~10 entries is sufficient for correlation.
    std::vector<std::string> contributing_log_ids;

    // Rule-specific key/value context: attacker IP, username, port, count, …
    std::unordered_map<std::string, std::string> metadata;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Generate a simple monotonically increasing string ID (thread-safe). */
    static std::string next_id();
};

// ── Serialization ─────────────────────────────────────────────────────────────

/**
 * Serialize an AlertEvent to a compact JSON string.
 *
 * Timestamp is encoded as Unix epoch seconds (integer) for portability.
 * All fields are always present in the output even when empty/default.
 */
std::string serialize(const AlertEvent& ev);

/**
 * Deserialize an AlertEvent from a JSON string produced by serialize().
 *
 * Returns std::nullopt if:
 *   - The input is not valid JSON.
 *   - Any required field (alert_id, rule_id, source_host) is missing or
 *     has the wrong type.
 *   - severity is not a recognised string value.
 *
 * Never throws.
 */
std::optional<AlertEvent> deserialize(std::string_view json);

}  // namespace dlads