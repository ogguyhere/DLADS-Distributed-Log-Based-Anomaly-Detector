#pragma once

#include "dlads/alert_event.hpp"

#include <optional>
#include <string_view>

namespace dlads {

/**
 * SuricataParser
 *
 * Parses a single line from Suricata's eve.json log into an AlertEvent.
 *
 * Only lines with "event_type":"alert" produce an AlertEvent.
 * All other event types (flow, dns, tls, http, stats, …) return nullopt.
 *
 * Suricata severity mapping (inverted — 1 is most severe):
 *   1 → CRITICAL
 *   2 → HIGH
 *   3 → MEDIUM
 *   4 → LOW
 *
 * Usage:
 *   SuricataParser parser;
 *   auto ev = parser.parse(line, "agent-01");
 *   if (ev) publisher.publish(*ev);
 */
class SuricataParser {
public:
    SuricataParser()  = default;
    ~SuricataParser() = default;

    /**
     * Parse one eve.json line.
     *
     * @param line      Raw JSON line from eve.json (no trailing newline).
     * @param node_id   Agent node ID stamped into alert.source_host.
     * @return          Populated AlertEvent, or nullopt if not an alert line.
     */
    [[nodiscard]]
    std::optional<AlertEvent> parse(std::string_view line,
                                    const std::string& node_id) const;

private:
    static Severity severity_from_suricata(int suricata_level) noexcept;
};

}  // namespace dlads