#pragma once

// suricata_adapter.hpp
// Tails Suricata's eve.json output and converts alert events
// into dlads::AlertEvent objects, published via a callback.
//
// Suricata must be installed and running separately.
// Default eve.json path: /var/log/suricata/eve.json
//
// Eve.json alert format (relevant fields):
// {
//   "timestamp": "2024-01-15T12:34:56.789+0000",
//   "event_type": "alert",
//   "src_ip": "192.168.1.100",
//   "dest_ip": "10.0.0.1",
//   "dest_port": 22,
//   "alert": {
//     "signature": "ET SCAN SSH BruteForce",
//     "signature_id": 2001219,
//     "severity": 2,
//     "category": "Attempted Information Leak"
//   }
// }

#include "dlads/alert_event.hpp"

#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace dlads {

class SuricataAdapter {
public:
    using AlertCallback = std::function<void(AlertEvent)>;

    /**
     * @param eve_json_path  Path to Suricata's eve.json log file.
     *                       Default: /var/log/suricata/eve.json
     * @param cb             Called once per parsed alert event.
     * @param source_host    Node ID / hostname to stamp on AlertEvents.
     */
    explicit SuricataAdapter(std::string    eve_json_path,
                              AlertCallback  cb,
                              std::string    source_host = "suricata-node");
    ~SuricataAdapter();

    void start();
    void stop();
    bool running() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

    // Total eve.json lines processed and alerts converted.
    int lines_processed() const noexcept { return lines_processed_; }
    int alerts_converted() const noexcept { return alerts_converted_; }

private:
    void run();
    bool parse_eve_line(const std::string& line, AlertEvent& out) const;

    // Map Suricata severity (1=high … 4=low) to dlads Severity.
    static Severity map_severity(int suricata_sev) noexcept;

    std::string    eve_path_;
    AlertCallback  cb_;
    std::string    source_host_;

    std::thread        thread_;
    std::atomic<bool>  stop_{ false };
    std::atomic<bool>  running_{ false };
    std::atomic<int>   lines_processed_{ 0 };
    std::atomic<int>   alerts_converted_{ 0 };
};

}  // namespace dlads