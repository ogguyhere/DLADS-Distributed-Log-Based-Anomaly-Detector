#pragma once

#include <atomic>
#include <string>
#include <thread>
#include <vector>

namespace dlads {

struct AgentConfig {
    std::string host;            // hostname shown in logs
    std::string log_path;        // file the tailer watches
    std::string attack_ip_base;  // e.g. "192.168.1." — appends 1/2/3
    int         interval_ms{ 200 };  // ms between log writes
};

class LogSimulator {
public:
    explicit LogSimulator(std::vector<AgentConfig> agents);
    ~LogSimulator();

    void start();
    void stop();

private:
    void agent_loop(AgentConfig cfg);

    std::vector<AgentConfig> agents_;
    std::vector<std::thread> threads_;
    std::atomic<bool>        stop_{ false };
};

}  // namespace dlads