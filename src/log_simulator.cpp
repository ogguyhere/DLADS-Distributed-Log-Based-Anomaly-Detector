#include "dlads/log_simulator.hpp"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <thread>

using namespace std::chrono_literals;

namespace dlads {

// ── Timestamp helper ──────────────────────────────────────────────────────────

static std::string syslog_ts() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%b %e %H:%M:%S", tm);
    return std::string(buf);
}

// ── Line generators ───────────────────────────────────────────────────────────

std::string gen_ssh_fail(const std::string& host,
                          const std::string& src_ip, int pid) {
    return syslog_ts() + " " + host + " sshd[" + std::to_string(pid) +
           "]: Failed password for root from " + src_ip + " port 54321 ssh2";
}

std::string gen_ssh_success(const std::string& host,
                             const std::string& src_ip, int pid) {
    return syslog_ts() + " " + host + " sshd[" + std::to_string(pid) +
           "]: Accepted password for root from " + src_ip + " port 54321 ssh2";
}

std::string gen_port_scan(const std::string& host,
                           const std::string& src_ip, int dport) {
    return syslog_ts() + " " + host +
           " kernel: iptables REJECT IN=eth0 SRC=" + src_ip +
           " DST=10.0.0.1 DPT=" + std::to_string(dport);
}

std::string gen_sudo_session(const std::string& host,
                              const std::string& username) {
    return syslog_ts() + " " + host +
           " sudo:  " + username +
           " : TTY=pts/0 ; PWD=/home/" + username +
           " ; USER=root ; COMMAND=/bin/bash";
}

std::string gen_sudo_open(const std::string& host,
                           const std::string& username) {
    return syslog_ts() + " " + host +
           " sudo[1234]: pam_unix(sudo:session): session opened"
           " for user root by " + username + "(uid=1001)";
}

std::string gen_auth_fail(const std::string& host,
                           const std::string& src_ip,
                           const std::string& service) {
    return syslog_ts() + " " + host + " " + service +
           "[9999]: authentication failure from " + src_ip;
}

std::string gen_background(const std::string& host, int idx) {
    static const char* sources[] = {
        "cron", "systemd", "NetworkManager", "kernel", "dbus"
    };
    static const char* msgs[] = {
        "Started Session.",
        "Reached target Basic System.",
        "pam_unix(cron:session): session opened for user root by (uid=0)",
        "NET: Registered protocol family 10",
        "New connection registered"
    };
    std::string src = sources[idx % 5];
    std::string msg = msgs[idx % 5];
    return syslog_ts() + " " + host + " " + src + "[" +
           std::to_string(1000 + idx) + "]: " + msg;
}

// ─────────────────────────────────────────────────────────────────────────────
// LogSimulator
// ─────────────────────────────────────────────────────────────────────────────

LogSimulator::LogSimulator(std::vector<AgentConfig> agents)
    : agents_(std::move(agents))
{}

LogSimulator::~LogSimulator() { stop(); }

void LogSimulator::start() {
    stop_.store(false);
    for (auto& ag : agents_) {
        // Create/truncate the log file
        std::ofstream f(ag.log_path, std::ios::trunc);
        f << syslog_ts() << " " << ag.host << " syslog: DLADS simulator started\n";
        threads_.emplace_back(&LogSimulator::agent_loop, this, ag);
    }
}

void LogSimulator::stop() {
    stop_.store(true);
    for (auto& t : threads_)
        if (t.joinable()) t.join();
    threads_.clear();
}

void LogSimulator::agent_loop(AgentConfig cfg) {
    std::mt19937 rng(std::hash<std::string>{}(cfg.host));
    std::uniform_int_distribution<int> port_dist(1024, 65535);
    std::uniform_int_distribution<int> bg_dist(0, 4);

    int  phase          = 0;   // 0=warmup 1=attack 2=cooldown cycling
    int  phase_ticks    = 0;
    int  bg_counter     = 0;
    int  attack_counter = 0;
    bool doing_portscan = false;
    int  scan_port      = 1024;

    // Rotate attack IPs per agent so the dashboard shows distinct sources
    std::string atk_ssh  = cfg.attack_ip_base + "1";
    std::string atk_scan = cfg.attack_ip_base + "2";
    std::string atk_multi= cfg.attack_ip_base + "3";

    while (!stop_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(cfg.interval_ms));

        std::ofstream f(cfg.log_path, std::ios::app);
        if (!f.is_open()) continue;

        // Always write background noise
        f << gen_background(cfg.host, bg_counter++) << "\n";

        phase_ticks++;

        // Cycle: 10s warmup → 30s attack → 10s cooldown → repeat
        if (phase == 0 && phase_ticks > 10000 / cfg.interval_ms) {
            phase = 1; phase_ticks = 0; attack_counter = 0;
            doing_portscan = false; scan_port = 1024;
            std::cout << "[Sim:" << cfg.host << "] attack phase\n";
        } else if (phase == 1 && phase_ticks > 30000 / cfg.interval_ms) {
            phase = 2; phase_ticks = 0;
            std::cout << "[Sim:" << cfg.host << "] cooldown phase\n";
        } else if (phase == 2 && phase_ticks > 10000 / cfg.interval_ms) {
            phase = 1; phase_ticks = 0; attack_counter = 0;
            doing_portscan = false; scan_port = 1024;
            std::cout << "[Sim:" << cfg.host << "] attack phase (repeat)\n";
        }

        if (phase == 1) {
            // SSH brute force — 3 attempts per tick
            for (int i = 0; i < 3; ++i)
                f << gen_ssh_fail(cfg.host, atk_ssh, 2200 + i) << "\n";

            // Port scan — one new port per tick
            if (scan_port < 1024 + 60)
                f << gen_port_scan(cfg.host, atk_scan, scan_port++) << "\n";

            // Multi-service auth failure
            if (attack_counter % 5 == 0)
                f << gen_auth_fail(cfg.host, atk_multi, "nginx") << "\n";
            if (attack_counter % 7 == 0)
                f << gen_auth_fail(cfg.host, atk_multi, "sshd")  << "\n";

            // Priv esc — once at start of attack phase
            if (attack_counter == 2)
                f << gen_sudo_open(cfg.host, "newuser") << "\n";

            attack_counter++;
        }

        f.flush();
    }
}

}  // namespace dlads