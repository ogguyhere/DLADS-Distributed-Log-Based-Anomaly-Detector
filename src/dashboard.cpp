// src/dashboard.cpp
// DLADS Live Terminal Dashboard
// Reads from coordinator REST API and renders in ncurses
// Run alongside dlads_coordinator

#include <ncurses.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
// ── HTTP fetch helper ─────────────────────────────────────────────────────────

static size_t write_cb(char* ptr, size_t size, size_t nmemb, std::string* out) {
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

std::string http_get(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return response;
}

// ── Shared state ──────────────────────────────────────────────────────────────

struct DashboardState {
    // Stats
    int total_alerts  = 0;
    int total_threats = 0;
    int active_nodes  = 0;

    // Nodes
    struct NodeEntry {
        std::string node_id;
        std::string host_ip;
        std::string status;
        int         alerts_sent = 0;
        int64_t     last_seen   = 0;
    };
    std::vector<NodeEntry> nodes;

    // Recent alerts (last 20)
    struct AlertEntry {
        std::string alert_id;
        std::string source_host;
        std::string rule_id;
        std::string severity;
        std::string description;
        std::string source_ip;
        double      anomaly_score = 0.0;
        int64_t     timestamp     = 0;
    };
    std::vector<AlertEntry> alerts;

    // Correlated threats
    struct ThreatEntry {
        std::string threat_id;
        std::string source_ip;
        std::string rule_id;
        std::string severity;
        std::string evidence;
    };
    std::vector<ThreatEntry> threats;

    std::string last_updated;
    std::mutex  mtx;
};

DashboardState state;
std::atomic<bool> running{true};

// ── Data fetcher thread ───────────────────────────────────────────────────────

void fetch_data(const std::string& base_url) {
    while (running) {
        try {
            // Fetch stats
            auto stats_raw = http_get(base_url + "/stats");
            auto nodes_raw = http_get(base_url + "/nodes");
            auto alerts_raw = http_get(base_url + "/alerts");
            auto threats_raw = http_get(base_url + "/threats");

            std::lock_guard<std::mutex> lock(state.mtx);

            // Parse stats
            if (!stats_raw.empty()) {
                auto j = nlohmann::json::parse(stats_raw, nullptr, false);
                if (!j.is_discarded()) {
                    state.total_alerts  = j.value("total_alerts",  0);
                    state.total_threats = j.value("total_threats", 0);
                    state.active_nodes  = j.value("active_nodes",  0);
                }
            }

            // Parse nodes
            if (!nodes_raw.empty()) {
                auto j = nlohmann::json::parse(nodes_raw, nullptr, false);
                if (!j.is_discarded() && j.is_array()) {
                    state.nodes.clear();
                    for (const auto& n : j) {
                        DashboardState::NodeEntry e;
                        e.node_id     = n.value("node_id",     "");
                        e.host_ip     = n.value("host_ip",     "");
                        e.status      = n.value("status",      "");
                        e.alerts_sent = n.value("alerts_sent", 0);
                        e.last_seen   = n.value("last_seen",   0LL);
                        state.nodes.push_back(e);
                    }
                }
            }

            // Parse alerts
            if (!alerts_raw.empty()) {
                auto j = nlohmann::json::parse(alerts_raw, nullptr, false);
                if (!j.is_discarded() && j.is_array()) {
                    state.alerts.clear();
                    for (const auto& a : j) {
                        DashboardState::AlertEntry e;
                        e.alert_id    = a.value("alert_id",    "");
                        e.source_host = a.value("source_host", "");
                        e.rule_id     = a.value("rule_id",     "");
                        e.severity    = a.value("severity",    "");
                        e.description = a.value("description", "");
                        e.anomaly_score = a.value("anomaly_score", 0.0);
                        e.timestamp   = a.value("timestamp",   0LL);
                        if (a.contains("metadata") && a["metadata"].contains("source_ip"))
                            e.source_ip = a["metadata"]["source_ip"];
                        state.alerts.push_back(e);
                    }
                    // Show most recent first
                    std::reverse(state.alerts.begin(), state.alerts.end());
                    if (state.alerts.size() > 20)
                        state.alerts.resize(20);
                }
            }

            // Parse threats
            if (!threats_raw.empty()) {
                auto j = nlohmann::json::parse(threats_raw, nullptr, false);
                if (!j.is_discarded() && j.is_array()) {
                    state.threats.clear();
                    for (const auto& t : j) {
                        DashboardState::ThreatEntry e;
                        e.threat_id = t.value("threat_id", "");
                        e.source_ip = t.value("source_ip", "");
                        e.rule_id   = t.value("rule_id",   "");
                        e.severity  = t.value("severity",  "");
                        e.evidence  = t.value("evidence",  "");
                        state.threats.push_back(e);
                    }
                    std::reverse(state.threats.begin(), state.threats.end());
                    if (state.threats.size() > 10)
                        state.threats.resize(10);
                }
            }

            // Timestamp
            auto now = std::chrono::system_clock::now();
            auto t   = std::chrono::system_clock::to_time_t(now);
            std::ostringstream oss;
            oss << std::put_time(std::localtime(&t), "%H:%M:%S");
            state.last_updated = oss.str();

        } catch (...) {}

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ── Color pair IDs ────────────────────────────────────────────────────────────

#define COL_HEADER    1   // white on blue
#define COL_CRITICAL  2   // white on red
#define COL_HIGH      3   // black on yellow
#define COL_MEDIUM    4   // black on cyan
#define COL_LOW       5   // white on default
#define COL_ALIVE     6   // green on default
#define COL_DEAD      7   // red on default
#define COL_TITLE     8   // cyan on default
#define COL_BORDER    9   // blue on default
#define COL_DIM       10  // dark on default

void init_colors() {
    start_color();
    use_default_colors();
    init_pair(COL_HEADER,   COLOR_WHITE,  COLOR_BLUE);
    init_pair(COL_CRITICAL, COLOR_WHITE,  COLOR_RED);
    init_pair(COL_HIGH,     COLOR_BLACK,  COLOR_YELLOW);
    init_pair(COL_MEDIUM,   COLOR_BLACK,  COLOR_CYAN);
    init_pair(COL_LOW,      COLOR_WHITE,  -1);
    init_pair(COL_ALIVE,    COLOR_GREEN,  -1);
    init_pair(COL_DEAD,     COLOR_RED,    -1);
    init_pair(COL_TITLE,    COLOR_CYAN,   -1);
    init_pair(COL_BORDER,   COLOR_BLUE,   -1);
    init_pair(COL_DIM,      COLOR_BLACK,  -1);
}

int severity_color(const std::string& sev) {
    if (sev == "CRITICAL") return COL_CRITICAL;
    if (sev == "HIGH")     return COL_HIGH;
    if (sev == "MEDIUM")   return COL_MEDIUM;
    return COL_LOW;
}

// ── Draw helpers ──────────────────────────────────────────────────────────────

void draw_border(WINDOW* win, const std::string& title) {
    wattron(win, COLOR_PAIR(COL_BORDER));
    box(win, 0, 0);
    wattroff(win, COLOR_PAIR(COL_BORDER));
    if (!title.empty()) {
        wattron(win, COLOR_PAIR(COL_TITLE) | A_BOLD);
        mvwprintw(win, 0, 2, " %s ", title.c_str());
        wattroff(win, COLOR_PAIR(COL_TITLE) | A_BOLD);
    }
}

void draw_hline(WINDOW* win, int row, int col, int width) {
    wattron(win, COLOR_PAIR(COL_BORDER));
    mvwhline(win, row, col, ACS_HLINE, width);
    wattroff(win, COLOR_PAIR(COL_BORDER));
}

// ── Top bar ───────────────────────────────────────────────────────────────────

void draw_topbar(WINDOW* win, int cols) {
    std::lock_guard<std::mutex> lock(state.mtx);
    wattron(win, COLOR_PAIR(COL_HEADER) | A_BOLD);
    mvwhline(win, 0, 0, ' ', cols);
    mvwprintw(win, 0, 2, "DLADS — Distributed Log Anomaly Detection System");
    wattroff(win, COLOR_PAIR(COL_HEADER) | A_BOLD);

    wattron(win, COLOR_PAIR(COL_HEADER));
    mvwprintw(win, 0, cols - 12, "  %s  ", state.last_updated.c_str());
    wattroff(win, COLOR_PAIR(COL_HEADER));

    // Stats row
    wattron(win, A_BOLD);
    mvwprintw(win, 1, 2, "Alerts: ");
    wattroff(win, A_BOLD);
    wattron(win, COLOR_PAIR(COL_MEDIUM));
    wprintw(win, "%-6d", state.total_alerts);
    wattroff(win, COLOR_PAIR(COL_MEDIUM));

    wattron(win, A_BOLD);
    mvwprintw(win, 1, 20, "Threats: ");
    wattroff(win, A_BOLD);
    wattron(win, COLOR_PAIR(COL_CRITICAL));
    wprintw(win, "%-6d", state.total_threats);
    wattroff(win, COLOR_PAIR(COL_CRITICAL));

    wattron(win, A_BOLD);
    mvwprintw(win, 1, 40, "Active Nodes: ");
    wattroff(win, A_BOLD);
    wattron(win, COLOR_PAIR(COL_ALIVE));
    wprintw(win, "%-4d", state.active_nodes);
    wattroff(win, COLOR_PAIR(COL_ALIVE));

    mvwprintw(win, 1, 60, "Press 'q' to quit");
}

// ── Node panel ────────────────────────────────────────────────────────────────

void draw_nodes(WINDOW* win) {
    std::lock_guard<std::mutex> lock(state.mtx);
    werase(win);
    draw_border(win, "Nodes");

    int row = 1;
    int max_rows;
    int max_cols;
    getmaxyx(win, max_rows, max_cols);

    // Header
    wattron(win, A_BOLD | A_UNDERLINE);
    mvwprintw(win, row++, 2, "%-18s %-16s %-8s %s",
              "Node ID", "Host IP", "Status", "Alerts");
    wattroff(win, A_BOLD | A_UNDERLINE);

    for (const auto& n : state.nodes) {
        if (row >= max_rows - 1) break;

        bool alive = (n.status == "ALIVE");
        mvwprintw(win, row, 2, "%-18s %-16s ",
                  n.node_id.substr(0, 17).c_str(),
                  n.host_ip.substr(0, 15).c_str());

        wattron(win, COLOR_PAIR(alive ? COL_ALIVE : COL_DEAD) | A_BOLD);
        wprintw(win, "%-8s", n.status.c_str());
        wattroff(win, COLOR_PAIR(alive ? COL_ALIVE : COL_DEAD) | A_BOLD);

        wprintw(win, " %d", n.alerts_sent);
        row++;
    }

    if (state.nodes.empty()) {
        wattron(win, COLOR_PAIR(COL_DIM));
        mvwprintw(win, 2, 2, "No nodes registered yet...");
        wattroff(win, COLOR_PAIR(COL_DIM));
    }
}

// ── Alert feed panel ──────────────────────────────────────────────────────────

void draw_alerts(WINDOW* win) {
    std::lock_guard<std::mutex> lock(state.mtx);
    werase(win);
    draw_border(win, "Live Alert Feed");

    int row = 1;
    int max_rows;
    int max_cols;
    getmaxyx(win, max_rows, max_cols);

    wattron(win, A_BOLD | A_UNDERLINE);
    mvwprintw(win, row++, 2, "%-12s %-22s %-10s %-16s",
              "Severity", "Rule", "Host", "Source IP");
    wattroff(win, A_BOLD | A_UNDERLINE);

    for (const auto& a : state.alerts) {
        if (row >= max_rows - 1) break;

        int col = severity_color(a.severity);
        wattron(win, COLOR_PAIR(col) | A_BOLD);
        mvwprintw(win, row, 2, "%-12s", a.severity.c_str());
        wattroff(win, COLOR_PAIR(col) | A_BOLD);

        // Truncate rule_id for display
        std::string rule = a.rule_id;
        if (rule.size() > 21) rule = rule.substr(0, 18) + "...";

        wprintw(win, " %-22s %-10s %-16s",
                rule.c_str(),
                a.source_host.substr(0, 9).c_str(),
                a.source_ip.substr(0, 15).c_str());
        row++;
    }

    if (state.alerts.empty()) {
        wattron(win, COLOR_PAIR(COL_DIM));
        mvwprintw(win, 2, 2, "No alerts received yet...");
        wattroff(win, COLOR_PAIR(COL_DIM));
    }
}

// ── Threats panel ─────────────────────────────────────────────────────────────

void draw_threats(WINDOW* win) {
    std::lock_guard<std::mutex> lock(state.mtx);
    werase(win);
    draw_border(win, "Correlated Threats");

    int row = 1;
    int max_rows;
    int max_cols;
    getmaxyx(win, max_rows, max_cols);

    wattron(win, A_BOLD | A_UNDERLINE);
    mvwprintw(win, row++, 2, "%-12s %-18s %-20s %s",
              "Severity", "Source IP", "Rule", "Evidence");
    wattroff(win, A_BOLD | A_UNDERLINE);

    for (const auto& t : state.threats) {
        if (row >= max_rows - 1) break;

        int col = severity_color(t.severity);
        wattron(win, COLOR_PAIR(col) | A_BOLD);
        mvwprintw(win, row, 2, "%-12s", t.severity.c_str());
        wattroff(win, COLOR_PAIR(col) | A_BOLD);

        std::string evidence = t.evidence;
        int avail = max_cols - 54;
        if (avail > 0 && (int)evidence.size() > avail)
            evidence = evidence.substr(0, avail - 3) + "...";

        wprintw(win, " %-18s %-20s %s",
                t.source_ip.substr(0, 17).c_str(),
                t.rule_id.substr(0, 19).c_str(),
                evidence.c_str());
        row++;
    }

    if (state.threats.empty()) {
        wattron(win, COLOR_PAIR(COL_DIM));
        mvwprintw(win, 2, 2, "No correlated threats yet...");
        wattroff(win, COLOR_PAIR(COL_DIM));
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    std::string base_url = "http://localhost:8080";
    if (argc > 1) base_url = argv[1];

    // Start data fetcher thread
    std::thread fetcher(fetch_data, base_url);

    // Init ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);
    init_colors();

    // Layout constants
    // ┌─────────────────────────────────┐
    // │         TOP BAR (2 rows)        │
    // ├──────────────────┬──────────────┤
    // │   ALERT FEED     │    NODES     │
    // │   (60% width)    │  (40% width) │
    // ├──────────────────┴──────────────┤
    // │       CORRELATED THREATS        │
    // └─────────────────────────────────┘

    WINDOW* topbar_win  = nullptr;
    WINDOW* alerts_win  = nullptr;
    WINDOW* nodes_win   = nullptr;
    WINDOW* threats_win = nullptr;

    auto create_windows = [&]() {
        int rows, cols;
        getmaxyx(stdscr, rows, cols);

        int topbar_h  = 2;
        int middle_h  = (rows - topbar_h) * 6 / 10;
        int threats_h = rows - topbar_h - middle_h;
        int left_w    = cols * 6 / 10;
        int right_w   = cols - left_w;

        if (topbar_win)  delwin(topbar_win);
        if (alerts_win)  delwin(alerts_win);
        if (nodes_win)   delwin(nodes_win);
        if (threats_win) delwin(threats_win);

        topbar_win  = newwin(topbar_h,  cols,    0,       0);
        alerts_win  = newwin(middle_h,  left_w,  topbar_h, 0);
        nodes_win   = newwin(middle_h,  right_w, topbar_h, left_w);
        threats_win = newwin(threats_h, cols,    topbar_h + middle_h, 0);
    };

    create_windows();

    while (running) {
        int rows, cols;
        getmaxyx(stdscr, rows, cols);

        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            running = false;
            break;
        }
        if (ch == KEY_RESIZE) {
            create_windows();
            clear();
            refresh();
        }

        // Draw all panels
        draw_topbar(topbar_win, cols);
        draw_alerts(alerts_win);
        draw_nodes(nodes_win);
        draw_threats(threats_win);

        // Refresh all windows
        wrefresh(topbar_win);
        wrefresh(alerts_win);
        wrefresh(nodes_win);
        wrefresh(threats_win);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // Cleanup
    delwin(topbar_win);
    delwin(alerts_win);
    delwin(nodes_win);
    delwin(threats_win);
    endwin();

    fetcher.join();
    return 0;
}