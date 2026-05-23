# DLADS — Distributed Log Analysis and Detection System

A distributed cybersecurity monitoring system that collects, processes, and analyzes network and system logs for intrusion detection. Agents watch machines for suspicious activity and forward alerts to a central coordinator that aggregates and correlates events across the network.

---

## Architecture

```
[ Agent Node ]  →  ZMQ (port 5555)  →  [ Coordinator ]  →  [ Dashboard ]
     ↓                                        ↓
  /status + /config                     REST API :8080
  HTTP :8081                            Threat correlation
     ↓
  Suricata eve.json   or   auth.log / syslog
```

**Coordinator** — receives alerts from all agents, correlates events, exposes a REST API and serves the web dashboard.

**Agent** — monitors a machine using either the built-in rule engine (auth.log / syslog) or Suricata (eve.json). Sends alerts via ZMQ and heartbeats every 10 seconds. Exposes a local HTTP API for status and live config changes.

**IDS modes (hot-swappable):**
- `builtin` — rule engine watching syslog / auth.log. Detects SSH brute force, port scans, privilege escalation, and multi-service auth failures. Works out of the box.
- `suricata` — tails Suricata's `eve.json`. Network-level signature detection with community rulesets. Requires Suricata installed and running.

Switching modes is done from the dashboard — no restart, no config editing.

---

## Build

```bash
cmake -B build
cmake --build build -j$(nproc)
```

Requires: `libzmq-dev`, `libsqlite3-dev`, a C++17 compiler.

---

## Running

**1. Start the coordinator**
```bash
./build/dlads_coordinator
```

**2. Start an agent**
```bash
./build/dlads_agent config/agent.yaml /var/log/dlads/agent2.log tcp://127.0.0.1:5555 agent-01 127.0.0.1
```

**3. Pipe system logs into the agent's watch file** (built-in mode)
```bash
sudo journalctl -f -o short --no-pager -t sshd -t sshd-session -t sudo \
  | sudo tee -a /var/log/dlads/agent2.log &
```

**4. Start the coordinator dashboard** (port 8080)
```bash
./build/dlads_dashboard
```

**5. Start the agent dashboard** (port 5173, proxies coordinator API)
```bash
cd dashboard/agent
npm run dev
```

---

## Switching IDS Mode

Open the agent dashboard → **Node Info** → click either mode card.

The agent hot-swaps the detection engine immediately, persists the choice to `config/agent.yaml`, and keeps all coordinator connections alive. No restart needed.

To use Suricata mode, Suricata must be installed and running:

```bash
sudo pacman -S suricata        # Arch  |  sudo apt install suricata  # Debian/Ubuntu
sudo suricata-update
sudo systemctl start suricata
```

---

## Simulating Attacks

```bash
bash tests/suricata_attacks.sh
```

Generates SSH brute-force attempts and port scans on the loopback interface. Alerts appear in the Live Feed within seconds.

---

## Ports

| Port | Service |
|------|---------|
| 5555 | ZMQ PUB — agent → coordinator alerts |
| 5556 | ZMQ PUSH — agent → coordinator heartbeat |
| 8080 | HTTP REST API — coordinator |
| 8081 | HTTP REST API — agent status + config |
| 5173 | Vite dev server — agent dashboard |

---

## Config

`config/agent.yaml` — agent identity, IDS mode, detection thresholds. Written automatically when you switch modes from the dashboard.

`config/rules.ini` — built-in rule engine thresholds (SSH window, port scan sensitivity, etc.).