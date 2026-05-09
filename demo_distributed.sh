#!/usr/bin/env bash
# demo_distributed.sh
#
# Simulates a real distributed deployment on one machine:
#   - 1 coordinator  (Partner B) — receives alerts, correlates, exposes REST
#   - 2 agents       (your side) — each watching its own log file
#
# Ports:
#   5555  — coordinator SUB (alerts from all agents)
#   5556  — coordinator PULL (heartbeats from all agents)
#   8080  — REST API
#
# Usage:
#   ./demo_distributed.sh [build_dir]
#   Default build_dir = ./build

set -euo pipefail

BUILD="${1:-./build}"
AGENT="$BUILD/dlads_agent"
COORD="$BUILD/dlads_coordinator"
CFG="config/agent.yaml"
COORD_IP="127.0.0.1"

LOG1="/tmp/dlads_agent1.log"
LOG2="/tmp/dlads_agent2.log"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'

log()    { echo -e "${GRN}[DEMO]${NC} $*"; }
warn()   { echo -e "${YLW}[DEMO]${NC} $*"; }
err()    { echo -e "${RED}[DEMO]${NC} $*"; }
header() { echo -e "\n${BLU}════════════════════════════════════════════════════════${NC}"; \
           echo -e "${BLU}  $*${NC}"; \
           echo -e "${BLU}════════════════════════════════════════════════════════${NC}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
for bin in "$AGENT" "$COORD"; do
    if [[ ! -f "$bin" ]]; then
        err "Binary not found: $bin"
        err "Build first: cmake -B build && cmake --build build -j\$(nproc)"
        exit 1
    fi
done

> "$LOG1"; > "$LOG2"
log "Log files cleared: $LOG1  $LOG2"

# ── Start coordinator ─────────────────────────────────────────────────────────
header "Starting Coordinator"
"$COORD" > /tmp/coordinator.log 2>&1 &
COORD_PID=$!
log "Coordinator PID=$COORD_PID  logs → /tmp/coordinator.log"
sleep 1  # let coordinator bind ports

# ── Start Agent 1 ─────────────────────────────────────────────────────────────
header "Starting Agent 1 (agent-auth-01)"
# Alert endpoint: connect to coordinator's SUB port
"$AGENT" "$CFG" "$LOG1" "tcp://$COORD_IP:5555" "agent-auth-01" "$COORD_IP" \
    > /tmp/agent1.log 2>&1 &
AGENT1_PID=$!
log "Agent 1 PID=$AGENT1_PID  watching=$LOG1  logs → /tmp/agent1.log"

# ── Start Agent 2 ─────────────────────────────────────────────────────────────
header "Starting Agent 2 (agent-web-01)"
"$AGENT" "$CFG" "$LOG2" "tcp://$COORD_IP:5555" "agent-web-01" "$COORD_IP" \
    > /tmp/agent2.log 2>&1 &
AGENT2_PID=$!
log "Agent 2 PID=$AGENT2_PID  watching=$LOG2  logs → /tmp/agent2.log"

# ── Cleanup trap ──────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    log "Shutting down all processes..."
    kill "$AGENT1_PID" "$AGENT2_PID" "$COORD_PID" 2>/dev/null || true
    wait "$AGENT1_PID" "$AGENT2_PID" "$COORD_PID" 2>/dev/null || true
    log "All stopped."
    echo ""
    log "Log files:"
    log "  Coordinator: /tmp/coordinator.log"
    log "  Agent 1:     /tmp/agent1.log"
    log "  Agent 2:     /tmp/agent2.log"
}
trap cleanup EXIT

sleep 2  # wait for ZMQ PUB/SUB handshake (agents connect to coordinator)
log "All processes ready. Starting attack simulation."

write1() { echo "$1" >> "$LOG1"; sleep "${2:-0.1}"; }
write2() { echo "$1" >> "$LOG2"; sleep "${2:-0.1}"; }
ts()     { date '+%b %e %H:%M:%S'; }

ATTACKER="203.0.113.42"

# ─────────────────────────────────────────────────────────────────────────────
header "PHASE 1 — SSH Brute Force on Agent 1 (agent-auth-01)"
# Demonstrates: single-node detection
log "Injecting 6 SSH failures from $ATTACKER into agent-auth-01..."

for i in $(seq 1 6); do
    write1 "$(ts) auth-host sshd[1000]: Failed password for root from $ATTACKER port 2200$i ssh2" 0.3
done
log "SSH brute force injected → expect SSH_BRUTE_FORCE_001 HIGH from agent-auth-01"
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
header "PHASE 2 — Port Scan on Agent 2 (agent-web-01)"
# Demonstrates: second node detects same attacker
log "Injecting 20 iptables REJECT lines from same IP into agent-web-01..."

for i in $(seq 1 20); do
    PORT=$((1000 + i))
    write2 "$(ts) web-host kernel[0]: iptables REJECT IN=eth0 SRC=$ATTACKER DST=10.0.0.2 DPT=$PORT PROTO=TCP" 0.05
done
log "Port scan injected → expect PORT_SCAN_001 HIGH from agent-web-01"
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
header "PHASE 3 — Cross-Node Correlation (coordinator)"
# At this point coordinator has alerts from BOTH nodes referencing same IP.
# If correlation window=120s and consensus threshold=2: CORRELATED THREAT fires.
log "Both agents have now reported alerts for $ATTACKER"
log "Coordinator should detect cross-node correlation → CORRELATED THREAT CRITICAL"
sleep 3

# ─────────────────────────────────────────────────────────────────────────────
header "PHASE 4 — Auth Failures Across Both Nodes (multi-service)"
log "Injecting auth failures across sshd (agent1) and sudo (agent2)..."

write1 "$(ts) auth-host sshd[2000]: Failed password for admin from $ATTACKER port 9001 ssh2" 0.2
write2 "$(ts) web-host sudo[2001]: authentication failure from $ATTACKER user=root" 0.2
write1 "$(ts) auth-host sshd[2002]: Failed password for root from $ATTACKER port 9002 ssh2" 0.2

log "Multi-service auth failures injected"
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
header "PHASE 5 — Privilege Escalation on Agent 2"
log "Injecting first-ever sudo session for 'newadmin' on agent-web-01..."
write2 "$(ts) web-host sudo[3000]: pam_unix(sudo:session): session opened for user root by newadmin(uid=1001)" 0.2
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
header "PHASE 6 — Normal Traffic (expect: no alerts)"
log "Injecting benign traffic on both agents..."
write1 "$(ts) auth-host sshd[9000]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2"
write2 "$(ts) web-host sshd[9001]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2"
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
log "All attack phases complete. Waiting 5s for coordinator to process..."
sleep 5

header "Querying REST API"
log "GET /alerts:"
curl -s http://localhost:8080/alerts | python3 -m json.tool 2>/dev/null || \
    curl -s http://localhost:8080/alerts

echo ""
log "GET /threats (correlated threats):"
curl -s http://localhost:8080/threats | python3 -m json.tool 2>/dev/null || \
    curl -s http://localhost:8080/threats

echo ""
log "GET /nodes (agent registry):"
curl -s http://localhost:8080/nodes | python3 -m json.tool 2>/dev/null || \
    curl -s http://localhost:8080/nodes

echo ""
log "GET /stats:"
curl -s http://localhost:8080/stats | python3 -m json.tool 2>/dev/null || \
    curl -s http://localhost:8080/stats

echo ""
header "DEMO COMPLETE"
echo ""
echo "  Expected results:"
echo "    /alerts  — 4+ alert entries (SSH, scan, auth, priv-esc)"
echo "    /threats — 1+ correlated threat (same IP flagged by both nodes)"
echo "    /nodes   — 2 nodes: agent-auth-01 and agent-web-01, both ALIVE"
echo ""
echo "  To scale to real distributed:"
echo "    Replace 127.0.0.1 with coordinator's actual IP."
echo "    Run dlads_agent on each host, pointing at the same coordinator."
echo "    No other changes needed."
echo ""
log "Tailing coordinator log for 5 more seconds..."
tail -f /tmp/coordinator.log &
TAIL_PID=$!
sleep 5
kill $TAIL_PID 2>/dev/null || true