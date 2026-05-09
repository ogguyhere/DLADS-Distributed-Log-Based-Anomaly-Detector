#!/usr/bin/env bash
# test_pipeline.sh — inject realistic log lines and verify rules fire.
#
# Usage:
#   ./test_pipeline.sh [agent_binary] [log_file]

set -euo pipefail

AGENT="${1:-./build/dlads_agent}"
LOG_FILE="${2:-/tmp/dlads_test.log}"
CFG="config/agent.yaml"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GRN}[TEST]${NC} $*"; }
warn() { echo -e "${YLW}[TEST]${NC} $*"; }
err()  { echo -e "${RED}[TEST]${NC} $*"; }

if [[ ! -f "$AGENT" ]]; then
    err "Agent binary not found at $AGENT"
    err "Build first: cmake -B build && cmake --build build"
    exit 1
fi

> "$LOG_FILE"
log "Test log file: $LOG_FILE"

log "Starting agent: $AGENT $CFG $LOG_FILE tcp://*:5556"
"$AGENT" "$CFG" "$LOG_FILE" "tcp://*:5556" &
AGENT_PID=$!
log "Agent PID: $AGENT_PID"

cleanup() {
    log "Stopping agent (PID $AGENT_PID)..."
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    log "Agent stopped."
}
trap cleanup EXIT

sleep 1
log "Agent ready."

write_line() { echo "$1" >> "$LOG_FILE"; sleep "${2:-0.1}"; }
ts() { date '+%b %e %H:%M:%S'; }

ATTACKER="203.0.113.42"
NORMAL="10.0.0.5"
HOST="testhost"

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  TEST 1 — SSH BRUTE FORCE"
echo "  Rule:    SSH_BRUTE_FORCE_001"
echo "  Expects: source=sshd, 'Failed password', 'from <ip>'"
echo "  Trigger: ssh_threshold=5 in agent.yaml (default=10, must lower)"
echo "════════════════════════════════════════════════════════"
log "Injecting 6 SSH failures (threshold must be <= 6 in agent.yaml)..."

for i in $(seq 1 6); do
    # 'from <ip>' must appear literally in the message — extract_src_ip scans for it
    write_line "$(ts) $HOST sshd[1000]: Failed password for root from $ATTACKER port 2200$i ssh2" 0.3
    log "  SSH fail #$i written"
done
sleep 1

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  TEST 2 — PORT SCAN"
echo "  Rule:    PORT_SCAN_001"
echo "  Expects: source=kernel, message contains REJECT + DPT=<port> + SRC=<ip>"
echo "  Trigger: scan_threshold=15 distinct ports in 30s"
echo "════════════════════════════════════════════════════════"
log "Injecting 20 iptables REJECT lines with distinct DPT ports..."

for i in $(seq 1 20); do
    PORT=$((1000 + i))
    # iptables log format: kernel source, message has SRC= DPT= REJECT
    write_line "$(ts) $HOST kernel[0]: iptables REJECT IN=eth0 SRC=$ATTACKER DST=10.0.0.1 DPT=$PORT PROTO=TCP" 0.05
done
log "  20 x iptables REJECT written"
sleep 1

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  TEST 3 — MULTI-SERVICE AUTH FAILURE"
echo "  Rule:    MULTI_SERVICE_AUTH_001"
echo "  Expects: 'authentication failure' OR 'Failed password' + src_ip"
echo "           from 2+ distinct log_source values"
echo "  Trigger: multi_min_services=2 (default)"
echo "════════════════════════════════════════════════════════"
log "Injecting auth failures across sshd + sudo from same IP..."

# sshd failure — 'from <ip>' in message so extract_src_ip finds it
write_line "$(ts) $HOST sshd[3001]: Failed password for root from $ATTACKER port 54321 ssh2" 0.2
# sudo failure — 'from <ip>' pattern in message
write_line "$(ts) $HOST sudo[3002]: authentication failure from $ATTACKER user=root" 0.2
# one more sshd to be safe
write_line "$(ts) $HOST sshd[3003]: Failed password for admin from $ATTACKER port 54322 ssh2" 0.2

log "  3 cross-service auth failures written"
sleep 1

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  TEST 4 — PRIVILEGE ESCALATION (first-time sudo)"
echo "  Rule:    PRIV_ESC_001"
echo "  Expects: source=sudo, 'session opened', 'by <username>'"
echo "           and that user has NO prior sudo in history"
echo "════════════════════════════════════════════════════════"
log "Injecting first-ever sudo session for user 'newadmin'..."

write_line "$(ts) $HOST sudo[4000]: pam_unix(sudo:session): session opened for user root by newadmin(uid=1001)" 0.2
sleep 1

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  TEST 5 — NORMAL TRAFFIC (expect: no alerts)"
echo "════════════════════════════════════════════════════════"
log "Injecting normal traffic — should NOT trigger any rules..."

write_line "$(ts) $HOST sshd[5000]: Accepted publickey for deploy from $NORMAL port 22 ssh2"
write_line "$(ts) $HOST sudo[5001]: pam_unix(sudo:session): session opened for user root by deploy(uid=1000)"
write_line "$(ts) $HOST kernel[0]: eth0: renamed from veth3a2f"

# Second sudo by same user — PRIV_ESC should NOT fire (seen before)
write_line "$(ts) $HOST sudo[5002]: pam_unix(sudo:session): session opened for user root by deploy(uid=1000)"

log "  4 normal lines written — zero alerts expected"
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
echo ""
log "All lines injected. Waiting 3s for final processing..."
sleep 3

echo ""
echo "════════════════════════════════════════════════════════"
echo "  DONE. Expected alerts:"
echo "    SSH_BRUTE_FORCE_001   — HIGH      (test 1)"
echo "    PORT_SCAN_001         — HIGH      (test 2)"
echo "    MULTI_SERVICE_AUTH_001— CRITICAL  (test 3)"
echo "    PRIV_ESC_001          — CRITICAL  (test 4)"
echo "  Expected silence: test 5 (normal traffic)"
echo ""
echo "  Look for: [RULES] ALERT FIRED"
echo "  Errors:   *************** lines"
echo "════════════════════════════════════════════════════════"