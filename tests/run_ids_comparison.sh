#!/bin/bash
# =============================================================================
# DLADS IDS Comparison Runner
#
# Usage:
#   bash tests/run_ids_comparison.sh              # start + auto-run attacks
#   bash tests/run_ids_comparison.sh --no-attacks # start only, run attacks manually
#
# If using --no-attacks, once you see "READY — run attacks now", open a second
# terminal and run:
#   bash tests/real_attack_ids.sh /var/log/dlads/system.log
# =============================================================================

BUILD="./build"
CFG="config/agent.yaml"
LOGFILE="/var/log/dlads/system.log"
EVE_JSON="/var/log/suricata/eve.json"
LOG_COORD="/tmp/dlads_coord.log"
LOG_BUILTIN="/tmp/dlads_builtin.log"
LOG_SURICATA="/tmp/dlads_suricata.log"
ATTACK_SCRIPT="tests/real_attack_ids.sh"

NO_ATTACKS=0
[[ "$*" == *"--no-attacks"* ]] && NO_ATTACKS=1

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

fail() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }
ok()   { echo -e "${GREEN}[✓] $1${NC}"; }
inf()  { echo -e "${YELLOW}[*] $1${NC}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────

[ -f "$BUILD/dlads_agent" ]       || fail "dlads_agent not built. Run: cd build && cmake .. && make -j\$(nproc)"
[ -f "$BUILD/dlads_coordinator" ] || fail "dlads_coordinator not built."
[ -f "$ATTACK_SCRIPT" ]           || fail "$ATTACK_SCRIPT not found in tests/"

if [ ! -f "$LOGFILE" ]; then
    sudo mkdir -p /var/log/dlads
    sudo touch "$LOGFILE" && sudo chmod 666 "$LOGFILE"
fi

if [ ! -f "$EVE_JSON" ]; then
    inf "Starting Suricata..."
    sudo systemctl start suricata
    sleep 5
    [ -f "$EVE_JSON" ] || fail "eve.json still missing after starting Suricata."
fi
sudo chmod 644 "$EVE_JSON" 2>/dev/null

# Confirm Suricata has rules loaded — warn but don't abort
SIG_COUNT=$(sudo grep "signatures processed" /var/log/suricata/suricata.log 2>/dev/null | tail -1 | grep -oP '\d+ signatures' | grep -oP '\d+')
if [ -z "$SIG_COUNT" ] || [ "$SIG_COUNT" -eq 0 ] 2>/dev/null; then
    echo -e "${RED}[!] Suricata has 0 rules loaded. Run: sudo suricata-update && sudo systemctl restart suricata${NC}"
    echo -e "${RED}    Continuing anyway — Suricata alerts will likely be 0.${NC}"
    sleep 2
else
    ok "Suricata: $SIG_COUNT signatures loaded"
fi

# ── Kill leftovers ────────────────────────────────────────────────────────────

pkill -f dlads_coordinator 2>/dev/null
pkill -f dlads_agent       2>/dev/null
pkill -f "journalctl -f"   2>/dev/null
sleep 1

echo -e "${CYAN}"
echo "============================================================"
echo "  DLADS — Rule Engine vs Suricata IDS Comparison"
echo "============================================================"
echo -e "${NC}"

# ── Journald forwarder ────────────────────────────────────────────────────────

inf "Starting journald → $LOGFILE"
sudo bash -c "journalctl -f -o short >> $LOGFILE 2>/dev/null" &
JOURNAL_PID=$!
sleep 2   # give journald forwarder time to attach before any log lines land

# ── Coordinator ───────────────────────────────────────────────────────────────

inf "Starting coordinator..."
"$BUILD/dlads_coordinator" > "$LOG_COORD" 2>&1 &
COORD_PID=$!
sleep 2
ok "Coordinator up (pid=$COORD_PID)"

sudo truncate -s 0 "$LOGFILE"

# ── Agent 1: builtin rule engine ──────────────────────────────────────────────

inf "Starting agent-builtin (rule engine)..."
"$BUILD/dlads_agent" \
    "$CFG" "$LOGFILE" "tcp://127.0.0.1:5555" "agent-builtin" "127.0.0.1" \
    > "$LOG_BUILTIN" 2>&1 &
BUILTIN_PID=$!

# Wait until agent confirms it is tailing before proceeding
for i in $(seq 1 20); do
    grep -q "watching\|TAILER.*start" "$LOG_BUILTIN" 2>/dev/null && break
    sleep 0.5
done
ok "agent-builtin live (pid=$BUILTIN_PID)"

# ── Agent 2: suricata ─────────────────────────────────────────────────────────

inf "Starting agent-suricata..."
"$BUILD/dlads_agent" \
    "$CFG" "$EVE_JSON" "tcp://127.0.0.1:5555" "agent-suricata" "127.0.0.1" \
    --ids=suricata \
    > "$LOG_SURICATA" 2>&1 &
SURICATA_PID=$!

for i in $(seq 1 20); do
    grep -q "tailing\|SURICATA.*start" "$LOG_SURICATA" 2>/dev/null && break
    sleep 0.5
done
ok "agent-suricata live (pid=$SURICATA_PID)"

# Extra buffer — let both agents fully settle before any log lines land
inf "Agents stabilising (5s)..."
sleep 5

# ── Attacks ───────────────────────────────────────────────────────────────────

if [ "$NO_ATTACKS" -eq 1 ]; then
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  READY — run attacks now in a second terminal:${NC}"
    echo -e "  ${YELLOW}bash tests/real_attack_ids.sh $LOGFILE${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
else
    inf "Running attacks..."
    bash "$ATTACK_SCRIPT" "$LOGFILE"

    # Wait for the entire detection pipeline to flush:
    # journald delay (~1s) + tailer poll (100ms) + ring buffer + rule engine
    inf "Waiting 10s for full pipeline flush..."
    sleep 10
fi

# ── Results ───────────────────────────────────────────────────────────────────

print_results() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  RESULTS — Rule Engine  (agent-builtin)${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    BUILTIN_ALERTS=$(grep "ALERT FIRED" "$LOG_BUILTIN" 2>/dev/null)
    if [ -z "$BUILTIN_ALERTS" ]; then
        echo -e "  ${YELLOW}No alerts — pipeline may still be processing${NC}"
    else
        echo "$BUILTIN_ALERTS" | while IFS= read -r line; do
            echo -e "  ${GREEN}▶${NC} $line"
        done
    fi

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  RESULTS — Suricata IDS  (agent-suricata)${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    SURICATA_ALERTS=$(grep "ALERT FIRED" "$LOG_SURICATA" 2>/dev/null)
    if [ -z "$SURICATA_ALERTS" ]; then
        echo -e "  ${YELLOW}No alerts — check Suricata rules: sudo grep 'signatures processed' /var/log/suricata/suricata.log${NC}"
    else
        echo "$SURICATA_ALERTS" | while IFS= read -r line; do
            echo -e "  ${CYAN}▶${NC} $line"
        done
    fi

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  SUMMARY${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    B=$(grep -c "ALERT FIRED" "$LOG_BUILTIN"  2>/dev/null || echo 0)
    S=$(grep -c "ALERT FIRED" "$LOG_SURICATA" 2>/dev/null || echo 0)
    echo ""
    echo -e "  Rule Engine alerts : ${BOLD}${GREEN}$B${NC}"
    echo -e "  Suricata alerts    : ${BOLD}${CYAN}$S${NC}"
    echo ""
    echo -e "  Coverage breakdown:"
    echo -e "  ${GREEN}Both IDS${NC}      → SSH brute force, port scan (different evidence)"
    echo -e "  ${GREEN}Rule-only${NC}     → Priv escalation, multi-service spray (host logs)"
    echo -e "  ${CYAN}Suricata-only${NC} → HTTP dir scan, DNS tunneling (network layer)"
    echo ""
    echo -e "  Full logs:"
    echo -e "  ${YELLOW}tail -f $LOG_BUILTIN  | grep -E 'ALERT|ERROR'${NC}"
    echo -e "  ${YELLOW}tail -f $LOG_SURICATA | grep -E 'ALERT|ERROR'${NC}"
    echo -e "  ${YELLOW}tail -f $LOG_COORD    | grep -E 'ALERT|THREAT'${NC}"
}

# Only print snapshot results when attacks were auto-run
[ "$NO_ATTACKS" -eq 0 ] && print_results

# ── Live stream ───────────────────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}Live alert stream — Ctrl+C to stop all processes${NC}"
echo ""

trap "echo '';
      echo 'Stopping...';
      kill $COORD_PID $BUILTIN_PID $SURICATA_PID $JOURNAL_PID 2>/dev/null;
      [ '$NO_ATTACKS' -eq 1 ] && print_results;
      echo 'Done.';
      exit 0" INT

tail -f "$LOG_BUILTIN" "$LOG_SURICATA" 2>/dev/null \
    | grep --line-buffered "ALERT FIRED" \
    | while IFS= read -r line; do
        if echo "$line" | grep -qi "suricata"; then
            echo -e "${CYAN}[SURICATA]${NC} $line"
        else
            echo -e "${GREEN}[BUILTIN ]${NC} $line"
        fi
    done