#!/bin/bash
# =============================================================================
# DLADS demo.sh — IDS Comparison Demo
#
# Terminal 1:  bash tests/demo.sh
#              Wait for ">>> RUN ATTACKS NOW <<<"
# Terminal 2:  bash tests/attack.sh /var/log/dlads/system.log
# Ctrl+C in Terminal 1 when attacks finish → summary prints
# =============================================================================

BUILD="./build"
CFG="config/agent.yaml"
LOGFILE="/var/log/dlads/system.log"
EVE_JSON="/var/log/suricata/eve.json"
LOG_COORD="/tmp/dlads_coord.log"
LOG_BUILTIN="/tmp/dlads_builtin.log"
LOG_SURICATA="/tmp/dlads_suricata.log"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

fail() { echo -e "${RED}[FAIL] $1${NC}"; exit 1; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
inf()  { echo -e "${YELLOW}[*]${NC} $1"; }

# ── Preflight ─────────────────────────────────────────────────────────────────

[ -f "$BUILD/dlads_agent" ]       || fail "dlads_agent not built. Run: cd build && cmake .. && make -j\$(nproc)"
[ -f "$BUILD/dlads_coordinator" ] || fail "dlads_coordinator not built."
[ -f "tests/attack.sh" ]          || fail "tests/attack.sh not found."

if ! systemctl is-active --quiet suricata; then
    inf "Starting Suricata..."
    sudo systemctl start suricata && sleep 4
fi
[ -f "$EVE_JSON" ] || fail "eve.json missing. Check: sudo systemctl status suricata"
sudo chmod 644 "$EVE_JSON" 2>/dev/null

if ! systemctl is-active --quiet sshd 2>/dev/null && \
   ! systemctl is-active --quiet ssh  2>/dev/null; then
    sudo systemctl start sshd 2>/dev/null || sudo systemctl start ssh 2>/dev/null
fi

# ── Kill leftovers ────────────────────────────────────────────────────────────

pkill -f dlads_coordinator 2>/dev/null
pkill -f dlads_agent       2>/dev/null
# Kill old journalctl forwarders
sudo pkill -f "journalctl -f" 2>/dev/null
sleep 1

# ── Clear log — prevents stale entries firing before attacks ──────────────────

sudo truncate -s 0 "$LOGFILE"
ok "Log cleared: $LOGFILE"

echo -e "${CYAN}"
echo "============================================================"
echo "  DLADS — Rule Engine vs Suricata IDS Comparison Demo"
echo "============================================================"
echo -e "${NC}"

# ── Journald forwarder — MUST be sudo to capture sshd/system messages ─────────

inf "Starting journald forwarder (sudo required for sshd logs)..."
sudo bash -c "journalctl -f -o short --no-tail >> $LOGFILE 2>/dev/null" &
JOURNAL_PID=$!
sleep 2
ok "Journald forwarder live (pid=$JOURNAL_PID)"

# ── Coordinator ───────────────────────────────────────────────────────────────

inf "Starting coordinator..."
"$BUILD/dlads_coordinator" > "$LOG_COORD" 2>&1 &
COORD_PID=$!
sleep 2
ok "Coordinator (pid=$COORD_PID)"

# ── Agent 1: builtin rule engine ──────────────────────────────────────────────

inf "Starting agent-builtin (rule engine)..."
"$BUILD/dlads_agent" \
    "$CFG" "$LOGFILE" "tcp://127.0.0.1:5555" "agent-builtin" "127.0.0.1" \
    > "$LOG_BUILTIN" 2>&1 &
BUILTIN_PID=$!

for i in $(seq 1 30); do
    grep -q "\[TAILER\].*watching" "$LOG_BUILTIN" 2>/dev/null && break
    sleep 0.5
done
ok "agent-builtin live (pid=$BUILTIN_PID)"

# ── Agent 2: suricata ─────────────────────────────────────────────────────────

inf "Starting agent-suricata (suricata backend)..."
"$BUILD/dlads_agent" \
    "$CFG" "$EVE_JSON" "tcp://127.0.0.1:5555" "agent-suricata" "127.0.0.1" \
    --ids=suricata \
    > "$LOG_SURICATA" 2>&1 &
SURICATA_PID=$!

for i in $(seq 1 30); do
    grep -q "\[SURICATA\]" "$LOG_SURICATA" 2>/dev/null && break
    sleep 0.5
done
ok "agent-suricata live (pid=$SURICATA_PID)"

inf "Pipeline settling (3s)..."
sleep 3

# ── Ready ─────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${BOLD}>>> RUN ATTACKS NOW in Terminal 2:${NC}                       ${CYAN}│${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}bash tests/attack.sh $LOGFILE${NC}  ${CYAN}│${NC}"
echo -e "${CYAN}│${NC}                                                          ${CYAN}│${NC}"
echo -e "${CYAN}│${NC}  Ctrl+C here when attacks finish → summary prints        ${CYAN}│${NC}"
echo -e "${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "${BOLD}Live alert stream:${NC}"
echo ""

# ── Print summary ─────────────────────────────────────────────────────────────

print_results() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  FINAL RESULTS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"

    echo -e "\n${BOLD}  Rule Engine (agent-builtin):${NC}"
    BUILTIN_ALERTS=$(grep "ALERT FIRED" "$LOG_BUILTIN" 2>/dev/null)
    if [ -z "$BUILTIN_ALERTS" ]; then
        echo -e "  ${YELLOW}No alerts fired${NC}"
    else
        echo "$BUILTIN_ALERTS" | while IFS= read -r line; do
            echo -e "  ${GREEN}▶${NC} $line"
        done
    fi

    echo -e "\n${BOLD}  Suricata IDS (agent-suricata):${NC}"
    SURICATA_ALERTS=$(grep "ALERT FIRED" "$LOG_SURICATA" 2>/dev/null)
    if [ -z "$SURICATA_ALERTS" ]; then
        echo -e "  ${YELLOW}No alerts fired${NC}"
    else
        echo "$SURICATA_ALERTS" | while IFS= read -r line; do
            echo -e "  ${CYAN}▶${NC} $line"
        done
    fi

    echo -e "\n${BOLD}  Coordinator (correlation):${NC}"
    COORD_OUT=$(grep -iE "alert|threat|correlat" "$LOG_COORD" 2>/dev/null | head -20)
    if [ -z "$COORD_OUT" ]; then
        echo -e "  ${YELLOW}No coordinator output${NC}"
    else
        echo "$COORD_OUT" | while IFS= read -r line; do
            echo -e "  ${YELLOW}▶${NC} $line"
        done
    fi

    B=$(grep -c "ALERT FIRED" "$LOG_BUILTIN"  2>/dev/null || echo 0)
    S=$(grep -c "ALERT FIRED" "$LOG_SURICATA" 2>/dev/null || echo 0)

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "  Rule Engine alerts : ${BOLD}${GREEN}$B${NC}"
    echo -e "  Suricata alerts    : ${BOLD}${CYAN}$S${NC}"
    echo ""
    echo -e "  ${GREEN}Both IDS${NC}      attacks 1+2 — SSH brute force, port scan"
    echo -e "  ${GREEN}Rule only${NC}     attacks 3+4 — priv esc, multi-service spray (host logs)"
    echo -e "  ${CYAN}Suricata only${NC} attacks 5+6 — HTTP dir scan, DNS tunneling (network)"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

trap "echo '';
      sudo kill $JOURNAL_PID 2>/dev/null;
      kill $COORD_PID $BUILTIN_PID $SURICATA_PID 2>/dev/null;
      print_results;
      exit 0" INT

# Live merged stream
tail -f "$LOG_BUILTIN" "$LOG_SURICATA" 2>/dev/null \
    | grep --line-buffered "ALERT FIRED" \
    | while IFS= read -r line; do
        if echo "$line" | grep -qi "suricata"; then
            echo -e "${CYAN}[SURICATA]${NC} $line"
        else
            echo -e "${GREEN}[BUILTIN ]${NC} $line"
        fi
    done