#!/bin/bash
# =============================================================================
# dlads.sh — build, launch, attack, and monitor DLADS in one terminal
#
# Usage (run from project root OR tests/ — script finds its own location):
#   ./dlads.sh                    → rule engine + auto attack
#   ./dlads.sh suricata           → suricata mode + auto attack
#   ./dlads.sh rules noattack     → rule engine, skip attacks
#   ./dlads.sh suricata noattack
# =============================================================================

# NO set -e here — grep returning nonzero (no match) must not kill the script.
# Individual critical steps use explicit exit on failure.

# ── Resolve project root regardless of where script is called from ────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# If script lives in tests/, root is one level up. Otherwise root = script dir.
if [[ "$SCRIPT_DIR" == */tests ]]; then
    ROOT="$(dirname "$SCRIPT_DIR")"
else
    ROOT="$SCRIPT_DIR"
fi
cd "$ROOT"

# ── Config ────────────────────────────────────────────────────────────────────
BUILD="$ROOT/build"
CFG="$ROOT/config/agent.yaml"
COORD_IP="127.0.0.1"
IDS_MODE="${1:-rules}"
RUN_ATTACK="${2:-attack}"
REFRESH=3

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m'
C='\033[0;36m' B='\033[0;34m' BOLD='\033[1m' NC='\033[0m'

if [[ "$IDS_MODE" != "rules" && "$IDS_MODE" != "suricata" ]]; then
    echo "Usage: $0 [rules|suricata] [attack|noattack]"
    exit 1
fi

if [ "$IDS_MODE" = "suricata" ]; then
    LOGFILE="/var/log/suricata/eve.json"
    IDS_FLAG="--ids=suricata"
    ATTACK_SCRIPT="$ROOT/tests/suricata_attack.sh"
else
    LOGFILE="/var/log/dlads/system.log"
    IDS_FLAG="--ids=rules"
    ATTACK_SCRIPT="$ROOT/tests/real_attack.sh"
fi

# ── Step 1: Build ─────────────────────────────────────────────────────────────
echo -e "${C}[1/5] Building...${NC}"
cmake --build "$BUILD" -j"$(nproc)" 2>&1 | grep -E "error:|Built target" || true

for bin in dlads_agent dlads_coordinator; do
    if [ ! -f "$BUILD/$bin" ]; then
        echo -e "${R}[ERROR] $BUILD/$bin missing. Run: cmake -B build && cmake --build build${NC}"
        exit 1
    fi
done
echo -e "${G}[1/5] Build OK${NC}"

# ── Step 2: Log file ──────────────────────────────────────────────────────────
echo -e "${C}[2/5] Checking log file...${NC}"
if [ ! -f "$LOGFILE" ]; then
    if [ "$IDS_MODE" = "suricata" ]; then
        echo -e "${R}[ERROR] $LOGFILE not found. Run: sudo systemctl start suricata${NC}"
        exit 1
    else
        sudo mkdir -p "$(dirname "$LOGFILE")"
        sudo touch "$LOGFILE"
        sudo chmod 666 "$LOGFILE"
    fi
fi
echo -e "${G}[2/5] Log file: $LOGFILE${NC}"

# ── Step 3: Kill old processes ────────────────────────────────────────────────
echo -e "${C}[3/5] Killing old processes...${NC}"
pkill -f dlads_coordinator 2>/dev/null || true
pkill -f dlads_agent       2>/dev/null || true
pkill -f "journalctl -f"   2>/dev/null || true
sleep 1
> /tmp/dlads_agent1.log
> /tmp/dlads_agent2.log
> /tmp/dlads_coordinator.log
echo -e "${G}[3/5] Clean${NC}"

# ── Step 4: Journald forwarder ────────────────────────────────────────────────
if [ "$IDS_MODE" = "rules" ]; then
    echo -e "${C}[4/5] Starting journald → $LOGFILE${NC}"
    sudo bash -c "journalctl -f -o short >> $LOGFILE" &
    sleep 1
else
    echo -e "${G}[4/5] Suricata mode — skipping journald${NC}"
fi

# ── Step 5: Start coordinator + agents ───────────────────────────────────────
echo -e "${C}[5/5] Starting coordinator and agents...${NC}"

"$BUILD/dlads_coordinator" >> /tmp/dlads_coordinator.log 2>&1 &
COORD_PID=$!
sleep 2

"$BUILD/dlads_agent" "$CFG" "$LOGFILE" "tcp://$COORD_IP:5555" \
    "agent-auth-01" "$COORD_IP" "$IDS_FLAG" \
    >> /tmp/dlads_agent1.log 2>&1 &
A1_PID=$!

"$BUILD/dlads_agent" "$CFG" "$LOGFILE" "tcp://$COORD_IP:5555" \
    "agent-web-01" "$COORD_IP" "$IDS_FLAG" \
    >> /tmp/dlads_agent2.log 2>&1 &
A2_PID=$!

sleep 2
echo -e "${G}coordinator=$COORD_PID  agent-auth-01=$A1_PID  agent-web-01=$A2_PID${NC}"

# ── Cleanup on Ctrl+C ─────────────────────────────────────────────────────────
cleanup() {
    echo -e "\n${Y}Shutting down...${NC}"
    kill "$COORD_PID" "$A1_PID" "$A2_PID" 2>/dev/null || true
    pkill -f "journalctl -f" 2>/dev/null || true
    wait 2>/dev/null || true

    echo ""
    echo -e "${BOLD}═══════════════ FINAL SUMMARY ═══════════════${NC}"
    S=$(curl -s --max-time 2 http://localhost:8080/stats 2>/dev/null || echo "")
    if [ -n "$S" ]; then
        echo -e "  total_alerts:  $(echo "$S" | grep -oP '"total_alerts":\K[0-9]+' || echo '?')"
        echo -e "  total_threats: $(echo "$S" | grep -oP '"total_threats":\K[0-9]+' || echo '?')"
        echo -e "  active_nodes:  $(echo "$S" | grep -oP '"active_nodes":\K[0-9]+' || echo '?')"
    fi
    A1=$(grep -c "\[RULES\] ALERT FIRED\|\[SURICATA\]" /tmp/dlads_agent1.log 2>/dev/null || echo 0)
    A2=$(grep -c "\[RULES\] ALERT FIRED\|\[SURICATA\]" /tmp/dlads_agent2.log 2>/dev/null || echo 0)
    echo -e "  agent-auth-01: $A1 alert(s) fired"
    echo -e "  agent-web-01:  $A2 alert(s) fired"
    echo -e "${BOLD}═════════════════════════════════════════════${NC}"
    exit 0
}
trap cleanup INT TERM

# ── Launch attack script in background ───────────────────────────────────────
if [ "$RUN_ATTACK" = "attack" ]; then
    if [ -f "$ATTACK_SCRIPT" ]; then
        echo -e "${Y}Launching attacks in 3s: $ATTACK_SCRIPT${NC}"
        sleep 3
        bash "$ATTACK_SCRIPT" >> /tmp/dlads_attacks.log 2>&1 &
        echo -e "${Y}Attack script running (pid=$!) — output → /tmp/dlads_attacks.log${NC}"
    else
        echo -e "${R}Attack script not found: $ATTACK_SCRIPT${NC}"
        echo -e "${Y}Run manually in another terminal: bash tests/real_attack.sh${NC}"
    fi
fi

# ── Helper functions ──────────────────────────────────────────────────────────
api()      { curl -s --max-time 2 "http://localhost:8080/$1" 2>/dev/null || echo ""; }
coord_up() { curl -s --max-time 1 http://localhost:8080/stats > /dev/null 2>&1; }

agent_summary() {
    local log="$1" name="$2"
    if [ ! -s "$log" ]; then
        echo -e "  ${R}✗${NC} $name — no output yet"; return
    fi
    if grep -q "\[INIT\].*all systems" "$log" 2>/dev/null; then
        local last
        last=$(grep "\[STATS\]" "$log" 2>/dev/null | tail -1)
        if [ -z "$last" ]; then
            echo -e "  ${Y}↻${NC} $name — running, waiting for first stats (10s)..."
            return
        fi
        local lines parsed fails alerts sent dropped ids
        lines=$(   echo "$last" | grep -oP 'lines_seen=\K[0-9]+'   || echo 0)
        parsed=$(  echo "$last" | grep -oP '(?<!\w)parsed=\K[0-9]+' || echo 0)
        fails=$(   echo "$last" | grep -oP 'parse_fail=\K[0-9]+'   || echo 0)
        alerts=$(  echo "$last" | grep -oP 'alerts=\K[0-9]+'       || echo 0)
        sent=$(    echo "$last" | grep -oP 'zmq_sent=\K[0-9]+'     || echo 0)
        dropped=$( echo "$last" | grep -oP 'zmq_dropped=\K[0-9]+' || echo 0)
        ids=$(     echo "$last" | grep -oP 'ids=\K\w+'             || echo '?')
        local ac="${NC}" dc="${NC}"
        [ "${alerts:-0}" -gt 0 ] && ac="${Y}"
        [ "${dropped:-0}" -gt 0 ] && dc="${R}"
        echo -e "  ${G}✓${NC} ${BOLD}$name${NC} [ids=$ids]  lines=${C}$lines${NC}  parsed=${C}$parsed${NC}  fail=$fails  alerts=${ac}$alerts${NC}  sent=$sent  dropped=${dc}$dropped${NC}"
    else
        echo -e "  ${R}✗${NC} $name — failed to start. Check: cat $log"
    fi
}

fired_alerts() {
    local log="$1" name="$2"
    grep "\[RULES\] ALERT FIRED\|\[SURICATA\] alert:" "$log" 2>/dev/null | tail -4 | while read -r line; do
        local ts rule sev col
        ts=$(echo "$line" | grep -oP '^\[\K[0-9:\.]+' || echo "??:??:??")
        if echo "$line" | grep -q "ALERT FIRED"; then
            rule=$(echo "$line" | grep -oP 'rule=\K\S+' || echo "?")
            sev=$( echo "$line" | grep -oP 'severity=\K\S+' || echo "?")
            col="${Y}"; [ "$sev" = "CRITICAL" ] && col="${R}"
            echo -e "    ${col}▶${NC} [$ts] ${BOLD}$rule${NC} $sev  ($name)"
        else
            local sid
            sid=$(echo "$line" | grep -oP 'sid=\K\S+' || echo "?")
            echo -e "    ${C}▶${NC} [$ts] SURICATA sid=$sid  ($name)"
        fi
    done
}

# ── Live monitor ──────────────────────────────────────────────────────────────
while true; do
    printf '\033[2J\033[H'

    printf "${BOLD}${B}╔═══════════════════════════════════════════════════════╗\n${NC}"
    printf "${BOLD}${B}║  DLADS Monitor  mode=%-10s  %s         ║\n${NC}" "$IDS_MODE" "$(date '+%H:%M:%S')"
    printf "${BOLD}${B}╚═══════════════════════════════════════════════════════╝\n${NC}"
    echo ""

    # Coordinator
    echo -e "${BOLD}COORDINATOR${NC}"
    if coord_up; then
        S=$(api stats)
        ta=$(echo "$S" | grep -oP '"total_alerts":\K[0-9]+'  || echo 0)
        tt=$(echo "$S" | grep -oP '"total_threats":\K[0-9]+' || echo 0)
        an=$(echo "$S" | grep -oP '"active_nodes":\K[0-9]+'  || echo 0)
        tc="${NC}"; [ "${tt:-0}" -gt 0 ] && tc="${R}${BOLD}"
        echo -e "  ${G}✓${NC} :8080  nodes=${C}$an${NC}  alerts=${Y}$ta${NC}  threats=${tc}$tt${NC}"
    else
        echo -e "  ${R}✗ not responding — check: tail /tmp/dlads_coordinator.log${NC}"
    fi
    echo ""

    # Agents
    echo -e "${BOLD}AGENTS${NC}"
    agent_summary "/tmp/dlads_agent1.log" "agent-auth-01"
    agent_summary "/tmp/dlads_agent2.log" "agent-web-01"
    echo ""

    # Detections
    echo -e "${BOLD}RECENT DETECTIONS${NC}"
    D1=$(fired_alerts "/tmp/dlads_agent1.log" "agent-auth-01")
    D2=$(fired_alerts "/tmp/dlads_agent2.log" "agent-web-01")
    if [ -z "$D1" ] && [ -z "$D2" ]; then
        echo -e "  ${Y}none yet${NC}"
    else
        [ -n "$D1" ] && echo "$D1"
        [ -n "$D2" ] && echo "$D2"
    fi
    echo ""

    # Correlated threats
    echo -e "${BOLD}CORRELATED THREATS${NC}"
    if coord_up; then
        T=$(api threats)
        if [ -z "$T" ] || [ "$T" = "[]" ]; then
            echo -e "  ${Y}none — need same src_ip from 2+ agents within 120s${NC}"
        else
            echo "$T" | python3 -c "
import sys, json
try:
    for t in json.load(sys.stdin):
        print(f\"  \033[1;31m▶ {t.get('threat_id','?')}\033[0m  ip={t.get('source_ip','?')}  sev={t.get('severity','?')}\")
        ev = t.get('evidence','')
        print(f\"    {ev[:88]}\")
except Exception as e:
    print(f'  parse error: {e}')
" 2>/dev/null || echo -e "  ${R}(could not parse threats)${NC}"
        fi
    fi
    echo ""

    # Coordinator log
    echo -e "${BOLD}COORDINATOR LOG (last 5)${NC}"
    if [ -s /tmp/dlads_coordinator.log ]; then
        tail -5 /tmp/dlads_coordinator.log | while read -r line; do
            if echo "$line" | grep -qiE "correlated|threat detected"; then
                echo -e "  ${R}${BOLD}$line${NC}"
            elif echo "$line" | grep -qE "\[alert\]|\[warn\]"; then
                echo -e "  ${Y}$line${NC}"
            else
                echo "  $line"
            fi
        done
    else
        echo -e "  ${Y}(empty)${NC}"
    fi

    echo ""
    echo -e "${B}──────────────────────────────────────────────────────${NC}"
    echo -e "  Ctrl+C to stop all  |  refreshes every ${REFRESH}s"
    echo -e "  logs: /tmp/dlads_agent1.log  /tmp/dlads_coordinator.log"

    sleep "$REFRESH"
done