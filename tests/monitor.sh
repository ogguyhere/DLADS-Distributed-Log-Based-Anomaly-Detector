#!/bin/bash
# =============================================================================
# monitor.sh — Live DLADS pipeline status in one terminal
# Run this in a separate terminal while run_demo.sh is running.
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

REFRESH=3  # seconds between updates

clear_screen() { printf '\033[2J\033[H'; }

# ── Check if a process is running by log file content ────────────────────────
agent_status() {
    local logfile="$1"
    local name="$2"
    if [ ! -f "$logfile" ]; then
        echo -e "  ${RED}✗${NC} $name — not started"
        return
    fi
    local last_seen
    last_seen=$(grep "\[STATS\]" "$logfile" 2>/dev/null | tail -1)
    if [ -z "$last_seen" ]; then
        local started
        started=$(grep "\[INIT\].*all systems" "$logfile" 2>/dev/null | tail -1 | cut -d']' -f1 | tr -d '[')
        if [ -n "$started" ]; then
            echo -e "  ${GREEN}✓${NC} $name — started at $started (no stats yet)"
        else
            echo -e "  ${YELLOW}?${NC} $name — log exists but agent not ready yet"
        fi
        return
    fi
    # Parse stats line: lines_seen=N parsed=N parse_fail=N alerts=N zmq_sent=N zmq_dropped=N
    local lines parsed fails alerts sent dropped
    lines=$(echo "$last_seen"   | grep -oP 'lines_seen=\K[0-9]+')
    parsed=$(echo "$last_seen"  | grep -oP 'parsed=\K[0-9]+')
    fails=$(echo "$last_seen"   | grep -oP 'parse_fail=\K[0-9]+')
    alerts=$(echo "$last_seen"  | grep -oP 'alerts=\K[0-9]+')
    sent=$(echo "$last_seen"    | grep -oP 'zmq_sent=\K[0-9]+')
    dropped=$(echo "$last_seen" | grep -oP 'zmq_dropped=\K[0-9]+')
    local ids
    ids=$(echo "$last_seen" | grep -oP 'ids=\K\w+')

    local alert_col="$GREEN"
    [ "${alerts:-0}" -gt 0 ] && alert_col="$YELLOW"

    local drop_col="$GREEN"
    [ "${dropped:-0}" -gt 0 ] && drop_col="$RED"

    echo -e "  ${GREEN}✓${NC} ${BOLD}$name${NC} [ids=${ids:-?}]"
    echo -e "    lines=${CYAN}${lines:-0}${NC}  parsed=${CYAN}${parsed:-0}${NC}  parse_fail=${fails:-0}  alerts=${alert_col}${alerts:-0}${NC}  zmq_sent=${sent:-0}  dropped=${drop_col}${dropped:-0}${NC}"
}

# ── Recent alerts from agent log ──────────────────────────────────────────────
recent_alerts() {
    local logfile="$1"
    local name="$2"
    grep "\[RULES\] ALERT FIRED" "$logfile" 2>/dev/null | tail -5 | while read -r line; do
        local ts rule sev
        ts=$(echo "$line"   | cut -d']' -f1 | tr -d '[')
        rule=$(echo "$line" | grep -oP 'rule=\K\S+')
        sev=$(echo "$line"  | grep -oP 'severity=\K\S+')
        local col="$YELLOW"
        [ "$sev" = "CRITICAL" ] && col="$RED"
        [ "$sev" = "HIGH" ]     && col="$YELLOW"
        echo -e "    ${col}▶${NC} [$ts] ${BOLD}$rule${NC} — $sev  (${name})"
    done
}

# ── REST API query ────────────────────────────────────────────────────────────
query_api() {
    local endpoint="$1"
    curl -s --max-time 2 "http://localhost:8080/$endpoint" 2>/dev/null
}

coord_running() {
    curl -s --max-time 1 http://localhost:8080/stats &>/dev/null
}

# ── Main loop ─────────────────────────────────────────────────────────────────
echo -e "${CYAN}DLADS Monitor starting — refreshes every ${REFRESH}s. Ctrl+C to exit.${NC}"
sleep 1

while true; do
    clear_screen

    NOW=$(date '+%H:%M:%S')
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║         DLADS Pipeline Monitor — $NOW             ║${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""

    # ── Coordinator ───────────────────────────────────────────────────────────
    echo -e "${BOLD}COORDINATOR${NC}"
    if coord_running; then
        STATS=$(query_api "stats")
        total_alerts=$(echo "$STATS" | grep -oP '"total_alerts":\K[0-9]+')
        total_threats=$(echo "$STATS" | grep -oP '"total_threats":\K[0-9]+')
        active_nodes=$(echo "$STATS" | grep -oP '"active_nodes":\K[0-9]+')

        threat_col="$GREEN"
        [ "${total_threats:-0}" -gt 0 ] && threat_col="${RED}${BOLD}"

        echo -e "  ${GREEN}✓${NC} Running on :8080"
        echo -e "  active_nodes=${CYAN}${active_nodes:-0}${NC}  total_alerts=${YELLOW}${total_alerts:-0}${NC}  correlated_threats=${threat_col}${total_threats:-0}${NC}"
    else
        echo -e "  ${RED}✗${NC} Not running or not responding on :8080"
    fi
    echo ""

    # ── Agents ────────────────────────────────────────────────────────────────
    echo -e "${BOLD}AGENTS${NC}"
    agent_status "/tmp/dlads_agent1.log" "agent-auth-01"
    agent_status "/tmp/dlads_agent2.log" "agent-web-01"
    echo ""

    # ── Recent alerts ─────────────────────────────────────────────────────────
    echo -e "${BOLD}RECENT DETECTIONS (last 5 per agent)${NC}"
    A1=$(recent_alerts "/tmp/dlads_agent1.log" "agent-auth-01")
    A2=$(recent_alerts "/tmp/dlads_agent2.log" "agent-web-01")
    if [ -z "$A1" ] && [ -z "$A2" ]; then
        echo -e "  ${YELLOW}none yet — run: bash tests/real_attack.sh${NC}"
    else
        [ -n "$A1" ] && echo "$A1"
        [ -n "$A2" ] && echo "$A2"
    fi
    echo ""

    # ── Correlated threats ────────────────────────────────────────────────────
    echo -e "${BOLD}CORRELATED THREATS${NC}"
    if coord_running; then
        THREATS=$(query_api "threats")
        if [ "$THREATS" = "[]" ] || [ -z "$THREATS" ]; then
            echo -e "  ${YELLOW}none yet — need alerts from 2+ nodes with same src_ip${NC}"
        else
            echo "$THREATS" | python3 -c "
import sys, json
try:
    threats = json.load(sys.stdin)
    for t in threats:
        print(f\"  \033[1;31m▶ THREAT {t.get('threat_id','?')}\033[0m\")
        print(f\"    ip={t.get('source_ip','?')}  rule={t.get('rule_id','?')}  severity={t.get('severity','?')}\")
        print(f\"    evidence: {t.get('evidence','?')[:80]}\")
except:
    print('  (parse error)')
" 2>/dev/null || echo "  $THREATS"
        fi
    else
        echo -e "  ${RED}coordinator offline${NC}"
    fi
    echo ""

    # ── Nodes registered ──────────────────────────────────────────────────────
    echo -e "${BOLD}REGISTERED NODES${NC}"
    if coord_running; then
        NODES=$(query_api "nodes")
        if [ "$NODES" = "[]" ] || [ -z "$NODES" ]; then
            echo -e "  ${YELLOW}none yet — waiting for heartbeats${NC}"
        else
            echo "$NODES" | python3 -c "
import sys, json
try:
    nodes = json.load(sys.stdin)
    for n in nodes:
        status = n.get('status','?')
        col = '\033[0;32m' if status == 'ALIVE' else '\033[0;31m'
        print(f\"  {col}●\033[0m {n.get('node_id','?')}  status={status}  alerts_sent={n.get('alerts_sent',0)}\")
except:
    print('  (parse error)')
" 2>/dev/null || echo "  $NODES"
        fi
    fi
    echo ""

    # ── Coordinator log tail ──────────────────────────────────────────────────
    echo -e "${BOLD}COORDINATOR LOG (last 5 lines)${NC}"
    if [ -f /tmp/dlads_coordinator.log ]; then
        tail -5 /tmp/dlads_coordinator.log | while read -r line; do
            if echo "$line" | grep -q "CORRELATED\|THREAT"; then
                echo -e "  ${RED}${BOLD}$line${NC}"
            elif echo "$line" | grep -q "\[alert\]"; then
                echo -e "  ${YELLOW}$line${NC}"
            else
                echo -e "  $line"
            fi
        done
    else
        echo -e "  ${YELLOW}no coordinator log yet${NC}"
    fi

    echo ""
    echo -e "${BLUE}─────────────────────────────────────────────────────${NC}"
    echo -e "  refreshing every ${REFRESH}s — Ctrl+C to exit"
    echo -e "  run attacks: ${YELLOW}bash tests/real_attack.sh${NC}"

    sleep "$REFRESH"
done