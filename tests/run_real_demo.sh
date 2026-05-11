#!/bin/bash
# =============================================================================
# DLADS Real Demo Runner
# Uses real journald output — no simulation
# =============================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

BUILD="./build"
CFG="config/agent.yaml"
LOGFILE="/var/log/dlads/system.log"

echo -e "${CYAN}"
echo "============================================="
echo "   DLADS Real System Demo"
echo "============================================="
echo -e "${NC}"

# Step 1 — ensure log file exists and is writable
if [ ! -f "$LOGFILE" ]; then
    echo -e "${RED}[ERROR] $LOGFILE not found${NC}"
    echo "        Run: sudo touch $LOGFILE && sudo chmod 666 $LOGFILE"
    exit 1
fi
echo -e "${GREEN}[1] Log file ready: $LOGFILE${NC}"

# Step 2 — ensure journald is forwarding to the file
if ! pgrep -f "journalctl -f" > /dev/null; then
    echo -e "${YELLOW}[2] Starting journald forwarder...${NC}"
    sudo bash -c "journalctl -f -o short >> $LOGFILE" &
    sleep 2
else
    echo -e "${GREEN}[2] Journald forwarder already running${NC}"
fi

# Step 3 — kill old processes
pkill -f dlads_coordinator 2>/dev/null
pkill -f dlads_agent 2>/dev/null
pkill -f dlads_dashboard 2>/dev/null
sleep 1

# Step 4 — start coordinator
$BUILD/dlads_coordinator > /tmp/dlads_coordinator.log 2>&1 &
COORD_PID=$!
echo -e "${GREEN}[3] Coordinator started (pid=$COORD_PID)${NC}"
sleep 2

# Step 5 — start agent 1 (auth events)
$BUILD/dlads_agent \
    "$CFG" \
    "$LOGFILE" \
    "tcp://127.0.0.1:5555" \
    "agent-auth-01" \
    "127.0.0.1" \
    > /tmp/dlads_agent1.log 2>&1 &
AGENT1_PID=$!
echo -e "${GREEN}[4] Agent-auth-01 started watching $LOGFILE (pid=$AGENT1_PID)${NC}"
sleep 1

# Step 6 — start agent 2 (same log, different node ID)
# Both agents watch the same real log file
# They get different node IDs so coordinator sees 2 distinct nodes
# This is valid for demo — in production each agent runs on a different host
$BUILD/dlads_agent \
    "$CFG" \
    "$LOGFILE" \
    "tcp://127.0.0.1:5555" \
    "agent-web-01" \
    "127.0.0.1" \
    > /tmp/dlads_agent2.log 2>&1 &
AGENT2_PID=$!
echo -e "${GREEN}[5] Agent-web-01 started watching $LOGFILE (pid=$AGENT2_PID)${NC}"
sleep 2

echo ""
echo -e "${CYAN}System is live. Now open two more terminals:${NC}"
echo ""
echo -e "  Terminal 2: ${YELLOW}bash tests/real_attack.sh${NC}"
echo -e "  Terminal 3: ${YELLOW}$BUILD/dlads_dashboard${NC}"
echo ""
echo -e "  Or watch logs: ${YELLOW}tail -f /tmp/dlads_coordinator.log${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop everything${NC}"

# Keep running until Ctrl+C
trap "echo 'Stopping...'; kill $COORD_PID $AGENT1_PID $AGENT2_PID 2>/dev/null; exit 0" INT
wait