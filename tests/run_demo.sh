#!/bin/bash
# =============================================================================
# run_demo.sh — start coordinator + agent, auto-detects Ubuntu vs Arch
# Works on both without manual forwarder setup.
#
# Ubuntu: agent watches /var/log/auth.log directly (SSH/sudo events live here)
# Arch:   installs rsyslog if needed, uses /var/log/auth.log same way
#
# Usage:
#   ./run_demo.sh              → starts everything, auto-detects log path
#   ./run_demo.sh noattack     → skip auto attack, run manually
# =============================================================================

BUILD="./build"
CFG="config/agent.yaml"
COORD_IP="127.0.0.1"
RUN_ATTACK="${1:-attack}"

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m' CYAN='\033[0;36m' NC='\033[0m'
log()  { echo -e "${GREEN}[demo]${NC} $*"; }
warn() { echo -e "${YELLOW}[demo]${NC} $*"; }
err()  { echo -e "${RED}[demo]${NC} $*"; exit 1; }

# ── Detect distro and set log file ───────────────────────────────────────────
if [ -f /etc/arch-release ]; then
    DISTRO="arch"
else
    DISTRO="ubuntu"
fi
log "Detected distro: $DISTRO"

setup_logfile() {
    if [ "$DISTRO" = "arch" ]; then
        # Arch: ensure rsyslog is writing auth events to /var/log/auth.log
        if ! command -v rsyslogd &>/dev/null; then
            warn "rsyslog not found — installing..."
            sudo pacman -S --noconfirm rsyslog
        fi
        if ! systemctl is-active --quiet rsyslog; then
            sudo systemctl enable --now rsyslog
        fi
        # rsyslog on Arch writes auth to /var/log/auth.log by default
        sudo touch /var/log/auth.log
        sudo chmod 644 /var/log/auth.log
    else
        # Ubuntu: /var/log/auth.log exists by default, just verify
        if [ ! -f /var/log/auth.log ]; then
            err "/var/log/auth.log not found — is rsyslog installed? sudo apt install rsyslog"
        fi
    fi
    LOGFILE="/var/log/auth.log"
    log "Log file: $LOGFILE"
}

setup_logfile

# ── Verify binaries ───────────────────────────────────────────────────────────
for bin in dlads_agent dlads_coordinator; do
    [ -f "$BUILD/$bin" ] || err "$BUILD/$bin not found — run: cmake --build build -j\$(nproc)"
done

# ── Kill old processes ────────────────────────────────────────────────────────
pkill -f dlads_coordinator 2>/dev/null || true
pkill -f dlads_agent       2>/dev/null || true
sleep 1
> /tmp/dlads_agent1.log
> /tmp/dlads_coordinator.log
log "Old processes cleared"

# ── Start coordinator ─────────────────────────────────────────────────────────
"$BUILD/dlads_coordinator" >> /tmp/dlads_coordinator.log 2>&1 &
COORD_PID=$!
log "Coordinator started (pid=$COORD_PID)"
sleep 2

# ── Start agent — watches auth.log directly, no forwarder needed ──────────────
"$BUILD/dlads_agent" \
    "$CFG" \
    "$LOGFILE" \
    "tcp://$COORD_IP:5555" \
    "agent-auth-01" \
    "$COORD_IP" \
    >> /tmp/dlads_agent1.log 2>&1 &
AGENT_PID=$!
log "Agent started (pid=$AGENT_PID) watching $LOGFILE"
sleep 2

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    log "Stopping..."
    kill "$COORD_PID" "$AGENT_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    log "Done."
}
trap cleanup EXIT

# ── Run attacks ───────────────────────────────────────────────────────────────
if [ "$RUN_ATTACK" = "attack" ]; then
    if [ -f "tests/real_attack.sh" ]; then
        log "Running attacks in 3s..."
        sleep 3
        bash tests/real_attack.sh &
        log "Attack script running (pid=$!) — logs → /tmp/dlads_attacks.log"
    else
        warn "tests/real_attack.sh not found — run attacks manually"
    fi
fi

log "System live:"
echo "  Agent API:   http://localhost:8080"
echo "  Dashboard:   http://localhost:5173  (run: cd dashboard/agent && npm run dev)"
echo "  Coord API:   http://localhost:8080"
echo "  Agent log:   tail -f /tmp/dlads_agent1.log"
echo "  Coord log:   tail -f /tmp/dlads_coordinator.log"
echo ""
warn "Press Ctrl+C to stop"

wait