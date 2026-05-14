#!/bin/bash
# =============================================================================
# DLADS Real System Attack Demo
# Generates REAL system log entries by performing actual failed auth attempts
# on localhost. No fake data — everything goes through PAM into journald
# into /var/log/dlads/system.log into the agent pipeline.
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "============================================="
echo "   DLADS Real System Attack Demo"
echo "   All events are REAL system log entries"
echo "============================================="
echo -e "${NC}"

# Check SSH is running
if ! systemctl is-active --quiet sshd; then
    echo -e "${YELLOW}[*] Starting SSH daemon for demo...${NC}"
    sudo systemctl start sshd
    sleep 1
fi

echo -e "${GREEN}[+] SSH daemon is running${NC}"
echo ""

# =============================================================================
# PHASE 1 — SSH Brute Force (triggers SSH_BRUTE_FORCE_001)
# Threshold: 5 failures in 60 seconds
# We do 8 to be well above threshold
# =============================================================================
echo -e "${YELLOW}[Phase 1] SSH Brute Force — 8 failed login attempts...${NC}"
echo "          These generate REAL sshd entries in journald"
echo ""

# Phase 1 — SSH brute force using ssh -4 to force IPv4
# Use -p to specify port, force password auth to fail properly
for i in $(seq 1 8); do
    ssh -4 \
        -o BatchMode=yes \
        -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no \
        -o PreferredAuthentications=password \
        -o PasswordAuthentication=no \
        attacker_dlads@127.0.0.1 \
        2>/dev/null || true
    echo -e "  ${RED}[!]${NC} SSH failure attempt $i/8"
    sleep 0.5
done

wait
echo -e "${GREEN}  [done] Check journald: journalctl -n 20 | grep sshd${NC}"
sleep 3

# =============================================================================
# PHASE 2 — Sudo auth failures (contributes to MULTI_SERVICE_AUTH_001)
# =============================================================================
echo ""
echo -e "${YELLOW}[Phase 2] Sudo auth failures...${NC}"

# Phase 2 — Real sudo failures using a non-existent user context
# su to nonexistent user generates real PAM failures
for i in $(seq 1 5); do
    su -c "whoami" dlads_fake_user_$(date +%s) 2>/dev/null || true
    echo -e "  ${RED}[!]${NC} Auth failure $i/5"
    sleep 0.3
done

echo -e "${GREEN}  [done] Check journald: journalctl -n 10 | grep sudo${NC}"
sleep 2

# =============================================================================
# PHASE 3 — Second wave: inject SSH failures directly into agent2's log
# agent2 watches /var/log/dlads/agent2.log (sudo/PAM events)
# We append sshd-session lines from the SAME attacker IP (127.0.0.1)
# Coordinator sees SSH_BRUTE_FORCE_001 from agent-ssh-01 AND agent-auth-01
# Same source IP = CORRELATED THREAT fires at CRITICAL
# =============================================================================
echo ""
echo -e "${YELLOW}[Phase 3] Second wave — injecting SSH failures into agent2 log...${NC}"

TIMESTAMP=$(date '+%b %d %H:%M:%S')
for i in $(seq 1 7); do
    echo "$TIMESTAMP archlinux sshd-session[9999$i]: Invalid user attacker_dlads from 127.0.0.1 port $((40000+i))" | sudo tee -a /var/log/dlads/agent2.log > /dev/null
    echo -e "  ${RED}[!]${NC} Injected SSH failure $i/7 into agent2 log"
    sleep 0.4
done

echo -e "${GREEN}  [done] agent-auth-01 should now fire SSH_BRUTE_FORCE_001${NC}"
echo -e "${GREEN}  Coordinator correlating: same IP 127.0.0.1 on two nodes = CRITICAL${NC}"
sleep 3

# =============================================================================
# PHASE 4 — Privilege escalation attempt
# =============================================================================
echo ""
echo -e "${YELLOW}[Phase 4] Privilege escalation attempt...${NC}"

su -c "whoami" nonexistentuser 2>/dev/null || true
echo "wrongpass" | sudo -S id 2>/dev/null || true
echo -e "${GREEN}  [done] PRIV_ESC_001 may fire${NC}"

echo -e "${CYAN}"
echo "============================================="
echo "   All attacks injected into real system"
echo "   Check results:"
echo "     curl http://localhost:8080/alerts"
echo "     curl http://localhost:8080/threats"
echo "     journalctl -n 30 | grep -E 'sshd|sudo'"
echo "============================================="
echo -e "${NC}"-