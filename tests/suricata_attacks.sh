#!/bin/bash
# =============================================================================
# Localhost Suricata Attack Script
# All traffic goes to 127.0.0.1 where Suricata CAN see it
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "============================================="
echo "   Localhost Suricata Attack Demo"
echo "   All traffic on 127.0.0.1"
echo "============================================="
echo -e "${NC}"

# =============================================================================
# Attack 1: Port scan on localhost
# =============================================================================
echo -e "${YELLOW}[Attack 1] Localhost port scan...${NC}"
for port in 22 80 443 3306 5432 8080; do
    timeout 1 nc -zv 127.0.0.1 $port 2>&1
    echo -e "  ${RED}[!]${NC} Scanned port $port"
    sleep 0.2
done

# =============================================================================
# Attack 2: SSH connection attempts to localhost
# =============================================================================
echo -e "\n${YELLOW}[Attack 2] SSH brute force on localhost...${NC}"
for i in {1..15}; do
    timeout 1 ssh -o ConnectTimeout=1 fakeuser$i@127.0.0.1 2>/dev/null
    echo -e "  ${RED}[!]${NC} SSH attempt $i/15"
    sleep 0.3
done

# =============================================================================
# Attack 3: HTTP attacks on local web server (if running)
# =============================================================================
echo -e "\n${YELLOW}[Attack 3] HTTP attacks on localhost...${NC}"

# Start a simple HTTP server for testing (if not running)
if ! nc -z 127.0.0.1 8080 2>/dev/null; then
    python3 -m http.server 8080 > /dev/null 2>&1 &
    HTTP_PID=$!
    sleep 2
fi

# SQL injection on localhost
curl -s "http://127.0.0.1:8080/?id=1'%20OR%20'1'='1" > /dev/null
curl -s "http://127.0.0.1:8080/?user=admin'%20--" > /dev/null
echo -e "  ${RED}[!]${NC} SQL injection attempts sent"

# Directory traversal
curl -s "http://127.0.0.1:8080/?file=../../../../etc/passwd" > /dev/null
echo -e "  ${RED}[!]${NC} Directory traversal sent"

# Malicious User-Agent
curl -s -A "sqlmap/1.0" "http://127.0.0.1:8080/" > /dev/null
echo -e "  ${RED}[!]${NC} Malicious User-Agent sent"

# Kill HTTP server if we started it
if [ ! -z "$HTTP_PID" ]; then
    kill $HTTP_PID 2>/dev/null
fi

# =============================================================================
# Attack 4: Fast connection attempts to local services
# =============================================================================
echo -e "\n${YELLOW}[Attack 4] Connection flood on localhost...${NC}"
for i in {1..20}; do
    timeout 1 nc -zv 127.0.0.1 22 2>&1 &
    timeout 1 nc -zv 127.0.0.1 80 2>&1 &
    timeout 1 nc -zv 127.0.0.1 443 2>&1 &
done
wait
echo -e "  ${RED}[!]${NC} 60 connection attempts sent"

echo -e "\n${GREEN}✓ All attacks completed on localhost!${NC}"
echo -e "${CYAN}"
echo "Check dashboard for alerts NOW"
echo "Also check: sudo tail -20 /var/log/suricata/fast.log"
echo -e "${NC}"