#!/bin/bash
echo "=== DLADS Demo - Controlled Attacks ==="
echo ""

# Attack 1: Exactly 5 SSH attempts (triggers 1 alert)
echo "[1] SSH Brute Force (5 attempts)"
for i in {1..5}; do
    timeout 1 ssh -o ConnectTimeout=1 testuser$i@127.0.0.1 2>/dev/null
    echo -n "."
    sleep 0.5
done
echo " ✓ (1 alert expected)"
sleep 2

# Attack 2: Scan exactly 5 ports (triggers 1 alert)
echo ""
echo "[2] Port Scan (5 ports)"
for port in 22 80 443 3306 8080; do
    timeout 1 nc -zv 127.0.0.1 $port 2>&1
    echo -n "."
    sleep 0.5
done
echo " ✓ (1 alert expected)"
sleep 2

# Attack 3: Single suspicious connection
echo ""
echo "[3] Suspicious User-Agent"
curl -s -A "sqlmap/1.0" "http://127.0.0.1:8080/" > /dev/null 2>&1
echo " ✓ (1 alert expected)"
sleep 2

# Attack 4: Another SSH burst (different pattern)
echo ""
echo "[4] Second SSH Pattern"
for i in {1..5}; do
    timeout 1 ssh -o ConnectTimeout=1 attacker$i@127.0.0.1 2>/dev/null
    echo -n "."
    sleep 0.5
done
echo " ✓ (1 alert expected)"

echo ""
echo "=== Demo Complete ==="
echo "Expected: 4-6 unique alerts"
