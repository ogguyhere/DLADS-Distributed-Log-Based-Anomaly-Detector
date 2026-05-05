#!/bin/bash
# =============================================================================
# DLADS Test Suite
# Tests: normal alerts, cross-node correlation, heartbeat, fault tolerance
# Usage: bash tests/test_system.sh
# Make sure ./build/dlads_coordinator is running before executing this
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

COORDINATOR_HOST="localhost"
ALERT_PORT=5555
HEARTBEAT_PORT=5556
API_PORT=8080

echo -e "${CYAN}"
echo "============================================="
echo "   DLADS System Test Suite"
echo "   Distributed Log Anomaly Detection"
echo "============================================="
echo -e "${NC}"

echo -e "${YELLOW}[*] Checking coordinator is reachable...${NC}"
if ! curl -s http://$COORDINATOR_HOST:$API_PORT/stats > /dev/null 2>&1; then
    echo -e "${RED}[ERROR] Coordinator not reachable on port $API_PORT${NC}"
    echo "        Start it first: ./build/dlads_coordinator"
    exit 1
fi
echo -e "${GREEN}[OK] Coordinator is running${NC}"
echo ""

# =============================================================================
# TEST 1 — Single node alert
# =============================================================================
echo -e "${BLUE}[TEST 1] Single node alert — should NOT trigger correlated threat${NC}"

python3 -c "
import zmq, json, time
ctx = zmq.Context()
sock = ctx.socket(zmq.PUB)
sock.connect('tcp://$COORDINATOR_HOST:$ALERT_PORT')
time.sleep(1.5)
alert = {
    'alert_id':             'test1-alert-001',
    'timestamp':            int(time.time()),
    'source_host':          'node-test1',
    'rule_id':              'RULE-SSH-BRUTE',
    'severity':             'HIGH',
    'anomaly_score':        0.0,
    'description':          'Test single node alert',
    'contributing_log_ids': ['log-t1-001'],
    'metadata':             {'source_ip': '10.0.0.1', 'username': 'root'}
}
sock.send_string(json.dumps(alert))
print('  Sent single alert from node-test1')
time.sleep(1)
"

sleep 2
THREATS=$(curl -s http://$COORDINATOR_HOST:$API_PORT/threats)
if echo "$THREATS" | grep -q "10.0.0.1"; then
    echo -e "${RED}[FAIL] Single node alert incorrectly triggered a correlated threat${NC}"
else
    echo -e "${GREEN}[PASS] Single node alert correctly did not trigger correlated threat${NC}"
fi
echo ""

# =============================================================================
# TEST 2 — Cross-node correlated threat
# =============================================================================
echo -e "${BLUE}[TEST 2] Cross-node correlation — two nodes, same IP, should trigger CRITICAL threat${NC}"

python3 -c "
import zmq, json, time
ctx = zmq.Context()
sock = ctx.socket(zmq.PUB)
sock.connect('tcp://$COORDINATOR_HOST:$ALERT_PORT')
time.sleep(1.5)

alert_a = {
    'alert_id':             'test2-alert-001',
    'timestamp':            int(time.time()),
    'source_host':          'node-auth-01',
    'rule_id':              'RULE-SSH-BRUTE',
    'severity':             'HIGH',
    'anomaly_score':        0.0,
    'description':          'Multiple failed SSH login attempts',
    'contributing_log_ids': ['log-t2-001', 'log-t2-002'],
    'metadata':             {'source_ip': '203.0.113.42', 'username': 'root', 'port': '22'}
}
sock.send_string(json.dumps(alert_a))
print('  Sent SSH brute force alert from node-auth-01')
time.sleep(2)

alert_b = {
    'alert_id':             'test2-alert-002',
    'timestamp':            int(time.time()),
    'source_host':          'node-web-01',
    'rule_id':              'RULE-SSH-BRUTE',
    'severity':             'MEDIUM',
    'anomaly_score':        0.0,
    'description':          'Repeated failed SSH attempts from same IP',
    'contributing_log_ids': ['log-t2-003'],
    'metadata':             {'source_ip': '203.0.113.42', 'username': 'admin', 'port': '22'}
}
sock.send_string(json.dumps(alert_b))
print('  Sent SSH alert from node-web-01 (same attacker IP)')
time.sleep(1)
"

sleep 3
THREATS=$(curl -s http://$COORDINATOR_HOST:$API_PORT/threats)
if echo "$THREATS" | grep -q "203.0.113.42"; then
    echo -e "${GREEN}[PASS] Cross-node correlated threat detected for 203.0.113.42${NC}"
    SEVERITY=$(echo "$THREATS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
[print('  Severity:', t['severity']) for t in d if '203.0.113.42' in t.get('source_ip','')]
" 2>/dev/null)
    echo -e "${GREEN}$SEVERITY${NC}"
else
    echo -e "${RED}[FAIL] Cross-node threat was not detected${NC}"
    echo "  Raw threats response: $THREATS"
fi
echo ""

# =============================================================================
# TEST 3 — Z-Score statistical anomaly alert
# =============================================================================
echo -e "${BLUE}[TEST 3] Z-Score anomaly alert — statistical detection${NC}"

python3 -c "
import zmq, json, time
ctx = zmq.Context()
sock = ctx.socket(zmq.PUB)
sock.connect('tcp://$COORDINATOR_HOST:$ALERT_PORT')
time.sleep(1.5)

alert = {
    'alert_id':             'test3-alert-001',
    'timestamp':            int(time.time()),
    'source_host':          'node-db-01',
    'rule_id':              'RULE-ZSCORE-ANOMALY',
    'severity':             'CRITICAL',
    'anomaly_score':        0.91,
    'description':          'Statistical anomaly: event rate deviated 9.12 std devs from baseline',
    'contributing_log_ids': ['log-t3-001'],
    'metadata': {
        'source_ip':     '172.16.0.55',
        'z_score':       '9.120',
        'current_rate':  '95.00',
        'baseline_mean': '5.00'
    }
}
sock.send_string(json.dumps(alert))
print('  Sent Z-score anomaly alert from node-db-01')
time.sleep(1)
"

sleep 2
ALERTS=$(curl -s http://$COORDINATOR_HOST:$API_PORT/alerts)
if echo "$ALERTS" | grep -q "RULE-ZSCORE-ANOMALY"; then
    echo -e "${GREEN}[PASS] Z-score anomaly alert received and stored${NC}"
else
    echo -e "${RED}[FAIL] Z-score alert not found in store${NC}"
fi
echo ""

# =============================================================================
# TEST 4 — Heartbeat and node registration
# =============================================================================
echo -e "${BLUE}[TEST 4] Heartbeat — node registration and status${NC}"

python3 << 'PYEOF'
import zmq, json, time
ctx = zmq.Context()
sock = ctx.socket(zmq.PUSH)
sock.connect('tcp://localhost:5556')
time.sleep(1.5)

for node_id, host_ip in [('node-hb-01', '192.168.1.10'), ('node-hb-02', '192.168.1.11')]:
    ping = {
        'node_id':    node_id,
        'host_ip':    host_ip,
        'uptime_sec': 60
    }
    sock.send_string(json.dumps(ping))
    print(f'  Sent heartbeat from {node_id} ({host_ip})')
    time.sleep(1.0)

time.sleep(1.0)
PYEOF

sleep 3
NODES=$(curl -s http://$COORDINATOR_HOST:$API_PORT/nodes)
if echo "$NODES" | grep -q "node-hb-01" && echo "$NODES" | grep -q "node-hb-02"; then
    echo -e "${GREEN}[PASS] Both heartbeat nodes registered successfully${NC}"
    echo "$NODES" | python3 -c "
import sys, json
nodes = json.load(sys.stdin)
for n in nodes:
    if 'hb' in n.get('node_id',''):
        print(f\"  node={n['node_id']} status={n['status']} ip={n['host_ip']}\")
" 2>/dev/null
else
    echo -e "${RED}[FAIL] Heartbeat nodes not found in registry${NC}"
    echo "  Raw nodes response: $NODES"
fi
echo ""

# =============================================================================
# TEST 5 — Fault tolerance
# =============================================================================
echo -e "${BLUE}[TEST 5] Fault tolerance — node goes silent, should be marked DEAD after 30s${NC}"
echo -e "${YELLOW}  Note: this test takes 35 seconds to complete...${NC}"

python3 << 'PYEOF'
import zmq, json, time
ctx = zmq.Context()
sock = ctx.socket(zmq.PUSH)
sock.connect('tcp://localhost:5556')
time.sleep(1.5)

ping = {'node_id': 'node-fault-01', 'host_ip': '192.168.1.99', 'uptime_sec': 10}
sock.send_string(json.dumps(ping))
print('  Registered node-fault-01')
time.sleep(0.5)
print('  Node-fault-01 going silent now...')
PYEOF

echo "  Waiting 35 seconds for dead threshold..."
sleep 35

NODES=$(curl -s http://$COORDINATOR_HOST:$API_PORT/nodes)
if echo "$NODES" | python3 -c "
import sys, json
nodes = json.load(sys.stdin)
dead = [n for n in nodes if n.get('node_id') == 'node-fault-01' and n.get('status') == 'DEAD']
exit(0 if dead else 1)
" 2>/dev/null; then
    echo -e "${GREEN}[PASS] node-fault-01 correctly marked as DEAD${NC}"
else
    echo -e "${RED}[FAIL] node-fault-01 not marked as DEAD${NC}"
    echo "  Raw nodes: $NODES"
fi
echo ""

# =============================================================================
# TEST 6 — REST API endpoints
# =============================================================================
echo -e "${BLUE}[TEST 6] REST API — all endpoints responding${NC}"

for endpoint in alerts threats nodes stats; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://$COORDINATOR_HOST:$API_PORT/$endpoint)
    if [ "$STATUS" = "200" ]; then
        echo -e "${GREEN}  [PASS] GET /$endpoint → 200 OK${NC}"
    else
        echo -e "${RED}  [FAIL] GET /$endpoint → $STATUS${NC}"
    fi
done
echo ""

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "${CYAN}"
echo "============================================="
echo "   Test Suite Complete"
echo "============================================="
echo -e "${NC}"

STATS=$(curl -s http://$COORDINATOR_HOST:$API_PORT/stats)
echo "Final system state:"
echo "$STATS" | python3 -c "
import sys, json
s = json.load(sys.stdin)
print(f\"  Total alerts:  {s['total_alerts']}\")
print(f\"  Total threats: {s['total_threats']}\")
print(f\"  Active nodes:  {s['active_nodes']}\")
" 2>/dev/null
echo ""