#!/bin/bash
# Run on orb -m ubuntu -u root
# Tests that curl to 8.8.8.8 from openclaw gateway exec gets blocked (SIGKILL)
set -e
cd /root/.openclaw/workspace 2>/dev/null || cd /tmp
export OPENCLAW_GATEWAY_TOKEN=$(python3 -c "import json; print(json.load(open('/root/.openclaw/openclaw.json'))['gateway']['auth']['token'])")

# Ensure 8.8.8.8 blocked
curl -s -X POST -H "Content-Type: application/json" -d '{"type":"ip","value":"8.8.8.8","platform":"linux"}' http://localhost:8477/api/custom-rules 2>/dev/null || true
sleep 3

# Restart monitor normal mode
systemctl restart clawedr-monitor 2>/dev/null || true
sleep 4

# Start gateway
pkill -f openclaw-gateway 2>/dev/null || true
sleep 2
openclaw gateway run --allow-unconfigured 2>/dev/null &
GPID=$!
sleep 10

# Invoke exec with host=gateway - gateway spawns curl
RESULT=$(curl -s -X POST "http://127.0.0.1:18789/tools/invoke" \
  -H "Authorization: Bearer $OPENCLAW_GATEWAY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool":"exec","args":{"command":"curl -s --connect-timeout 2 http://8.8.8.8/ 2>&1; echo EXIT:$?","host":"gateway"}}')

echo "Result: $RESULT"
sleep 3

# Check alerts
ALERTS=$(curl -s http://localhost:8477/api/alerts)
if echo "$ALERTS" | grep -q '8.8.8.8'; then
  echo "PASS: Block alert for 8.8.8.8"
else
  echo "FAIL: No block alert. Alerts: $ALERTS"
fi

# Check if curl got exit 137 (SIGKILL)
if echo "$RESULT" | grep -q 'EXIT:137'; then
  echo "PASS: curl received SIGKILL (exit 137)"
elif echo "$RESULT" | grep -q 'EXIT:'; then
  echo "INFO: curl exit: $(echo "$RESULT" | grep -o 'EXIT:[0-9]*')"
fi

kill $GPID 2>/dev/null || true
