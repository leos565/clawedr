#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== ClawEDR macOS End-to-End Test ===${NC}"

echo "[*] Killing running Mac instances..."
sudo launchctl unload /Library/LaunchDaemons/com.clawedr.monitor.plist 2>/dev/null || true
sudo pkill -9 -f openclaw || true
sudo pkill -9 -f uvicorn || true
sudo pkill -9 -f log_tailer.py || true
# give ports time to free
sleep 2

echo "[*] Cleaning old policy and logs..."
sudo rm -f /usr/local/share/clawedr/compiled_policy.json
sudo rm -f /etc/clawedr/user_rules.yaml
sudo rm -f /var/log/clawedr*.log

echo "[*] Compiling Master Rules..."
cd /Users/leo/clawedr
python3 main.py compile

echo "[*] Fresh Install..."
export CLAWEDR_BASE_URL="file:///Users/leo/clawedr/deploy"
sudo -E ./deploy/install.sh

echo "[*] Verifying Services..."
sleep 5
if ! curl -s http://localhost:8477/api/status > /dev/null; then
    echo -e "${RED}Dashboard failed to start!${NC}"
    exit 1
fi
echo -e "${GREEN}Dashboard is up.${NC}"

echo "[*] Adding Custom Rule (block example.com via custom rule)..."
curl -s -X POST -H "Content-Type: application/json" -d '{"id": "USR-DOM-01", "type": "domain", "value": "example.com", "action": "deny"}' http://localhost:8477/api/user-rules
sleep 3
if ! grep -q USR-DOM-01 /etc/clawedr/user_rules.yaml; then
    echo -e "${RED}Custom rule not saved!${NC}"
fi

echo "[*] Starting mock openclaw..."
cat << 'EOF' > /tmp/mock_openclaw.sh
#!/bin/bash
while true; do sleep 1; done
EOF
chmod +x /tmp/mock_openclaw.sh
bash -c "exec -a openclaw /tmp/mock_openclaw.sh" &
MOCK_PID=$!

# For network lsof polling
sleep 2

echo "[*] Triggering blocked actions..."
# Network monitor relies on lsof which has 10s poll interval
bash -c "exec -a openclaw python3 -c 'import socket, time; s=socket.socket(); s.settimeout(2); 
try:
    s.connect((\"144.76.217.73\", 80))
except:
    pass
time.sleep(15)'" &
NET_PID=$!

# Give lsof tailer time to catch it
sleep 15

# Seatbelt exec block - should be instant but we'll trigger it anyway
# We invoke sandbox-exec directly using our compiled profile to simulate OpenClaw wrapper
sandbox-exec -f /usr/local/share/clawedr/clawedr.sb nc -z 127.0.0.1 80 2>/dev/null || true

# Seatbelt path block (Keychains)
sandbox-exec -f /usr/local/share/clawedr/clawedr.sb ls ~/Library/Keychains 2>/dev/null || true

# Wait for log_show to poll (runs every 4 seconds) and dispatch
sleep 10

echo "[*] Fetching alerts..."
ALERTS=$(curl -s http://localhost:8477/api/alerts)

echo -e "\n${BLUE}--- Alert Report ---${NC}"
echo "$ALERTS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['alerts'], indent=2))" || true

if echo "$ALERTS" | grep -q "144.76.217.73"; then
    echo -e "${GREEN}[PASS] Network blocking alert successfully generated!${NC}"
else
    echo -e "${RED}[FAIL] Missing network block alert!${NC}"
fi

if echo "$ALERTS" | grep -q "nc"; then
    echo -e "${GREEN}[PASS] Seatbelt exec alert successfully generated!${NC}"
else
    echo -e "${RED}[FAIL] Missing Seatbelt exec block alert!${NC}"
fi

if echo "$ALERTS" | grep -q 'Keychains'; then
    echo -e "${GREEN}[PASS] Seatbelt path alert successfully generated!${NC}"
else
    echo -e "${RED}[FAIL] Missing Seatbelt path block alert!${NC}"
fi

echo "[*] Cleanup..."
kill -9 $MOCK_PID 2>/dev/null || true
kill -9 $NET_PID 2>/dev/null || true
sudo launchctl unload /Library/LaunchDaemons/com.clawedr.monitor.plist 2>/dev/null || true

echo -e "${GREEN}macOS Test Complete.${NC}"
