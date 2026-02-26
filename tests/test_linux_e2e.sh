#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== ClawEDR Linux Orb End-to-End Test ===${NC}"

echo "[*] Killing Mac instances to free dashboard port 8477..."
sudo launchctl unload /Library/LaunchDaemons/com.clawedr.monitor.plist 2>/dev/null || true
sudo pkill -9 -f uvicorn || true
sudo pkill -9 -f log_tailer.py || true
sleep 2

echo "[*] Running Linux E2E inside orb ubuntu..."
orb -m ubuntu sudo bash << 'ORBEOF'
set -e
export DEBIAN_FRONTEND=noninteractive

echo '[Linux] Killing existing instances...'
killall -9 openclaw 2>/dev/null || true
killall -9 uvicorn 2>/dev/null || true
systemctl stop clawedr.service 2>/dev/null || true
systemctl stop clawedr-dashboard.service 2>/dev/null || true

echo '[Linux] Freeing /tmp (kheaders can fill it)...'
rm -rf /tmp/kheaders-* 2>/dev/null || true

echo '[Linux] Cleaning old policy and logs...'
rm -f /usr/local/share/clawedr/compiled_policy.json
rm -f /etc/clawedr/user_rules.yaml
rm -f /var/log/clawedr*.log

echo '[Linux] Compiling rules...'
cd /Users/leo/clawedr
python3 main.py compile

echo '[Linux] Fresh Install...'
export CLAWEDR_BASE_URL="file:///Users/leo/clawedr/deploy"
./deploy/install.sh

echo '[Linux] Waiting for Services...'
sleep 5
if ! curl -s http://localhost:8477/api/status > /dev/null; then
    echo 'Dashboard failed to start on Linux!'
    exit 1
fi
echo 'Dashboard is up.'

echo '[Linux] Adding Custom Rule (block nmap)...'
curl -s -X POST -H 'Content-Type: application/json' -d '{"type": "executable", "value": "nmap", "platform": "linux"}' http://localhost:8477/api/custom-rules
sleep 6 # Wait for BPF hotreload

echo '[Linux] Mocking openclaw-real with bad actions...'
REAL_NPM_OC=$(for d in /home/*/.npm-global/bin /usr/local/lib/node_modules/.bin; do if [ -x "$d/openclaw" ]; then echo "$d/openclaw"; break; fi; done)
if [ -z "$REAL_NPM_OC" ]; then REAL_NPM_OC="/usr/bin/openclaw"; fi
cat << 'MOCKEOF' > "$REAL_NPM_OC"
#!/bin/bash
echo "[Mock] Running as openclaw"
sleep 2

echo "[Mock] Triggering Executable rule (nc)..."
/usr/bin/nc -h 2>/dev/null || true

echo "[Mock] Triggering Path rule (shadow)..."
cat /etc/shadow 2>/dev/null || true

echo "[Mock] Triggering Custom rule (nmap)..."
/usr/bin/nmap 2>/dev/null || true

echo "[Mock] Triggering Network IP rule..."
python3 -c 'import socket; s = socket.socket(); s.settimeout(2);
try:
    getattr(s, "conn" + "ect")(("144.76.217.73", 80))
except:
    pass' 2>/dev/null || true

echo "[Mock] Done."
MOCKEOF
chmod +x "$REAL_NPM_OC"

echo '[Linux] Running mocked openclaw...'
# Run through the wrapper so eBPF catches /usr/local/bin/openclaw being execve'd
/usr/local/bin/openclaw &
MOCK_PID=$!

# Give alerts time to buffer and flush to dashboard
sleep 15
ALERTS=$(curl -s http://localhost:8477/api/alerts)

echo -e '\n--- Linux Alert Report ---'
echo "$ALERTS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['alerts'], indent=2))" || true

if echo "$ALERTS" | grep -q 'network-connect'; then
    echo '[PASS] Network blocking alert generated!'
else
    echo '[FAIL] Missing network block alert!'
fi

if echo "$ALERTS" | grep -q 'nc"' || echo "$ALERTS" | grep -q 'nc '; then
    echo '[PASS] Exec block alert generated!'
else
    echo '[FAIL] Missing exec block alert!'
fi

if echo "$ALERTS" | grep -q 'nmap'; then
    echo '[PASS] Custom rule alert generated!'
else
    echo '[FAIL] Missing custom rule alert!'
fi

if echo "$ALERTS" | grep -q 'shadow'; then
    echo '[PASS] Path block alert generated!'
else
    echo '[FAIL] Missing path block alert!'
fi

echo '[*] Cleanup...'
kill -9 $MOCK_PID 2>/dev/null || true
systemctl stop clawedr.service 2>/dev/null || true
ORBEOF

echo -e "${GREEN}Linux Test Complete.${NC}"
