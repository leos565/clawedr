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
sleep 1

echo "[*] Running Linux E2E inside orb ubuntu..."
orb -m ubuntu -u root bash << 'ORBEOF'
set -e
export DEBIAN_FRONTEND=noninteractive

echo '[Linux] Syncing latest ui-revamp code for testing...'
rm -rf /tmp/clawedr_update 2>/dev/null || true
git clone -b ui-revamp https://github.com/leos565/clawedr.git /tmp/clawedr_update
cp -r /tmp/clawedr_update/deploy/* /usr/local/share/clawedr/
rm -rf /tmp/clawedr_update

echo '[Linux] Restarting existing openclaw services to pick up changes...'
systemctl restart clawedr.service 2>/dev/null || true
systemctl restart clawedr-dashboard.service 2>/dev/null || true
systemctl restart clawedr-monitor.service 2>/dev/null || true

echo '[Linux] Waiting for Services...'
sleep 3
if ! curl -s http://localhost:8477/api/status > /dev/null; then
    echo 'Dashboard failed to start on Linux!'
    exit 1
fi
echo 'Dashboard is up.'

echo '[Linux] Adding Custom Rules (block nmap, block 1.1.1.1 for DNS test)...'
TOKEN=$(cat /etc/clawedr/settings.yaml | grep dashboard_token | awk '{print $2}')
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"type": "executable", "value": "nmap", "platform": "linux"}' http://localhost:8477/api/custom-rules
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"type": "ip", "value": "1.1.1.1", "platform": "linux"}' http://localhost:8477/api/custom-rules
sleep 4 # Wait for BPF hotreload

echo '[Linux] Phase 1: Mock script (CLAWEDR_TARGET_BINARY) — validates BPF rules without OpenClaw deps'
echo '         Production uses real openclaw only; mock is test-harness only.'
MOCK_SCRIPT="/tmp/clawedr_e2e_mock.sh"
cat << 'MOCKEOF' > "$MOCK_SCRIPT"
#!/bin/bash
echo "[Mock] Running as openclaw"
sleep 1
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
echo "[Mock] Triggering DNS/UDP rule (sendto to 1.1.1.1:53)..."
# Run BEFORE curl - python is pipe-sink, curl is pipe-source; order matters for heuristic
python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns = bytes([0x00,0x00,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01])
s.sendto(dns, ("1.1.1.1", 53))
' 2>/dev/null || true
echo "[Mock] Triggering Domain rule (pastebin.com via argv)..."
curl -s --connect-timeout 1 https://pastebin.com/robots.txt 2>/dev/null || true
echo "[Mock] Done."
MOCKEOF
chmod +x "$MOCK_SCRIPT"

echo '[Linux] Running mock script...'
"$MOCK_SCRIPT" &
MOCK_PID=$!

# Give alerts time to buffer and flush to dashboard
sleep 10

# Debug: if alerts empty, show block log and monitor tail for troubleshooting
ALERTS=$(curl -H "Authorization: Bearer $TOKEN" -s http://localhost:8477/api/alerts)
if [ "$(echo "$ALERTS" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d.get("alerts",[])))' 2>/dev/null)" = "0" ]; then
  echo -e '\n[Debug] No alerts; block log:'
  cat /var/log/clawedr.log 2>/dev/null || echo "(empty)"
fi

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

if echo "$ALERTS" | grep -q '"rule_id": "DOM-016"' && echo "$ALERTS" | grep -q 'pastebin'; then
    echo '[PASS] Domain block alert generated (argv filter, DOM-016)!'
elif echo "$ALERTS" | grep -q 'pastebin' && echo "$ALERTS" | grep -q 'DOM-'; then
    echo '[PASS] Domain block alert generated (argv filter)!'
else
    echo '[FAIL] Missing domain block alert (must be DOM rule, not BIN - curl is allowed)!'
fi

if echo "$ALERTS" | grep -q 'USR-IP' && echo "$ALERTS" | grep -q '1.1.1.1'; then
    echo '[PASS] DNS/UDP block alert generated (sendto to 1.1.1.1)!'
else
    echo '[FAIL] Missing DNS/UDP block alert (nslookup via 1.1.1.1 should be blocked)!'
fi

echo '[*] Cleanup...'
kill -9 $MOCK_PID 2>/dev/null || true
rm -f "$MOCK_SCRIPT" 2>/dev/null || true
# Truncate block log so dashboard stops showing test alerts
: > /var/log/clawedr.log 2>/dev/null || true

echo '[Linux] Phase 2: Real OpenClaw — verify blocking of gateway/agent exec'
OPENCLAW_TEST="${OPENCLAW_TEST:-$(cd /Users/leo/clawedr 2>/dev/null && pwd)/tests/test_openclaw_curl_block.sh}"
if command -v openclaw >/dev/null 2>&1 && [ -f "${OPENCLAW_TEST}" ]; then
  bash "${OPENCLAW_TEST}" 2>&1 || true
else
  echo '[SKIP] openclaw not installed or test script not found — Phase 2 skipped'
fi
ORBEOF

echo -e "${GREEN}Linux Test Complete.${NC}"
