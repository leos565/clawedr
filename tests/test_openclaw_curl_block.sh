#!/bin/bash
# E2E test: curl to 8.8.8.8 from OpenClaw must be blocked (SIGKILL).
# Run: orb -m ubuntu -u root bash /Users/leo/clawedr/tests/test_openclaw_curl_block.sh
set -e

echo "=== OpenClaw curl 8.8.8.8 Block E2E Test ==="

# 0. Deploy latest monitor if running from dev (orb mounts host fs)
if [ -f /Users/leo/clawedr/deploy/linux/monitor.py ]; then
  echo "[0] Deploying latest monitor from repo..."
  cp /Users/leo/clawedr/deploy/linux/monitor.py /usr/local/share/clawedr/monitor.py 2>/dev/null || true
fi

# 1. Verify clawedr and openclaw
echo "[1] Verifying ClawEDR..."
systemctl is-active clawedr-monitor || { echo "FAIL: clawedr-monitor not active"; exit 1; }
echo "[1] OK: clawedr-monitor active"

echo "[2] Verifying OpenClaw..."
command -v openclaw || { echo "FAIL: openclaw not found"; exit 1; }
echo "[2] OK: openclaw at $(which openclaw)"

# 2. Ensure 8.8.8.8 blocked
echo "[3] Ensuring 8.8.8.8 in blocked_ips..."
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"type":"ip","value":"8.8.8.8","platform":"linux"}' \
  http://localhost:8477/api/custom-rules 2>/dev/null || true
sleep 4

# 3. Restart monitor (normal mode, no CLAWEDR_TARGET_BINARY)
echo "[4] Restarting monitor..."
systemctl restart clawedr-monitor
sleep 5

# Clear block log so we only see new alerts
: > /var/log/clawedr.log 2>/dev/null || true

# 4. Ensure exec is allowed and bypass approvals for test
echo "[4b] Configuring gateway tools..."
python3 -c "
import json
p='/root/.openclaw/openclaw.json'
with open(p) as f: c=json.load(f)
c.setdefault('gateway',{}).setdefault('tools',{})['allow']=['exec']
c.setdefault('tools',{})['allow']=['exec','process','read']
c.setdefault('tools',{}).setdefault('exec',{})['security']='full'
c.setdefault('tools',{}).setdefault('exec',{})['ask']='off'
c.setdefault('tools',{}).setdefault('exec',{})['host']='gateway'  # Run on host so ClawEDR tracks
# Force sandbox off so exec runs on gateway host (not Docker)
c.setdefault('agents',{}).setdefault('defaults',{})['sandbox']={'mode':'off'}
# Remove invalid profile if we added it
if 'tools' in c and 'profile' in c.get('tools',{}):
    del c['tools']['profile']
with open(p,'w') as f: json.dump(c,f,indent=2)
" 2>/dev/null || true

# 5. Run curl as child of tracked process — three methods:
# A) Node direct: node spawns curl (same as gateway exec) — verifies BPF
# B) OpenClaw agent: agent CLI uses exec host=gateway — direct agent flow
# C) OpenClaw cron: cron triggers agent -> exec — scheduled flow
echo "[5] Starting gateway and running curl..."
cd /root/.openclaw/workspace 2>/dev/null || cd /tmp
TOKEN=$(python3 -c "import json; print(json.load(open('/root/.openclaw/openclaw.json'))['gateway']['auth']['token'])")
export OPENCLAW_GATEWAY_TOKEN="$TOKEN"

pkill -f "openclaw.*gateway" 2>/dev/null || true
sleep 2
openclaw gateway run --allow-unconfigured 2>/dev/null &
GPID=$!
sleep 12

# 5a) Node direct test (always works if BPF correct)
echo "[5a] Node->curl (simulates gateway exec)..."
RESULT=$(node -e "
const { execSync } = require('child_process');
try {
  const r = execSync('curl -s --connect-timeout 3 http://8.8.8.8/ 2>&1; echo EXIT:\$?', { encoding: 'utf8' });
  console.log(r);
} catch (e) {
  console.log('Killed, signal:', e.signal, 'exit:', e.status);
  if (e.stdout) console.log(e.stdout);
}
" 2>&1) || true
echo "Node result: $RESULT"

# 5b) OpenClaw agent direct (agent CLI -> gateway exec -> curl)
# Requires: API key (openclaw agents add main), tools.exec.host=gateway
echo "[5b] OpenClaw agent->exec->curl..."
AGENT_RESULT=$(timeout 90 openclaw agent --agent main --message "Use the exec tool to run this command and report only the exit code: curl -s --connect-timeout 2 http://8.8.8.8/ 2>&1; echo EXIT:\$?" 2>&1) || true
echo "Agent result: ${AGENT_RESULT:0:200}..."

# 5c) OpenClaw cron (cron->agent->exec->curl)
# Requires: configured channel (telegram, etc.) for cron-triggered agent
echo "[5c] OpenClaw cron->agent->exec->curl..."
openclaw cron list 2>/dev/null | grep -A1 clawedr-test | grep id | sed 's/.*"id": "\([^"]*\)".*/\1/' | xargs -r -I{} openclaw cron rm {} 2>/dev/null || true
CRON_ADD=$(openclaw cron add --name clawedr-test --cron "0 0 1 1 *" --message "Use the exec tool to run: curl -s --connect-timeout 2 http://8.8.8.8/ 2>&1; echo EXIT:\$?" --json 2>/dev/null) || true
CRON_ID=$(echo "$CRON_ADD" | grep -o '"id": "[^"]*"' | head -1 | cut -d'"' -f4)
if [ -n "$CRON_ID" ]; then
  CRON_RESULT=$(timeout 60 openclaw cron run "$CRON_ID" 2>&1) || true
  openclaw cron rm "$CRON_ID" 2>/dev/null || true
  echo "Cron result: $CRON_RESULT"
fi
sleep 5

# 6. Check alerts and block log
echo "[6] Checking alerts and block log..."
ALERTS=$(curl -s http://localhost:8477/api/alerts 2>/dev/null || echo '{"alerts":[]}')
BLOCK_LOG=$(tail -20 /var/log/clawedr.log 2>/dev/null || tail -20 /var/log/clawedr_monitor.log 2>/dev/null || echo "")
if echo "$ALERTS" | grep -q '8.8.8.8'; then
  echo "[PASS] Block alert for 8.8.8.8"
elif echo "$BLOCK_LOG" | grep -q '8.8.8.8'; then
  echo "[PASS] Block logged for 8.8.8.8 (monitor log)"
else
  echo "[FAIL] No block alert for 8.8.8.8"
  echo "Alerts: $ALERTS"
  echo "Block log tail: $BLOCK_LOG"
fi

# Check exit codes
if echo "$RESULT" | grep -q 'EXIT:137\|signal: SIGKILL'; then
  echo "[PASS] Node test: curl received SIGKILL (exit 137)"
elif echo "$RESULT" | grep -q 'EXIT:'; then
  echo "[INFO] Node test curl exit: $(echo "$RESULT" | grep -o 'EXIT:[0-9]*')"
fi
if echo "$AGENT_RESULT" | grep -q 'EXIT:137\|137\|SIGKILL'; then
  echo "[PASS] Agent test: curl blocked (exit 137)"
elif echo "$AGENT_RESULT" | grep -q 'EXIT:'; then
  echo "[INFO] Agent test curl exit: $(echo "$AGENT_RESULT" | grep -o 'EXIT:[0-9]*' | head -1)"
fi

kill $GPID 2>/dev/null || true
echo "=== Done ==="
