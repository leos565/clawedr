#!/usr/bin/env sh
# ClawEDR Linux Shield Setup
# Called by install.sh after assets are placed in /usr/local/share/clawedr/
set -eu

log() { printf '[clawedr-shield-linux] %s\n' "$*"; }

CLAWEDR_DIR="/usr/local/share/clawedr"
CLAWEDR_POLICY="$CLAWEDR_DIR/compiled_policy.json"
CLAWEDR_BPF="$CLAWEDR_DIR/bpf_hooks.c"
SERVICE_PATH="/etc/systemd/system/clawedr-monitor.service"

log "Verifying compiled policy at $CLAWEDR_DIR/compiled_policy.json"
if [ ! -f "$CLAWEDR_DIR/compiled_policy.json" ]; then
    log "ERROR: compiled_policy.json not found"
    exit 1
fi

log "Checking for BCC/eBPF support"
if ! command -v python3 >/dev/null 2>&1; then
    log "ERROR: python3 required"
    exit 1
fi

log "Ensuring /var/log/clawedr_monitor.log is writable"
touch /var/log/clawedr_monitor.log 2>/dev/null || true

log "Installing ClawEDR monitor systemd service"
PYTHON3="$(command -v python3 || echo /usr/bin/python3)"
cat > "$SERVICE_PATH" <<SERVICE
[Unit]
Description=ClawEDR Shield Monitor
After=network.target

[Service]
Type=simple
ExecStart=$PYTHON3 $CLAWEDR_DIR/monitor.py
Environment=CLAWEDR_POLICY_PATH=$CLAWEDR_POLICY
Environment=CLAWEDR_BPF_SOURCE=$CLAWEDR_BPF
Environment=CLAWEDR_LOG_FILE=/var/log/clawedr_monitor.log
Environment=PYTHONPATH=$CLAWEDR_DIR
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=clawedr-monitor

[Install]
WantedBy=multi-user.target
SERVICE

systemctl stop clawedr-monitor 2>/dev/null || true
systemctl reset-failed clawedr-monitor 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
systemctl enable clawedr-monitor 2>/dev/null || true
systemctl start clawedr-monitor 2>/dev/null || true
log "Monitor started as systemd service (systemctl kill clawedr-monitor -s SIGHUP to reload rules)"

log "Linux Shield setup complete"
