#!/usr/bin/env sh
# ClawEDR Linux Shield Setup
# Called by install.sh after assets are placed in /usr/local/share/clawedr/
set -eu

log() { printf '[clawedr-shield-linux] %s\n' "$*"; }

CLAWEDR_DIR="/usr/local/share/clawedr"

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

log "Starting ClawEDR monitor daemon"
if command -v systemd-run >/dev/null 2>&1 && pidof systemd >/dev/null 2>&1; then
    systemd-run --unit=clawedr-monitor \
        --description="ClawEDR Shield Monitor" \
        --collect \
        python3 "$CLAWEDR_DIR/monitor.py"
    log "Monitor started as systemd transient unit (journalctl -u clawedr-monitor)"
else
    nohup python3 "$CLAWEDR_DIR/monitor.py" >/dev/null 2>&1 &
    log "Monitor PID: $! (no systemd — logs in /var/log/clawedr_monitor.log only)"
fi

log "Linux Shield setup complete"
