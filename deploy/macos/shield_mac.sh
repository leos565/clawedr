#!/usr/bin/env sh
# ClawEDR macOS Shield Setup
# Called by install.sh after assets are placed in /usr/local/share/clawedr/
set -eu

log() { printf '[clawedr-shield-mac] %s\n' "$*"; }

CLAWEDR_DIR="/usr/local/share/clawedr"

log "Verifying Seatbelt profile at $CLAWEDR_DIR/clawedr.sb"
if [ ! -f "$CLAWEDR_DIR/clawedr.sb" ]; then
    log "ERROR: clawedr.sb not found"
    exit 1
fi

log "Verifying sandbox-exec is available"
if ! command -v sandbox-exec >/dev/null 2>&1; then
    log "ERROR: sandbox-exec not found — is this macOS?"
    exit 1
fi

log "Starting log tailer daemon"
if command -v python3 >/dev/null 2>&1; then
    # Install pyoslog so logs appear in Console.app (optional; fallback to /tmp file if missing)
    python3 -m pip install --quiet pyoslog 2>/dev/null || true
    nohup python3 "$CLAWEDR_DIR/log_tailer.py" \
        > /tmp/clawedr_log_tailer.log 2>&1 &
    log "Log tailer PID: $!"
else
    log "WARNING: python3 not found — log tailer not started"
fi

log "macOS Shield setup complete"
