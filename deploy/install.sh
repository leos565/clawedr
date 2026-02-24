#!/usr/bin/env sh
# ClawEDR Universal Dispatcher — ONE-LINER INSTALLER
# Detects OS via uname -s, fetches the correct Shield setup script,
# and on macOS installs the Zero-Habit Hijack openclaw wrapper.
#
# Usage:
#   curl -fsSL <REGISTRY_URL>/install.sh | sudo sh

set -eu

CLAWEDR_VERSION="${CLAWEDR_VERSION:-latest}"

# Derive the base URL from where this script was fetched, or fall back to a
# hardcoded default.  Override with CLAWEDR_BASE_URL if needed.
CLAWEDR_BASE_URL="${CLAWEDR_BASE_URL:-https://raw.githubusercontent.com/leos565/clawedr/main/deploy}"

log()  { printf '[clawedr] %s\n' "$*"; }
die()  { log "ERROR: $*"; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)  echo "linux" ;;
        *)      die "Unsupported OS: $(uname -s)" ;;
    esac
}

fetch() {
    url="$1"; dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url" || die "Failed to download $url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url" || die "Failed to download $url"
    else
        die "Neither curl nor wget found"
    fi
}

install_macos() {
    log "Detected macOS — installing ClawEDR Shield"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    fetch "$CLAWEDR_BASE_URL/macos/shield_mac.sh"  "$tmpdir/shield_mac.sh"
    fetch "$CLAWEDR_BASE_URL/macos/clawedr.sb"      "$tmpdir/clawedr.sb"
    fetch "$CLAWEDR_BASE_URL/macos/log_tailer.py"   "$tmpdir/log_tailer.py"

    mkdir -p /usr/local/share/clawedr
    cp "$tmpdir/clawedr.sb"    /usr/local/share/clawedr/
    cp "$tmpdir/log_tailer.py" /usr/local/share/clawedr/
    chmod +x "$tmpdir/shield_mac.sh"
    sh "$tmpdir/shield_mac.sh"

    # Zero-Habit Hijack: install the openclaw wrapper
    install_openclaw_wrapper

    log "macOS Shield installed successfully"
}

install_linux() {
    log "Detected Linux — installing ClawEDR Shield"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    fetch "$CLAWEDR_BASE_URL/compiled_policy.json"    "$tmpdir/compiled_policy.json"
    fetch "$CLAWEDR_BASE_URL/linux/shield_linux.sh"    "$tmpdir/shield_linux.sh"
    fetch "$CLAWEDR_BASE_URL/linux/bpf_hooks.c"        "$tmpdir/bpf_hooks.c"
    fetch "$CLAWEDR_BASE_URL/linux/monitor.py"         "$tmpdir/monitor.py"

    mkdir -p /usr/local/share/clawedr
    cp "$tmpdir/compiled_policy.json" /usr/local/share/clawedr/
    cp "$tmpdir/bpf_hooks.c"         /usr/local/share/clawedr/
    cp "$tmpdir/monitor.py"          /usr/local/share/clawedr/
    chmod +x "$tmpdir/shield_linux.sh"
    sh "$tmpdir/shield_linux.sh"

    install_openclaw_wrapper_linux

    log "Linux Shield installed successfully"
}

install_openclaw_wrapper() {
    CLAWEDR_REAL="/usr/local/share/clawedr/openclaw-real"
    CLAWEDR_SB="/usr/local/share/clawedr/clawedr.sb"

    # Find real openclaw (before we overwrite)
    _save_real_openclaw() {
        local path="$1"
        if [ ! -e "$path" ]; then return 1; fi
        if grep -q "CLAWEDR_SB" "$path" 2>/dev/null; then return 1; fi
        local resolved
        resolved=$(python3 -c "import os; print(os.path.realpath('$path'))" 2>/dev/null) || resolved="$path"
        log "Saving real openclaw from $path -> $CLAWEDR_REAL"
        cat > "$CLAWEDR_REAL" <<INNER
#!/bin/sh
exec node "$resolved" "\$@"
INNER
        chmod +x "$CLAWEDR_REAL"
        return 0
    }

    if [ ! -x "$CLAWEDR_REAL" ]; then
        _save_real_openclaw /opt/homebrew/bin/openclaw || \
        _save_real_openclaw /usr/local/bin/openclaw || \
        true
    fi

    if [ ! -x "$CLAWEDR_REAL" ]; then
        log "WARNING: Could not find real openclaw — install openclaw first (npm install -g openclaw)"
        return 0
    fi

    _install_wrapper_at() {
        local path="$1"
        if [ ! -e "$path" ]; then return 0; fi
        log "Installing ClawEDR wrapper at $path"
        cat > "$path" <<'WRAPPER'
#!/usr/bin/env sh
# openclaw — ClawEDR Zero-Habit Hijack wrapper (macOS)
CLAWEDR_SB="/usr/local/share/clawedr/clawedr.sb"
CLAWEDR_REAL="/usr/local/share/clawedr/openclaw-real"
if [ -f "$CLAWEDR_SB" ] && [ -x "$CLAWEDR_REAL" ]; then
    exec sandbox-exec -f "$CLAWEDR_SB" -- "$CLAWEDR_REAL" "$@"
else
    [ -x "$CLAWEDR_REAL" ] || { echo "[openclaw] ERROR: $CLAWEDR_REAL not found" >&2; exit 1; }
    exec "$CLAWEDR_REAL" "$@"
fi
WRAPPER
        chmod +x "$path"
    }

    _install_wrapper_at /opt/homebrew/bin/openclaw
    _install_wrapper_at /usr/local/bin/openclaw
}

install_openclaw_wrapper_linux() {
    log "Installing openclaw wrapper at /usr/local/bin/openclaw"
    cat > /usr/local/bin/openclaw <<'WRAPPER'
#!/usr/bin/env sh
# openclaw — ClawEDR wrapper (Linux / eBPF)
# Ensures the BPF monitor daemon is running, then delegates to the real
# OpenClaw binary.  The monitor auto-detects this binary in BPF and
# tracks the entire process tree for policy enforcement.
CLAWEDR_DIR="/usr/local/share/clawedr"
CLAWEDR_POLICY="$CLAWEDR_DIR/compiled_policy.json"
CLAWEDR_BPF="$CLAWEDR_DIR/bpf_hooks.c"
CLAWEDR_MONITOR="$CLAWEDR_DIR/monitor.py"
CLAWEDR_PID="/tmp/clawedr-monitor.pid"

_find_real_openclaw() {
    for d in /home/*/.npm-global/bin /usr/local/lib/node_modules/.bin; do
        if [ -x "$d/openclaw" ] && [ "$(readlink -f "$d/openclaw")" != "$(readlink -f /usr/local/bin/openclaw)" ]; then
            echo "$d/openclaw"
            return
        fi
    done
}

CLAWEDR_REAL="$(_find_real_openclaw)"
if [ -z "$CLAWEDR_REAL" ]; then
    echo "[clawedr] ERROR: Cannot find real openclaw binary" >&2
    exit 1
fi

if [ ! -f "$CLAWEDR_POLICY" ]; then
    echo "[clawedr] WARNING: Policy not found — running unprotected" >&2
    exec "$CLAWEDR_REAL" "$@"
fi

if [ -f "$CLAWEDR_PID" ] && kill -0 "$(cat "$CLAWEDR_PID")" 2>/dev/null; then
    :
else
    echo "[clawedr] Starting ClawEDR eBPF monitor..."
    sudo CLAWEDR_POLICY_PATH="$CLAWEDR_POLICY" \
         CLAWEDR_BPF_SOURCE="$CLAWEDR_BPF" \
         CLAWEDR_LOG_FILE=/var/log/clawedr_monitor.log \
        nohup python3 "$CLAWEDR_MONITOR" >/dev/null 2>&1 &
    MONITOR_PID=$!
    echo "$MONITOR_PID" > "$CLAWEDR_PID" 2>/dev/null || true
    sleep 2
    echo "[clawedr] Monitor active (PID $MONITOR_PID)"
fi

exec "$CLAWEDR_REAL" "$@"
WRAPPER
    chmod +x /usr/local/bin/openclaw
}

# --- main ---
OS="$(detect_os)"
log "ClawEDR Installer v${CLAWEDR_VERSION} — OS=$OS"

case "$OS" in
    macos) install_macos ;;
    linux) install_linux ;;
esac

log "Done. Run 'openclaw <your-agent>' to start with protection enabled."
