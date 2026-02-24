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
    # Run lookup as SUDO_USER when available — root's PATH may not include Homebrew
    _save_real_openclaw() {
        local path="$1"
        if [ ! -e "$path" ]; then return 1; fi
        if grep -q "CLAWEDR_SB" "$path" 2>/dev/null; then return 1; fi
        local resolved
        if [ -n "$SUDO_USER" ]; then
            resolved=$(sudo -u "$SUDO_USER" python3 -c "import os; print(os.path.realpath('$path'))" 2>/dev/null) || resolved="$path"
        else
            resolved=$(python3 -c "import os; print(os.path.realpath('$path'))" 2>/dev/null) || resolved="$path"
        fi
        log "Saving real openclaw from $path -> $CLAWEDR_REAL"
        cat > "$CLAWEDR_REAL" <<INNER
#!/bin/sh
exec node "$resolved" "\$@"
INNER
        chmod +x "$CLAWEDR_REAL"
        return 0
    }

    # Prefer path from user's environment (which openclaw as SUDO_USER)
    if [ ! -x "$CLAWEDR_REAL" ] && [ -n "$SUDO_USER" ]; then
        user_path=$(sudo -u "$SUDO_USER" which openclaw 2>/dev/null)
        [ -n "$user_path" ] && _save_real_openclaw "$user_path" || true
    fi

    if [ ! -x "$CLAWEDR_REAL" ]; then
        _save_real_openclaw /opt/homebrew/bin/openclaw || \
        _save_real_openclaw /usr/local/bin/openclaw || \
        true
    fi

    # Fallback: find openclaw.mjs in npm global modules
    if [ ! -x "$CLAWEDR_REAL" ]; then
        mjs_paths="/opt/homebrew/lib/node_modules/openclaw/openclaw.mjs /usr/local/lib/node_modules/openclaw/openclaw.mjs"
        if [ -n "$SUDO_USER" ]; then
            npm_prefix=$(sudo -u "$SUDO_USER" npm config get prefix 2>/dev/null)
            [ -n "$npm_prefix" ] && mjs_paths="$npm_prefix/lib/node_modules/openclaw/openclaw.mjs $mjs_paths"
        fi
        for mjs in $mjs_paths; do
            if [ -f "$mjs" ] && ! grep -q "CLAWEDR_SB" "$mjs" 2>/dev/null; then
                log "Saving real openclaw from $mjs -> $CLAWEDR_REAL"
                cat > "$CLAWEDR_REAL" <<INNER
#!/bin/sh
exec node "$mjs" "\$@"
INNER
                chmod +x "$CLAWEDR_REAL"
                break
            fi
        done
    fi

    if [ ! -x "$CLAWEDR_REAL" ]; then
        log "WARNING: Could not find real openclaw — install openclaw first (npm install -g openclaw)"
        return 0
    fi

    _install_wrapper_at() {
        local path="$1"
        if [ ! -e "$path" ]; then return 0; fi
        log "Installing ClawEDR wrapper at $path"
        rm -f "$path"
        cat > "$path" <<'WRAPPER'
#!/usr/bin/env sh
# openclaw — ClawEDR Zero-Habit Hijack wrapper (macOS)
CLAWEDR_SB="/usr/local/share/clawedr/clawedr.sb"
CLAWEDR_REAL="/usr/local/share/clawedr/openclaw-real"
REAL_OPENCLAW=""
REAL_OPENCLAW_ARG0=""
if [ -x "$CLAWEDR_REAL" ]; then
    REAL_OPENCLAW="$CLAWEDR_REAL"
elif [ -x /opt/homebrew/bin/openclaw ] && ! grep -q "CLAWEDR_SB" /opt/homebrew/bin/openclaw 2>/dev/null; then
    REAL_OPENCLAW="/opt/homebrew/bin/openclaw"
elif [ -f /opt/homebrew/lib/node_modules/openclaw/openclaw.mjs ]; then
    REAL_OPENCLAW="/opt/homebrew/bin/node"
    REAL_OPENCLAW_ARG0="/opt/homebrew/lib/node_modules/openclaw/openclaw.mjs"
fi
if [ -n "$REAL_OPENCLAW" ] && [ -f "$CLAWEDR_SB" ]; then
    [ -n "$REAL_OPENCLAW_ARG0" ] && exec sandbox-exec -f "$CLAWEDR_SB" -- "$REAL_OPENCLAW" "$REAL_OPENCLAW_ARG0" "$@"
    exec sandbox-exec -f "$CLAWEDR_SB" -- "$REAL_OPENCLAW" "$@"
elif [ -n "$REAL_OPENCLAW" ]; then
    [ -n "$REAL_OPENCLAW_ARG0" ] && exec "$REAL_OPENCLAW" "$REAL_OPENCLAW_ARG0" "$@"
    exec "$REAL_OPENCLAW" "$@"
else
    echo "[openclaw] ERROR: ClawEDR not installed. Run: curl -fsSL https://raw.githubusercontent.com/leos565/clawedr/main/deploy/install.sh | sudo sh" >&2
    exit 1
fi
WRAPPER
        chmod +x "$path"
    }

    # Only install at /usr/local/bin — do NOT overwrite /opt/homebrew/bin/openclaw.
    # npm/node may run `node /opt/homebrew/bin/openclaw`; that path must stay the
    # real .mjs. Ensure /usr/local/bin is before /opt/homebrew/bin in PATH.
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

uninstall_macos() {
    log "Uninstalling ClawEDR (macOS)"
    pkill -f "log_tailer.py" 2>/dev/null || true
    # Restore openclaw if we overwrote it (older installs overwrote both paths)
    _restore() {
        local path="$1"
        [ ! -e "$path" ] || ! grep -q "CLAWEDR_SB" "$path" 2>/dev/null && return 0
        if [ -f /usr/local/share/clawedr/openclaw-real ]; then
            resolved=$(grep 'exec node "' /usr/local/share/clawedr/openclaw-real 2>/dev/null | sed 's/.*exec node "\([^"]*\)".*/\1/')
            if [ -n "$resolved" ] && [ -f "$resolved" ]; then
                log "Restoring openclaw at $path"
                rm -f "$path"
                ln -sf "$resolved" "$path" 2>/dev/null || cp /usr/local/share/clawedr/openclaw-real "$path"
                [ -x "$path" ] || chmod +x "$path"
            fi
        fi
    }
    _restore /opt/homebrew/bin/openclaw
    _restore /usr/local/bin/openclaw
    rm -rf /usr/local/share/clawedr
    log "ClawEDR uninstalled"
}

uninstall_linux() {
    log "Uninstalling ClawEDR (Linux)"
    pkill -f "monitor.py" 2>/dev/null || true
    systemctl stop clawedr-monitor 2>/dev/null || true
    rm -f /tmp/clawedr-monitor.pid /var/log/clawedr_monitor.log
    rm -rf /usr/local/share/clawedr
    rm -f /usr/local/bin/openclaw
    log "ClawEDR uninstalled. Run 'npm install -g openclaw' to restore openclaw."
}

# --- main ---
if [ "${1:-}" = "--uninstall" ]; then
    OS="$(detect_os)"
    case "$OS" in
        macos) uninstall_macos ;;
        linux) uninstall_linux ;;
    esac
    exit 0
fi

OS="$(detect_os)"
log "ClawEDR Installer v${CLAWEDR_VERSION} — OS=$OS"

case "$OS" in
    macos) install_macos ;;
    linux) install_linux ;;
esac

log "Done. Run 'openclaw <your-agent>' to start with protection enabled."
