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

CLAWEDR_DIR="/usr/local/share/clawedr"
CLAWEDR_DASHBOARD_PORT="${CLAWEDR_DASHBOARD_PORT:-8477}"

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
    if [ "${url#file://}" != "$url" ]; then
        cp "${url#file://}" "$dest" || die "Failed to copy local $url"
        return
    elif [ "${url#http}" = "$url" ]; then
        cp "$url" "$dest" || die "Failed to copy local $url"
        return
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url" || die "Failed to download $url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url" || die "Failed to download $url"
    else
        die "Neither curl nor wget found"
    fi
}

# ---------------------------------------------------------------------------
# Dashboard: pip deps + service install (shared by both platforms)
# ---------------------------------------------------------------------------

install_dashboard_deps() {
    log "Installing Dashboard dependencies (fastapi, uvicorn)..."

    # Prefer pip3, fall back to pip, then python3 -m pip
    PIP=""
    if command -v pip3 >/dev/null 2>&1; then
        PIP="pip3"
    elif command -v pip >/dev/null 2>&1; then
        PIP="pip"
    else
        PIP="python3 -m pip"
    fi

    # Strategy: try normal install first.  On modern Debian/Ubuntu, system-managed
    # packages (e.g. typing_extensions) can block pip.  We handle this with:
    #   1. --break-system-packages (PEP 668 override)
    #   2. --ignore-installed (skip uninstall of apt-managed packages)
    #   3. --force-reinstall as last resort
    if $PIP install --quiet --break-system-packages --ignore-installed \
            fastapi uvicorn typing-extensions pydantic pyyaml 2>/dev/null; then
        log "Dashboard dependencies installed successfully"
    elif $PIP install --quiet --break-system-packages --force-reinstall \
            fastapi uvicorn typing-extensions pydantic pyyaml 2>/dev/null; then
        log "Dashboard dependencies installed (force-reinstall)"
    elif $PIP install --quiet fastapi uvicorn typing-extensions pydantic pyyaml 2>/dev/null; then
        log "Dashboard dependencies installed"
    else
        log "WARNING: Could not install dependencies via pip."
        log "  Install manually: pip3 install fastapi uvicorn typing-extensions pydantic pyyaml"
    fi
}

install_dashboard_launchd() {
    log "Installing Dashboard launchd service..."

    PLIST_LABEL="com.clawedr.dashboard"
    PLIST_DIR="/Library/LaunchDaemons"
    PLIST_PATH="$PLIST_DIR/$PLIST_LABEL.plist"

    # Stop existing service first
    if launchctl list "$PLIST_LABEL" >/dev/null 2>&1; then
        log "Stopping existing dashboard service..."
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
    fi

    # Find python3 binary path
    PYTHON3="$(command -v python3 || echo /usr/bin/python3)"

    cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$PLIST_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON3</string>
        <string>$CLAWEDR_DIR/dashboard/app.py</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>CLAWEDR_POLICY_PATH</key>
        <string>$CLAWEDR_DIR/compiled_policy.json</string>
        <key>CLAWEDR_DASHBOARD_PORT</key>
        <string>$CLAWEDR_DASHBOARD_PORT</string>
        <key>PYTHONPATH</key>
        <string>$CLAWEDR_DIR</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/clawedr_dashboard.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/clawedr_dashboard.log</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
PLIST

    launchctl load -w "$PLIST_PATH" 2>/dev/null || true
    log "Dashboard launchd service installed and started at http://localhost:$CLAWEDR_DASHBOARD_PORT"
}

install_dashboard_systemd() {
    log "Installing Dashboard systemd service..."

    PYTHON3="$(command -v python3 || echo /usr/bin/python3)"
    SERVICE_PATH="/etc/systemd/system/clawedr-dashboard.service"

    # Stop existing service first to avoid conflicts
    if systemctl is-active clawedr-dashboard >/dev/null 2>&1; then
        log "Stopping existing dashboard service..."
        systemctl stop clawedr-dashboard 2>/dev/null || true
    fi

    cat > "$SERVICE_PATH" <<SERVICE
[Unit]
Description=ClawEDR Dashboard
After=network.target

[Service]
Type=simple
ExecStart=$PYTHON3 $CLAWEDR_DIR/dashboard/app.py
Environment=CLAWEDR_POLICY_PATH=$CLAWEDR_DIR/compiled_policy.json
Environment=CLAWEDR_DASHBOARD_PORT=$CLAWEDR_DASHBOARD_PORT
Environment=PYTHONPATH=$CLAWEDR_DIR
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=clawedr-dashboard

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload 2>/dev/null || true
    systemctl enable clawedr-dashboard 2>/dev/null || true
    systemctl restart clawedr-dashboard 2>/dev/null || true
    log "Dashboard systemd service installed and started at http://localhost:$CLAWEDR_DASHBOARD_PORT"
}

# ---------------------------------------------------------------------------
# macOS install
# ---------------------------------------------------------------------------

install_macos() {
    log "Detected macOS — installing ClawEDR Shield"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    fetch "$CLAWEDR_BASE_URL/macos/shield_mac.sh"           "$tmpdir/shield_mac.sh"
    fetch "$CLAWEDR_BASE_URL/macos/clawedr.sb"               "$tmpdir/clawedr.sb"
    fetch "$CLAWEDR_BASE_URL/macos/log_tailer.py"            "$tmpdir/log_tailer.py"
    fetch "$CLAWEDR_BASE_URL/macos/apply_macos_policy.py"    "$tmpdir/apply_macos_policy.py"
    fetch "$CLAWEDR_BASE_URL/compiled_policy.json"           "$tmpdir/compiled_policy.json"
    # Shared modules
    fetch "$CLAWEDR_BASE_URL/shared/user_rules.py"           "$tmpdir/user_rules.py"
    fetch "$CLAWEDR_BASE_URL/shared/alert_dispatcher.py"     "$tmpdir/alert_dispatcher.py"
    # Dashboard
    fetch "$CLAWEDR_BASE_URL/dashboard/app.py"               "$tmpdir/dashboard_app.py"
    fetch "$CLAWEDR_BASE_URL/dashboard/templates/index.html" "$tmpdir/dashboard_index.html"

    mkdir -p "$CLAWEDR_DIR/shared"
    mkdir -p "$CLAWEDR_DIR/dashboard/templates"
    mkdir -p "/etc/clawedr"
    chmod 777 "/etc/clawedr" || true
    
    # Initialize persistent log file with wide permissions
    touch "/var/log/clawedr.log"
    chmod 666 "/var/log/clawedr.log" || true
    
    cp "$tmpdir/clawedr.sb"              "$CLAWEDR_DIR/"
    cp "$tmpdir/log_tailer.py"           "$CLAWEDR_DIR/"
    cp "$tmpdir/apply_macos_policy.py"   "$CLAWEDR_DIR/"
    cp "$tmpdir/compiled_policy.json"    "$CLAWEDR_DIR/"
    cp "$tmpdir/user_rules.py"           "$CLAWEDR_DIR/shared/"
    cp "$tmpdir/alert_dispatcher.py"     "$CLAWEDR_DIR/shared/"
    cp "$tmpdir/dashboard_app.py"        "$CLAWEDR_DIR/dashboard/app.py"
    cp "$tmpdir/dashboard_index.html"    "$CLAWEDR_DIR/dashboard/templates/index.html"
    touch "$CLAWEDR_DIR/shared/__init__.py"
    touch "$CLAWEDR_DIR/dashboard/__init__.py"
    chmod +x "$tmpdir/shield_mac.sh"
    sh "$tmpdir/shield_mac.sh"

    # Zero-Habit Hijack: install the openclaw wrapper
    install_openclaw_wrapper

    # Dashboard
    install_dashboard_deps
    install_dashboard_launchd

    log "macOS Shield installed successfully"
}

# ---------------------------------------------------------------------------
# Linux install
# ---------------------------------------------------------------------------

install_linux() {
    log "Detected Linux — installing ClawEDR Shield"

    # Stop clawedr services if running so install can replace files and restart cleanly
    if command -v systemctl >/dev/null 2>&1; then
        for svc in clawedr-monitor clawedr-dashboard; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                log "Stopping existing $svc service..."
                systemctl stop "$svc" 2>/dev/null || true
            fi
        done
    fi

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    fetch "$CLAWEDR_BASE_URL/compiled_policy.json"           "$tmpdir/compiled_policy.json"
    fetch "$CLAWEDR_BASE_URL/linux/shield_linux.sh"          "$tmpdir/shield_linux.sh"
    fetch "$CLAWEDR_BASE_URL/linux/bpf_hooks.c"              "$tmpdir/bpf_hooks.c"
    fetch "$CLAWEDR_BASE_URL/linux/monitor.py"               "$tmpdir/monitor.py"
    # Shared modules
    fetch "$CLAWEDR_BASE_URL/shared/user_rules.py"           "$tmpdir/user_rules.py"
    fetch "$CLAWEDR_BASE_URL/shared/alert_dispatcher.py"     "$tmpdir/alert_dispatcher.py"
    # Dashboard
    fetch "$CLAWEDR_BASE_URL/dashboard/app.py"               "$tmpdir/dashboard_app.py"
    fetch "$CLAWEDR_BASE_URL/dashboard/templates/index.html" "$tmpdir/dashboard_index.html"

    mkdir -p "$CLAWEDR_DIR/shared"
    mkdir -p "$CLAWEDR_DIR/dashboard/templates"
    mkdir -p "/etc/clawedr"
    chmod 777 "/etc/clawedr" || true
    
    # Initialize persistent log file with wide permissions
    touch "/var/log/clawedr.log"
    chmod 666 "/var/log/clawedr.log" || true
    
    cp "$tmpdir/compiled_policy.json" "$CLAWEDR_DIR/"
    cp "$tmpdir/bpf_hooks.c"         "$CLAWEDR_DIR/"
    cp "$tmpdir/monitor.py"          "$CLAWEDR_DIR/"
    cp "$tmpdir/user_rules.py"       "$CLAWEDR_DIR/shared/"
    cp "$tmpdir/alert_dispatcher.py" "$CLAWEDR_DIR/shared/"
    cp "$tmpdir/dashboard_app.py"    "$CLAWEDR_DIR/dashboard/app.py"
    cp "$tmpdir/dashboard_index.html" "$CLAWEDR_DIR/dashboard/templates/index.html"
    touch "$CLAWEDR_DIR/shared/__init__.py"
    touch "$CLAWEDR_DIR/dashboard/__init__.py"
    chmod +x "$tmpdir/shield_linux.sh"
    sh "$tmpdir/shield_linux.sh"

    install_openclaw_wrapper_linux

    # Dashboard
    install_dashboard_deps
    install_dashboard_systemd

    log "Linux Shield installed successfully"
}

# ---------------------------------------------------------------------------
# openclaw wrapper — macOS
# ---------------------------------------------------------------------------

install_openclaw_wrapper() {
    CLAWEDR_REAL="$CLAWEDR_DIR/openclaw-real"
    CLAWEDR_SB="$CLAWEDR_DIR/clawedr.sb"

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

    # Ensure wrapper is used: prepend /usr/local/bin so it's found before homebrew's openclaw
    if [ -n "$SUDO_USER" ]; then
        home=$(eval "echo ~$SUDO_USER")
        for rc in .zshrc .bash_profile .bashrc; do
            rcf="$home/$rc"
            [ -f "$rcf" ] || continue
            if grep -q 'ClawEDR.*PATH.*usr/local/bin' "$rcf" 2>/dev/null; then
                :
            else
                log "Prepending /usr/local/bin to PATH in $rcf"
                printf '\n# ClawEDR: wrapper must precede homebrew\n[ -d /usr/local/bin ] && export PATH="/usr/local/bin:$PATH"\n' >> "$rcf"
                chown "$SUDO_USER" "$rcf" 2>/dev/null || true
                break
            fi
        done
    fi
}

# ---------------------------------------------------------------------------
# openclaw wrapper — Linux
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

uninstall_macos() {
    log "Uninstalling ClawEDR (macOS)"

    # Stop dashboard
    PLIST_PATH="/Library/LaunchDaemons/com.clawedr.dashboard.plist"
    if [ -f "$PLIST_PATH" ]; then
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        rm -f "$PLIST_PATH"
        log "Dashboard launchd service removed"
    fi

    pkill -f "log_tailer.py" 2>/dev/null || true
    pkill -f "clawedr.*dashboard" 2>/dev/null || true

    # Restore openclaw if we overwrote it
    _restore() {
        local path="$1"
        [ ! -e "$path" ] || ! grep -q "CLAWEDR_SB" "$path" 2>/dev/null && return 0
        if [ -f "$CLAWEDR_DIR/openclaw-real" ]; then
            resolved=$(grep 'exec node "' "$CLAWEDR_DIR/openclaw-real" 2>/dev/null | sed 's/.*exec node "\([^"]*\)".*/\1/')
            if [ -n "$resolved" ] && [ -f "$resolved" ]; then
                log "Restoring openclaw at $path"
                rm -f "$path"
                ln -sf "$resolved" "$path" 2>/dev/null || cp "$CLAWEDR_DIR/openclaw-real" "$path"
                [ -x "$path" ] || chmod +x "$path"
            fi
        fi
    }
    _restore /opt/homebrew/bin/openclaw
    _restore /usr/local/bin/openclaw
    rm -rf "$CLAWEDR_DIR"
    rm -f /tmp/clawedr_dashboard.log
    log "ClawEDR uninstalled"
}

uninstall_linux() {
    log "Uninstalling ClawEDR (Linux)"

    # Stop dashboard
    systemctl stop clawedr-dashboard 2>/dev/null || true
    systemctl disable clawedr-dashboard 2>/dev/null || true
    rm -f /etc/systemd/system/clawedr-dashboard.service
    systemctl daemon-reload 2>/dev/null || true
    log "Dashboard systemd service removed"

    pkill -f "monitor.py" 2>/dev/null || true
    pkill -f "clawedr.*dashboard" 2>/dev/null || true
    systemctl stop clawedr-monitor 2>/dev/null || true
    rm -f /tmp/clawedr-monitor.pid /var/log/clawedr_monitor.log
    rm -rf "$CLAWEDR_DIR"
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

log ""
log "Done. Run 'openclaw <your-agent>' to start with protection enabled."
log "Dashboard is running at http://localhost:$CLAWEDR_DASHBOARD_PORT"
if [ "$OS" = "macos" ]; then
    log ""
    log "macOS: Run 'source ~/.zshrc' (or open a new terminal), then restart the"
    log "  gateway. The openclaw alias ensures the sandbox is applied."
fi
