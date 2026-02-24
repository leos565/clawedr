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
CLAWEDR_BASE_URL="${CLAWEDR_BASE_URL:-https://raw.githubusercontent.com/leoclaw/clawedr/main/deploy}"

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

    log "Linux Shield installed successfully"
}

install_openclaw_wrapper() {
    # The openclaw wrapper transparently interposes the Shield so the user
    # never has to change how they invoke their agent CLI.
    log "Installing openclaw wrapper at /usr/local/bin/openclaw"
    cat > /usr/local/bin/openclaw <<'WRAPPER'
#!/usr/bin/env sh
# openclaw — ClawEDR Zero-Habit Hijack wrapper
# Runs the user's agent under the Seatbelt profile so the Shield is
# always active, transparently.
CLAWEDR_SB="/usr/local/share/clawedr/clawedr.sb"
if [ -f "$CLAWEDR_SB" ]; then
    exec sandbox-exec -f "$CLAWEDR_SB" -- "$@"
else
    echo "[openclaw] WARNING: Seatbelt profile not found at $CLAWEDR_SB — running unprotected" >&2
    exec "$@"
fi
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
