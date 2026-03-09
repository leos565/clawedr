# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**ClawEDR** is a kernel-level endpoint detection and response system for AI coding agents (specifically OpenClaw). It enforces security policies by intercepting system calls via eBPF on Linux and Apple Seatbelt on macOS, blocking dangerous executables, paths, domains, and behavioral patterns.

## Build / Development Commands

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# The Execution Loop (main.py CLI):
./main.py sync      # Fetch ClawSec advisory feed + merge with master_rules.yaml
./main.py compile   # Generate deploy/compiled_policy.json + deploy/macos/clawedr.sb
./main.py test      # Run pytest builder/tests/
./main.py publish   # git add/commit/push deploy/
./main.py all       # sync → compile → test (skips publish)
```

## Applying Changes to the Testing VM

After every editing session, sync the deploy files to the OrbStack Ubuntu VM and restart services:

```bash
cd /Users/leo/clawedr && orb -m ubuntu -u root bash -c '
set -e
CLAWEDR_DIR="/usr/local/share/clawedr"
SRC="/Users/leo/clawedr/deploy"

echo "[*] Syncing deploy files to $CLAWEDR_DIR..."
cp "$SRC/compiled_policy.json" "$CLAWEDR_DIR/"
cp "$SRC/linux/bpf_hooks.c" "$CLAWEDR_DIR/"
cp "$SRC/linux/monitor.py" "$CLAWEDR_DIR/"
cp "$SRC/shared/user_rules.py" "$CLAWEDR_DIR/shared/"
cp "$SRC/shared/alert_dispatcher.py" "$CLAWEDR_DIR/shared/"
cp "$SRC/shared/rule_updater.py" "$CLAWEDR_DIR/shared/"
cp "$SRC/shared/policy_verify.py" "$CLAWEDR_DIR/shared/"
cp "$SRC/dashboard/app.py" "$CLAWEDR_DIR/dashboard/"
cp "$SRC/dashboard/templates/index.html" "$CLAWEDR_DIR/dashboard/templates/"

echo "[*] Restarting clawedr-monitor..."
systemctl restart clawedr-monitor 2>/dev/null || true

echo "[*] Restarting clawedr-dashboard..."
systemctl restart clawedr-dashboard 2>/dev/null || true

sleep 3
echo "[*] Status:"
systemctl is-active clawedr-monitor 2>/dev/null && echo "  clawedr-monitor: active" || echo "  clawedr-monitor: failed"
systemctl is-active clawedr-dashboard 2>/dev/null && echo "  clawedr-dashboard: active" || echo "  clawedr-dashboard: failed"
echo "[*] Done."
'
```

Both `clawedr-monitor` and `clawedr-dashboard` should report `active`. If either reports `failed`, check `journalctl -u clawedr-monitor -n 50` or `journalctl -u clawedr-dashboard -n 50` inside the VM.

## Testing

```bash
# CI-safe (skips platform enforcement tests):
python3 -m pytest builder/tests/ -v --ignore=builder/tests/test_linux_bpf.py -k "not Enforcement"

# Run a specific test class:
python3 -m pytest builder/tests/test_mac_sb.py::TestSeatbeltProfileSyntax -v

# E2E tests (require live OS environment):
bash tests/test_macos_e2e.sh
bash tests/test_linux_e2e.sh
```

Linux BPF tests (`test_linux_bpf.py`) require an OrbStack Ubuntu VM accessible via SSH — configure the host in `builder/config.yaml`.

## Architecture: Three Components

### 1. THE FORGE (`builder/` + `main.py`)
Policy compilation pipeline:
- `builder/master_rules.yaml` — Source of truth for all manual rules (Rule IDs: `BIN-*`, `DOM-*`, `PATH-*`, `LIN-*`, `MAC-*`)
- `builder/threat_aggregator.py` — Downloads ClawSec feed, merges with master_rules → `.merged_rules.json`
- `builder/compiler.py` — Reads merged rules, outputs `deploy/compiled_policy.json` (HMAC-signed) and `deploy/macos/clawedr.sb` (Seatbelt LISP profile)

### 2. THE REGISTRY (`deploy/`)
Distributable artifacts installed via `deploy/install.sh` (curl | sh):
- `deploy/compiled_policy.json` — Universal policy consumed by both platforms
- `deploy/linux/` — eBPF hooks + Shield daemon
- `deploy/macos/` — Seatbelt profile + log tailer
- `deploy/shared/` — User rules, alert dispatch, policy verification, rule updater
- `deploy/dashboard/` — FastAPI backend (port 8477) + browser UI

### 3. THE SHIELD (runtime, installed on end-user machines)

**Linux** (`deploy/linux/monitor.py` + `deploy/linux/bpf_hooks.c`):
- `bpf_hooks.c` (873 LOC) — eBPF programs for `execve`/`openat`/`socket_connect` interception; runs in-kernel
- `monitor.py` (1428 LOC) — Python daemon: loads BPF via BCC, hot-reloads maps when policy changes, scoped to OpenClaw processes and descendants
- Enforcement layers: blocked executables (SIGKILL on execve), blocked paths (openat hash check), deny rules (argv matching), heuristics (pipe sibling detection, rate limits)

**macOS** (`deploy/macos/`):
- `clawedr.sb` — Compiled Seatbelt profile (deny rules for blocked paths/executables)
- `apply_macos_policy.py` — Rebuilds `.sb` profile when `user_rules.yaml` changes
- `log_tailer.py` — Monitors sandbox violation logs, dispatches alerts to OpenClaw chat

**Dashboard** (`deploy/dashboard/app.py`, 945 LOC):
- FastAPI on port 8477
- Key endpoints: `/api/alerts`, `/api/rules`, `/api/user-rules`, `/api/custom-rules`, `/api/sessions`

## Rule ID System

Rule IDs enable precise user exemptions (`~/.clawedr/user_rules.yaml` survives updates):

| Prefix | Meaning |
|--------|---------|
| `BIN-*` | Blocked executables |
| `DOM-*` | Blocked domains |
| `PATH-MAC-*`, `PATH-LIN-*` | OS-specific blocked paths |
| `LIN-*`, `MAC-*` | OS-specific deny rules |
| `THRT-*` | Auto-generated from threat feed |
| `USR-*` | User custom rules |
| `HEU-*` | Heuristic detection rules |

## Data Flow

```
master_rules.yaml + ClawSec feed
        ↓ (threat_aggregator.py)
  .merged_rules.json
        ↓ (compiler.py)
compiled_policy.json + clawedr.sb
        ↓ (install.sh on end-user machine)
Shield daemon (monitor.py / sandbox-exec)
        ↓
Violation logs → dashboard/app.py → Browser UI + alert_dispatcher.py
```

## Key Files

| File | Purpose |
|------|---------|
| `builder/master_rules.yaml` | All manual security rules; edit here to add/modify rules |
| `builder/config.yaml` | Forge environment config (Linux VM host for BPF tests) |
| `deploy/compiled_policy.json` | Generated; do not edit manually |
| `deploy/linux/bpf_hooks.c` | eBPF kernel hooks — C with BCC macros |
| `deploy/linux/monitor.py` | Linux Shield daemon — BCC Python bindings |
| `deploy/dashboard/app.py` | FastAPI dashboard backend |
| `.github/workflows/ci.yml` | CI: compile + verify artifacts + run unit tests |
