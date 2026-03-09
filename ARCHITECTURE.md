# ClawEDR Architecture

## Project Layout

```
clawedr/
├── builder/                      # THE FORGE — private build tools
│   ├── threat_aggregator.py      # Fetches ClawSec advisory feed
│   ├── compiler.py               # Compiles rules into kernel policies
│   ├── master_rules.yaml         # Manual overrides (source of truth, Rule IDs)
│   ├── config.yaml               # Forge environment config (VM host, etc.)
│   └── tests/
│       ├── test_mac_sb.py        # macOS Seatbelt enforcement tests
│       └── test_linux_bpf.py     # Linux eBPF tests via OrbStack VM
│
├── deploy/                       # THE REGISTRY — public artifacts
│   ├── install.sh                # One-liner OS-detecting dispatcher
│   ├── compiled_policy.json      # Universal policy (Rule IDs for both OSes)
│   ├── linux/
│   │   ├── bpf_hooks.c           # eBPF tracepoint hooks (execve interception)
│   │   ├── monitor.py            # Shield daemon — hot-reloads BPF maps
│   │   └── shield_linux.sh       # Linux setup script (systemd integration)
│   ├── macos/
│   │   ├── clawedr.sb            # Compiled Seatbelt LISP profile
│   │   ├── log_tailer.py         # Sandbox log monitor + alert dispatcher
│   │   ├── apply_macos_policy.py # Runtime Seatbelt generator (applies exemptions)
│   │   └── shield_mac.sh         # macOS setup script
│   ├── shared/
│   │   ├── user_rules.py         # Reads/writes ~/.clawedr/user_rules.yaml
│   │   └── alert_dispatcher.py   # Pushes alerts to OpenClaw chat
│   └── dashboard/
│       ├── app.py                # FastAPI backend (alerts, rules, exemptions)
│       └── templates/index.html  # Browser-based dashboard UI
│
├── main.py                       # Forge CLI (sync / compile / test / publish)
├── requirements-dev.txt          # Forge-only Python dependencies
└── .github/workflows/ci.yml     # CI validation on push
```

## Three-Component Architecture

### 1. The Forge (`builder/` + `main.py`)

The Forge runs on the developer's machine. It fetches threat intelligence, compiles kernel policies, validates them, and publishes to the Registry.

**`sync`** pulls the [ClawSec advisory feed](https://clawsec.prompt.security/advisories/feed.json), extracts `affected_skills`, `malicious_hashes`, and `blocked_domains`, and merges them with manual overrides in `builder/master_rules.yaml`. The result is cached at `builder/.merged_rules.json`.

**`compile`** reads the merged rules and produces:
- `deploy/compiled_policy.json` — universal policy consumed by both platforms at runtime
- `deploy/macos/clawedr.sb` — Seatbelt LISP profile with `deny` rules for every blocked path/executable

**`test`** runs `pytest builder/tests/` covering Seatbelt syntax validation, runtime enforcement, and Linux eBPF policy loading.

**`publish`** stages `deploy/`, commits, and pushes to GitHub.

### 2. The Registry (`deploy/`)

Public artifacts served over HTTPS from GitHub. End-users pull these via `install.sh`.

### 3. The Shield (end-user runtime)

Kernel-level enforcement daemon installed on end-user machines.

## Threat Intelligence Pipeline

```
ClawSec Feed (community)          master_rules.yaml (manual)
  ├── affected_skills        +      ├── blocked_paths
  ├── malicious_hashes       +      ├── blocked_domains
  └── blocked_domains        +      ├── blocked_executables
                                    └── custom_deny_rules
                             ↓
                    .merged_rules.json
                             ↓
              ┌──────────────┴──────────────┐
              │                             │
    compiled_policy.json            clawedr.sb
         (Linux)                     (macOS)
```

Feed entries **add to** manual rules, never replace them.

## Shield: Linux (eBPF)

The Shield runs as a background daemon (`monitor.py`) that:

1. Loads `compiled_policy.json` into eBPF hash maps
2. Auto-detects OpenClaw processes (gateway, agent, node) and tracks their entire process tree via BPF `fork`/`exit` hooks — only these processes are subject to policy enforcement
3. Hooks `execve()` via BPF tracepoints — blocked executables spawned by OpenClaw receive `SIGKILL`
4. Polls for policy file changes and **hot-reloads** BPF maps without restarting

Logs are written to both `/var/log/clawedr_monitor.log` and `journalctl -u clawedr-monitor`.

### Network Blocking

eBPF LSM `socket_connect` blocks connections at the kernel level (returns `-EPERM`). Requires `CONFIG_BPF_LSM=y` and `lsm=...,bpf` in the kernel cmdline. Falls back to tracepoint + SIGKILL if unavailable.

### Process Tracking Scope

ClawEDR only monitors OpenClaw (gateway, agent, node) and their descendants. Non-OpenClaw processes are never tracked. The install script sets `tools.exec.host=gateway` and `agents.defaults.sandbox.mode=off` in `~/.openclaw/openclaw.json` so that agent exec runs on the gateway host and is subject to blocking. Restart the gateway after install for the config to take effect.

### Anti-Tamper

Deny rules (LIN-030, LIN-031) block `kill`/`pkill`/`systemctl stop clawedr` when run by an OpenClaw descendant. They do not affect admin operations from a normal shell.

## Shield: macOS (Seatbelt)

1. `openclaw` wrapper runs the agent under `sandbox-exec -f clawedr.sb`
2. The `.sb` profile denies file reads/writes to sensitive paths (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/Library/Keychains`)
3. `log_tailer.py` monitors sandbox violation events and dispatches alerts

Seatbelt profiles bind at process start and cannot be hot-reloaded. Logs appear in Console.app (subsystem `com.clawedr.shield`) or `/tmp/clawedr_log_tailer.log`.

**macOS note:** Ensure `/usr/local/bin` comes before `/opt/homebrew/bin` in PATH. Verify with: `sandbox-exec -f /usr/local/share/clawedr/clawedr.sb -- nc -h` (should fail with "Operation not permitted").

## Dashboard

Web UI on port 8477, auto-installed as a system service on both platforms.

### Features

- **Alerts** — Real-time blocked actions with Rule IDs. Click "Exempt" to bypass a rule.
- **Policy Rules** — Browse all active rules by category. Toggle exemptions inline. Add/edit/delete custom rules.
- **Platform filtering** — Auto-detects OS, pill bar to switch views.
- **Sessions** — Active OpenClaw instances being monitored.
- **Settings** — Auto-update toggle, manual update check.
- **Rule updates** — Hourly registry checks. Linux: auto-enforced via hot-reload. macOS: banner prompts restart.

### API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/status` | Shield health: OS, policy state, OpenClaw availability |
| `GET` | `/api/alerts` | Recent blocked actions parsed from logs |
| `GET` | `/api/rules` | Full compiled policy with Rule IDs |
| `GET` | `/api/user-rules` | Current user exemptions and custom rules |
| `POST` | `/api/user-rules` | Update exemptions (preserves custom rules) |
| `GET` | `/api/custom-rules` | List all user-defined custom rules |
| `POST` | `/api/custom-rules` | Add a custom rule (`{"type": "domain", "value": "evil.com", "platform": "both"}`) |
| `PUT` | `/api/custom-rules/{id}` | Update a custom rule |
| `DELETE` | `/api/custom-rules/{id}` | Delete a custom rule |
| `GET` | `/api/sessions` | Active OpenClaw sessions |
| `GET` | `/api/settings` | Dashboard settings |
| `POST` | `/api/settings` | Update settings |
| `GET` | `/api/updates` | Check for rule updates from registry |
| `POST` | `/api/updates/apply` | Download and apply updates |

### Service Management

```sh
# macOS
sudo launchctl unload /Library/LaunchDaemons/com.clawedr.dashboard.plist   # stop
sudo launchctl load -w /Library/LaunchDaemons/com.clawedr.dashboard.plist  # start
cat /tmp/clawedr_dashboard.log

# Linux
sudo systemctl stop clawedr-dashboard
sudo systemctl start clawedr-dashboard
sudo journalctl -u clawedr-dashboard -f
```

## User Rules

All customizations in `~/.clawedr/user_rules.yaml` survive system updates.

### Exemptions

```yaml
exempted_rule_ids:
  - "BIN-001"    # Allow nc
  - "LIN-004"    # Allow stratum+tcp
```

### Custom Rules

```yaml
custom_rules:
  - id: USR-BIN-001
    type: executable
    value: terraform
  - id: USR-DOM-001
    type: domain
    value: evil.com
  - id: USR-HASH-001
    type: hash
    value: "sha256:a1b2c3d4e5f6..."
  - id: USR-PATH-001
    type: path
    value: /var/secrets
    platform: linux
  - id: USR-ARG-001
    type: argument
    value: "--password"
```

| Type | Blocks | Validation |
|------|--------|------------|
| `executable` | Binary by name | No paths, no protected binaries |
| `domain` | Domain name or IP | RFC-compliant, rejects URLs |
| `hash` | SHA-256 file hash | 64 hex chars, optional `sha256:` prefix |
| `path` | File/directory access | Absolute or `~/`, cannot be root |
| `argument` | Command-line args (regex) | Must be valid regex |

**Linux:** Custom rules merge into BPF maps on every policy reload (hot-reloaded).
**macOS:** `apply_macos_policy.py` rebuilds `clawedr.sb` including custom rules. Requires agent restart.

## Testing

| Test | Platform | Validates |
|------|----------|-----------|
| Profile syntax | macOS | `.sb` file has valid Seatbelt directives |
| Blocked path enforcement | macOS | `sandbox-exec` denies reads to `~/.ssh` |
| Allowed commands | macOS | Benign commands work under sandbox |
| VM SSH connectivity | Linux | SSH to the test VM works |
| BCC availability | Linux | Python BCC bindings importable |
| Policy loading | Linux | `compiled_policy.json` parses correctly |
| Blocked executable | Linux | `nc` appears in blocked list |

Configure the Linux test VM in `builder/config.yaml`:

```yaml
linux_vm:
  host: "orb"
  user: "ubuntu"
```

## CI

GitHub Actions (`.github/workflows/ci.yml`) runs on every push to `main`:

1. Installs Python dependencies
2. Compiles policies from `master_rules.yaml`
3. Verifies `deploy/` artifacts exist
4. Runs unit tests (skips platform-specific enforcement tests)
