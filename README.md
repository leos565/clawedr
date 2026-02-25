# ClawEDR

[![Python](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Linux-FF6F00?logo=linux&logoColor=white)](https://ebpf.io/)
[![Seatbelt](https://img.shields.io/badge/Seatbelt-macOS-000000?logo=apple&logoColor=white)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)
[![Shell](https://img.shields.io/badge/shell-bash%20%7C%20sh-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![C](https://img.shields.io/badge/C-BPF%20hooks-A8B9CC?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language))
[![YAML](https://img.shields.io/badge/YAML-master%20rules-CB171E?logo=yaml)](https://yaml.org/)

Kernel-level endpoint detection and response for AI coding agents. ClawEDR sits between your agent and the operating system, enforcing security policies via **eBPF** (Linux) and **Seatbelt** (macOS) so that compromised or malicious tool-use never reaches sensitive files, networks, or processes.

## Architecture

ClawEDR is split into three components:

```
┌─────────────────────────────┐
│  THE FORGE (private)        │   Compiles policies, runs
│  builder/ + main.py         │   tests, pushes artifacts.
└──────────────┬──────────────┘
               │ git push
               ▼
┌─────────────────────────────┐
│  THE REGISTRY (GitHub)      │   Public. Serves compiled
│  deploy/                    │   policies over HTTPS.
└──────────────┬──────────────┘
               │ curl | sh
               ▼
┌─────────────────────────────┐
│  THE SHIELD (end-user)      │   Microscopic background agent.
│  eBPF (Linux) / Seatbelt    │   Enforces policy at the kernel.
│  (macOS)                    │
└─────────────────────────────┘
```

## Quick Start (End-User)

Install the Shield with a single command:

```sh
curl -fsSL https://raw.githubusercontent.com/leos565/clawedr/main/deploy/install.sh | sudo sh
```

Then run your agent through the wrapper:

```sh
openclaw <your-agent-command>
```

On macOS the `openclaw` wrapper transparently enforces the Seatbelt profile. On Linux the eBPF monitor daemon runs in the background and enforces policies at the kernel level.

**macOS:** The wrapper is installed at `/usr/local/bin/openclaw`. Ensure `/usr/local/bin` comes before `/opt/homebrew/bin` in your PATH. **Restart the gateway after installing** — the sandbox applies only to processes started after install. To verify: `sandbox-exec -f /usr/local/share/clawedr/clawedr.sb -- nc -h` should fail with "Operation not permitted".

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

## The Forge (Developer Workflow)

The Forge runs on your local machine. It fetches threat intelligence, compiles kernel policies, validates them, and publishes to the Registry.

### Prerequisites

- Python 3.11+
- [OrbStack](https://orbstack.dev) with an Ubuntu VM (for Linux eBPF tests)

### Setup

```sh
# Clone and enter the repo
git clone https://github.com/leos565/clawedr.git
cd clawedr

# Create virtualenv and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

### The Execution Loop

Four commands, run in sequence:

```sh
# 1. Sync — fetch the latest ClawSec threat feed and merge with master_rules.yaml
./main.py sync

# 2. Compile — generate deploy/compiled_policy.json (Linux) and deploy/macos/clawedr.sb (macOS)
./main.py compile

# 3. Test — run the full Seatbelt + eBPF test suite
./main.py test

# 4. Publish — commit and push deploy/ to the GitHub registry
./main.py publish
```

Or run steps 1-3 together:

```sh
./main.py all
```

### What Each Step Does

**`sync`** pulls the [ClawSec advisory feed](https://clawsec.prompt.security/advisories/feed.json), extracts `affected_skills`, `malicious_hashes`, and `blocked_domains`, and merges them with your manual overrides in `builder/master_rules.yaml`. The result is cached at `builder/.merged_rules.json`.

**`compile`** reads the merged rules and produces two outputs:
- `deploy/compiled_policy.json` — flat policy consumed by the Linux eBPF hooks
- `deploy/macos/clawedr.sb` — Seatbelt LISP profile with `deny` rules for every blocked path

**`test`** runs `pytest builder/tests/` which includes:
- macOS Seatbelt syntax validation and runtime enforcement via `sandbox-exec`
- Linux eBPF policy validation via SSH to an OrbStack Ubuntu VM

**`publish`** stages `deploy/`, commits, and pushes to GitHub.

## Threat Intelligence

ClawEDR consumes the ClawSec community feed and merges it with local rules:

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

## Shield Behavior

### Linux

The Shield runs as a background daemon (`monitor.py`) that:

1. Loads `compiled_policy.json` into eBPF hash maps
2. Auto-detects OpenClaw processes (gateway, agent, node) and tracks their entire process tree via BPF `fork`/`exit` hooks — only these processes are subject to policy enforcement
3. Hooks `execve()` via BPF tracepoints — blocked executables spawned by OpenClaw receive `SIGKILL`
4. Polls for policy file changes and **hot-reloads** BPF maps without restarting

Logs are written to both `/var/log/clawedr_monitor.log` and `journalctl -u clawedr-monitor` (on systemd hosts).

### macOS

The Shield uses Apple's Seatbelt sandbox:

1. `openclaw` wraps the agent process under `sandbox-exec -f clawedr.sb`
2. The `.sb` profile denies file reads/writes to sensitive paths (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/Library/Keychains`)
3. `log_tailer.py` monitors sandbox violation events and sends a macOS notification when new threat intelligence is available, prompting the user to restart

Logs appear in **Console.app** when `pyoslog` is installed (filter by subsystem `com.clawedr.shield`). Otherwise they go to `/tmp/clawedr_log_tailer.log`.

Seatbelt profiles are bound at process start and cannot be hot-reloaded.

## Rule IDs

Every rule in ClawEDR has a unique, stable identifier for traceability and user exemptions:

| Prefix | Category | Example |
|--------|----------|---------|
| `BIN-xxx` | Blocked executables | `BIN-001` → `nc` |
| `DOM-xxx` | Blocked domains | `DOM-016` → `pastebin.com` |
| `PATH-MAC-xxx` | macOS blocked paths | `PATH-MAC-001` → `~/.ssh` |
| `PATH-LIN-xxx` | Linux blocked paths | `PATH-LIN-002` → `/etc/shadow` |
| `LIN-xxx` | Linux deny rules | `LIN-001` → port 4444 block |
| `MAC-xxx` | macOS deny rules | `MAC-006` → osascript block |
| `THRT-*` | Threat feed entries | Auto-generated hash-based IDs |

Rule IDs are defined in `builder/master_rules.yaml` and propagated into `compiled_policy.json`. When a block occurs, the Shield logs and alerts reference the exact Rule ID.

## Dashboard

ClawEDR includes a local web dashboard for monitoring alerts and managing user exemptions.

### Running the Dashboard

```sh
# Install dependencies (if not already)
pip install fastapi uvicorn

# Start on port 8477 (default)
python3 -m deploy.dashboard.app

# Or with a custom port / policy path
CLAWEDR_DASHBOARD_PORT=9000 CLAWEDR_POLICY_PATH=/path/to/compiled_policy.json python3 -m deploy.dashboard.app
```

Open [http://localhost:8477](http://localhost:8477) in your browser.

### Features

- **Alerts tab** — Real-time view of blocked actions with Rule IDs. Click "Exempt" to quickly bypass a rule.
- **Policy Rules tab** — Browse all active rules with inline toggle switches. Search by Rule ID, value, or category. Exempted rules are visually dimmed.
- **Sessions dropdown** — Shows active OpenClaw instances being monitored (queries `openclaw sessions --active 5 --json`).

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/status` | Shield health: OS, policy state, OpenClaw availability |
| `GET` | `/api/alerts` | Recent blocked actions parsed from logs |
| `GET` | `/api/rules` | Full compiled policy with Rule IDs |
| `GET` | `/api/user-rules` | Current user exemptions from `~/.clawedr/user_rules.yaml` |
| `POST` | `/api/user-rules` | Update exemptions (JSON body: `{"exempted_rule_ids": [...]}`) |
| `GET` | `/api/sessions` | Active OpenClaw sessions |

## User Exemptions

Users can bypass specific rules by ID without modifying the system policy. Exemptions are stored in `~/.clawedr/user_rules.yaml`:

```yaml
exempted_rule_ids:
  - "BIN-001"    # Allow nc
  - "LIN-004"    # Allow stratum+tcp
```

- **Linux:** `monitor.py` skips loading exempted Rule IDs into BPF maps at runtime.
- **macOS:** `apply_macos_policy.py` generates `clawedr.sb` excluding exempted rules.
- **Persistence:** `~/.clawedr/` is never touched by `install.sh`, so exemptions survive updates.

The easiest way to manage exemptions is through the Dashboard toggle switches.

## Testing

Run the full suite:

```sh
source .venv/bin/activate
./main.py test
```

The test matrix covers:

| Test | Platform | What it validates |
|------|----------|-------------------|
| Profile syntax | macOS | `.sb` file has valid Seatbelt directives |
| Blocked path enforcement | macOS | `sandbox-exec` denies reads to `~/.ssh` |
| Allowed commands | macOS | Benign commands still work under sandbox |
| VM SSH connectivity | Linux (OrbStack) | SSH to the test VM works |
| BCC availability | Linux (OrbStack) | Python BCC bindings are importable |
| Policy loading | Linux (OrbStack) | `compiled_policy.json` parses and has entries |
| Blocked executable | Linux (OrbStack) | `nc` appears in the blocked list |

### Configuring the Linux VM

Edit `builder/config.yaml` to point at your OrbStack VM:

```yaml
linux_vm:
  host: "orb"
  user: "ubuntu"
```

## CI

A GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push to `main`:

1. Installs Python dependencies
2. Compiles policies from `master_rules.yaml`
3. Verifies `deploy/` artifacts exist
4. Runs unit-level tests (skips platform-specific enforcement tests)

## License

MIT
