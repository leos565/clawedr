🦞 CLAWEDR_MASTER_PLAN.md (v2.0 - Intelligence-First)
## 1. The Architectural Split
THE FORGE (Local/Private): Your MacBook. It polls the ClawSec Feed, validates CVEs, runs the UPC (Universal Policy Compiler), and executes the Kernel Test Suite.

THE REGISTRY (Cloud/Public): A simple static file host (e.g., GitHub Pages) serving the install.sh and the latest compiled_policy.json.

THE SHIELD (Client/End-User): A microscopic, OS-aware background agent that pulls the "pre-digested" policy and enforces it via eBPF (Linux) or Seatbelt (Mac).

## 2. Directory Scaffolding
Markdown
/clawedr-project
│
├── /builder                 # 🛠️ THE FORGE (Your Private Workspace)
│   ├── master_rules.yaml    # Your manual overrides (Source of Truth)
│   ├── threat_aggregator.py # NEW: Pulls https://clawsec.prompt.security/advisories/feed.json
│   ├── compiler.py          # Transpiles YAML + Threat Intel -> .json / .sb
│   └── /tests               # Automated Pre-Ship Testing Matrix
│       ├── test_mac_sb.py   # Native Mac Seatbelt validation
│       └── test_linux_bpf.py# SSH-based Linux eBPF validation (OrbStack)
│
├── /deploy                  # 📦 THE REGISTRY (What the world sees)
│   ├── install.sh           # THE ONE-LINER DISPATCHER
│   ├── compiled_policy.json # The "Brain": Pre-digested denylists & hashes
│   ├── /linux               # Linux Client Payload (monitor.py, bpf_hooks.c)
│   └── /macos               # Mac Client Payload (log_tailer.py, clawedr.sb)
## 3. Module Deep-Dive
### A. The Threat Aggregator (/builder/threat_aggregator.py)
This script is the "Intelligence Bridge." It ensures you aren't manually tracking every new malicious skill.

Action: Downloads the feed.json from the ClawSec repo.

Parsing: Extracts affected_skills, malicious_hashes, and blocked_domains.

Merging: Combines these community threats with your own master_rules.yaml.

Result: Feeds a single, unified data object to the Compiler.

### B. The Universal Policy Compiler (/builder/compiler.py)
Output 1 (Linux): Generates compiled_policy.json. This is a flat mapping of PID-to-Rule for the eBPF hooks.

Output 2 (macOS): Generates the clawedr.sb LISP profile. It dynamically injects (deny file-read*) rules for every malicious path identified in the Threat Feed.

### C. The Universal Dispatcher (/deploy/install.sh)
Detects OS via uname -s.

Fetches the correct shield_<os>.sh setup script.

Zero-Habit Hijack (Mac): Automatically installs the /usr/local/bin/openclaw wrapper so the user never has to change how they run their agent.

## 4. The Forge Execution Loop (Your Workflow)
Sync Intel: python3 builder/threat_aggregator.py (ClawEDR now knows about today's new CVEs).

Transpile: python3 builder/compiler.py (Rules are turned into Kernel LISP/C).

Validate: pytest builder/tests/ (Ensures the new LISP doesn't have a syntax error that would brick a Mac Mini).

Publish: git push (The /deploy folder is now live).

## 5. The Shield Lifecycle (The User's Experience)
Linux: The Shield daemon sees the new compiled_policy.json, clears its BPF maps, and reloads the new hashes without restarting OpenClaw.

macOS: The Shield notifies the user: "New Threat Intelligence Available. Please restart OpenClaw to apply kernel-level updates."