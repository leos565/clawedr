# ClawEDR Configurable Heuristics Engine

This document outlines the design and implementation feasibility of a configurable heuristics engine for ClawEDR, specifically targeting autonomous AI agents utilizing popular skills from ClawHub.

## Architecture & Configuration

To provide administrators with control, the engine supports a **three-tier enforcement hierarchy** per heuristic:

| Mode | Behavior |
|:---|:---|
| **Disabled** | Rule ignored entirely |
| **Alert** | Triggers dashboard alert, does NOT kill/block |
| **Enforce** | Triggers alert AND blocks/kills the process |

These are defined in `master_rules.yaml` under the `heuristics:` section, compiled into `compiled_policy.json`, and manageable via the Dashboard.

```yaml
heuristics:
  HEU-GOG-001:
    name: "Mass Email Exfiltration (Forwarding Loop)"
    description: "Agent executes `gog gmail send/forward` >20 times in 10s."
    action: "enforce"      # Options: 'enforce', 'alert', 'disabled'
    threshold: 20
    window_seconds: 10
```

On Linux, `monitor.py` reads this configuration and populates eBPF maps (`heu_configs`), allowing the kernel to perform high-speed stateful tracking (sliding windows) and enforce the configured action (Kill via SIGKILL or Alert only) with zero userspace latency.

## Heuristics Catalog & Feasibility

The following table summarizes 55 heuristics mapped to popular ClawHub skills, detailing the logic and the feasibility on macOS (App Sandbox/Seatbelt).

### macOS App Sandbox / Seatbelt Feasibility Overview

macOS enforces security primarily through the App Sandbox (Seatbelt), configured via Scheme/Profile files (`.sb`). Unlike eBPF on Linux, which allows arbitrary stateful logic and sliding windows in the kernel, Seatbelt is a declarative, stateless policy engine. It evaluates each syscall (e.g., `file-read-data`, `process-exec`, `network-outbound`) independently against regex patterns and path rules.

**What Seatbelt CAN do:**
*   **Static Path Blocking:** Perfectly block access to specific files (e.g., `~/.ssh/authorized_keys`, `.env`).
*   **Static Binary Blocking:** Prevent execution of specific binaries (e.g., `/usr/bin/python3`).
*   **Static Network Blocking:** Block all outbound connections or connections to specific (hardcoded) IP/port combinations.

**What Seatbelt CANNOT do:**
*   **Stateful Counting / Sliding Windows:** Seatbelt cannot count how many times an agent ran a command in the last 10 seconds.
*   **Argv Inspection:** Seatbelt rules evaluate the executable path (`process-exec`), not the arguments (`argv`). It cannot distinguish between `gh pr create` and `gh pr list`.
*   **Dynamic Enforcement based on Content:** It cannot inspect the payload of a network request or the bytes written to a file.

Therefore, many heuristics that rely on rate-limiting or inspecting command arguments are **Not Feasible (NF)** purely within the macOS kernel via Seatbelt. They would require userspace polling (slow and incomplete) or an Endpoint Security (ES) system extension (complex and requires Apple approval).

### The Rules Table

| ID | Category | Skill | Name | Threshold | Action Logic (Linux eBPF) | macOS Feasibility |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **HEU-GOG-001** | Gog (Workspace) | Gog (85k↓) | Mass Email Exfiltration | >20 in 10s | `sys_exit_execve` parsing `argv[0]==gog` and `argv[1]==gmail`. Sliding window counter. | **NF**. Seatbelt cannot count or inspect argv. |
| **HEU-GOG-002** | Gog (Workspace) | Gog | The "Inbox Purge" | Any | `sys_exit_execve` matching `argv` for destructive strings (`trash`, `delete`) combined with broad queries. | **NF**. Seatbelt cannot inspect argv. |
| **HEU-GOG-003** | Gog (Workspace) | Gog | Mass Drive Scraping | >50 in 10s | Sliding window on `gog drive download` executions. | **NF**. |
| **HEU-GOG-004** | Gog (Workspace) | Gog | Unauthorized Scopes | Any | Block `gog auth add` with elevated admin scopes in `argv`. | **NF**. |
| **HEU-GOG-005** | Gog (Workspace) | Gog | Spreadsheet Corruption | >10 in 30s | Stateful sliding window counting the specific Sheet ID in `argv`. | **NF**. |
| **HEU-GOG-006** | Gog (Workspace) | Gog | Calendar Mass Delete | >10 in 5s | Sliding window on `gog calendar delete` executions. | **NF**. |
| **HEU-GOG-007** | Gog (Workspace) | Gog | Contact Export Spam | >5 in 30s | Sliding window on `gog contacts export` executions. | **NF**. |
| **HEU-GIT-001** | GitHub | Github (71k↓) | Issue / PR Spam | >5 in 60s | Sliding window on `gh` binary where `argv` contains `create`. | **NF**. |
| **HEU-GIT-002** | GitHub | Github | Mass PR Approval | >3 in 10s | Sliding window on `gh pr merge`. | **NF**. |
| **HEU-GIT-003** | GitHub | Github | CI/CD Budget Exhaustion | >5 in 60s | Block consecutive `gh workflow run` commands. | **NF**. |
| **HEU-GIT-004** | GitHub | Github | Destructive API Calls | Any | Immediate block on `gh api -X DELETE` against repo metadata. | **NF**. |
| **HEU-GIT-005** | GitHub | Github | Branch Protection Bypass | Any | Block `gh api` calls targeting branch protection endpoints. | **NF**. |
| **HEU-GIT-006** | GitHub | Github | Mass Repo Clone | >5 in 30s | Sliding window on `gh repo clone` or `git clone`. | **NF**. |
| **HEU-BRW-001** | Agent Browser | Agent Browser (72k↓) | Scrape Loop | >20 in 30s | Hash the full `argv` of `agent-browser`. Kill if threshold exceeded. | **NF**. |
| **HEU-BRW-002** | Agent Browser | Agent Browser | Localhost SSRF | Any | Block `agent-browser goto` containing `127.0.0.1` or `localhost`. | **NF** (for argv). |
| **HEU-BRW-003** | Agent Browser | Agent Browser | Form Autofill Scraping | Any | Detect `agent-browser` extracting form field data via argv inspection. | **NF**. |
| **HEU-BRW-004** | Agent Browser | Agent Browser | Cookie Exfiltration | Any | Detect `agent-browser` reading cookies and posting to external URLs. | **NF**. |
| **HEU-BRW-005** | Agent Browser | Agent Browser | Iframe Injection | Any | Detect `agent-browser` injecting scripts/iframes via `evaluate` argv. | **NF**. |
| **HEU-SRH-001** | Web Search | Tavily (98k↓), Brave, Baidu | Infinite Search Loop | >30 in 60s | Sliding window on search binary executions. | **NF**. |
| **HEU-SRH-002** | Web Search | Tavily, Brave, Baidu | Search Query Exfil | >3 in 60s | Detect base64-encoded data in search query argv. | **NF**. |
| **HEU-SRH-003** | Web Search | Tavily, Brave, Baidu | API Key Abuse | >5 in 30s | Detect rotating API key patterns in search command argv. | **NF**. |
| **HEU-PKM-001** | Notion/Obsidian | Notion (41k↓), Obsidian (36k↓) | Mass Page Deletion | >10 in 10s | Sliding window on `notion`/file delete operations. | **NF**. |
| **HEU-PKM-002** | Notion/Obsidian | Notion, Obsidian | Vault Data Exfiltration | >50 in 30s | Sliding window on bulk file reads from vault directories. | **NF**. |
| **HEU-PKM-003** | Notion/Obsidian | Notion | Database Schema Wipe | Any | Detect destructive Notion API calls (database delete/archive). | **NF**. |
| **HEU-EML-001** | Email | Himalaya (23k↓) | Mass Email Send | >20 in 30s | Sliding window on `himalaya send` executions. | **NF**. |
| **HEU-EML-002** | Email | Himalaya | Attachment Exfiltration | >10 in 10s | Sliding window on attachment download commands. | **NF**. |
| **HEU-EML-003** | Email | Himalaya | IMAP Credential Abuse | Any | Detect reads of IMAP credential config files. | **Partial**. Can block file reads to known config paths. |
| **HEU-SIA-001** | Self-Improving | self-improving-agent (117k↓) | The Schizophrenia Loop | >100B/s for 5s | Track `sys_enter_write` byte volume to `.learnings/ERRORS.md`. | **NF**. Seatbelt cannot rate limit bytes. |
| **HEU-SIA-002** | Self-Improving | self-improving-agent | Prompt Injection Overwrite | Any | Block `sys_enter_openat` with `O_TRUNC` targeting `CLAUDE.md`. | **Partial**. Can deny *all* writes to `CLAUDE.md`. |
| **HEU-SIA-003** | Self-Improving | self-improving-agent | Config Overwrite Loop | >20 in 10s | Sliding window on writes to `.learnings/` config files. | **NF**. |
| **HEU-SIA-004** | Self-Improving | self-improving-agent | Learnings DDoS | >50 in 5s | Sliding window on file creation in `.learnings/` directory. | **NF**. |
| **HEU-PAG-001** | Proactive Agent | Proactive Agent (59k↓) | Autonomous Cron Abuse | >5 in 60s | Sliding window on cron job creation commands. | **NF**. |
| **HEU-PAG-002** | Proactive Agent | Proactive Agent | WAL Flooding | >1000 in 30s | Sliding window on WAL protocol file writes. | **NF**. |
| **HEU-PAG-003** | Proactive Agent | Proactive Agent | Runaway Autonomous Loop | >10 in 60s | Track autonomous sub-task spawning via process fork/exec. | **NF**. |
| **HEU-API-001** | API Gateway/MCP | API Gateway (34k↓), MCPorter (29k↓) | Mass API Call Burst | >50 in 30s | Sliding window on API gateway binary executions. | **NF**. |
| **HEU-API-002** | API Gateway/MCP | API Gateway, MCPorter | Scope Escalation | Any | Detect MCP tool additions with elevated permissions in argv. | **NF**. |
| **HEU-API-003** | API Gateway/MCP | API Gateway, MCPorter | Cross-Service Exfil | >3 in 60s | Detect read-from-one-API-post-to-another patterns. | **NF**. |
| **HEU-NOD-001** | Node/NPM | (general) | Rogue Payload Install | Any | Post-initialization block of `npm install -g`. | **NF**. |
| **HEU-NOD-002** | Node/NPM | (general) | Infinite Process Spawn | >30 in 60s | Rate limit `node index.js` (Tavily search) execution. | **NF**. |
| **HEU-FS-001** | File System | — | Mass Deletion / Nuking | >50 in 3s | Sliding window counter on `unlinkat` or `rmdir` syscalls per TGID. | **NF**. |
| **HEU-FS-002** | File System | — | Rapid Chmod Spam | >100 in 5s | Sliding window counter on `chmod` or `fchmodat`. | **NF**. |
| **HEU-FS-003** | File System | — | Mass File Encryption | >100 in 10s | Detect rapid file extension changes (ransomware pattern). | **NF**. |
| **HEU-FS-004** | File System | — | Symlink Abuse | >20 in 5s | Sliding window on `symlinkat` targeting sensitive paths. | **NF**. |
| **HEU-SYS-001** | System / Shell | — | Runaway Fork Bomb | >100 in 1s | Sliding window counter on `sched_process_fork`. | **NF**. Seatbelt can deny fork entirely, but breaks agent. |
| **HEU-SYS-002** | System / Shell | — | The "Where am I?" Loop | >50 in 15s | Ring buffer of commands. Kill if 100% recon commands. | **NF**. |
| **HEU-SYS-003** | System / Shell | — | Panic Deletion | Any | Zero tolerance block on `rm -rf *` via `argv` matching. | **NF**. |
| **HEU-SYS-004** | System / Shell | — | Cron Persistence | >3 in 60s | Sliding window on cron file writes. | **NF**. |
| **HEU-SYS-005** | System / Shell | — | Env Var Poisoning | Any | Block modifications to PATH/LD_PRELOAD/LD_LIBRARY_PATH. | **Partial**. Can block specific env var file writes. |
| **HEU-NET-001** | Network | — | DNS Tunneling | >50 in 30s | Track DNS queries per unique subdomain of a single domain. | **NF**. |
| **HEU-NET-002** | Network | — | Port Scanning Burst | >20 in 10s | Sliding window on unique port connections to same host. | **NF**. |
| **HEU-NET-003** | Network | — | Mass Outbound Connections | >50 in 30s | Sliding window on `connect()` to unique destinations. | **NF**. |
| **HEU-NET-004** | Network | — | Reverse Proxy Setup | Any | Block socat/ngrok/localtunnel binary execution. | **NF**. |
| **HEU-CRD-001** | Credential | — | Password File Enum | >5 in 10s | Sliding window on credential file reads. | **Partial**. Static path blocking only. |
| **HEU-CRD-002** | Credential | — | Token Harvesting | >3 in 30s | Detect env var reads matching TOKEN/SECRET/KEY patterns. | **NF**. |
| **HEU-CRD-003** | Credential | — | SSH Agent Hijack | Any | Block SSH_AUTH_SOCK access or ssh-add with foreign keys. | **Partial**. Can block SSH agent socket path. |


## Summary

The eBPF architecture on Linux allows ClawEDR to implement highly sophisticated, stateful heuristics based on process behavior, syscall rates, and argument inspection, mitigating complex risks from agent tools like `gog`, `gh`, `agent-browser`, Tavily, Notion, Himalaya, and more.

Conversely, macOS Seatbelt is designed for static, binary allow/deny policies. Implementing these behavior-based heuristics on macOS using the current Seatbelt architecture is generally **not feasible**. To achieve parity on macOS, an Endpoint Security (ES) framework extension would be required, which shifts the project away from a lightweight, dependency-free approach.

### Dashboard Management

All 55 heuristic rules can be managed through the ClawEDR Dashboard under the **Heuristics** category tab:

- **Three-tier enforcement**: Each rule can be set to Disabled, Alert, or Enforce
- **Group toggles**: Toggle all rules in a subcategory (e.g., all Gog rules) at once
- **Platform awareness**: Rules not feasible on the current OS are greyed out with an advisory tooltip
- **Real-time apply**: Changes are saved to `~/.clawedr/user_rules.yaml` and hot-reloaded on Linux
