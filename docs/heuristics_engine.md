# ClawEDR Configurable Heuristics Engine

This document outlines the design and implementation feasibility of a configurable heuristics engine for ClawEDR, specifically targeting autonomous AI agents utilizing popular skills from ClawHub.

## Architecture & Configuration

To provide administrators with control, the engine supports configurable enforcement modes per heuristic. These are defined in `master_rules.yaml` and compiled into `compiled_policy.json`.

```yaml
heuristics:
  linux:
    HEU-GOG-001:
      name: "Mass Email Exfiltration (Forwarding Loop)"
      description: "Agent executes `gog gmail send/forward` > 20 times in 10s."
      action: "block"      # Options: 'block', 'alert', 'disabled'
      threshold: 20
      window_seconds: 10
```

On Linux, `monitor.py` reads this configuration and populates eBPF maps (`heu_configs`), allowing the kernel to perform high-speed stateful tracking (sliding windows) and enforce the configured action (Kill via SIGKILL or Alert only) with zero userspace latency.

## Heuristics Catalog & Feasibility

The following table summarizes 20 heuristics mapped to popular ClawHub skills, detailing the logic and the feasibility on macOS (App Sandbox/Seatbelt).

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

| ID | Category | Name | Threshold | Action Logic (Linux eBPF) | macOS Feasibility |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **HEU-GOG-001** | Gog (Workspace)| Mass Email Exfiltration | >20 in 10s | `sys_exit_execve` parsing `argv[0]==gog` and `argv[1]==gmail`. Hash argv and increments sliding window counter. | **NF**. Seatbelt cannot count or inspect argv. |
| **HEU-GOG-002** | Gog (Workspace)| The "Inbox Purge" | Any | `sys_exit_execve` matching `argv` for destructive strings (`trash`, `delete`) combined with broad queries (`is:inbox`). | **NF**. Seatbelt cannot inspect argv. |
| **HEU-GOG-003** | Gog (Workspace)| Mass Drive Scraping | >50 in 10s | Sliding window on `gog drive download` executions. | **NF**. |
| **HEU-GOG-004** | Gog (Workspace)| Unauthorized Scopes | Any | Block `gog auth add` with elevated admin scopes in `argv`. | **NF**. |
| **HEU-GOG-005** | Gog (Workspace)| Spreadsheet Corruption | Repeated | Stateful sliding window counting the specific Sheet ID in `argv`. | **NF**. |
| **HEU-GIT-001** | GitHub | Issue / PR Spam | >5 in 60s | Sliding window on `gh` binary where `argv` contains `create`. | **NF**. |
| **HEU-GIT-002** | GitHub | Mass PR Approval | >3 in 10s | Sliding window on `gh pr merge`. | **NF**. |
| **HEU-GIT-003** | GitHub | CI/CD Budget Exhaustion | Repeated | Block consecutive `gh workflow run` commands. | **NF**. |
| **HEU-GIT-004** | GitHub | Destructive API Calls | Any | Immediate block on `gh api -X DELETE` against repo metadata. | **NF**. |
| **HEU-BRW-001** | Agent Browser | Scrape Loop | >20 in 30s | Hash the full `argv` of `agent-browser`. Kill if threshold exceeded. | **NF**. |
| **HEU-BRW-002** | Agent Browser | Localhost SSRF | Any | Block `agent-browser goto` containing `127.0.0.1` or `localhost`. | **NF** (for argv). *Could* block all outbound local network via Seatbelt, but breaks the agent itself. |
| **HEU-SIA-001** | Self-Improving | The Schizophrenia Loop | >100 in 5s | Track `sys_enter_write` byte volume to `.learnings/ERRORS.md`. | **NF**. Seatbelt allows/denies write access entirely, cannot rate limit bytes. |
| **HEU-SIA-002** | Self-Improving | Prompt Injection Overwrite | Any | Block `sys_enter_openat` with `O_TRUNC` targeting `CLAUDE.md`. | **Partial**. Seatbelt can deny *all* writes to `CLAUDE.md`, but cannot distinguish append vs truncate. |
| **HEU-NOD-001** | Node/NPM | Rogue Payload Install | Any | Post-initialization block of `npm install -g`. | **NF**. Seatbelt blocks `npm` entirely or not at all; no argv inspection. |
| **HEU-NOD-002** | Node/NPM | Infinite Web Search | >30 in 60s | Rate limit `node index.js` (Tavily search) execution. | **NF**. |
| **HEU-FS-001** | File System | Mass Deletion / Nuking | >50 in 3s | Sliding window counter on `unlinkat` or `rmdir` syscalls per TGID. | **NF**. |
| **HEU-FS-002** | File System | Rapid Chmod Spam | >100 in 5s | Sliding window counter on `chmod` or `fchmodat`. | **NF**. |
| **HEU-SYS-001** | System / Shell | Runaway Fork Bomb | >100 in 1s | Sliding window counter on `sched_process_fork`. | **NF**. Seatbelt can deny fork entirely (`process-fork`), but breaks the agent. |
| **HEU-SYS-002** | System / Shell | The "Where am I?" Loop | >50 in 15s | Ring buffer of commands. Kill if 100% recon commands (e.g., `whoami`). | **NF**. |
| **HEU-SYS-003** | System / Shell | Panic Deletion | Any | Zero tolerance block on `rm -rf *` via `argv` matching. | **NF**. |


## Summary

The eBPF architecture on Linux allows ClawEDR to implement highly sophisticated, stateful heuristics based on process behavior, syscall rates, and argument inspection, mitigating complex risks from agent tools like `gog` and `gh`.

Conversely, macOS Seatbelt is designed for static, binary allow/deny policies. Implementing these behavior-based heuristics on macOS using the current Seatbelt architecture is generally **not feasible**. To achieve parity on macOS, an Endpoint Security (ES) framework extension would be required, which shifts the project away from a lightweight, dependency-free approach.
