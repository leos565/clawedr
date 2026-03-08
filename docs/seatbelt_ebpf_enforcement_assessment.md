# Seatbelt and eBPF Enforcement Feasibility Assessment

This document assesses whether ClawEDR's rule set (including Crust-adapted rules) is feasible and enforceable with **macOS Seatbelt** and **Linux eBPF**. Each rule category is evaluated against the capabilities and limitations of each enforcement layer.

---

## Executive Summary

| Category | Seatbelt (macOS) | eBPF (Linux) | Notes |
|----------|------------------|--------------|-------|
| Blocked paths | Full | Full | Both enforce at open/read/write |
| Blocked executables | Full | Full | Both block exec |
| Blocked domains | Monitor-only | Full (IP) | Seatbelt cannot filter by hostname |
| Blocked IPs | Monitor-only | Full | Seatbelt cannot filter by IP |
| Deny rules (argv) | N/A | Full | Userspace cmdline matching |
| Heuristics | None | Partial | Rate limits require kernel state |
| Except patterns | Limited | Full | Seatbelt regex lacks `.*` |
| ** glob patterns | Limited | Full | Seatbelt rejects kleene star |

**Overall:** Path and executable rules are fully enforceable on both platforms. Network rules (domain/IP) are enforced on Linux only; macOS monitors but cannot block. Advanced features (except, `**` globs, heuristics) have partial or no support on Seatbelt.

---

## 1. Enforcement Architecture

### Linux (eBPF)

```
┌─────────────────────────────────────────────────────────────────┐
│  monitor.py (userspace)                                          │
│  - Loads policy into BPF maps                                    │
│  - Expands path globs at load time                               │
│  - Matches deny_rules via /proc/pid/cmdline (post-execve)        │
│  - Domain rules: inject as argv patterns (curl to domain)        │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│  bpf_hooks.c (kernel)                                            │
│  - execve: blocked_hashes (SIGKILL)                              │
│  - openat/statx: blocked_path_hashes (SIGKILL or LSM -EPERM)     │
│  - connect: blocked_ips (LSM -EPERM or tracepoint SIGKILL)       │
│  - deny_rules: userspace reads cmdline, decides SIGKILL          │
└─────────────────────────────────────────────────────────────────┘
```

**Hooks:** `sys_enter_execve`, `sys_exit_execve`, `sys_enter_openat`, `sys_enter_connect`, optional LSM `file_open` and `socket_connect`.

### macOS (Seatbelt)

```
┌─────────────────────────────────────────────────────────────────┐
│  apply_macos_policy.py / compiler.py                             │
│  - Generates .sb LISP profile from policy                        │
│  - Paths: (deny file-read* / file-write* (subpath|regex))        │
│  - Execs: (deny process-exec (literal path))                     │
│  - Network: (deny network-outbound (remote tcp "port"))          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│  sandbox-exec -f clawedr.sb -- openclaw agent ...                │
│  - Profile bound at process start (no hot-reload)                │
│  - Domain/IP: NOT supported by Seatbelt; log_tailer monitors      │
└─────────────────────────────────────────────────────────────────┘
```

**Capabilities:** `file-read*`, `file-write*`, `process-exec`, `network-outbound`, `network-bind`, `subpath`, `regex`, `literal`.

---

## 2. Rule Category Assessment

### 2.1 Blocked Paths (PATH-MAC-*, PATH-LIN-*)

| Aspect | Seatbelt | eBPF | Feasible? |
|--------|----------|------|-----------|
| Path matching | `subpath` (prefix), `regex` | Hash lookup of resolved path | Yes |
| `~` expansion | `/Users/*` in regex | `/home/*` expansion at load | Yes |
| Single `*` | `[^/]+` in regex | `glob()` + `_expand_missing_wildcard` | Yes |
| `**` recursive | **No** — regex rejects `.*` (kleene star) | Yes — `glob(recursive=True)` at load | Seatbelt: No; eBPF: Yes |
| Except patterns | **Limited** — fixed-depth only | Full — expand except, subtract from blocked | Seatbelt: Partial; eBPF: Yes |
| Read vs write | `file-read*` / `file-write*` separate | Combined — openat sees path, not flags | Seatbelt: Yes; eBPF: No (would need open flags) |

**Seatbelt limitations encountered:**
- `(with report)` modifier: "report modifier does not apply to deny action" on some macOS versions — removed.
- Regex `.*` (kleene star): "unsupported syntax: kleene star" — cannot match arbitrary path depth.
- Workaround: Use fixed-depth patterns or simple paths; avoid `**` on macOS.

**eBPF implementation:**
- Paths expanded to concrete strings at load time; djb2 hash stored in `blocked_path_hashes`.
- `openat` and `statx` see filename; LSM `file_open` sees full path via `bpf_d_path()`.
- Map size: 4096 entries; `**` expansion can be large — monitor total.

---

### 2.2 Blocked Executables (BIN-*)

| Aspect | Seatbelt | eBPF | Feasible? |
|--------|----------|------|-----------|
| By name | `(deny process-exec (literal path))` | Hash of filename in `blocked_hashes` | Yes |
| Multiple prefixes | Emit rule per `/usr/bin/`, `/usr/local/bin/`, etc. | Single hash for basename + prefix hashes | Yes |
| Full path | `(literal "/full/path")` | Hash of full path | Yes |

**Both platforms:** Full enforcement. No limitations.

---

### 2.3 Blocked Domains (DOM-*)

| Aspect | Seatbelt | eBPF | Feasible? |
|--------|----------|------|-----------|
| Hostname filter | **Not supported** | No — connect() sees IP, not hostname | No (kernel) |
| Workaround | — | Inject as argv pattern: `*domain*` in cmdline | Yes (userspace) |
| When effective | — | When agent runs `curl https://domain.com` — argv contains domain | Yes |

**Seatbelt:** Cannot filter by hostname. Domain blocking is **monitor-only** (log_tailer polls lsof).

**eBPF:** Domain rules are implemented as deny_rules matching argv (e.g. `*pastebin.com*`). Effective when the command line contains the domain. Does not catch direct IP connections to that domain.

---

### 2.4 Blocked IPs (IP-*)

| Aspect | Seatbelt | eBPF | Feasible? |
|--------|----------|------|-----------|
| IP filter | **Not supported** — only `*` or `localhost` | `blocked_ips` hash map; LSM/tracepoint on connect | Seatbelt: No; eBPF: Yes |
| Cloud metadata (169.254.169.254) | No | Yes — IP in `blocked_ips` | eBPF only |

**Seatbelt:** No IP-level filtering. Monitor-only.

**eBPF:** Full enforcement via `socket_connect` (LSM) or connect tracepoint. `blocked_ips` map holds IPs; connect handler checks destination.

---

### 2.5 Custom Deny Rules (LIN-*, MAC-*)

| Aspect | Seatbelt | eBPF | Feasible? |
|--------|----------|------|-----------|
| Port-based (MAC-001..005) | `(deny network-outbound (remote tcp "*:4444"))` | LIN-001/002: port in connect handler | Yes |
| Executable literal (MAC-006..017) | `(deny process-exec (literal path))` | N/A — use blocked_executables | Yes |
| Argv pattern (LIN-003..052) | N/A | Userspace: read `/proc/pid/cmdline`, fnmatch | Yes |
| Network bind (MAC-018/019) | `(deny network-bind)` / `(allow network-bind localhost)` | N/A | Yes |

**Linux deny_rules:** Evaluated in userspace after `sys_exit_execve`. Monitor reads `/proc/<pid>/cmdline`, matches against `match` patterns. Substring/glob match. No kernel involvement for argv.

**macOS:** Raw Seatbelt LISP. Port blocks and process-exec blocks are native. No argv-based rules on Seatbelt.

---

### 2.6 Malicious Hashes (HASH-*)

| Aspect | Seatbelt | eBPF | Feasible? |
|--------|----------|------|-----------|
| File hash at exec | Not supported | Would need read file + hash before exec | Not implemented |
| Current implementation | — | Userspace: hash of executed file, compare | Partial (if implemented) |

**Status:** Hash checking requires reading file content before or at exec. eBPF execve hook sees path, not content. Would need userspace pre-read or a different hook. **Not currently enforced** in ClawEDR.

---

### 2.7 Heuristics (HEU-*)

| Aspect | Seatbelt | eBPF | Feasible? |
|--------|----------|------|-----------|
| Rate-based (e.g. >20 in 10s) | **No** — stateless | Requires sliding window in kernel | Partial |
| Argv pattern (threshold=1) | No | Same as deny_rules | Yes |
| Multi-syscall (openat + write) | No | New tracepoints + correlation | Complex |

**Seatbelt:** Stateless. No counters, no correlation across events. **Heuristics not feasible.**

**eBPF:** Per `docs/ebpf_heuristics_implementation_plan.md`, heuristics require:
- Sliding window state in BPF maps
- Argv inspection at execve (limited stack)
- Possibly new tracepoints (unlinkat, chmod, symlinkat)

**Status:** Infrastructure exists (`heu_configs`, `heu_state`); full implementation is planned but not complete. Rate-based heuristics are **partially feasible** on Linux.

---

## 3. Crust-Adapted Rules: Specific Assessment

### 3.1 Path Rules Added from Crust

| Rule / Category | Seatbelt | eBPF | Notes |
|-----------------|----------|------|-------|
| `.env` files | `~/.env` only (no `**`) | `**/.env*` with except | Seatbelt: top-level only |
| `.git-credentials`, `.netrc` | Yes | Yes | — |
| Shell history | Yes | Yes | — |
| Package tokens (`.npmrc`, etc.) | Yes | Yes | — |
| Terraform state | `~/terraform.tfstate` (no `**`) | `**/terraform.tfstate` | Seatbelt: home dir only |
| Shell RC, `authorized_keys` | Yes | Yes | — |
| Persistence (cron, systemd, launchd) | Yes (LaunchAgents) | Yes | — |
| System config (`/etc/hosts`, etc.) | Yes | Yes | — |
| Agent config (`.cursor/mcp.json`, etc.) | `~/.cursor/mcp.json` (no `**`) | `**/.mcp.json` | Seatbelt: home only |
| VS Code, `.git/hooks` | `~/.vscode/settings.json` | `**/.vscode/settings.json` | Same pattern |
| Desktop app tokens (Slack, Discord) | Yes | Yes | — |
| GitHub CLI `hosts.yml` | Yes | Yes | — |
| Linux keyring | N/A | Yes | — |

### 3.2 Deny Rules Added from Crust

| Rule | Seatbelt | eBPF | Notes |
|------|----------|------|-------|
| LIN-050: `/dev/tcp/` | N/A | Yes | Argv match |
| LIN-051: `nc * -e` | N/A | Yes | Argv match |
| LIN-052: `socat * exec:` | N/A | Yes | Argv match |
| IP-007/008: Cloud metadata | No | Yes | IP block |

### 3.3 Except Patterns

| Pattern | Seatbelt | eBPF | Notes |
|---------|----------|------|-------|
| `.env.example`, `.env.template` | **No** — would need `.*` in regex | Yes | Linux: expand except, subtract from blocked set |

---

## 4. Limitations Summary

### Seatbelt (macOS)

1. **No `**` (recursive) globs** — Regex does not support kleene star (`.*`). Use fixed-depth or simple paths.
2. **No except patterns** — Cannot express "block X except Y" with arbitrary depth.
3. **No domain/IP filtering** — Only port-based network rules. Domain/IP is monitor-only.
4. **No hot-reload** — Profile bound at process start; restart required for policy changes.
5. **No heuristics** — Stateless; no rate limits or behavioral rules.
6. **`(with report)`** — Not supported on some macOS versions; removed from deny rules.

### eBPF (Linux)

1. **No read vs write distinction** — `openat` sees path; distinguishing O_RDONLY vs O_WRONLY would need `open_how` or similar.
2. **Domain rules are argv-based** — Effective when domain appears in cmdline; direct IP connections not caught.
3. **Deny rules are userspace** — `/proc/cmdline` read after exec; slight TOCTOU window.
4. **Map capacity** — `blocked_path_hashes`: 4096; `blocked_ips`: 1024. Large `**` expansion can hit limits.
5. **LSM optional** — Without `CONFIG_BPF_LSM`, network and file blocking fall back to SIGKILL (process dies).
6. **Heuristics incomplete** — Sliding-window and multi-syscall heuristics require more implementation.

---

## 5. Recommendations

1. **macOS:** Keep path rules simple. Avoid `**`; use `~/.path` for home-level only. Document that full recursive + except is Linux-only.
2. **Linux:** Monitor `blocked_path_hashes` usage when using `**`; consider capping expansion per rule.
3. **Domain blocking:** Document that it relies on argv (e.g. `curl domain.com`); direct IP access may bypass.
4. **Heuristics:** Prioritize Linux implementation per `ebpf_heuristics_implementation_plan.md`; accept no heuristic support on macOS.
5. **Malicious hashes:** Defer or implement as a separate userspace pre-exec check.

---

## 6. Conclusion

**Feasibility:** The core rule set (blocked paths, executables, IPs, deny rules) is **feasible and enforceable** on both platforms within their constraints. Crust-adapted path coverage is fully enforceable on Linux; on macOS it is enforceable with simplified paths (no `**`, no except).

**Enforceability:** 
- **Linux:** Strong — kernel-level blocking via eBPF (and LSM when available). Deny rules and domain rules run in userspace but are effective for typical agent command patterns.
- **macOS:** Moderate — Seatbelt provides strong path and exec blocking, but network rules are port-only, and advanced path features are limited. Suitable for credential and path protection; network exfiltration is monitor-only.
