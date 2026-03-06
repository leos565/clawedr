# eBPF Heuristics Implementation Plan

This document outlines a phased plan to implement actual eBPF filters for all 55 heuristic alerts defined in `master_rules.yaml`. The heuristics engine is designed in `docs/heuristics_engine.md`; this plan focuses on the Linux eBPF implementation.

## Current State

### What Exists
- **bpf_hooks.c**: execve (enter+exit), openat, statx, connect, sendto, fork, exit tracepoints
- **Maps**: `blocked_hashes`, `blocked_path_hashes`, `tracked_pids`, `target_bins`, `dangerous_sources/sinks` (pipe heuristic), `blocked_ips`, `pipe_sources`, `protected_pids`, `parent_tracked_bins`
- **Pipe heuristic**: The only behavioral heuristic currently in-kernel (dangerous source + sink sibling detection)
- **monitor.py**: `apply_policy()` applies blocked_executables, blocked_paths, deny_rules, malicious_hashes, blocked_ips, pipe_heuristic — **no `_apply_heuristics()`**
- **compiled_policy.json**: Contains full `heuristics` section with `action`, `threshold`, `window_seconds` per rule
- **user_rules.py**: `get_heuristic_overrides()` returns per-rule `disabled`|`alert`|`enforce` overrides

### What's Missing
- No `heu_configs` or heuristic state maps in BPF
- No kernel-side sliding window logic for rate-based heuristics
- No argv inspection in BPF for heuristic matching (deny_rules do argv in userspace via `/proc/cmdline`)
- No `_apply_heuristics()` in monitor.py
- No heuristic event type in `event_t` / perf buffer for alert-only vs enforce

---

## Heuristic Classification by Event Source

Heuristics fall into categories by the syscall/tracepoint they require:

| Event Source | Heuristics | BPF Hook | Notes |
|-------------|------------|----------|-------|
| **execve + argv** | GOG-001..007, GIT-001..006, BRW-001..005, SRH-001..003, PKM-001..003, EML-001..003, SIA-002, PAG-001, PAG-003, API-001..003, NOD-001..002, SYS-002..005, NET-004 | `sys_enter_execve` | argv available; need pattern matching |
| **openat** | SIA-002, SIA-003, SIA-004, SYS-004, CRD-001, EML-003 | `sys_enter_openat` | Path + flags (O_TRUNC) |
| **write** | SIA-001, PAG-002 | `sys_enter_write` | Byte volume or path |
| **unlinkat / rmdir** | HEU-FS-001, HEU-PKM-001 | `sys_enter_unlinkat`, `sys_enter_rmdir` | New tracepoints |
| **chmod / fchmodat** | HEU-FS-002 | `sys_enter_chmod`, `sys_enter_fchmodat` | New tracepoints |
| **symlinkat** | HEU-FS-004 | `sys_enter_symlinkat` | New tracepoint |
| **fork** | HEU-SYS-001 | `sched_process_fork` | Already hooked |
| **connect** | HEU-NET-002, HEU-NET-003 | `sys_enter_connect` | Already hooked; need per-host/port state |
| **DNS** | HEU-NET-001 | kprobe on `dns_query` or userspace | Complex; may defer |

---

## Technical Design

### 1. Argv Access in BPF

At `sys_enter_execve`, `args->argv` is a `const char *const *` (userspace pointer). We can read with `bpf_probe_read_user()`. Constraints:
- BPF stack limited (~512 bytes); cannot copy full argv
- Read argv[0], argv[1], argv[2] in small chunks (e.g. 32–64 bytes each)
- Match against predefined patterns (binary name + subcommand keywords)

### 2. Sliding Window in Kernel

For heuristics with `threshold > 1` and `window_seconds > 0`:

```
Key: (tgid << 16) | heu_slot   // heu_slot = compact heuristic ID 0..63
Value: struct { u32 count; u64 window_start_ns; }
```

Logic on each matching event:
1. `now = bpf_ktime_get_ns()`
2. Lookup `(tgid, heu_slot)` → `(count, window_start)`
3. If `now - window_start > window_ns`: reset `count=0`, `window_start=now`
4. `count++`
5. If `count >= threshold`: trigger (alert or kill), optionally reset

### 3. Immediate Heuristics (threshold=1, window=0)

No sliding window. On first matching event: alert or kill based on `action`.

### 4. Event Structure Extension

Extend `event_t` or add a heuristic-specific event:

```c
// New action values: 4 = heuristic_alert, 5 = heuristic_block
// New field: u32 heu_id (or use filename as string "HEU-GOG-001")
```

Or reuse `action=1` (blocked) with `filename` set to heuristic ID for dashboard correlation.

### 5. Config Map Design

**Option A: Per-heuristic config map (userspace-populated)**

```c
struct heu_config {
    u8  enabled;      // 0=disabled, 1=alert, 2=enforce
    u8  heu_slot;     // 0..55
    u16 threshold;
    u16 window_sec;
    u32 binary_hash;  // djb2 of primary binary (gog, gh, etc.)
    // argv patterns: fixed-size bloom or hash set
};
BPF_ARRAY(heu_configs, struct heu_config, 64);
```

**Option B: Separate maps for flexibility**

- `heu_enabled`: heu_slot → u8 (0/1/2)
- `heu_params`: heu_slot → (threshold, window_sec)
- `heu_binary_slots`: binary_hash → bitmap of heu_slots (one binary can trigger multiple heuristics)
- `heu_argv_patterns`: (heu_slot, pattern_hash) → 1 (for argv substring matching)

Monitor would populate these from `compiled_policy.json` + `get_heuristic_overrides()`.

---

## Phased Implementation Plan

### Phase 1: Foundation (Low Risk)
**Goal**: Kernel infra for heuristics without changing behavior.

1. **Add heuristic maps to bpf_hooks.c**
   - `heu_configs`: array of config structs (enabled, threshold, window_sec, binary_hash, argv_pattern_hash)
   - `heu_state`: hash map `(tgid<<16|heu_slot) → (count, window_start_ns)` for sliding windows
   - `heu_binary_to_slots`: hash map `binary_hash → bitmap` (which heuristics fire for this binary)

2. **Extend event_t**
   - Add `u8 heu_action` (0=none, 1=alert, 2=block) and `u16 heu_slot` for heuristic events
   - Or repurpose `action` values 4, 5 for heuristic_alert, heuristic_block

3. **Add `_apply_heuristics()` in monitor.py**
   - Read `policy["heuristics"]` and `get_heuristic_overrides()`
   - For each heuristic with `action != "disabled"`: compute binary hash, argv pattern hashes, populate `heu_configs` and `heu_binary_to_slots`
   - Call from `apply_policy()` after `_apply_pipe_heuristic()`

4. **Compiler / schema**
   - Add optional `binaries` and `argv_patterns` to each heuristic in master_rules.yaml for precise matching (e.g. `gog`, `gmail`, `send`)

---

### Phase 2: Execve-Based Heuristics (High Value)
**Goal**: Implement the majority of heuristics that depend on execve + argv.

1. **Argv reader helper in BPF**
   - `read_argv_prefix(pid, argv_ptr, buf, len)` — read first N bytes of argv[0], argv[1], argv[2] via `bpf_probe_read_user`
   - Build a 64-byte "signature" (e.g. hash of "gog\0gmail\0send") for fast lookup

2. **Implement execve heuristic check**
   - In `sys_enter_execve`, after pipe heuristic:
     - If tracked, lookup `binary_hash` in `heu_binary_to_slots`
     - For each slot in bitmap: read argv, compute pattern hash, compare to config
     - If match: update sliding window (or immediate trigger)
     - On threshold breach: emit event with `heu_action`/`heu_slot`, optionally `bpf_send_signal(SIGKILL)` if enforce

3. **Heuristics to implement (execve, in priority order)**
   - **Tier 1 (simple argv match, immediate)**: HEU-SYS-003 (rm -rf), HEU-NET-004 (socat/ngrok), HEU-GOG-004 (gog auth scopes), HEU-GIT-004 (gh api -X DELETE), HEU-BRW-002 (localhost)
   - **Tier 2 (sliding window, single binary)**: HEU-GOG-001, HEU-GOG-003, HEU-GOG-006, HEU-GIT-001, HEU-GIT-002, HEU-BRW-001, HEU-SRH-001, HEU-NOD-002
   - **Tier 3 (more complex argv)**: HEU-GOG-002, HEU-GOG-005, HEU-GOG-007, HEU-GIT-003, HEU-GIT-005, HEU-GIT-006, HEU-BRW-003..005, HEU-SRH-002..003, HEU-PKM-001..003, HEU-EML-001..003, HEU-NOD-001, HEU-SYS-002, HEU-SYS-004, HEU-SYS-005, HEU-PAG-001, HEU-PAG-003, HEU-API-001..003

4. **master_rules.yaml schema extension**
   ```yaml
   HEU-GOG-001:
     binaries: ["gog"]
     argv_patterns: ["gmail", "send"]  # argv must contain these
     # OR argv_subcommand: ["gmail", "send"]  # argv[1]==gmail, argv[2]==send
   ```

---

### Phase 3: Syscall-Based Heuristics (FS, Fork)
**Goal**: Add tracepoints for unlinkat, rmdir, chmod, fchmodat, symlinkat; implement FS and fork heuristics.

1. **New tracepoints in bpf_hooks.c**
   - `sys_enter_unlinkat`, `sys_enter_rmdir` → HEU-FS-001, HEU-PKM-001
   - `sys_enter_chmod`, `sys_enter_fchmodat` → HEU-FS-002
   - `sys_enter_symlinkat` → HEU-FS-004
   - `sched_process_fork` (existing) → HEU-SYS-001 (sliding window on fork count per parent TGID)

2. **Path-based heuristics**
   - HEU-SIA-002: openat with O_TRUNC and path containing `CLAUDE.md`
   - HEU-SIA-003, SIA-004: openat path containing `.learnings/`
   - HEU-SYS-004: openat path containing `cron`
   - HEU-CRD-001: openat path matching credential file patterns
   - HEU-EML-003: openat path matching IMAP config

3. **Write-based heuristics**
   - HEU-SIA-001: `sys_enter_write` to path containing `ERRORS.md` — byte rate (requires byte counter + time)
   - HEU-PAG-002: `sys_enter_write` to WAL files — count

---

### Phase 4: Network Heuristics
**Goal**: HEU-NET-002 (port scan), HEU-NET-003 (mass connections).

1. **Extend connect handler**
   - Add `heu_connect_state`: (tgid, dest_ip) → (port_count, port_bitmap or list, window_start)
   - On connect: extract dest IP and port; update state; if unique ports to same host > threshold in window, trigger

2. **HEU-NET-001 (DNS tunneling)**
   - Defer or implement via kprobe on `dns_query` / `resolv_query` if available
   - Alternatively: userspace tail of DNS logs (less ideal)

---

### Phase 5: Complex / Deferred Heuristics (Commented Out)
**Goal**: Heuristics requiring multi-event correlation or harder detection.

These 5 rules are **commented out** in `master_rules.yaml` so they do not appear in the dashboard. They can be re-enabled when implementation becomes feasible.

- **HEU-SYS-002** ("Where am I?" loop): Ring buffer of last N commands, check if all recon — complex; consider userspace
- **HEU-FS-003** (ransomware): Detect extension changes — needs filename before/after or rename tracking
- **HEU-API-003** (cross-service exfil): Read from one API, post to another — requires process-level state across many events
- **HEU-CRD-002** (token harvesting): Env var reads — would need ptrace or /proc/pid/environ hook
- **HEU-NET-001** (DNS tunneling): DNS query inspection (kprobe/resolv) not feasible in eBPF

---

## File Change Summary

| File | Changes |
|------|---------|
| `deploy/linux/bpf_hooks.c` | Add heu_configs, heu_state, heu_binary_to_slots; argv reader; heuristic checks in execve, openat, write, unlinkat, chmod, symlinkat, fork, connect |
| `deploy/linux/monitor.py` | Add `_apply_heuristics()`; extend `_print_event` for heuristic events; dispatch alerts for heuristic_alert |
| `builder/master_rules.yaml` | Add `binaries`, `argv_patterns` (or `argv_subcommand`) per heuristic where needed |
| `builder/compiler.py` | Pass through new heuristic fields to compiled_policy.json |
| `deploy/shared/alert_dispatcher.py` | Ensure heuristic alerts include rule_id, heu_slot for dashboard |
| `docs/heuristics_engine.md` | Update with implementation status per heuristic |

---

## Testing Strategy

1. **Unit**: Python tests for `_apply_heuristics()` map population
2. **BPF verifier**: Ensure no unbounded loops; use `#pragma unroll` where needed
3. **E2E**: Extend `tests/test_linux_e2e.sh` with heuristic tests (e.g. run `gog gmail send` in loop, expect block at threshold)
4. **Regression**: Ensure existing pipe heuristic and deny_rules still work

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| BPF stack overflow from argv reads | Limit reads to 3–4 argv slots, 32 bytes each; use per-CPU maps for temp buffers |
| Verifier rejection of complex logic | Split into helper functions; avoid loops over variable-length data |
| False positives on legitimate agent use | Conservative thresholds; alert-first for new heuristics; user overrides |
| Performance impact | Heuristic check only when binary in heu_binary_to_slots; early exit for disabled |

---

## Success Criteria

- [x] All 55 heuristics have a defined eBPF implementation path (or documented deferral)
- [x] Phase 1–2 complete: ≥15 execve-based heuristics enforced in-kernel
- [x] User overrides (disabled/alert/enforce) respected via heu_configs
- [x] Dashboard receives heuristic alerts with correct rule_id
- [x] No regression in existing blocked_executables, blocked_paths, deny_rules, pipe heuristic

## Implementation Status (Current Branch)

**Implemented:**
- Phase 1: heu_configs, heu_state, heu_binary_to_slots, heu_argv_patterns, heu_syscall_slots maps
- Phase 2: execve argv reader + heuristic check (sys_enter_execve)
- Phase 3: unlinkat, fchmodat, symlinkat tracepoints; sched_process_fork heuristic (HEU-SYS-001)
- _apply_heuristics() in monitor.py; heuristic event handler (action 4/5)
- HEURISTIC_DEFINITIONS with binaries/argv_patterns for 50 heuristics

**Deferred:**
- HEU-SIA-001, HEU-PAG-002 (write tracepoint)
- HEU-NET-002, HEU-NET-003 (connect per-host/port state)
- Path-based openat heuristics (SIA-002, SIA-003, SIA-004, SYS-004, CRD-001, EML-003)
