#!/usr/bin/env python3
# pyre-unsafe  — This module depends on BCC (Linux-only BPF library) whose
# types Pyre2 cannot resolve, causing cascading type errors.
"""
ClawEDR Linux Shield Monitor.

Watches compiled_policy.json for changes and hot-reloads the eBPF maps
without restarting OpenClaw.

Scoped enforcement: only OpenClaw processes (and their descendants) are
tracked.  The monitor populates the BPF target_bins map with djb2 hashes
of known OpenClaw binary paths so the kernel hooks can auto-detect them.

Enforcement layers:
  1. blocked_executables — BPF execve hash check (in-kernel)
  2. blocked_paths       — BPF openat hash check (in-kernel)
  3. deny_rules (single) — userspace argv matching via /proc/pid/cmdline
  4. deny_rules (pipes)  — BPF sibling heuristic (in-kernel)

User overrides:
  Reads ~/.clawedr/user_rules.yaml and skips loading any Rule IDs the
  user has exempted.

Lifecycle:
  1. Load bpf_hooks.c via BCC.
  2. Populate target_bins with OpenClaw binary path hashes.
  3. Bootstrap tracked_pids from /proc for already-running OpenClaw procs.
  4. Load compiled_policy.json -> apply user exemptions -> populate all
     BPF maps + in-memory rules.
  5. Poll for policy file changes and hot-reload.
"""

import ctypes
import fnmatch
import logging.handlers
import glob as globmod
import json
import logging
import os
import pwd
import shutil
import signal
import subprocess
import sys
import time

# Add parent and script dir to path so we can import shared (works for both
# deploy/linux/ layout and install at /usr/local/share/clawedr/)
_script_dir = os.path.dirname(os.path.abspath(__file__))
_parent = os.path.dirname(_script_dir)
sys.path.insert(0, _parent)
sys.path.insert(0, _script_dir)
from shared.user_rules import get_exempted_rule_ids, get_custom_rules, get_heuristic_overrides, get_rule_mode, USER_RULES_PATH  # pyre-ignore[21]
from shared.alert_dispatcher import dispatch_alert_async  # pyre-ignore[21]
from shared.policy_verify import verify_policy  # pyre-ignore[21]

logger = logging.getLogger("clawedr.monitor")
block_logger = logging.getLogger("clawedr.blocked")

POLICY_PATH = os.environ.get(
    "CLAWEDR_POLICY_PATH", "/usr/local/share/clawedr/compiled_policy.json"
)
BPF_SOURCE_PATH = os.environ.get(
    "CLAWEDR_BPF_SOURCE", "/usr/local/share/clawedr/bpf_hooks.c"
)
POLL_INTERVAL = int(os.environ.get("CLAWEDR_POLL_INTERVAL", "2"))
BLOCK_LOG_FILE = "/var/log/clawedr.log"
MONITOR_LOG_FILE = os.environ.get("CLAWEDR_LOG_FILE", "/var/log/clawedr_monitor.log")

_bpf_instance = None
_deny_rules: dict[str, dict] = {}
_blocked_domains: dict[str, str] = {}  # rule_id -> domain, for fast connect-time check
_malicious_hashes: dict[str, str] = {}
_hash_to_rule_id: dict[int, str] = {}
_ip_to_rule_id: dict[str, str] = {}
_heu_slot_to_rule_id: dict[int, str] = {}

PATH_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/")

# Heuristic definitions: rule_id -> {binaries, argv_patterns, syscall_type}
# syscall_type: None=execve, "fork"=sched_process_fork, "unlinkat", "chmod", "symlinkat"
HEURISTIC_DEFINITIONS: dict[str, dict] = {
    "HEU-GOG-001": {"binaries": ["gog"], "argv_patterns": ["gmail", "send"], "syscall_type": None},
    "HEU-GOG-002": {"binaries": ["gog"], "argv_patterns": ["gmail", "trash"], "syscall_type": None},
    "HEU-GOG-003": {"binaries": ["gog"], "argv_patterns": ["drive", "download"], "syscall_type": None},
    "HEU-GOG-004": {"binaries": ["gog"], "argv_patterns": ["auth", "add"], "syscall_type": None},
    "HEU-GOG-005": {"binaries": ["gog"], "argv_patterns": ["sheets"], "syscall_type": None},
    "HEU-GOG-006": {"binaries": ["gog"], "argv_patterns": ["calendar", "delete"], "syscall_type": None},
    "HEU-GOG-007": {"binaries": ["gog"], "argv_patterns": ["contacts", "export"], "syscall_type": None},
    "HEU-GIT-001": {"binaries": ["gh"], "argv_patterns": ["create"], "syscall_type": None},
    "HEU-GIT-002": {"binaries": ["gh"], "argv_patterns": ["pr", "merge"], "syscall_type": None},
    "HEU-GIT-003": {"binaries": ["gh"], "argv_patterns": ["workflow", "run"], "syscall_type": None},
    "HEU-GIT-004": {"binaries": ["gh"], "argv_patterns": ["api", "DELETE"], "syscall_type": None},
    "HEU-GIT-005": {"binaries": ["gh"], "argv_patterns": ["api", "branch"], "syscall_type": None},
    "HEU-GIT-006": {"binaries": ["gh", "git"], "argv_patterns": ["clone"], "syscall_type": None},
    "HEU-BRW-001": {"binaries": ["agent-browser", "npx"], "argv_patterns": ["agent-browser"], "syscall_type": None},
    "HEU-BRW-002": {"binaries": ["agent-browser", "npx"], "argv_patterns": ["127.0.0.1", "localhost"], "syscall_type": None},
    "HEU-BRW-003": {"binaries": ["agent-browser", "npx"], "argv_patterns": ["agent-browser", "form"], "syscall_type": None},
    "HEU-BRW-004": {"binaries": ["agent-browser", "npx"], "argv_patterns": ["agent-browser", "cookie"], "syscall_type": None},
    "HEU-BRW-005": {"binaries": ["agent-browser", "npx"], "argv_patterns": ["agent-browser", "evaluate"], "syscall_type": None},
    "HEU-SRH-001": {"binaries": ["tavily", "node", "python", "npx"], "argv_patterns": ["search"], "syscall_type": None},
    "HEU-SRH-002": {"binaries": ["tavily", "node", "python", "npx"], "argv_patterns": ["search"], "syscall_type": None},
    "HEU-SRH-003": {"binaries": ["tavily", "node", "python", "npx"], "argv_patterns": ["search"], "syscall_type": None},
    "HEU-PKM-001": {"binaries": ["notion", "obsidian"], "argv_patterns": ["delete"], "syscall_type": None},
    "HEU-PKM-002": {"binaries": ["notion", "obsidian"], "argv_patterns": ["export"], "syscall_type": None},
    "HEU-PKM-003": {"binaries": ["notion"], "argv_patterns": ["database", "delete"], "syscall_type": None},
    "HEU-EML-001": {"binaries": ["himalaya"], "argv_patterns": ["send"], "syscall_type": None},
    "HEU-EML-002": {"binaries": ["himalaya"], "argv_patterns": ["attachment", "download"], "syscall_type": None},
    "HEU-EML-003": {"binaries": ["himalaya", "cat"], "argv_patterns": ["credentials"], "syscall_type": None},
    "HEU-SIA-002": {"binaries": ["node", "python", "bash"], "argv_patterns": ["CLAUDE.md"], "syscall_type": None},
    "HEU-PAG-001": {"binaries": ["crontab", "bash"], "argv_patterns": ["cron"], "syscall_type": None},
    "HEU-PAG-003": {"binaries": ["node", "python"], "argv_patterns": ["agent"], "syscall_type": None},
    "HEU-API-001": {"binaries": ["node", "python"], "argv_patterns": ["api", "gateway"], "syscall_type": None},
    "HEU-API-002": {"binaries": ["node", "python"], "argv_patterns": ["mcp", "add"], "syscall_type": None},
    "HEU-NOD-001": {"binaries": ["npm"], "argv_patterns": ["install", "-g"], "syscall_type": None},
    "HEU-NOD-002": {"binaries": ["node"], "argv_patterns": [], "syscall_type": None},
    "HEU-FS-001": {"binaries": [], "argv_patterns": [], "syscall_type": "unlinkat"},
    "HEU-FS-002": {"binaries": [], "argv_patterns": [], "syscall_type": "chmod"},
    "HEU-FS-004": {"binaries": [], "argv_patterns": [], "syscall_type": "symlinkat"},
    "HEU-SYS-001": {"binaries": [], "argv_patterns": [], "syscall_type": "fork"},
    "HEU-SYS-003": {"binaries": ["rm", "bash", "sh"], "argv_patterns": ["-rf", "/"], "syscall_type": None},
    "HEU-SYS-004": {"binaries": ["crontab", "bash"], "argv_patterns": ["cron"], "syscall_type": None},
    "HEU-SYS-005": {"binaries": ["export", "bash"], "argv_patterns": ["PATH=", "LD_PRELOAD", "LD_LIBRARY_PATH"], "syscall_type": None},
    # HEU-NET-002 / HEU-NET-003: require connect() syscall inspection — not yet implemented.
    # Excluded from active dict; they will show as unknown in dashboard until implemented.
    # "HEU-NET-002": deferred (connect-level filtering not implemented)
    # "HEU-NET-003": deferred (connect-level filtering not implemented)
    "HEU-NET-004": {
        "binaries": ["socat", "ngrok", "localtunnel", "lt"],
        "argv_patterns": ["tcp-connect:", "tcp-listen:", "ngrok http", "ngrok tcp", "--port"],
        "syscall_type": None,
    },
    "HEU-CRD-001": {"binaries": ["cat", "grep"], "argv_patterns": ["passwd", "shadow", "credentials"], "syscall_type": None},
    "HEU-CRD-003": {"binaries": ["ssh-add"], "argv_patterns": ["ssh-add"], "syscall_type": None},
    # HEU-SIA-001 / HEU-PAG-002: require write() syscall inspection — not yet implemented.
    # "HEU-SIA-001": deferred (write-level filtering not implemented)
    # "HEU-PAG-002": deferred (write-level filtering not implemented)
    "HEU-SIA-003": {"binaries": ["node", "python"], "argv_patterns": [".learnings"], "syscall_type": None},
    "HEU-SIA-004": {"binaries": ["node", "python"], "argv_patterns": [".learnings"], "syscall_type": None},
}


# ---------------------------------------------------------------------------
# Hashing (must match simple_hash in bpf_hooks.c)
# ---------------------------------------------------------------------------

def _djb2_hash(s: str) -> int:
    h = 5381
    # Cap at 256 chars to match BPF simple_hash MAX_FILENAME_LEN
    for c in s.encode()[:256]:  # pyre-ignore[9]: slice
        h = ((h << 5) + h) + c
        h &= 0xFFFFFFFFFFFFFFFF
    return h


def _ip_int_to_str(ip_int: int) -> str:
    """Convert u32 IP (host byte order) to dotted-decimal string."""
    import socket
    import struct
    try:
        return socket.inet_ntoa(struct.pack("=I", ip_int & 0xFFFFFFFF))
    except Exception:
        return "0.0.0.0"


# ---------------------------------------------------------------------------
# Target binary discovery
# ---------------------------------------------------------------------------

WRAPPER_PATH = "/usr/local/bin/openclaw"

def _resolve_openclaw_paths() -> list[str]:
    paths: set[str] = set()
    paths.add(WRAPPER_PATH)

    target_env = os.environ.get("CLAWEDR_TARGET_BINARY")
    if target_env:
        logger.warning(
            "CLAWEDR_TARGET_BINARY=%s — test mode; production tracks real openclaw only",
            target_env,
        )
        paths.add(target_env)
        try:
            paths.add(os.path.realpath(target_env))
        except OSError:
            pass
        # When target is a script, kernel execve fires for the interpreter (bash/sh).
        # Add interpreters so we track the process tree (nc, nslookup, etc.).
        if target_env.endswith((".sh", ".bash")):
            for interp in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
                if os.path.exists(interp):
                    paths.add(interp)
                    try:
                        paths.add(os.path.realpath(interp))
                    except OSError:
                        pass
            logger.info("target_bins: adding shell interpreter for script target")
        return sorted(paths)

    real_bin = shutil.which("openclaw")
    if real_bin and os.path.realpath(real_bin) == os.path.realpath(WRAPPER_PATH):
        for npm_bin in _find_npm_openclaws():
            paths.add(npm_bin)

    all_bins = list(paths)
    if real_bin:
        all_bins.append(real_bin)
        
    # Also add openclaw.mjs from common install locations (gateway runs as node)
    for mjs in [
        "/usr/lib/node_modules/openclaw/openclaw.mjs",
        "/usr/local/lib/node_modules/openclaw/openclaw.mjs",
    ]:
        if os.path.exists(mjs):
            paths.add(mjs)
            try:
                paths.add(os.path.realpath(mjs))
            except OSError:
                pass

    for rb in all_bins:
        paths.add(rb)
        try:
            resolved = os.path.realpath(rb)
            paths.add(resolved)
            # OpenClaw is a Node script: kernel execs node, not openclaw.
            # Add node so we track the process tree. (All node processes
            # will be tracked; acceptable on OpenClaw-focused hosts.)
            if resolved.endswith((".mjs", ".js", ".cjs")):
                node_bin = shutil.which("node") or "/usr/bin/node"
                if os.path.exists(node_bin):
                    paths.add(node_bin)
                    try:
                        paths.add(os.path.realpath(node_bin))
                    except OSError:
                        pass
                    logger.info("target_bins: adding node interpreter for OpenClaw script")
        except OSError:
            pass

    return sorted(paths)


def _find_npm_openclaws() -> list[str]:
    cands = []
    
    import glob
    for pattern in [
        "/home/*/.npm-global/bin/openclaw",
        "/usr/local/lib/node_modules/.bin/openclaw",
        "/usr/local/bin/openclaw",
        "/usr/lib/node_modules/.bin/openclaw",
        "/usr/bin/openclaw",
    ]:
        for m in glob.glob(pattern):
            if os.path.realpath(m) != os.path.realpath(WRAPPER_PATH):
                cands.append(m)
                
    try:
        result = subprocess.run(
            ["npm", "config", "get", "prefix"],
            capture_output=True, text=True, timeout=5,
        )
        prefix = result.stdout.strip()
        if prefix:
            candidate = os.path.join(prefix, "bin", "openclaw")
            if os.path.exists(candidate) and os.path.realpath(candidate) != os.path.realpath(WRAPPER_PATH):
                cands.append(candidate)
    except Exception:
        pass

    return cands


# ---------------------------------------------------------------------------
# BPF loading
# ---------------------------------------------------------------------------

def _pidns_defines() -> str:
    """Return C #define directives for the monitor's PID namespace."""
    try:
        st = os.stat("/proc/self/ns/pid")
        defines = f"#define PIDNS_DEV {st.st_dev}ULL\n#define PIDNS_INO {st.st_ino}ULL\n"
        logger.info("PID namespace: dev=%d ino=%d", st.st_dev, st.st_ino)
        return defines
    except OSError:
        logger.warning("Cannot stat /proc/self/ns/pid — namespace PID unavailable")
        return ""


def load_bpf(source_path: str):
    global _bpf_instance
    from bcc import BPF  # pyre-ignore[21]: Linux-only

    logger.info("Compiling BPF program from %s", source_path)
    with open(source_path) as f:
        src = f.read()
    src = _pidns_defines() + src

    # Try BPF LSM first (kernel-level block); fallback to tracepoint+SIGKILL
    for use_lsm, cflags in [(True, ["-DCLAWEDR_USE_LSM"]), (False, [])]:
        try:
            _bpf_instance = BPF(text=src, cflags=cflags)
            logger.info(
                "BPF program loaded — %s",
                "LSM socket_connect (kernel-level block)" if use_lsm else "tracepoint fallback (SIGKILL)",
            )
            break
        except Exception as e:
            if use_lsm:
                logger.warning(
                    "BPF LSM unavailable (%s), falling back to tracepoint+SIGKILL",
                    e,
                )
            else:
                raise

    def _print_event(cpu, data, size):
        event = _bpf_instance["events"].event(data)
        comm = event.comm.decode(errors="replace")
        filename = event.filename.decode(errors="replace")
        ns_pid = event.ns_pid if event.ns_pid else event.pid
        if event.action == 1 and filename == "NETWORK_CONNECT":
            # Blocked IP (enforce)
            ip_int = getattr(event, "blocked_ip", 0)
            ip_str = _ip_int_to_str(ip_int) if ip_int else "0.0.0.0"
            rule_id = _ip_to_rule_id.get(ip_str, "IP-005")
            block_logger.warning(
                "BLOCKED [%s] action=network-connect pid=%d comm=%s target=%s",
                rule_id, ns_pid, comm, ip_str,
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action="network-connect",
                target=ip_str,
                pid=ns_pid,
                comm=comm,
            )
        elif event.action == 6 and filename == "NETWORK_CONNECT":
            # Blocked IP (alert-only)
            ip_int = getattr(event, "blocked_ip", 0)
            ip_str = _ip_int_to_str(ip_int) if ip_int else "0.0.0.0"
            rule_id = _ip_to_rule_id.get(ip_str, "IP-005")
            block_logger.warning(
                "ALERT [%s] action=network-connect pid=%d comm=%s target=%s",
                rule_id, ns_pid, comm, ip_str,
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action="network-connect",
                target=ip_str,
                pid=ns_pid,
                comm=comm,
            )
        elif event.action == 6:
            # Security rule alert-only (execve, openat, statx)
            rule_id = _find_rule_id_for_block(filename)
            block_logger.warning(
                "ALERT [%s] pid=%d uid=%d comm=%s file=%s",
                rule_id, ns_pid, event.uid, comm, filename,
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action="observed",
                target=filename,
                pid=ns_pid,
                comm=comm,
            )
        elif event.action == 3 and filename == "CONNECT_ATTEMPT":
            # Connect not in blocked_ips: check cmdline for blocked domains (argv-based)
            ip_int = getattr(event, "blocked_ip", 0)
            ip_str = _ip_int_to_str(ip_int) if ip_int else "0.0.0.0"
            _check_connect_domain_rules(ns_pid, comm, ip_str)
        elif event.action == 1:
            # Blocked by BPF (enforce) — find the matching rule ID
            rule_id = _find_rule_id_for_block(filename)
            block_logger.warning(
                "BLOCKED [%s] pid=%d uid=%d comm=%s file=%s",
                rule_id, ns_pid, event.uid, comm, filename,
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action="execve",
                target=filename,
                pid=ns_pid,
                comm=comm,
            )
        elif event.action == 0:
            # sys_enter_execve: evt.filename IS the real exec path. Check
            # malicious content hashes here — this is the only point where we
            # have the path before the process image is replaced.
            # Use event.pid (host PID) for /proc access, not ns_pid.
            _check_malicious_hashes(event.pid, comm, filename)
        elif event.action == 2:
            # Post-exec (sys_exit_execve): /proc/cmdline now has the new argv.
            # NOTE: evt.filename here is comm (bpf_hooks.c copies comm→filename
            # at exit), so it cannot be used for file I/O. Malicious hash
            # checking is done at action=0 where the real path is available.
            matched_deny = _check_deny_rules(ns_pid, comm, filename)
            if not matched_deny:
                logger.debug(
                    "[observed] pid=%d uid=%d comm=%s",
                    ns_pid, event.uid, comm,
                )
        elif event.action in (4, 5):
            # Heuristic alert (4) or block (5)
            heu_slot = getattr(event, "heu_slot", 0) or 0
            rule_id = _heu_slot_to_rule_id.get(heu_slot, f"HEU-{heu_slot:03d}")
            action_str = "heuristic_block" if event.action == 5 else "heuristic_alert"
            block_logger.warning(
                "HEURISTIC [%s] %s pid=%d comm=%s",
                rule_id, action_str, ns_pid, comm,
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action=action_str,
                target=comm,
                pid=ns_pid,
                comm=comm,
            )
            if event.action == 5:
                # Use event.pid (host-namespace PID) for os.kill — ns_pid is the
                # in-container PID and is only valid within the process namespace.
                # BPF bpf_send_signal already fired; this is belt-and-suspenders.
                try:
                    os.kill(event.pid, 9)
                except OSError:
                    pass

    _bpf_instance["events"].open_perf_buffer(_print_event)
    return _bpf_instance


# Reverse lookup: filename hash -> rule ID (populated during apply_policy)
_hash_to_rule_id: dict[int, str] = {}


def _find_rule_id_for_block(filename: str) -> str:
    """Find the Rule ID that matches a blocked filename."""
    h = _djb2_hash(filename)
    if h in _hash_to_rule_id:
        return _hash_to_rule_id[h]
    # Try bare name
    bare = os.path.basename(filename)
    h2 = _djb2_hash(bare)
    if h2 in _hash_to_rule_id:
        return _hash_to_rule_id[h2]
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Layer 4: malicious_hashes — userspace sha256 matching
# ---------------------------------------------------------------------------

def _check_malicious_hashes(host_pid: int, comm: str, exec_path: str) -> str | None:
    """Check the SHA-256 of the file being exec'd against the malicious hash list.

    Called at action=0 (sys_enter_execve) where exec_path is the real path and
    host_pid is the host-namespace PID suitable for /proc access.

    Reads via /proc/{host_pid}/exe when available (resolves symlinks, survives
    path changes); falls back to exec_path directly.
    """
    if not _malicious_hashes:
        return None

    import hashlib
    try:
        # /proc/{host_pid}/exe is a symlink to the exact binary the kernel
        # is loading. Prefer it over exec_path to avoid TOCTOU on the path.
        exe_path = f"/proc/{host_pid}/exe"
        if not os.path.exists(exe_path):
            # Process may not have started yet; fall back to the exec path from
            # the syscall args (still reliable at sys_enter time).
            exe_path = exec_path
        if not exe_path or not os.path.isabs(exe_path):
            return None

        sha256 = hashlib.sha256()
        with open(exe_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
    except OSError:
        return None

    for rule_id, target_hash in _malicious_hashes.items():
        if file_hash == target_hash:
            mode = get_rule_mode(rule_id)
            log_msg = "BLOCKED" if mode == "enforce" else "ALERT"
            block_logger.warning(
                "%s [%s] action=exec_hash hash=%s pid=%d comm=%s file=%s",
                log_msg, rule_id, file_hash, host_pid, comm, exec_path,
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action="exec_hash",
                target=f"{exec_path} (sha256:{file_hash})",
                pid=host_pid,
                comm=comm,
            )
            if mode == "enforce":
                try:
                    os.kill(host_pid, 9)
                except OSError:
                    pass
            return rule_id

    return None

# ---------------------------------------------------------------------------
# Connect-time domain check (argv-based, no DNS)
# ---------------------------------------------------------------------------

def _check_connect_domain_rules(pid: int, comm: str, ip_str: str) -> str | None:
    """At connect(): read cmdline, check for blocked domains. Kill if match.
    Provides a second chance to block when exec-time check raced."""
    if not _blocked_domains:
        return None
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read(4096)
    except OSError:
        return None

    cmdline = raw.replace(b"\x00", b" ").decode(errors="replace").strip()
    if not cmdline:
        return None

    # Exempt our own alert dispatch
    if "openclaw agent" in cmdline and "ClawEDR Alert" in cmdline:
        return None

    for rule_id, domain in _blocked_domains.items():
        if domain in cmdline:
            mode = get_rule_mode(rule_id)
            log_msg = "BLOCKED" if mode == "enforce" else "ALERT"
            block_logger.warning(
                "%s [%s] (domain=connect) pid=%d comm=%s target=%s cmdline=%s",
                log_msg, rule_id, pid, comm, ip_str, cmdline[:150],
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action="deny_rule",
                target=cmdline[:200],
                pid=pid,
                comm=comm,
            )
            if mode == "enforce":
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
            return rule_id

    return None


# ---------------------------------------------------------------------------
# Layer 2: deny_rules — userspace argv matching
# ---------------------------------------------------------------------------

def _check_deny_rules(pid: int, comm: str, filename: str) -> str | None:
    """Read /proc/<pid>/cmdline and match against loaded deny_rules.

    Returns the Rule ID if matched, None otherwise.
    """
    if not _deny_rules:
        return None
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read(4096)
    except OSError:
        return None

    cmdline = raw.replace(b"\x00", b" ").decode(errors="replace").strip()
    if not cmdline:
        return None

    # Exempt our own child processes (e.g. alert dispatcher). The alert message
    # contains the blocked command and would match deny_rules. Exempting by
    # parent PID is more targeted than matching cmdline content.
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            stat = f.read()
        ppid = int(stat.split(")", 1)[1].split()[1])
        if ppid == os.getpid():
            return None
    except (OSError, IndexError, ValueError):
        pass

    # Exempt our own alert dispatch: openclaw agent --message "ClawEDR Alert..."
    # The message embeds the blocked cmdline and rule descriptions (e.g. "port 4444")
    # which can falsely match LIN-001 and cause an alert cascade.
    if "openclaw agent" in cmdline and "ClawEDR Alert" in cmdline:
        return None

    for rule_id, rule in _deny_rules.items():
        pattern = rule.get("match", "")
        if not pattern:
            continue
        # Optional: only match when the executable is the intended binary
        # (avoids matching "bash -c find ..." or alert processes)
        required_exec = rule.get("executable")
        if required_exec and comm != required_exec:
            continue
        if fnmatch.fnmatch(cmdline, pattern) or fnmatch.fnmatch(cmdline, f"*{pattern}*"):
            mode = get_rule_mode(rule_id)
            log_msg = "BLOCKED" if mode == "enforce" else "ALERT"
            block_logger.warning(
                "%s [%s] (deny_rule=%s) pid=%d cmdline=%s",
                log_msg, rule_id, rule.get("rule", "unknown"), pid, cmdline[:200],
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action="deny_rule",
                target=cmdline[:200],
                pid=pid,
                comm=comm,
            )
            if mode == "enforce":
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
            return rule_id

    return None


# ---------------------------------------------------------------------------
# Target bins map
# ---------------------------------------------------------------------------

def populate_target_bins(paths: list[str]) -> None:
    if _bpf_instance is None:
        return
    target_map = _bpf_instance["target_bins"]
    for p in paths:
        if p == WRAPPER_PATH:
            logger.info("target_bins: skipping wrapper %s (tracked after exec)", p)
            continue
        h = _djb2_hash(p)
        target_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
        logger.info("target_bins += %s (hash %016x)", p, h)


def populate_parent_tracked_bins() -> None:
    """Populate parent_tracked_bins: shells we only track when parent is tracked.
    Agent runs commands via sh -c 'curl ...'; this ensures those curls get tracked."""
    if _bpf_instance is None:
        return
    parent_map = _bpf_instance["parent_tracked_bins"]
    for interp in ("/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"):
        if os.path.exists(interp):
            try:
                resolved = os.path.realpath(interp)
                for p in (interp, resolved):
                    h = _djb2_hash(p)
                    parent_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
                logger.info("parent_tracked_bins += %s (agent-spawned shells)", interp)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Bootstrap: seed tracked_pids for already-running OpenClaw processes
# ---------------------------------------------------------------------------

def _read_exe(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None


def _get_descendants(pid: int) -> list[int]:
    result: list[int] = []
    try:
        tasks_dir = f"/proc/{pid}/task"
        for tid in os.listdir(tasks_dir):
            children_file = os.path.join(tasks_dir, tid, "children")
            try:
                with open(children_file) as f:
                    for child_pid_str in f.read().split():
                        child_pid = int(child_pid_str)
                        result.append(child_pid)
                        result.extend(_get_descendants(child_pid))
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return result


def _read_cmdline(pid: int) -> str:
    """Read /proc/pid/cmdline as a string (nulls replaced with spaces)."""
    try:
        with open(f"/proc/{pid}/cmdline") as f:
            return f.read().replace("\x00", " ")
    except OSError:
        return ""


def bootstrap_tracked_pids(target_paths: list[str], quiet: bool = False) -> None:
    """Seed tracked_pids from running OpenClaw processes. quiet=True for periodic re-scan."""
    if _bpf_instance is None:
        return

    real_paths = set()
    for p in target_paths:
        try:
            real_paths.add(os.path.realpath(p))
        except OSError:
            real_paths.add(p)

    tracked_map = _bpf_instance["tracked_pids"]
    seeded = 0

    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        exe = _read_exe(pid)
        if exe is None:
            continue

        try:
            exe_real = os.path.realpath(exe)
        except OSError:
            exe_real = exe

        # Match by exe path (node, openclaw.mjs, etc.)
        if exe_real in real_paths or exe in real_paths:
            tracked_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
            seeded += 1
            if not quiet:
                logger.info("Bootstrap: tracking PID %d (%s)", pid, exe)
            for child in _get_descendants(pid):
                tracked_map[ctypes.c_uint32(child)] = ctypes.c_uint8(1)
                seeded += 1
                if not quiet:
                    logger.info("Bootstrap: tracking descendant PID %d", child)
            continue

        # Fallback: match by cmdline (gateway runs as node with openclaw.mjs in argv)
        cmdline = _read_cmdline(pid)
        is_openclaw_cmdline = (
            "openclaw" in cmdline or "openclaw.mjs" in cmdline or "openclaw-gateway" in cmdline
        )
        is_node_or_openclaw_exe = "node" in exe or "openclaw" in exe
        if is_openclaw_cmdline and is_node_or_openclaw_exe:
            tracked_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
            seeded += 1
            if not quiet:
                logger.info("Bootstrap: tracking PID %d (cmdline match: %s)", pid, exe)
            for child in _get_descendants(pid):
                tracked_map[ctypes.c_uint32(child)] = ctypes.c_uint8(1)
                seeded += 1
                if not quiet:
                    logger.info("Bootstrap: tracking descendant PID %d", child)

    if not quiet:
        logger.info("Bootstrap complete — %d PIDs seeded into tracked_pids", seeded)


def populate_protected_pids(target_paths: list[str]) -> None:
    """Mark OpenClaw gateway PIDs as protected — openat/statx will log but not SIGKILL them.

    This prevents a blocked path access from killing the OpenClaw process itself.
    Only subprocesses (which are not in protected_pids) get SIGKILLed.
    """
    if _bpf_instance is None:
        return

    real_paths = set()
    for p in target_paths:
        try:
            real_paths.add(os.path.realpath(p))
        except OSError:
            real_paths.add(p)

    protected_map = _bpf_instance["protected_pids"]
    protected_map.clear()
    count = 0

    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        exe = _read_exe(pid)
        if exe is None:
            continue

        try:
            exe_real = os.path.realpath(exe)
        except OSError:
            exe_real = exe

        # Match OpenClaw gateway/agent processes (not their children)
        if exe_real in real_paths or exe in real_paths:
            protected_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
            count += 1
            continue

        # Fallback: cmdline match for node-based gateway
        cmdline = _read_cmdline(pid)
        is_openclaw_cmdline = (
            "openclaw" in cmdline or "openclaw.mjs" in cmdline or "openclaw-gateway" in cmdline
        )
        is_node_or_openclaw_exe = "node" in exe or "openclaw" in exe
        if is_openclaw_cmdline and is_node_or_openclaw_exe:
            protected_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
            count += 1

    logger.debug("Protected %d OpenClaw PIDs against openat/statx SIGKILL", count)


# ---------------------------------------------------------------------------
# Policy loading — blocked executables
# ---------------------------------------------------------------------------

def load_policy(path: str) -> dict:
    with open(path) as f:
        policy = json.load(f)
    ok, msg = verify_policy(policy)
    if not ok:
        raise RuntimeError(f"Policy verification failed: {msg}")
    logger.info("Policy verification: %s", msg)
    return policy


def apply_policy(policy: dict) -> None:
    global _bpf_instance, _deny_rules

    if _bpf_instance is None:
        logger.warning("BPF not loaded — skipping map update")
        return

    # Load user exemptions
    exempted = get_exempted_rule_ids()
    if exempted:
        logger.info("User exemptions active: %s", ", ".join(sorted(exempted)))

    # Merge in custom rules from ~/.clawedr/user_rules.yaml
    custom = get_custom_rules()
    if custom:
        logger.info("Merging %d custom user rules into policy", len(custom))
        for rule in custom:
            rid = rule.get("id", "")
            rtype = rule.get("type", "")
            val = rule.get("value", "")
            plat = rule.get("platform", "both")
            if plat not in ("both", "linux"):
                continue  # Skip macOS-only custom rules on Linux
            if rid in exempted:
                continue  # Skip disabled custom rules

            if rtype == "executable":
                policy.setdefault("blocked_executables", {})[rid] = val
            elif rtype == "hash":
                policy.setdefault("malicious_hashes", {})[rid] = val.removeprefix("sha256:")
            elif rtype == "path":
                policy.setdefault("blocked_paths", {}).setdefault("linux", {})[rid] = val
            elif rtype == "domain":
                policy.setdefault("blocked_domains", {})[rid] = val
            elif rtype == "ip":
                policy.setdefault("blocked_ips", {})[rid] = val
            elif rtype == "argument":
                policy.setdefault("deny_rules", {}).setdefault("linux", {})[rid] = {
                    "match": val,
                    "action": "deny",
                    "scope": "argv",
                }

    _apply_blocked_executables(policy, exempted)
    _apply_blocked_paths(policy, exempted)
    _apply_deny_rules(policy, exempted)
    _apply_malicious_hashes(policy, exempted)
    _apply_blocked_ips(policy, exempted)
    _apply_pipe_heuristic()
    _apply_heuristics(policy, exempted)


def _apply_blocked_executables(policy: dict, exempted: set[str]) -> None:
    execs = policy.get("blocked_executables", {})
    logger.info("Applying %d blocked executables (%d exempted)",
                len(execs), len(set(execs) & exempted))

    blocked_map = _bpf_instance["blocked_hashes"]
    blocked_map.clear()
    _hash_to_rule_id.clear()

    loaded = 0
    skipped = 0
    for rule_id, name in execs.items():
        if rule_id in exempted:
            logger.info("Skipping exempted rule %s (%s)", rule_id, name)
            skipped += 1
            continue
        mode = get_rule_mode(rule_id)
        val = 2 if mode == "enforce" else 1  # 1=alert, 2=enforce
        for prefix in PATH_PREFIXES:
            h = _djb2_hash(prefix + name)
            blocked_map[ctypes.c_uint64(h)] = ctypes.c_uint8(val)
            _hash_to_rule_id[h] = rule_id
            loaded += 1
        h = _djb2_hash(name)
        blocked_map[ctypes.c_uint64(h)] = ctypes.c_uint8(val)
        _hash_to_rule_id[h] = rule_id
        loaded += 1

    logger.info("Loaded %d entries into blocked_hashes BPF map (%d skipped)", loaded, skipped)


# ---------------------------------------------------------------------------
# Layer 1: blocked_paths — BPF openat enforcement
# ---------------------------------------------------------------------------

_SENSITIVE_SUBFILES = [
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "authorized_keys", "known_hosts", "config",
    "credentials", "accessTokens.json",
    "user_rules.yaml",  # ClawEDR config
]
# Extra files for /usr/local/share/clawedr (compiled policy, etc.)
_CLAWEDR_INSTALL_SUBFILES = ["compiled_policy.json", "bpf_hooks.c", "monitor.py"]


def _add_subpaths(directory: str, out: set[str]) -> None:
    """Add well-known sensitive subfiles beneath a directory."""
    for sub in _SENSITIVE_SUBFILES:
        out.add(os.path.join(directory, sub))
    # ClawEDR install dir: block policy, monitor, BPF source
    if "clawedr" in directory:
        for sub in _CLAWEDR_INSTALL_SUBFILES:
            out.add(os.path.join(directory, sub))
            out.add(sub)  # relative: cd /usr/local/share/clawedr && cat compiled_policy.json
        out.add("user_rules.yaml")  # relative: cd /etc/clawedr && cat user_rules.yaml


def _expand_blocked_paths(raw_paths: dict[str, str]) -> dict[str, set[str]]:
    """Expand wildcard paths into concrete filesystem paths.

    Returns a mapping of rule_id -> set of concrete paths.
    """
    result: dict[str, set[str]] = {}
    for rule_id, p in raw_paths.items():
        concrete: set[str] = set()
        if "*" in p:
            expanded = globmod.glob(p)
            if expanded:
                for ep in expanded:
                    concrete.add(ep)
                    _add_subpaths(ep, concrete)
            _expand_missing_wildcard(p, concrete)
        else:
            concrete.add(p)
            _add_subpaths(p, concrete)
        result[rule_id] = concrete
    return result


def _expand_missing_wildcard(pattern: str, out: set[str]) -> None:
    """For /home/*/.ssh style patterns, enumerate home dirs and add subpaths."""
    parts = pattern.split("*")
    if len(parts) != 2:
        return
    parent_dir = parts[0].rstrip("/")
    suffix = parts[1]
    for d in globmod.glob(os.path.join(parent_dir, "*")):
        if not os.path.isdir(d):
            continue
        synth = d + suffix
        out.add(synth)
        _add_subpaths(synth, out)


def _apply_blocked_paths(policy: dict, exempted: set[str]) -> None:
    raw_paths = policy.get("blocked_paths", {})
    if isinstance(raw_paths, dict) and "linux" in raw_paths:
        raw_paths = raw_paths.get("linux", {})
    if not raw_paths:
        return

    # Filter out exempted rules
    filtered = {rid: p for rid, p in raw_paths.items() if rid not in exempted}

    expanded = _expand_blocked_paths(filtered)

    path_map = _bpf_instance["blocked_path_hashes"]
    path_map.clear()

    _BPF_PATH_MAP_CAPACITY = 4096
    loaded = 0
    truncated = 0
    for rule_id, paths in expanded.items():
        mode = get_rule_mode(rule_id)
        val = 2 if mode == "enforce" else 1  # 1=alert, 2=enforce
        for p in sorted(paths):
            if loaded >= _BPF_PATH_MAP_CAPACITY:
                truncated += 1
                continue
            h = _djb2_hash(p)
            path_map[ctypes.c_uint64(h)] = ctypes.c_uint8(val)
            _hash_to_rule_id[h] = rule_id
            loaded += 1

    if truncated:
        logger.warning(
            "blocked_path_hashes BPF map full (%d capacity): %d path entries were NOT loaded. "
            "Reduce ** glob expansions or increase BPF_HASH size in bpf_hooks.c.",
            _BPF_PATH_MAP_CAPACITY, truncated,
        )
    logger.info("Loaded %d entries into blocked_path_hashes BPF map", loaded)


# ---------------------------------------------------------------------------
# Layer 2: deny_rules — load into memory for userspace matching
# ---------------------------------------------------------------------------

def _apply_deny_rules(policy: dict, exempted: set[str]) -> None:
    """Load deny_rules for argv matching. blocked_domains are injected as domain-in-cmdline rules.
    Domain rules are loaded FIRST so they take precedence over generic LIN-* rules (e.g. LIN-001
    *4444* would otherwise match alert messages that mention port 4444)."""
    global _deny_rules
    raw = policy.get("deny_rules", {})
    if isinstance(raw, dict) and "linux" in raw:
        raw = raw.get("linux", {})

    _deny_rules = {}
    skipped = 0

    # Load domain rules FIRST so they match before generic rules (curl to blocked domain -> DOM-xxx)
    global _blocked_domains
    _blocked_domains = {}
    for rule_id, domain in policy.get("blocked_domains", {}).items():
        if rule_id in exempted:
            skipped += 1
            continue
        _blocked_domains[rule_id] = domain
        _deny_rules[rule_id] = {"match": f"*{domain}*", "rule": "blocked_domain", "scope": "argv"}

    for rule_id, rule in raw.items():
        if rule_id in exempted:
            logger.info("Skipping exempted deny_rule %s", rule_id)
            skipped += 1
            continue
        if rule_id in _deny_rules:
            continue
        if isinstance(rule, dict) and rule.get("match"):
            _deny_rules[rule_id] = rule

    logger.info("Loaded %d deny_rules for userspace matching (%d skipped)",
                len(_deny_rules), skipped)

# ---------------------------------------------------------------------------
# malicious_hashes logic
# ---------------------------------------------------------------------------

def _apply_malicious_hashes(policy: dict, exempted: set[str]) -> None:
    global _malicious_hashes
    raw = policy.get("malicious_hashes", {})
    _malicious_hashes = {}
    skipped = 0
    invalid = 0
    for rule_id, h in raw.items():
        if rule_id in exempted:
            skipped += 1
            continue
        # Strip optional "sha256:" prefix so stored hashes match hashlib output
        h_clean = h.lower().removeprefix("sha256:")
        if len(h_clean) != 64 or not all(c in "0123456789abcdef" for c in h_clean):
            logger.warning("Malicious hash rule %s has invalid SHA-256 value — skipping", rule_id)
            invalid += 1
            continue
        _malicious_hashes[rule_id] = h_clean

    logger.info(
        "Loaded %d malicious hashes for userspace exec checking (%d exempted, %d invalid)",
        len(_malicious_hashes), skipped, invalid,
    )

# ---------------------------------------------------------------------------
# blocked_ips logic
# ---------------------------------------------------------------------------

def _apply_blocked_ips(policy: dict, exempted: set[str]) -> None:
    global _ip_to_rule_id
    if _bpf_instance is None:
        return

    raw_ips = policy.get("blocked_ips", {})

    _ip_to_rule_id = {}
    ip_map = _bpf_instance["blocked_ips"]
    ip_map.clear()

    import socket
    import struct
    loaded = 0

    for rule_id, ip in raw_ips.items():
        if rule_id in exempted:
            continue
        mode = get_rule_mode(rule_id)
        val = 2 if mode == "enforce" else 1  # 1=alert, 2=enforce
        try:
            ip_int = struct.unpack("=I", socket.inet_aton(ip))[0]
            ip_map[ctypes.c_uint32(ip_int)] = ctypes.c_uint8(val)
            _ip_to_rule_id[ip] = rule_id
            loaded += 1
        except Exception as e:
            logger.warning("Skipping blocked IP %s (%s): %s", rule_id, ip, e)

    logger.info("Loaded %d blocked IPs to BPF map", loaded)


# ---------------------------------------------------------------------------
# Layer 3: pipe heuristic — populate dangerous sources/sinks
# ---------------------------------------------------------------------------

_DANGEROUS_SOURCE_NAMES = ["curl", "wget", "nc", "ncat"]
_DANGEROUS_SINK_NAMES = [
    "bash", "sh", "dash", "zsh",
    "python3", "python", "ruby", "perl", "node",
]


def _apply_pipe_heuristic() -> None:
    if _bpf_instance is None:
        return

    src_map = _bpf_instance["dangerous_sources"]
    src_map.clear()
    loaded_src = 0
    for name in _DANGEROUS_SOURCE_NAMES:
        for prefix in PATH_PREFIXES:
            h = _djb2_hash(prefix + name)
            src_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
            loaded_src += 1
        h = _djb2_hash(name)
        src_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
        loaded_src += 1

    PIPE_HEURISTIC_RULE_ID = "LIN-PIPE-001"
    sink_map = _bpf_instance["dangerous_sinks"]
    sink_map.clear()
    loaded_sink = 0
    for name in _DANGEROUS_SINK_NAMES:
        for prefix in PATH_PREFIXES:
            h = _djb2_hash(prefix + name)
            sink_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
            _hash_to_rule_id.setdefault(h, PIPE_HEURISTIC_RULE_ID)
            loaded_sink += 1
        h = _djb2_hash(name)
        sink_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
        _hash_to_rule_id.setdefault(h, PIPE_HEURISTIC_RULE_ID)
        loaded_sink += 1

    logger.info(
        "Pipe heuristic: %d dangerous sources, %d dangerous sinks loaded",
        loaded_src, loaded_sink,
    )


# ---------------------------------------------------------------------------
# Layer 5: heuristic rules — execve/syscall rate limits + argv matching
# ---------------------------------------------------------------------------

_SYSCALL_TYPE_IDS = {"fork": 1, "unlinkat": 2, "chmod": 3, "symlinkat": 4, "write": 5, "connect": 6}


class _HeuConfig(ctypes.Structure):
    _fields_ = [
        ("enabled", ctypes.c_uint8),
        ("num_patterns", ctypes.c_uint8),
        ("threshold", ctypes.c_uint16),
        ("window_sec", ctypes.c_uint16),
        ("binary_hash", ctypes.c_uint32),
    ]


def _apply_heuristics(policy: dict, exempted: set[str]) -> None:
    """Populate heu_configs, heu_argv_patterns, heu_binary_to_slots, heu_syscall_slots."""
    global _heu_slot_to_rule_id

    if _bpf_instance is None:
        return

    heuristics = policy.get("heuristics", {})
    overrides = get_heuristic_overrides()

    # Build slot assignment: sorted rule IDs get slots 0, 1, 2, ...
    all_rule_ids = sorted(heuristics.keys())
    rule_id_to_slot = {rid: i for i, rid in enumerate(all_rule_ids)}
    _heu_slot_to_rule_id = {i: rid for i, rid in enumerate(all_rule_ids)}

    heu_binary = _bpf_instance["heu_binary_to_slots"]
    heu_binary.clear()
    heu_syscall = _bpf_instance["heu_syscall_slots"]
    heu_syscall.clear()

    loaded = 0
    for rule_id, hconfig in heuristics.items():
        if rule_id in exempted:
            continue
        mode = overrides.get(rule_id, hconfig.get("action", "disabled"))
        if mode == "disabled":
            continue

        slot = rule_id_to_slot.get(rule_id)
        if slot is None or slot >= 64:
            continue

        defn = HEURISTIC_DEFINITIONS.get(rule_id, {})
        threshold = hconfig.get("threshold", 1)
        window_sec = hconfig.get("window_seconds", 0)
        enabled = 2 if mode == "enforce" else 1

        # Config struct: enabled, num_patterns, threshold, window_sec, binary_hash
        binary_hash_val = 0
        if defn.get("binaries"):
            binary_hash_val = _djb2_hash(defn["binaries"][0]) & 0xFFFFFFFF

        patterns = defn.get("argv_patterns", [])
        num_patterns = min(len(patterns), 4)

        cfg = _HeuConfig(
            enabled=enabled,
            num_patterns=num_patterns,
            threshold=threshold,
            window_sec=window_sec,
            binary_hash=binary_hash_val,
        )
        _bpf_instance["heu_configs"][ctypes.c_uint32(slot)] = cfg

        # Argv patterns
        for i, pat in enumerate(patterns[:4]):
            ph = _djb2_hash(pat) & 0xFFFFFFFFFFFFFFFF
            idx = slot * 4 + i
            _bpf_instance["heu_argv_patterns"][ctypes.c_uint32(idx)] = ctypes.c_uint64(ph)

        # Binary -> slots bitmap (execve heuristics)
        syscall_type = defn.get("syscall_type")
        if syscall_type is None and defn.get("binaries"):
            for bin_name in defn["binaries"]:
                hashes_to_add = [_djb2_hash(bin_name)]
                for prefix in PATH_PREFIXES:
                    hashes_to_add.append(_djb2_hash(prefix + bin_name))
                for h in hashes_to_add:
                    key = ctypes.c_uint64(h)
                    try:
                        existing = heu_binary[key]
                        bm = existing.value if hasattr(existing, "value") else int(existing)
                    except (KeyError, TypeError):
                        bm = 0
                    bm |= 1 << slot
                    heu_binary[key] = ctypes.c_uint64(bm)

        # Syscall type -> slot (last one wins for shared types like connect)
        if syscall_type:
            type_id = _SYSCALL_TYPE_IDS.get(syscall_type)
            if type_id is not None:
                heu_syscall[ctypes.c_uint32(type_id)] = ctypes.c_uint8(slot)

        loaded += 1

    logger.info("Loaded %d heuristic rules into BPF maps", loaded)


# ---------------------------------------------------------------------------
# Main poll loop
# ---------------------------------------------------------------------------

def watch_and_reload(path: str, interval: int = POLL_INTERVAL) -> None:
    global _bpf_instance
    last_mtime = 0.0
    running = True

    def _stop(signum, frame):
        nonlocal running
        logger.info("Received signal %d, shutting down", signum)
        running = False

    def _reload(signum, frame):
        nonlocal last_mtime
        logger.info("Received SIGHUP, reloading policy immediately")
        try:
            policy = load_policy(path)
            apply_policy(policy)
            mtimes = []
            for check_path in (path, USER_RULES_PATH):
                try:
                    mtimes.append(os.path.getmtime(check_path))
                except FileNotFoundError:
                    pass
            last_mtime = max(mtimes) if mtimes else last_mtime
        except Exception:
            logger.exception("Reload failed")

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGHUP, _reload)

    logger.info("Monitoring %s (poll every %ds, SIGHUP to reload)", path, interval)

    next_policy_check = 0.0
    next_bootstrap = 0.0
    BOOTSTRAP_INTERVAL = 15  # Re-scan for openclaw processes (e.g. gateway started after monitor)

    while running:
        now = time.monotonic()
        if now >= next_bootstrap:
            try:
                target_paths = _resolve_openclaw_paths()
                bootstrap_tracked_pids(target_paths, quiet=True)
                populate_protected_pids(target_paths)
            except Exception:
                logger.exception("Periodic bootstrap failed")
            next_bootstrap = now + BOOTSTRAP_INTERVAL

        if now >= next_policy_check:
            mtimes = []
            for check_path in (path, USER_RULES_PATH):
                try:
                    mtimes.append(os.path.getmtime(check_path))
                except FileNotFoundError:
                    pass
            
            if mtimes:
                mtime = max(mtimes)
                if mtime != last_mtime:
                    logger.info("Policy or user rules changed (mtime %.0f → %.0f), reloading", last_mtime, mtime)
                    policy = load_policy(path)
                    apply_policy(policy)
                    last_mtime = mtime
            
            # (Exception handling merged appropriately above)
            next_policy_check = now + interval

        if _bpf_instance is not None:
            try:
                _bpf_instance.perf_buffer_poll(timeout=5)
            except Exception:
                logger.exception("Crash in perf_buffer_poll")

    logger.info("Monitor stopped.")


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(fmt)
    root.addHandler(stdout_handler)

    try:
        monitor_fh = logging.FileHandler(MONITOR_LOG_FILE)
        monitor_fh.setFormatter(fmt)
        root.addHandler(monitor_fh)
    except PermissionError:
        logger.warning("Cannot write to %s — monitor file logging disabled", MONITOR_LOG_FILE)

    block_logger.setLevel(logging.WARNING)
    block_logger.propagate = False

    block_stdout = logging.StreamHandler(sys.stdout)
    block_stdout.setFormatter(fmt)
    block_logger.addHandler(block_stdout)

    try:
        block_fh = logging.handlers.RotatingFileHandler(
            BLOCK_LOG_FILE,
            maxBytes=512 * 1024,  # 512KB
            backupCount=1,
        )
        block_fh.setFormatter(fmt)
        block_logger.addHandler(block_fh)
    except PermissionError:
        logger.warning("Cannot write to %s — block file logging disabled", BLOCK_LOG_FILE)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    setup_logging()
    logger.info("ClawEDR Linux Shield Monitor starting")

    if not os.path.exists(POLICY_PATH):
        logger.error("Policy file not found: %s", POLICY_PATH)
        return 1

    bpf_src = BPF_SOURCE_PATH
    if not os.path.exists(bpf_src):
        logger.error("BPF source not found: %s", bpf_src)
        return 1

    try:
        load_bpf(bpf_src)
    except Exception as exc:
        logger.error("Failed to load BPF program: %s", exc)
        return 1

    target_paths = _resolve_openclaw_paths()
    logger.info("OpenClaw binary paths: %s", target_paths)
    populate_target_bins(target_paths)
    populate_parent_tracked_bins()
    bootstrap_tracked_pids(target_paths)
    populate_protected_pids(target_paths)

    policy = load_policy(POLICY_PATH)
    apply_policy(policy)
    watch_and_reload(POLICY_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
