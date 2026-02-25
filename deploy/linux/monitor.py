#!/usr/bin/env python3
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

# Add parent directory to path so we can import shared modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.user_rules import get_exempted_rule_ids, get_custom_rules
from shared.alert_dispatcher import dispatch_alert_async

logger = logging.getLogger("clawedr.monitor")
block_logger = logging.getLogger("clawedr.blocked")

POLICY_PATH = os.environ.get(
    "CLAWEDR_POLICY_PATH", "/usr/local/share/clawedr/compiled_policy.json"
)
BPF_SOURCE_PATH = os.environ.get(
    "CLAWEDR_BPF_SOURCE", "/usr/local/share/clawedr/bpf_hooks.c"
)
POLL_INTERVAL = int(os.environ.get("CLAWEDR_POLL_INTERVAL", "5"))
BLOCK_LOG_FILE = "/var/log/clawedr.log"
MONITOR_LOG_FILE = os.environ.get("CLAWEDR_LOG_FILE", "/var/log/clawedr_monitor.log")

_bpf_instance = None
_deny_rules: dict[str, dict] = {}

PATH_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/")


# ---------------------------------------------------------------------------
# Hashing (must match simple_hash in bpf_hooks.c)
# ---------------------------------------------------------------------------

def _djb2_hash(s: str) -> int:
    h = 5381
    for c in s.encode():
        h = ((h << 5) + h) + c
        h &= 0xFFFFFFFFFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# Target binary discovery
# ---------------------------------------------------------------------------

WRAPPER_PATH = "/usr/local/bin/openclaw"

def _resolve_openclaw_paths() -> list[str]:
    paths: set[str] = set()
    paths.add(WRAPPER_PATH)

    target_env = os.environ.get("CLAWEDR_TARGET_BINARY")
    if target_env:
        paths.add(target_env)
        try:
            paths.add(os.path.realpath(target_env))
        except OSError:
            pass
        return sorted(paths)

    real_bin = shutil.which("openclaw")
    if real_bin and os.path.realpath(real_bin) == os.path.realpath(WRAPPER_PATH):
        npm_bin = _find_npm_openclaw()
        if npm_bin:
            real_bin = npm_bin

    if real_bin:
        paths.add(real_bin)
        try:
            resolved = os.path.realpath(real_bin)
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


def _find_npm_openclaw() -> str | None:
    try:
        result = subprocess.run(
            ["npm", "config", "get", "prefix"],
            capture_output=True, text=True, timeout=5,
        )
        prefix = result.stdout.strip()
        if prefix:
            candidate = os.path.join(prefix, "bin", "openclaw")
            if os.path.exists(candidate):
                return candidate
    except Exception:
        pass

    for pattern in [
        "/home/*/.npm-global/bin/openclaw",
        "/usr/local/bin/openclaw",
    ]:
        matches = globmod.glob(pattern)
        for m in matches:
            if os.path.realpath(m) != os.path.realpath(WRAPPER_PATH):
                return m
    return None


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
    from bcc import BPF

    logger.info("Compiling BPF program from %s", source_path)
    with open(source_path) as f:
        src = f.read()
    src = _pidns_defines() + src
    _bpf_instance = BPF(text=src)
    logger.info("BPF program loaded — tracepoints attached")

    def _print_event(cpu, data, size):
        event = _bpf_instance["events"].event(data)
        comm = event.comm.decode(errors="replace")
        filename = event.filename.decode(errors="replace")
        ns_pid = event.ns_pid if event.ns_pid else event.pid
        if event.action == 1:
            # Blocked by BPF — find the matching rule ID
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
        elif event.action == 2:
            # Post-exec (sys_exit_execve): /proc/cmdline now has the new argv.
            # This is when deny_rules must run — at enter, cmdline was still the shell.
            matched_rule = _check_deny_rules(ns_pid, comm, filename)
            if not matched_rule:
                logger.info(
                    "[observed] pid=%d uid=%d comm=%s file=%s",
                    ns_pid, event.uid, comm, filename,
                )
        # else action=0: sys_enter_execve — cmdline still shows old process.
        # Skip deny_rules and logging; the exit event (action=2) carries the real argv.

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
            block_logger.warning(
                "BLOCKED [%s] (deny_rule=%s) pid=%d cmdline=%s",
                rule_id, rule.get("rule", "unknown"), pid, cmdline[:200],
            )
            dispatch_alert_async(
                rule_id=rule_id,
                action="deny_rule",
                target=cmdline[:200],
                pid=pid,
                comm=comm,
            )
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


def bootstrap_tracked_pids(target_paths: list[str]) -> None:
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

        if exe_real in real_paths or exe in real_paths:
            tracked_map[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
            seeded += 1
            logger.info("Bootstrap: tracking PID %d (%s)", pid, exe)
            for child in _get_descendants(pid):
                tracked_map[ctypes.c_uint32(child)] = ctypes.c_uint8(1)
                seeded += 1
                logger.info("Bootstrap: tracking descendant PID %d", child)

    logger.info("Bootstrap complete — %d PIDs seeded into tracked_pids", seeded)


# ---------------------------------------------------------------------------
# Policy loading — blocked executables
# ---------------------------------------------------------------------------

def load_policy(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


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

            if rtype == "executable":
                policy.setdefault("blocked_executables", {})[rid] = val
            elif rtype == "domain":
                policy.setdefault("blocked_domains", {})[rid] = val
            elif rtype == "hash":
                policy.setdefault("malicious_hashes", {})[rid] = val.removeprefix("sha256:")
            elif rtype == "path":
                policy.setdefault("blocked_paths", {})[rid] = val
            elif rtype == "argument":
                # Inject as a deny_rule with argv matching
                deny_list = policy.setdefault("deny_rules", [])
                deny_list.append({
                    "id": rid,
                    "match": val,
                    "action": "deny",
                    "scope": "argv",
                })

    _apply_blocked_executables(policy, exempted)
    _apply_blocked_paths(policy, exempted)
    _apply_deny_rules(policy, exempted)
    _apply_pipe_heuristic()


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
        for prefix in PATH_PREFIXES:
            h = _djb2_hash(prefix + name)
            blocked_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
            _hash_to_rule_id[h] = rule_id
            loaded += 1
        h = _djb2_hash(name)
        blocked_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
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
]


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


def _add_subpaths(directory: str, out: set[str]) -> None:
    """Add well-known sensitive subfiles beneath a directory."""
    for sub in _SENSITIVE_SUBFILES:
        out.add(os.path.join(directory, sub))


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

    loaded = 0
    for rule_id, paths in expanded.items():
        for p in sorted(paths):
            h = _djb2_hash(p)
            path_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
            _hash_to_rule_id[h] = rule_id
            loaded += 1

    logger.info("Loaded %d entries into blocked_path_hashes BPF map", loaded)


# ---------------------------------------------------------------------------
# Layer 2: deny_rules — load into memory for userspace matching
# ---------------------------------------------------------------------------

def _apply_deny_rules(policy: dict, exempted: set[str]) -> None:
    global _deny_rules
    raw = policy.get("deny_rules", {})
    if isinstance(raw, dict) and "linux" in raw:
        raw = raw.get("linux", {})

    _deny_rules = {}
    skipped = 0
    for rule_id, rule in raw.items():
        if rule_id in exempted:
            logger.info("Skipping exempted deny_rule %s", rule_id)
            skipped += 1
            continue
        if isinstance(rule, dict) and rule.get("match"):
            _deny_rules[rule_id] = rule

    logger.info("Loaded %d deny_rules for userspace matching (%d skipped)",
                len(_deny_rules), skipped)


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

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    logger.info("Monitoring %s (poll every %ds)", path, interval)

    next_policy_check = 0.0

    while running:
        now = time.monotonic()
        if now >= next_policy_check:
            try:
                mtime = os.path.getmtime(path)
                if mtime != last_mtime:
                    logger.info("Policy file changed (mtime %.0f → %.0f), reloading", last_mtime, mtime)
                    policy = load_policy(path)
                    apply_policy(policy)
                    last_mtime = mtime
            except FileNotFoundError:
                logger.warning("Policy file not found at %s — waiting", path)
            except json.JSONDecodeError as exc:
                logger.error("Corrupt policy JSON: %s", exc)
            next_policy_check = now + interval

        if _bpf_instance is not None:
            try:
                _bpf_instance.perf_buffer_poll(timeout=50)
            except Exception:
                pass

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
        block_fh = logging.FileHandler(BLOCK_LOG_FILE)
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
    bootstrap_tracked_pids(target_paths)

    policy = load_policy(POLICY_PATH)
    apply_policy(policy)
    watch_and_reload(POLICY_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
