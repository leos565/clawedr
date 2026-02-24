#!/usr/bin/env python3
"""
ClawEDR Linux Shield Monitor.

Watches compiled_policy.json for changes and hot-reloads the eBPF maps
without restarting OpenClaw.

Scoped enforcement: only OpenClaw processes (and their descendants) are
tracked.  The monitor populates the BPF target_bins map with djb2 hashes
of known OpenClaw binary paths so the kernel hooks can auto-detect them.

Lifecycle:
  1. Load bpf_hooks.c via BCC.
  2. Populate target_bins with OpenClaw binary path hashes.
  3. Bootstrap tracked_pids from /proc for already-running OpenClaw procs.
  4. Load compiled_policy.json -> populate BPF blocked_hashes map.
  5. Poll for policy file changes and hot-reload.
"""

import ctypes
import glob
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time

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
    """Return all filesystem paths that represent the OpenClaw binary."""
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
            paths.add(os.path.realpath(real_bin))
        except OSError:
            pass

    return sorted(paths)


def _find_npm_openclaw() -> str | None:
    """Try to locate the real (npm-installed) openclaw binary."""
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
        matches = glob.glob(pattern)
        for m in matches:
            if os.path.realpath(m) != os.path.realpath(WRAPPER_PATH):
                return m
    return None


# ---------------------------------------------------------------------------
# BPF loading
# ---------------------------------------------------------------------------

def load_bpf(source_path: str):
    global _bpf_instance
    from bcc import BPF

    logger.info("Compiling BPF program from %s", source_path)
    with open(source_path) as f:
        src = f.read()
    _bpf_instance = BPF(text=src)
    logger.info("BPF program loaded — tracepoints attached")

    def _print_event(cpu, data, size):
        event = _bpf_instance["events"].event(data)
        comm = event.comm.decode(errors="replace")
        filename = event.filename.decode(errors="replace")
        if event.action == 1:
            block_logger.warning(
                "BLOCKED pid=%d uid=%d comm=%s file=%s",
                event.pid, event.uid, comm, filename,
            )
        else:
            logger.info(
                "[observed] pid=%d uid=%d comm=%s file=%s",
                event.pid, event.uid, comm, filename,
            )

    _bpf_instance["events"].open_perf_buffer(_print_event)
    return _bpf_instance


# ---------------------------------------------------------------------------
# Target bins map
# ---------------------------------------------------------------------------

def populate_target_bins(paths: list[str]) -> None:
    """Insert djb2 hashes of OpenClaw binary paths into the BPF map."""
    if _bpf_instance is None:
        return
    target_map = _bpf_instance["target_bins"]
    for p in paths:
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
    """Walk /proc/<pid>/task/*/children recursively."""
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
    """Scan /proc for running OpenClaw processes and seed tracked_pids."""
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
# Policy loading
# ---------------------------------------------------------------------------

def load_policy(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def apply_policy(policy: dict) -> None:
    global _bpf_instance
    execs = policy.get("blocked_executables", [])
    domains = policy.get("blocked_domains", [])
    hashes = policy.get("malicious_hashes", [])
    logger.info(
        "Applying policy: %d blocked executables, %d blocked domains, %d hashes",
        len(execs), len(domains), len(hashes),
    )

    if _bpf_instance is None:
        logger.warning("BPF not loaded — skipping map update")
        return

    blocked_map = _bpf_instance["blocked_hashes"]
    blocked_map.clear()

    loaded = 0
    for name in execs:
        for path_prefix in ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/"):
            full = path_prefix + name
            h = _djb2_hash(full)
            blocked_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
            loaded += 1

        h = _djb2_hash(name)
        blocked_map[ctypes.c_uint64(h)] = ctypes.c_uint8(1)
        loaded += 1

    logger.info("Loaded %d entries into blocked_hashes BPF map", loaded)


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

    while running:
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

        if _bpf_instance is not None:
            try:
                _bpf_instance.perf_buffer_poll(timeout=100)
            except Exception:
                pass

        time.sleep(max(0, interval - 0.1))

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
