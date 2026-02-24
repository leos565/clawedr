#!/usr/bin/env python3
"""
ClawEDR Linux Shield Monitor.

Watches compiled_policy.json for changes and hot-reloads the eBPF maps
without restarting OpenClaw.

Lifecycle:
  1. Load compiled_policy.json → populate BPF hash maps.
  2. Watch the file (via mtime polling) for updates.
  3. On change → clear BPF maps → reload new hashes/rules.
"""

import json
import logging
import os
import signal
import sys
import time

logger = logging.getLogger("clawedr.monitor")

POLICY_PATH = os.environ.get(
    "CLAWEDR_POLICY_PATH", "/usr/local/share/clawedr/compiled_policy.json"
)
POLL_INTERVAL = int(os.environ.get("CLAWEDR_POLL_INTERVAL", "5"))


def load_policy(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def apply_policy(policy: dict) -> None:
    """Apply the policy to eBPF maps.

    In a full implementation this would use the BCC Python bindings to
    update the BPF hash maps.  For now it logs what would happen.
    """
    logger.info(
        "Applying policy: %d blocked executables, %d blocked domains, %d hashes",
        len(policy.get("blocked_executables", [])),
        len(policy.get("blocked_domains", [])),
        len(policy.get("malicious_hashes", [])),
    )
    # TODO: BCC map update — bpf["blocked_hashes"].clear(); ...


def watch_and_reload(path: str, interval: int = POLL_INTERVAL) -> None:
    """Poll for policy changes and hot-reload."""
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

        time.sleep(interval)

    logger.info("Monitor stopped.")


LOG_FILE = os.environ.get("CLAWEDR_LOG_FILE", "/var/log/clawedr_monitor.log")


def setup_logging() -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(fmt)
    root.addHandler(stdout_handler)

    try:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except PermissionError:
        logger.warning("Cannot write to %s — file logging disabled", LOG_FILE)


def main() -> int:
    setup_logging()
    logger.info("ClawEDR Linux Shield Monitor starting")

    if not os.path.exists(POLICY_PATH):
        logger.error("Policy file not found: %s", POLICY_PATH)
        return 1

    policy = load_policy(POLICY_PATH)
    apply_policy(policy)
    watch_and_reload(POLICY_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
