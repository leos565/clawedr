#!/usr/bin/env python3
"""
ClawEDR Forge CLI — the 4-step Execution Loop.

Usage:
    ./main.py sync      Fetch ClawSec feed and merge with master_rules.yaml
    ./main.py compile   Transpile merged rules into kernel policies
    ./main.py test      Run the Seatbelt + eBPF test suite
    ./main.py publish   Commit and push deploy/ to the GitHub registry
    ./main.py all       Run sync → compile → test in sequence
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

logger = logging.getLogger("clawedr")


def cmd_sync(args: argparse.Namespace) -> int:
    from builder.threat_aggregator import sync
    try:
        merged = sync(feed_url=args.feed_url)
        logger.info(
            "Sync complete — %d domains, %d hashes, %d skills tracked",
            len(merged.get("blocked_domains", [])),
            len(merged.get("malicious_hashes", [])),
            len(merged.get("affected_skills", [])),
        )
        return 0
    except Exception as exc:
        logger.error("Sync failed: %s", exc)
        return 1


def cmd_compile(_args: argparse.Namespace) -> int:
    from builder.compiler import compile_all
    try:
        compile_all()
        return 0
    except Exception as exc:
        logger.error("Compile failed: %s", exc)
        return 1


def cmd_test(_args: argparse.Namespace) -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "builder/tests/", "-v"],
        cwd=str(PROJECT_ROOT),
    )
    return result.returncode


def cmd_publish(args: argparse.Namespace) -> int:
    cmds = [
        ["git", "add", "deploy/"],
        ["git", "commit", "-m", args.message],
        ["git", "push"],
    ]
    for cmd in cmds:
        logger.info("Running: %s", " ".join(cmd))
        result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
        if result.returncode != 0:
            logger.error("Command failed: %s", " ".join(cmd))
            return result.returncode
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    for fn in (cmd_sync, cmd_compile, cmd_test):
        rc = fn(args)
        if rc != 0:
            return rc
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="clawedr",
        description="ClawEDR Forge CLI",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_sync = sub.add_parser("sync", help="Fetch and merge threat intelligence")
    p_sync.add_argument(
        "--feed-url",
        default="https://clawsec.prompt.security/advisories/feed.json",
        help="Override the ClawSec feed URL",
    )
    p_sync.set_defaults(func=cmd_sync)

    p_compile = sub.add_parser("compile", help="Transpile rules into kernel policies")
    p_compile.set_defaults(func=cmd_compile)

    p_test = sub.add_parser("test", help="Run the test suite")
    p_test.set_defaults(func=cmd_test)

    p_publish = sub.add_parser("publish", help="Commit and push deploy/ to GitHub")
    p_publish.add_argument(
        "-m", "--message",
        default="chore: update compiled policies",
        help="Git commit message",
    )
    p_publish.set_defaults(func=cmd_publish)

    p_all = sub.add_parser("all", help="Run sync -> compile -> test")
    p_all.add_argument(
        "--feed-url",
        default="https://clawsec.prompt.security/advisories/feed.json",
    )
    p_all.set_defaults(func=cmd_all)

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
