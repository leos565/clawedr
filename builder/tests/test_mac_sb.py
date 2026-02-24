"""
ClawEDR macOS Seatbelt Tests.

Validates that the compiled clawedr.sb profile correctly blocks access
to sensitive paths when enforced via sandbox-exec.
"""

import os
import platform
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEPLOY_MACOS = PROJECT_ROOT / "deploy" / "macos"
SB_PROFILE = DEPLOY_MACOS / "clawedr.sb"

IS_MACOS = platform.system() == "Darwin"

pytestmark = pytest.mark.skipif(not IS_MACOS, reason="macOS-only tests")


@pytest.fixture(autouse=True)
def require_seatbelt_profile():
    if not SB_PROFILE.exists():
        pytest.skip(f"Seatbelt profile not found at {SB_PROFILE} — run ./main.py compile first")


class TestSeatbeltProfileSyntax:
    """Verify the .sb file is syntactically valid by loading it."""

    def test_profile_is_not_empty(self):
        content = SB_PROFILE.read_text()
        assert len(content) > 0

    def test_profile_has_version_directive(self):
        content = SB_PROFILE.read_text()
        assert "(version 1)" in content

    def test_profile_has_deny_rules(self):
        content = SB_PROFILE.read_text()
        assert "(deny " in content


class TestSeatbeltEnforcement:
    """Run commands under sandbox-exec and assert blocked behaviour."""

    def _sandbox_run(self, *cmd: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["sandbox-exec", "-f", str(SB_PROFILE), "--", *cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_blocked_ssh_read(self):
        """Reading ~/.ssh should be denied by the profile."""
        ssh_dir = os.path.expanduser("~/.ssh")
        if not os.path.isdir(ssh_dir):
            pytest.skip("~/.ssh does not exist on this machine")

        result = self._sandbox_run("ls", ssh_dir)
        assert result.returncode != 0, (
            f"Expected non-zero exit when reading ~/.ssh under sandbox, "
            f"got rc={result.returncode}"
        )

    def test_allowed_command_succeeds(self):
        """A benign command should still work under the sandbox."""
        result = self._sandbox_run("echo", "hello")
        assert result.returncode == 0
        assert "hello" in result.stdout
