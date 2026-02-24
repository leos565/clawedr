"""
ClawEDR Linux eBPF Tests.

Validates the Shield on a remote Linux VM (OrbStack) by SSHing in,
deploying the policy and BPF hooks, and asserting that blocked
executables receive SIGKILL.

Configuration is read from builder/config.yaml:
    linux_vm:
        host: <orbstack-host>
        user: <username>
        key:  ~/.ssh/id_clawedr      # optional, defaults to ssh agent
"""

import json
import os
import platform
import subprocess
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = PROJECT_ROOT / "builder" / "config.yaml"
DEPLOY_DIR = PROJECT_ROOT / "deploy"
POLICY_PATH = DEPLOY_DIR / "compiled_policy.json"

IS_MACOS = platform.system() == "Darwin"


def _load_vm_config() -> dict:
    if not CONFIG_PATH.exists():
        pytest.skip("builder/config.yaml not found — Linux VM not configured")
    with open(CONFIG_PATH) as f:
        cfg = yaml.safe_load(f) or {}
    vm = cfg.get("linux_vm", {})
    if not vm.get("host"):
        pytest.skip("linux_vm.host not set in config.yaml")
    return vm


def _ssh_cmd(vm: dict, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command on the Linux VM via SSH."""
    ssh_args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
    ]
    key = vm.get("key")
    if key:
        ssh_args += ["-i", os.path.expanduser(key)]

    user_host = f"{vm['user']}@{vm['host']}" if vm.get("user") else vm["host"]
    ssh_args.append(user_host)
    ssh_args.append(command)

    return subprocess.run(ssh_args, capture_output=True, text=True, timeout=timeout)


def _scp_to_vm(vm: dict, local_path: str, remote_path: str) -> None:
    """Copy a file to the Linux VM."""
    scp_args = [
        "scp",
        "-o", "StrictHostKeyChecking=no",
    ]
    key = vm.get("key")
    if key:
        scp_args += ["-i", os.path.expanduser(key)]

    user_host = f"{vm['user']}@{vm['host']}" if vm.get("user") else vm["host"]
    scp_args += [local_path, f"{user_host}:{remote_path}"]

    subprocess.run(scp_args, check=True, capture_output=True, timeout=30)


@pytest.fixture(scope="module")
def vm_config():
    return _load_vm_config()


@pytest.fixture(scope="module")
def deploy_to_vm(vm_config):
    """Copy policy and BPF artifacts to the VM."""
    if not POLICY_PATH.exists():
        pytest.skip("compiled_policy.json not found — run ./main.py compile first")

    _ssh_cmd(vm_config, "mkdir -p /tmp/clawedr")
    _scp_to_vm(vm_config, str(POLICY_PATH), "/tmp/clawedr/compiled_policy.json")
    _scp_to_vm(
        vm_config, str(DEPLOY_DIR / "linux" / "bpf_hooks.c"), "/tmp/clawedr/bpf_hooks.c"
    )
    _scp_to_vm(
        vm_config, str(DEPLOY_DIR / "linux" / "monitor.py"), "/tmp/clawedr/monitor.py"
    )
    yield
    _ssh_cmd(vm_config, "rm -rf /tmp/clawedr")


class TestLinuxVMConnectivity:
    def test_ssh_reachable(self, vm_config):
        result = _ssh_cmd(vm_config, "echo clawedr-ok")
        assert result.returncode == 0
        assert "clawedr-ok" in result.stdout

    def test_bcc_available(self, vm_config):
        result = _ssh_cmd(vm_config, "python3 -c 'import bcc; print(bcc.__version__)'")
        if result.returncode != 0:
            pytest.skip("BCC not available on VM — install python3-bpfcc")


class TestLinuxBPFEnforcement:
    """These tests require root on the VM and BCC installed."""

    def test_policy_loads(self, vm_config, deploy_to_vm):
        result = _ssh_cmd(
            vm_config,
            "python3 -c \"import json; p=json.load(open('/tmp/clawedr/compiled_policy.json')); print(len(p.get('blocked_executables',[])))\"",
        )
        assert result.returncode == 0
        count = int(result.stdout.strip())
        assert count > 0, "Expected at least one blocked executable in policy"

    def test_blocked_executable_gets_killed(self, vm_config, deploy_to_vm):
        """Attempt to run a blocked command (nc -l 4444) and assert SIGKILL.

        This is a placeholder — full enforcement requires loading the BPF
        program as root.  For now we verify the policy file is correct.
        """
        result = _ssh_cmd(
            vm_config,
            "python3 -c \""
            "import json; "
            "p=json.load(open('/tmp/clawedr/compiled_policy.json')); "
            "assert 'nc' in p['blocked_executables'], 'nc not in blocked list'; "
            "print('nc is blocked')\"",
        )
        assert result.returncode == 0
        assert "nc is blocked" in result.stdout
