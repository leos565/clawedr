# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (`main`) | Yes |
| Older releases | No — please update to `main` |

ClawEDR does not use versioned releases at this time. The `main` branch is the supported version. Compiled policy artifacts in `deploy/` are regenerated on every push.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately by using [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) on this repository.

Include in your report:
- A clear description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- The component affected (`bpf_hooks.c`, `monitor.py`, policy compiler, dashboard, etc.)
- Any suggested mitigations you have identified

You will receive an acknowledgement within **48 hours** and a status update within **7 days**. We aim to ship a fix within **14 days** for critical issues.

We do not operate a bug bounty program at this time, but we will credit researchers in the fix commit and changelog unless you prefer to remain anonymous.

## Scope

The following are considered in-scope:

- **Policy bypass** — any technique that allows a monitored process to execute a blocked binary, access a blocked path, or connect to a blocked domain without triggering enforcement
- **Privilege escalation** — vulnerabilities that allow an unprivileged process to escalate to root through ClawEDR's components (monitor daemon, dashboard, installer)
- **Dashboard injection / auth bypass** — XSS, CSRF, or unauthenticated access to the FastAPI dashboard (port 8477)
- **Policy tampering** — weaknesses in the HMAC policy signature that allow undetected modification of `compiled_policy.json`
- **Audit log integrity** — bypasses to the HMAC-chained audit log that allow undetected deletion or modification of entries
- **Output scanner / injection detector evasion** — inputs that smuggle secrets or prompt-injection payloads past the pattern library without triggering a match

The following are considered out-of-scope:

- Attacks requiring physical access to the host machine
- Denial-of-service against the monitoring daemon without code execution
- Issues in third-party dependencies not introduced by this project
- The threat model does not cover a fully compromised host kernel

## Threat Model

ClawEDR is designed to contain a **compromised or misbehaving AI coding agent**, not a human attacker with shell access.

**What ClawEDR protects against:**
- An agent executing dangerous binaries (`nmap`, `nc`, `curl` to untrusted destinations, etc.)
- An agent reading or writing sensitive paths (`~/.ssh`, `/etc/passwd`, credential files)
- An agent making outbound connections to blocked domains or IPs
- Prompt-injection attacks embedded in tool results or file content flowing into the agent
- Secrets and PII surfaced in LLM output before reaching the user

**What ClawEDR does not protect against:**
- A human attacker with root access to the host — enforcement runs as root and can be terminated
- Kernel exploits that bypass eBPF / Seatbelt enforcement
- Agents that modify ClawEDR's own policy files before the monitor loads them (file integrity is checked via HMAC, but a root-capable attacker can regenerate the HMAC)
- macOS enforcement gaps during the brief window before `sandbox-exec` wraps the agent process

## Security Architecture Notes

**eBPF enforcement (Linux):** Policy is enforced in-kernel via BPF programs loaded by `monitor.py`. The BPF programs run in the kernel's verifier-checked sandbox. The monitor must run as root to load BPF programs; the monitored agent process does not require elevated privileges.

**Seatbelt enforcement (macOS):** The compiled `.sb` profile is passed to `sandbox-exec` at agent launch. Violations are denied by the kernel before the syscall completes.

**Policy authenticity:** `compiled_policy.json` is HMAC-signed at compile time. The monitor verifies the signature on load and on every hot-reload. A policy file with an invalid signature is rejected.

**Audit log integrity:** Alert events are written to an HMAC-chained audit log. Each entry includes a MAC over the previous entry's hash, making undetected deletion or reordering detectable.

**Dashboard:** The web UI binds to `127.0.0.1:8477` by default and has no authentication. It is intended for local use only. Do not expose port 8477 to untrusted networks.

**User rules:** Per-user exemptions (`~/.clawedr/user_rules.yaml`) are loaded with lower precedence than the compiled policy and cannot grant permissions that exceed the compiled policy's allow-list.
