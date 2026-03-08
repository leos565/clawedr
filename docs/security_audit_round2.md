# ClawEDR Security Audit — Round 2 Findings & Fixes

Audit date: 2026-03-08. All items below were found, fixed, and tests verified.

---

## CRITICAL

### C1 — `rule_updater.py` applies downloaded policy without signature verification
**File**: `deploy/shared/rule_updater.py:167–181`
**Fixed in**: `download_and_apply()`

`download_and_apply()` fetched `compiled_policy.json` from GitHub and wrote it directly to disk. The monitor hot-reloads on file change. `verify_policy()` was never called, so a compromised registry or MITM attack could push malicious rules that took immediate kernel-level effect on Linux.

**Fix**: Added `verify_policy(remote)` call before writing. If a local signing key exists and verification fails, the update is aborted with a clear error. If no key is configured (fresh install), a warning is logged and the update proceeds — consistent with the signed-locally, verified-remotely design intent.

---

### C2 — `clawedr.sb` downloaded and written with no integrity check
**File**: `deploy/shared/rule_updater.py:189–194`
**Fixed in**: `download_and_apply()`

The Seatbelt profile was fetched with `resp.read().decode()` and written with `sb_dest.write_text(sb_content)` — no validation, no size cap, no content check. A compromised registry could push an empty `.sb` or one missing `(allow default)`, removing all macOS sandbox protections silently.

**Fix**:
- Added `_fetch_text()` with a 2 MB size cap
- Added `_validate_seatbelt_profile()` that checks for required markers `(version 1)` and `(allow default)`, rejects empty content, and rejects profiles with `(deny default)` but no `(allow default)`
- Write is now atomic (temp file + `os.replace()`) matching the JSON policy approach
- If validation fails, existing profile is kept and a warning is logged

---

## HIGH

### H1 — Dashboard token accepted via query parameter
**File**: `deploy/dashboard/app.py:94` (middleware) and `:675` (`/api/auth/check`)
**Fixed in**: `TokenAuthMiddleware.dispatch()` and `auth_check()`

`?token=<token>` was accepted as the second auth vector. Query parameters appear in nginx/Apache access logs, load balancer logs, browser history, and `Referer` headers on any subsequent navigation. The token could leak silently without any indication.

**Fix**: Removed query parameter support from both the middleware and `/api/auth/check`. Token is now accepted only via `Authorization: Bearer <token>` header or `clawedr_token` cookie.

---

### H2 — Installer generates weak token with `uuid.uuid4()`
**File**: `deploy/install.sh:643`
**Fixed in**: inline python block

The dashboard runtime (`user_rules.py`) was updated in Round 1 to use `secrets.token_urlsafe(32)`, but the installer's inline Python block still used `uuid.uuid4()`. On first install, this weak token is written to `settings.yaml` and persists as the active dashboard token until explicitly regenerated. UUID4 has ~122 bits of entropy versus `token_urlsafe(32)`'s 256 bits, and on some platforms UUID4 uses partially predictable seeds.

**Fix**: Changed `import uuid` → `import secrets` and `str(uuid.uuid4())` → `secrets.token_urlsafe(32)`.

---

### H3 — `CLAWEDR_REGISTRY_URL` env var trusted without HTTPS or host validation
**File**: `deploy/shared/rule_updater.py:22–25`
**Fixed in**: `_validate_registry_url()`

The update URL was taken directly from environment with no scheme or host check. An attacker controlling the environment (process env, `.env` file, systemd `EnvironmentFile`) could redirect updates to an arbitrary HTTP server, delivering malicious policies.

**Fix**: Added `_validate_registry_url()` mirroring the pattern from `threat_aggregator.py`. Enforces HTTPS and an explicit allowlist (`raw.githubusercontent.com`, `github.com`, `api.github.com`, `clawsec.prompt.security`). Both `check_for_updates()` and `download_and_apply()` call it before any network request.

---

### H4 — Any non-empty `dashboard_bind_addresses` caused binding to `0.0.0.0`
**File**: `deploy/dashboard/app.py:919–921`
**Fixed in**: `main()` and the settings endpoint

The bind logic was: if `extra_addrs` list is non-empty → `bind_host = "0.0.0.0"`. The stored addresses were logged but never actually used — uvicorn only received `0.0.0.0`. Setting any address (even `127.0.0.2`) silently exposed the dashboard on all network interfaces.

**Fix**:
- Settings endpoint now validates each address with `ipaddress.ip_address()`, rejecting invalid values
- `main()` uses `extra_addrs[0]` as the bind host directly instead of switching to `0.0.0.0`
- Default remains `127.0.0.1`

---

## MEDIUM

### M1 — `_content_hash` didn't exclude `_signature`
**File**: `deploy/shared/rule_updater.py:63`
**Fixed in**: `_content_hash()`

The hash excluded `_meta` but not `_signature`. After signing the local policy (Round 1 change), its `_signature` field differs from the unsigned remote copy. Every update check reported a content mismatch even when rules were identical, causing spurious "has updates" banners and potential unnecessary update downloads.

**Fix**: `_content_hash` now excludes both `_meta` and `_signature`.

---

### M2 — `pgrep -f "monitor.py"` matches any process with that string in cmdline
**File**: `deploy/dashboard/app.py:378`
**Fixed in**: Linux monitor reload fallback

The fallback to `pgrep -f "monitor.py"` would match any process whose command line contained `monitor.py` — including user scripts, editor buffers, or Python REPLs running in a directory containing the file. These processes would receive an unexpected SIGHUP.

**Fix**: Changed to `pgrep -f "/usr/local/share/clawedr/monitor.py"` — anchored to the known installation path.

---

### M3 — Deny rule attribution in log_tailer used reversed substring match
**File**: `deploy/macos/log_tailer.py:151`
**Fixed in**: sandbox event handler deny rule lookup (step 3)

The original check was `target in directive` — it tested whether the sandbox violation target (e.g., `"4444"`) appeared inside the raw Seatbelt LISP directive string (e.g., `(deny network-outbound (remote tcp "*:4444"))`). This produced wrong rule ID attribution: any target that happened to appear anywhere in the LISP syntax (including punctuation, keywords like `"deny"`, `"tcp"`) would match.

**Fix**: Now extracts quoted values from the directive with a regex (`"([^"]+)"`), strips leading glob wildcards, and checks whether the sandbox target ends with the extracted value. More correct, though rule attribution for custom deny rules is inherently best-effort since Seatbelt doesn't report which rule triggered.

---

### M4 — Heuristic SIGKILL used `ns_pid` instead of `event.pid`
**File**: `deploy/linux/monitor.py:417`
**Fixed in**: heuristic event handler (action 5)

For containerized processes, `ns_pid` is the PID within the container's namespace. `os.kill()` operates on host-namespace PIDs. Using `ns_pid` for the userspace fallback kill could target the wrong process when container PIDs and host PIDs differ.

**Fix**: Changed `os.kill(ns_pid, 9)` → `os.kill(event.pid, 9)`. `event.pid` is always the host-namespace PID (`pid_tgid >> 32` in BPF). Added a comment explaining the distinction and that `bpf_send_signal` already fired in the kernel.

---

## LOW

### L1 — Dashboard token printed to stderr at startup
**File**: `deploy/dashboard/app.py:914`

`print(f"  Dashboard Token:  {token}\n")` sent the auth token to stderr on every startup. This appears in systemd journal (`journalctl -u clawedr-dashboard`), Docker log output, and any log aggregation that captures stderr — potentially accessible to users who shouldn't have dashboard access.

**Fix**: Removed the `print()` call. The logger line was changed to point users to the settings file path rather than printing the token value. The token remains readable from `/etc/clawedr/settings.yaml` (which is 0600) by the authorized user.

---

## Summary

| ID | Severity | File | Fixed |
|----|----------|------|-------|
| C1 | Critical | rule_updater.py | ✓ verify_policy before applying |
| C2 | Critical | rule_updater.py | ✓ validate + atomic write for .sb |
| H1 | High | app.py | ✓ removed query param auth |
| H2 | High | install.sh | ✓ secrets.token_urlsafe(32) |
| H3 | High | rule_updater.py | ✓ _validate_registry_url() |
| H4 | High | app.py | ✓ validate IPs, bind to specific address |
| M1 | Medium | rule_updater.py | ✓ exclude _signature from content hash |
| M2 | Medium | app.py | ✓ anchor pgrep to install path |
| M3 | Medium | log_tailer.py | ✓ fix reversed substring match |
| M4 | Medium | monitor.py | ✓ os.kill uses event.pid not ns_pid |
| L1 | Low | app.py | ✓ removed token from stderr output |

All 11 items fixed. Test suite: 9/9 passing.
