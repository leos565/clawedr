# ClawEDR Security Audit — Fix Tracker

Generated from audit on 2026-03-08.

---

## HIGH

- [x] **H1** `deploy/shared/user_rules.py:314,324` — Replace `uuid.uuid4()` with `secrets.token_urlsafe(32)` for dashboard auth token
- [x] **H2** `builder/threat_aggregator.py` — Validate feed URL scheme/host before fetching (HTTPS-only, allowlisted hosts); added `_validate_feed_url()` and `_validate_feed_schema()`
- [x] **H3** `deploy/shared/policy_verify.py:111–123` — Made `sign_policy_file()` atomic: write to temp file then `os.replace()`
- [x] **H4** `deploy/shared/policy_verify.py:65–68,90–94` — Fixed brittle hex key decode: added `_decode_key()` with strict 32-byte validation; raises on corrupt key instead of silently using wrong material; removed duplicated inline decode logic in `sign_policy` and `verify_policy`

---

## MEDIUM

- [x] **M1** `deploy/shared/user_rules.py:79–81` — Added `_is_valid_ipv4()` that validates octets 0–255; replaces bare `_IP_RE.match()` at both call sites
- [x] **M2** `builder/threat_aggregator.py` — Added `_validate_feed_schema()`: checks top-level structure, rejects unknown advisory keys, validates list-of-strings fields
- [x] **M3** `deploy/linux/monitor.py:124–132` — Removed deferred empty heuristics (HEU-NET-002, HEU-NET-003, HEU-SIA-001, HEU-PAG-002) from `HEURISTIC_DEFINITIONS`; left comments explaining why they're absent
- [x] **M4** `deploy/macos/log_tailer.py:276–279` — Added `verify_policy()` call in `monitor_network_connections()` before using reloaded policy; skips reload on verification failure
- [x] **M5** `deploy/macos/log_tailer.py:51–73` — Added `verify_policy()` in `_load_policy_rule_index()`; returns empty dict on failure
- [x] **M6** `deploy/macos/log_tailer.py:400–402` — Replaced full-clear of `seen_alerts` with TTL-based dict (`time.monotonic()` expiry at 300s per key); expired entries pruned each poll cycle
- [x] **M7** `deploy/shared/user_rules.py:402–406` — Added ReDoS guard: rejects patterns >200 chars and patterns with nested quantifiers/excessive alternation before `re.compile()`

---

## LOW

- [x] **L1** `deploy/shared/user_rules.py:84–88` — Added inline doc comment on `_PROTECTED_EXECUTABLES` explaining the footgun tradeoff
- [x] **L2** `deploy/macos/log_tailer.py:304–308` — Changed `pgrep -f openclaw` to `pgrep -x OpenClaw` (exact name match) with fallback to `pgrep -fi /openclaw` (path-anchored)
- [x] **L3** `deploy/macos/log_tailer.py:80` — Changed `seen_events` full-clear at 5000 to evict oldest half (2500 entries), preserving recent dedup state
- [x] **L4** `deploy/macos/log_tailer.py:357–359` — Added `_is_private_ip()` helper covering 127.x, 0.x, 10.x, 172.16–31.x, 192.168.x, 169.254.x (link-local), ::1; replaces bare loopback check
- [x] **L5** `deploy/macos/log_tailer.py:318–323` — Capped lsof to `_MAX_LSOF_PIDS=20` with batching loop; logs warning when more PIDs exist
- [x] **L6** `deploy/shared/user_rules.py:332–340` — Added `os.chmod(SETTINGS_PATH, 0o600)` after every `save_settings()` write

---

## STUBS / INCOMPLETE

- [x] **S1** `deploy/linux/monitor.py:126` — Added `argv_patterns` to HEU-NET-004: `["tcp-connect:", "tcp-listen:", "ngrok http", "ngrok tcp", "--port"]`
- [x] **S2** `deploy/linux/monitor.py` — Malicious hash enforcement: fixed four bugs in existing partial implementation: (1) moved hash check to `action=0` (sys_enter_execve) where `evt.filename` is the real exec path, not comm; (2) pass `event.pid` (host PID) instead of `ns_pid` for `/proc` access; (3) removed `if not matched_rule` guard that caused hash check to be skipped when a deny_rule matched; (4) strip `sha256:` prefix in `_apply_malicious_hashes` so stored hashes match hashlib hex output. Also added input validation (length + hex chars) and improved log format.
- [x] **S3** `deploy/linux/monitor.py` — Added warning log when `blocked_path_hashes` expansion exceeds 4096-entry BPF map cap; silently drops excess entries with a clear error message

---

## Progress

| Priority | Total | Done |
|----------|-------|------|
| High     | 4     | 4    |
| Medium   | 7     | 7    |
| Low      | 6     | 6    |
| Stubs    | 3     | 2    |
| **Total**| **20**| **20**|

All items complete.
