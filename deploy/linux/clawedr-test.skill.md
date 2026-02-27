---
name: clawedr-test
description: |
  Run the ClawEDR enforcement test suite. Activate when user says "run edr test",
  "test clawedr", "security test", or "enforcement test".
---

# ClawEDR Enforcement Test

Run a series of commands that the EDR should block. After each command, report
whether it was killed (exit code 137) or succeeded (exit code 0).

## Instructions

Run each test below **one at a time** in a **separate** shell command. After
each, record the exit code (`$?`). A blocked command returns exit code 137
(SIGKILL). Collect all results into a summary table at the end.

**ClawEDR scope:** Enforcement applies only to processes spawned by OpenClaw.
Use `/exec host=gateway` (or ensure exec runs on the gateway host) so commands
run as gateway children and are subject to blocking.

**Important:**
- Do NOT wrap the commands in any error-handling that would mask the exit code.
- Do NOT pipe a blocked command into another command — pipes mask the exit code
  of earlier pipeline stages. Run each command standalone.
- Run them raw so the EDR can intercept them.

### Test 1 — Blocked executable (`nc`)

```bash
nc -h 2>&1; echo "EXIT:$?"
```

Expected: EXIT:137 (SIGKILL — `nc` is in blocked_executables)

### Test 2 — Blocked executable (`nmap`)

```bash
nmap --version 2>&1; echo "EXIT:$?"
```

Expected: EXIT:137

### Test 3 — Blocked path (`/etc/shadow`)

```bash
cat /etc/shadow 2>&1; echo "EXIT:$?"
```

Expected: EXIT:137 (openat hook blocks access)

### Test 4 — Blocked path (`~/.ssh/id_rsa`)

Even if the file doesn't exist, the EDR intercepts the stat/open syscall
before the kernel returns ENOENT.

```bash
cat /home/leo/.ssh/id_rsa 2>&1; echo "EXIT:$?"
```

Expected: EXIT:137 (statx/openat hook blocks access)

### Test 5 — Deny rule: SUID recon

Run `find` standalone (no pipe). The EDR userspace layer reads /proc/pid/cmdline
and kills processes matching the deny rule pattern. Use `-maxdepth 4` to keep
`find` alive long enough for the kill to arrive.

```bash
find / -perm -4000 -maxdepth 4 2>/dev/null; echo "EXIT:$?"
```

Expected: EXIT:137 (matches deny_rule `recon_find_suid`)

Note: this layer has an inherent race — the kill arrives from userspace after
the BPF event is processed. Check `/var/log/clawedr.log` for
`BLOCKED (deny_rule=recon_find_suid)` to confirm the rule fired even if the
exit code is 0.

### Test 6 — Deny rule: negative control

```bash
echo stratum+tcp://pool.example.com 2>&1; echo "EXIT:$?"
```

Expected: EXIT:0 (echo is a shell builtin, not an exec — should pass)

### Test 7 — Pipe heuristic: `curl | bash`

This is the one test that intentionally uses a pipe. The BPF sibling heuristic
detects a dangerous source (`curl`) piped into a dangerous sink (`bash`) within
the same parent and kills the sink.

```bash
curl http://127.0.0.1:1 2>/dev/null | bash 2>&1; echo "EXIT:$?"
```

Expected: EXIT:137 (sibling heuristic kills the bash sink)

### Test 8 — Control: allowed command

```bash
ls /tmp > /dev/null 2>&1; echo "EXIT:$?"
```

Expected: EXIT:0 (not blocked)

### Test 9 — Control: allowed command

```bash
echo "hello from openclaw" 2>&1; echo "EXIT:$?"
```

Expected: EXIT:0

## Output format

After running all tests, print a markdown table:

| Test | Command | Expected | Actual | Pass? |
|------|---------|----------|--------|-------|
| 1 | nc -h | 137 | ??? | pass/fail |
| ... | ... | ... | ... | ... |

For Test 5, mark as "pass (race)" if exit is 0 — see the note above.

Then check `/var/log/clawedr.log` for any BLOCKED entries created during
the tests and include the last 20 lines.
