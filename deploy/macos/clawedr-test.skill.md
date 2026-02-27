---
name: clawedr-test
description: |
  Run the ClawEDR macOS Seatbelt enforcement test suite. Activate when user says
  "run edr test", "test clawedr", "security test", or "enforcement test".
---

# ClawEDR macOS Seatbelt Test

Run a series of commands that the EDR Seatbelt profile should block. After each
command, report whether the operation was denied or succeeded.

## Instructions

Run each test below **one at a time** in a **separate** shell command. After
each, record the exit code and any error output. On macOS, Seatbelt denies
operations by returning "Operation not permitted" — it does NOT kill the
process. So blocked commands return non-zero exit codes (typically 1) with
an error message, not exit code 137.

**ClawEDR scope:** Enforcement applies only to processes spawned by OpenClaw.
Use `/exec host=gateway` (or ensure exec runs on the gateway host) so commands
run as gateway children and are subject to blocking.

**Important:**
- Do NOT wrap the commands in any error-handling that would mask the exit code.
- Run them raw so the sandbox can intercept them.
- Capture both stdout and stderr.

### Test 1 — Blocked executable (`nc`)

```bash
/usr/bin/nc -h 2>&1; echo "EXIT:$?"
```

Expected: "Operation not permitted" and non-zero exit code (sandbox blocks exec)

### Test 2 — Blocked executable (`osascript`)

```bash
/usr/bin/osascript -e 'display dialog "test"' 2>&1; echo "EXIT:$?"
```

Expected: "Operation not permitted" and non-zero exit code

### Test 3 — Blocked executable (`security`)

The `security` command accesses Keychain. The sandbox blocks its execution.

```bash
/usr/bin/security dump-keychain 2>&1; echo "EXIT:$?"
```

Expected: "Operation not permitted" and non-zero exit code

### Test 4 — Blocked executable (`dscl`)

```bash
/usr/bin/dscl . -list /Users 2>&1; echo "EXIT:$?"
```

Expected: "Operation not permitted" and non-zero exit code

### Test 5 — Blocked path (`~/.ssh`)

The `.ssh` directory exists on this machine.

```bash
ls ~/.ssh/ 2>&1; echo "EXIT:$?"
```

Expected: "Operation not permitted" (Seatbelt denies file-read* on ~/.ssh)

### Test 6 — Blocked path (`~/Library/Keychains`)

```bash
ls ~/Library/Keychains/ 2>&1; echo "EXIT:$?"
```

Expected: "Operation not permitted" (Seatbelt denies file-read* on ~/Library/Keychains)

### Test 7 — Blocked path (`~/Library/Messages`)

```bash
ls ~/Library/Messages/ 2>&1; echo "EXIT:$?"
```

Expected: "Operation not permitted" (Seatbelt denies file-read*)

### Test 8 — Blocked path (`~/Library/Mail`)

```bash
ls ~/Library/Mail/ 2>&1; echo "EXIT:$?"
```

Expected: "Operation not permitted" (Seatbelt denies file-read*)

### Test 9 — Blocked network port (4444 — common reverse shell)

```bash
curl -s --connect-timeout 3 http://127.0.0.1:4444/ 2>&1; echo "EXIT:$?"
```

Expected: Non-zero exit code with a connection/permission error (Seatbelt blocks
outbound to port 4444)

### Test 10 — Control: allowed command

```bash
ls /tmp > /dev/null 2>&1; echo "EXIT:$?"
```

Expected: EXIT:0 (not blocked)

### Test 11 — Control: allowed command

```bash
echo "hello from openclaw" 2>&1; echo "EXIT:$?"
```

Expected: EXIT:0

### Test 12 — Control: allowed file read

```bash
cat /etc/hosts 2>&1 | head -1; echo "EXIT:$?"
```

Expected: EXIT:0 (/etc/hosts is not a blocked path)

## Output format

After running all tests, print a markdown table:

| Test | Command | Expected | Actual exit | Error msg | Pass? |
|------|---------|----------|-------------|-----------|-------|
| 1 | /usr/bin/nc -h | denied | ??? | ??? | pass/fail |
| ... | ... | ... | ... | ... | ... |

Mark a test as "pass" if:
- For blocked tests (1-9): the command was denied (non-zero exit, "Operation not permitted" or similar error)
- For control tests (10-12): the command succeeded (exit 0)
