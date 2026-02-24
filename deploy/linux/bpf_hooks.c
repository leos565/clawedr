/*
 * ClawEDR eBPF Hooks — loaded via BCC on Linux.
 *
 * Hooks into execve() to check process names against the blocked list
 * and emits events via BPF_PERF_OUTPUT for monitor.py to consume.
 *
 * The blocked_hashes map is populated from compiled_policy.json by
 * the monitor daemon.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_FILENAME_LEN 256

struct event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    u8  action; // 0 = log, 1 = blocked (SIGKILL)
};

BPF_HASH(blocked_hashes, u64, u8, 1024);
BPF_PERF_OUTPUT(events);

static __always_inline u64 simple_hash(const char *s, int len) {
    u64 h = 5381;
    for (int i = 0; i < len && i < MAX_FILENAME_LEN; i++) {
        char c = 0;
        bpf_probe_read_user(&c, 1, &s[i]);
        if (c == 0) break;
        h = ((h << 5) + h) + (u64)c;
    }
    return h;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    const char *fname = args->filename;
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), fname);

    u64 h = simple_hash(fname, MAX_FILENAME_LEN);
    u8 *is_blocked = blocked_hashes.lookup(&h);

    if (is_blocked) {
        evt.action = 1;
        events.perf_submit(args, &evt, sizeof(evt));
        // SIGKILL the offending process
        bpf_send_signal(SIGKILL);
    } else {
        evt.action = 0;
        events.perf_submit(args, &evt, sizeof(evt));
    }

    return 0;
}
