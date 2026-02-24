/*
 * ClawEDR eBPF Hooks — loaded via BCC on Linux.
 *
 * Scoped enforcement: only processes in the OpenClaw process tree are
 * monitored.  The target_bins map (populated by monitor.py) holds djb2
 * hashes of known OpenClaw binary paths.  When execve fires for one of
 * those binaries the PID is added to tracked_pids.  Fork/exit hooks
 * propagate and clean up tracking for all descendants.
 *
 * blocked_hashes is populated from compiled_policy.json by the monitor.
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
    u8  action; // 0 = observed, 1 = blocked (SIGKILL)
};

BPF_HASH(blocked_hashes, u64, u8, 1024);
BPF_HASH(tracked_pids, u32, u8, 8192);
BPF_HASH(target_bins, u64, u8, 16);
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

/* Auto-detect OpenClaw binary + enforce policy on tracked tree. */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    const char *fname = args->filename;
    u64 h = simple_hash(fname, MAX_FILENAME_LEN);

    u8 *is_target = target_bins.lookup(&h);
    if (is_target) {
        u8 one = 1;
        tracked_pids.update(&pid, &one);
    }

    u8 *is_tracked = tracked_pids.lookup(&pid);
    if (!is_tracked)
        return 0;

    evt.pid = pid;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), fname);

    u8 *is_blocked = blocked_hashes.lookup(&h);
    if (is_blocked) {
        evt.action = 1;
        events.perf_submit(args, &evt, sizeof(evt));
        bpf_send_signal(SIGKILL);
    } else {
        evt.action = 0;
        events.perf_submit(args, &evt, sizeof(evt));
    }

    return 0;
}

/* Propagate tracking from parent to child on fork. */
TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent_pid = args->parent_pid;
    u32 child_pid = args->child_pid;

    u8 *tracked = tracked_pids.lookup(&parent_pid);
    if (tracked) {
        u8 one = 1;
        tracked_pids.update(&child_pid, &one);
    }

    return 0;
}

/* Remove exiting processes from the tracked set. */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    tracked_pids.delete(&pid);

    return 0;
}
