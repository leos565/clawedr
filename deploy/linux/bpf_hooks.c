/*
 * ClawEDR eBPF Hooks — loaded via BCC on Linux.
 *
 * Scoped enforcement: only processes in the OpenClaw process tree are
 * monitored.  The target_bins map (populated by monitor.py) holds djb2
 * hashes of known OpenClaw binary paths.  When execve fires for one of
 * those binaries the PID is added to tracked_pids.  Fork/exit hooks
 * propagate and clean up tracking for all descendants.
 *
 * Enforcement layers:
 *   1. blocked_hashes    — execve filename hash (SIGKILL on match)
 *   2. blocked_path_hashes — openat + statx filename hash (SIGKILL on match)
 *   3. pipe heuristic    — dangerous source + sink sibling detection
 *
 * PID namespace: the monitor passes PIDNS_DEV/PIDNS_INO at compile time
 * so events can include the namespace PID for /proc access.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAX_FILENAME_LEN 256
#define PIPE_WINDOW_NS   2000000000ULL  /* 2 seconds */

struct event_t {
    u32 pid;
    u32 ns_pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    u8  action; // 0 = observed (enter), 1 = blocked (SIGKILL), 2 = post-exec (exit, for deny_rules)
};

/* --- Maps populated by monitor.py --- */
BPF_HASH(blocked_hashes, u64, u8, 1024);
BPF_HASH(blocked_path_hashes, u64, u8, 4096);
BPF_HASH(tracked_pids, u32, u8, 8192);
BPF_HASH(target_bins, u64, u8, 16);
BPF_HASH(dangerous_sources, u64, u8, 64);
BPF_HASH(dangerous_sinks, u64, u8, 64);

BPF_HASH(pipe_sources, u32, u64, 256);

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

static __always_inline u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    bpf_probe_read_kernel(&ppid, sizeof(ppid),
        &task->real_parent->tgid);
    return ppid;
}

static __always_inline u32 get_ns_pid(void) {
#if defined(PIDNS_DEV) && defined(PIDNS_INO)
    struct bpf_pidns_info ni = {};
    if (bpf_get_ns_current_pid_tgid(PIDNS_DEV, PIDNS_INO, &ni, sizeof(ni)) == 0)
        return ni.tgid;
#endif
    return bpf_get_current_pid_tgid() >> 32;
}

/* ── execve: auto-detect OpenClaw, enforce blocked execs + pipe heuristic ── */
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
    evt.ns_pid = get_ns_pid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), fname);

    /* Layer 1: blocked executable */
    u8 *is_blocked = blocked_hashes.lookup(&h);
    if (is_blocked) {
        evt.action = 1;
        events.perf_submit(args, &evt, sizeof(evt));
        bpf_send_signal(SIGKILL);
        return 0;
    }

    /* Layer 3: pipe heuristic — record dangerous sources, kill sinks */
    u8 *is_source = dangerous_sources.lookup(&h);
    if (is_source) {
        u32 ppid = get_ppid();
        u64 now = bpf_ktime_get_ns();
        pipe_sources.update(&ppid, &now);
    }

    u8 *is_sink = dangerous_sinks.lookup(&h);
    if (is_sink) {
        u32 ppid = get_ppid();
        u64 *src_ts = pipe_sources.lookup(&ppid);
        if (src_ts) {
            u64 now = bpf_ktime_get_ns();
            if ((now - *src_ts) < PIPE_WINDOW_NS) {
                evt.action = 1;
                events.perf_submit(args, &evt, sizeof(evt));
                bpf_send_signal(SIGKILL);
                return 0;
            }
        }
    }

    evt.action = 0;
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* ── execve exit: deny_rules need /proc/cmdline after process replacement ──
 * At sys_enter_execve, /proc/pid/cmdline still shows the OLD process (shell).
 * At sys_exit_execve, the process has been replaced; cmdline has the NEW argv.
 * We submit a second event here so userspace can match deny_rules correctly.
 */
TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u8 *is_tracked = tracked_pids.lookup(&pid);
    if (!is_tracked)
        return 0;

    struct event_t evt = {};
    evt.pid = pid;
    evt.ns_pid = get_ns_pid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.filename, evt.comm, sizeof(evt.comm));
    evt.action = 2;  /* post-exec: /proc/cmdline now has new argv */
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

/* ── openat: enforce blocked paths ── */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u8 *is_tracked = tracked_pids.lookup(&pid);
    if (!is_tracked)
        return 0;

    const char *fname = args->filename;
    u64 h = simple_hash(fname, MAX_FILENAME_LEN);

    u8 *is_blocked = blocked_path_hashes.lookup(&h);
    if (is_blocked) {
        struct event_t evt = {};
        evt.pid = pid;
        evt.ns_pid = get_ns_pid();
        evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), fname);
        evt.action = 1;
        events.perf_submit(args, &evt, sizeof(evt));
        bpf_send_signal(SIGKILL);
    }

    return 0;
}

/* ── statx: enforce blocked paths (covers Rust coreutils / newer libc) ── */
TRACEPOINT_PROBE(syscalls, sys_enter_statx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u8 *is_tracked = tracked_pids.lookup(&pid);
    if (!is_tracked)
        return 0;

    const char *fname = (const char *)args->filename;
    u64 h = simple_hash(fname, MAX_FILENAME_LEN);

    u8 *is_blocked = blocked_path_hashes.lookup(&h);
    if (is_blocked) {
        struct event_t evt = {};
        evt.pid = pid;
        evt.ns_pid = get_ns_pid();
        evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), fname);
        evt.action = 1;
        events.perf_submit(args, &evt, sizeof(evt));
        bpf_send_signal(SIGKILL);
    }

    return 0;
}

/* ── fork: propagate tracking from parent to child ── */
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

/* ── exit: clean up tracked set ── */
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    tracked_pids.delete(&pid);

    return 0;
}
