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
 * Network blocking: when CLAWEDR_USE_LSM is defined, uses BPF LSM
 * socket_connect to block at kernel level (-EPERM). Otherwise falls back
 * to tracepoint + SIGKILL.
 *
 * PID namespace: the monitor passes PIDNS_DEV/PIDNS_INO at compile time
 * so events can include the namespace PID for /proc access.
 */

#include <linux/fs.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <uapi/linux/ptrace.h>

#define MAX_FILENAME_LEN 256
#define PIPE_WINDOW_NS 2000000000ULL /* 2 seconds */

struct event_t {
  u32 pid;
  u32 ns_pid;
  u32 uid;
  char comm[TASK_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
  u8 action; // 0 = observed (enter), 1 = blocked (SIGKILL), 2 = post-exec
             // (exit, for deny_rules), 3 = connect_attempt (userspace domain check)
  u32 blocked_ip; // for connect events: IP in host byte order
};

/* --- Maps populated by monitor.py --- */
BPF_HASH(blocked_hashes, u64, u8, 1024);
BPF_HASH(blocked_path_hashes, u64, u8, 4096);
BPF_HASH(tracked_pids, u32, u8, 8192);
BPF_HASH(target_bins, u64, u8, 16);
BPF_HASH(dangerous_sources, u64, u8, 64);
BPF_HASH(dangerous_sinks, u64, u8, 64);

BPF_HASH(pipe_sources, u32, u64, 256);
BPF_HASH(blocked_ips, u32, u8, 1024);
/* Shell interpreters: only track when parent is tracked (agent-spawned shells) */
BPF_HASH(parent_tracked_bins, u64, u8, 16);

BPF_PERF_OUTPUT(events);

static __always_inline u64 simple_hash(const char *s, int len) {
  u64 h = 5381;
  for (int i = 0; i < len && i < MAX_FILENAME_LEN; i++) {
    char c = 0;
    bpf_probe_read_user(&c, 1, &s[i]);
    if (c == 0)
      break;
    h = ((h << 5) + h) + (u64)c;
  }
  return h;
}

static __always_inline u32 get_ppid(void) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  u32 ppid = 0;
  bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
  return ppid;
}

static __always_inline u32 get_grandparent_pid(void) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  u32 gpid = 0;
  if (task->real_parent && task->real_parent->real_parent)
    bpf_probe_read_kernel(&gpid, sizeof(gpid),
                          &task->real_parent->real_parent->tgid);
  return gpid;
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
  } else {
    /* Shell interpreters: track only when parent is tracked (agent runs sh -c "curl ...") */
    u8 *is_parent_tracked_bin = parent_tracked_bins.lookup(&h);
    if (is_parent_tracked_bin) {
      u32 ppid = get_ppid();
      u8 *parent_tracked = tracked_pids.lookup(&ppid);
      if (parent_tracked) {
        u8 one = 1;
        tracked_pids.update(&pid, &one);
      }
    }
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
    u64 now = bpf_ktime_get_ns();
    u32 ppid = get_ppid();
    pipe_sources.update(&ppid, &now);
    u32 gpid = get_grandparent_pid();
    if (gpid)
      pipe_sources.update(&gpid, &now);
  }

  u8 *is_sink = dangerous_sinks.lookup(&h);
  if (is_sink) {
    u32 ppid = get_ppid();
    u64 *src_ts = pipe_sources.lookup(&ppid);
    if (!src_ts) {
      u32 gpid = get_grandparent_pid();
      src_ts = pipe_sources.lookup(&gpid);
    }
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
  evt.action = 2; /* post-exec: /proc/cmdline now has new argv */
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

/* Helper: check blocked IP and optionally kill (used by sendto tracepoint) */
static __always_inline int _check_blocked_ip(void *ctx, u32 pid, u32 ip, int do_kill) {
  u8 *is_blocked = blocked_ips.lookup(&ip);
  if (!is_blocked)
    return 0;

  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));
  /* Exempt sudo/systemctl: may connect to 8.8.8.8 for DNS; child processes (e.g. curl) still blocked */
  if (comm[0] == 's' && comm[1] == 'u' && comm[2] == 'd' && comm[3] == 'o' && (comm[4] == '\0' || comm[4] == ' '))
    return 0;
  if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' && comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'c' && comm[7] == 't' && comm[8] == 'l' && (comm[9] == '\0' || comm[9] == ' '))
    return 0;

  struct event_t evt = {};
  evt.pid = pid;
  evt.ns_pid = get_ns_pid();
  evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  __builtin_memcpy(&evt.comm, comm, sizeof(comm));
  evt.blocked_ip = ip;
  const char msg[] = "NETWORK_CONNECT";
  __builtin_memcpy((void *)evt.filename, msg, sizeof(msg));
  evt.action = 1;
  events.perf_submit(ctx, &evt, sizeof(evt));
  if (do_kill)
    bpf_send_signal(SIGKILL);
  return 1;
}

#ifdef CLAWEDR_USE_LSM
/* ── LSM socket_connect: block at kernel level (return -EPERM) ──
 * Tracepoints cannot prevent syscalls; LSM actually blocks the connect.
 * Requires CONFIG_BPF_LSM=y and lsm=...,bpf in kernel cmdline.
 */
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u8 *is_tracked = tracked_pids.lookup(&pid);
  if (!is_tracked)
    return 0;

  if (addrlen < 8)
    return 0;

  short family = 0;
  bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
  if (family != 2) /* AF_INET */
    return 0;

  u32 ip = 0;
  bpf_probe_read_kernel(&ip, sizeof(ip), (void *)address + 4);

  u8 *is_blocked = blocked_ips.lookup(&ip);
  if (!is_blocked)
    return 0;

  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));
  if (comm[0] == 's' && comm[1] == 'u' && comm[2] == 'd' && comm[3] == 'o' && (comm[4] == '\0' || comm[4] == ' '))
    return 0;
  if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' && comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'c' && comm[7] == 't' && comm[8] == 'l' && (comm[9] == '\0' || comm[9] == ' '))
    return 0;

  struct event_t evt = {};
  evt.pid = pid;
  evt.ns_pid = get_ns_pid();
  evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  __builtin_memcpy(&evt.comm, comm, sizeof(comm));
  evt.blocked_ip = ip;
  const char msg[] = "NETWORK_CONNECT";
  __builtin_memcpy((void *)evt.filename, msg, sizeof(msg));
  evt.action = 1;
  events.perf_submit(sock, &evt, sizeof(evt));
  return -1; /* -EPERM */
}
#endif

/* ── connect tracepoint ── */
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u8 *is_tracked = tracked_pids.lookup(&pid);
  if (!is_tracked)
    return 0;

  struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
  short family = 0;
  bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

  if (family == 2) { /* AF_INET */
    u32 ip = 0;
    bpf_probe_read_user(&ip, sizeof(ip),
                        (void *)addr + 4); /* sin_addr in sockaddr_in */

#ifdef CLAWEDR_USE_LSM
    /* LSM does blocking; we only emit CONNECT_ATTEMPT for non-blocked IPs (domain check) */
    u8 *is_blocked = blocked_ips.lookup(&ip);
    if (!is_blocked) {
#else
    /* Fallback: tracepoint + SIGKILL when LSM unavailable */
    if (_check_blocked_ip(args, pid, ip, 1))
      return 0;
    {
#endif
      struct event_t evt = {};
      evt.pid = pid;
      evt.ns_pid = get_ns_pid();
      evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
      bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
      evt.blocked_ip = ip;
      const char msg2[] = "CONNECT_ATTEMPT";
      __builtin_memcpy((void *)evt.filename, msg2, sizeof(msg2));
      evt.action = 3;
      events.perf_submit(args, &evt, sizeof(evt));
    }
  }

  return 0;
}

/* ── sendto: enforce blocked IPs for UDP (e.g. DNS to 1.1.1.1:53) ── */
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u8 *is_tracked = tracked_pids.lookup(&pid);
  if (!is_tracked)
    return 0;

  /* Tracepoint fields: fd, buff, len, flags, addr, addr_len (kernel naming) */
  unsigned long dest_addr = 0;
  unsigned long addrlen = 0;
  bpf_probe_read_kernel(&dest_addr, sizeof(dest_addr), &args->addr);
  bpf_probe_read_kernel(&addrlen, sizeof(addrlen), &args->addr_len);

  if (dest_addr == 0 || addrlen < 8)
    return 0;

  struct sockaddr *addr = (struct sockaddr *)dest_addr;
  short family = 0;
  bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

  if (family == 2) { /* AF_INET */
    u32 ip = 0;
    bpf_probe_read_user(&ip, sizeof(ip), (void *)addr + 4);
    _check_blocked_ip(args, pid, ip, 1);
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
