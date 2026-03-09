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
 *   4. heuristic rules   — execve/syscall rate limits + argv matching
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
#define MAX_HEU_SLOTS 64
#define MAX_ARGV_PATTERNS 4
#define ARGV_READ_LEN 32

struct event_t {
  u32 pid;
  u32 ns_pid;
  u32 uid;
  char comm[TASK_COMM_LEN];
  char filename[MAX_FILENAME_LEN];
  u8 action; // 0 = observed (enter), 1 = blocked (SIGKILL), 2 = post-exec
             // (exit, for deny_rules), 3 = connect_attempt (userspace domain
             // check), 4 = heuristic_alert, 5 = heuristic_block,
             // 6 = security_alert (match but no kill)
  u32 blocked_ip; // for connect events: IP in host byte order
  u16 heu_slot;   // for heuristic events: slot index for rule_id lookup
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
/* Shell interpreters: only track when parent is tracked (agent-spawned shells)
 */
BPF_HASH(parent_tracked_bins, u64, u8, 16);
/* OpenClaw gateway PIDs: never SIGKILL these (openat/statx log-only) */
BPF_HASH(protected_pids, u32, u8, 16);

/* --- Heuristic maps --- */
struct heu_config_t {
  u8 enabled; // 0=disabled, 1=alert, 2=enforce
  u8 num_patterns;
  u16 threshold;
  u16 window_sec;
  u32 binary_hash;
};
struct heu_state_val_t {
  u32 count;
  u64 window_start_ns;
};
BPF_ARRAY(heu_configs, struct heu_config_t, MAX_HEU_SLOTS);
BPF_ARRAY(heu_argv_patterns, u64, MAX_HEU_SLOTS *MAX_ARGV_PATTERNS);
BPF_HASH(heu_binary_to_slots, u64, u64, 1024); // binary_hash -> bitmap of slots
BPF_HASH(heu_state, u64, struct heu_state_val_t, 8192);
/* Path-based heuristics (openat): path_contains_hash -> bitmap of slots */
BPF_HASH(heu_path_slots, u64, u64, 256);
/* Syscall-based: unlinkat, chmod, symlinkat, fork, write */
BPF_HASH(heu_fork_state, u32, struct heu_state_val_t, 256);
BPF_HASH(heu_connect_state, u64, struct heu_state_val_t, 1024); // (tgid<<32|ip)
/* Syscall type -> heu_slot: 1=fork, 2=unlinkat, 3=chmod, 4=symlinkat, 5=write
 */
BPF_HASH(heu_syscall_slots, u32, u8, 16);

BPF_PERF_OUTPUT(events);

/* Per-CPU scratch buffers to avoid BPF stack overflow (512-byte limit).
 * lsm__file_open needs path_buf (256) + event_t (~291) = 547 bytes.
 */
BPF_PERCPU_ARRAY(scratch_path, char, MAX_FILENAME_LEN);
BPF_PERCPU_ARRAY(scratch_evt, struct event_t, 1);

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

/* Hash path from kernel buffer (e.g. bpf_d_path output); must match djb2. */
static __always_inline u64 hash_path_buf(const char *buf, int max_len) {
  u64 h = 5381;
  for (int i = 0; i < max_len && i < MAX_FILENAME_LEN; i++) {
    char c = 0;
    bpf_probe_read_kernel(&c, 1, &buf[i]);
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

/* Hash a string from userspace (argv slot). */
static __always_inline u64 hash_argv_slot(const char *ptr) {
  u64 h = 5381;
  for (int i = 0; i < ARGV_READ_LEN; i++) {
    char c = 0;
    if (bpf_probe_read_user(&c, 1, ptr + i) != 0 || c == 0)
      break;
    h = ((h << 5) + h) + (u64)(unsigned char)c;
  }
  return h;
}

/* Check if argv matches heuristic slot patterns. Returns 1 if all patterns
 * match. */
static __always_inline int heu_argv_matches(u8 slot, u64 h0, u64 h1, u64 h2) {
  u32 slot32 = slot;
  struct heu_config_t *cfg = heu_configs.lookup(&slot32);
  if (!cfg || cfg->num_patterns == 0)
    return 1; /* no patterns = match (e.g. binary-only heuristic) */
#pragma unroll
  for (int i = 0; i < MAX_ARGV_PATTERNS; i++) {
    if (i >= cfg->num_patterns)
      break;
    u32 idx = slot * MAX_ARGV_PATTERNS + i;
    u64 *p = heu_argv_patterns.lookup(&idx);
    if (!p)
      continue;
    u64 ph = *p;
    if (h0 != ph && h1 != ph && h2 != ph)
      return 0;
  }
  return 1;
}

/* Update sliding window and check threshold. Returns 1 if should trigger. */
static __always_inline int heu_sliding_window(u32 pid, u8 slot, u16 threshold,
                                              u16 window_sec,
                                              int *out_do_kill) {
  if (threshold == 0)
    return 0;
  u64 key = ((u64)pid << 16) | slot;
  u64 now = bpf_ktime_get_ns();
  u64 window_ns = (u64)window_sec * 1000000000ULL;
  struct heu_state_val_t *st = heu_state.lookup(&key);
  struct heu_state_val_t newst = {};
  if (st) {
    if (now - st->window_start_ns > window_ns) {
      newst.count = 1;
      newst.window_start_ns = now;
    } else {
      newst.count = st->count + 1;
      newst.window_start_ns = st->window_start_ns;
    }
  } else {
    newst.count = 1;
    newst.window_start_ns = now;
  }
  heu_state.update(&key, &newst);
  if (newst.count >= threshold) {
    *out_do_kill = 0; /* caller sets from config.enabled */
    return 1;
  }
  return 0;
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
    /* Shell interpreters: track only when parent is tracked (agent runs sh -c
     * "curl ...") */
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

  /* Layer 1: blocked executable — value 1=alert, 2=enforce */
  u8 *mode = blocked_hashes.lookup(&h);
  if (mode) {
    evt.action = (*mode == 2) ? 1 : 6;
    events.perf_submit(args, &evt, sizeof(evt));
    if (*mode == 2)
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

  /* Layer 4: heuristic rules — execve argv + sliding window */
  u64 *slots_bm = heu_binary_to_slots.lookup(&h);
  if (slots_bm && *slots_bm) {
    /* Read argv[0], argv[1], argv[2] for pattern matching */
    u64 h0 = 0, h1 = 0, h2 = 0;
    const char *const *argv_ptr = (const char *const *)args->argv;
    if (argv_ptr) {
      const char *p0 = NULL, *p1 = NULL, *p2 = NULL;
      bpf_probe_read_user(&p0, sizeof(p0), &argv_ptr[0]);
      if (p0)
        h0 = hash_argv_slot(p0);
      bpf_probe_read_user(&p1, sizeof(p1), &argv_ptr[1]);
      if (p1)
        h1 = hash_argv_slot(p1);
      bpf_probe_read_user(&p2, sizeof(p2), &argv_ptr[2]);
      if (p2)
        h2 = hash_argv_slot(p2);
    }
    u64 bm = *slots_bm;
#pragma unroll
    for (u8 s = 0; s < MAX_HEU_SLOTS; s++) {
      if ((bm & (1ULL << s)) == 0)
        continue;
      u32 s32 = s;
      struct heu_config_t *cfg = heu_configs.lookup(&s32);
      if (!cfg || cfg->enabled == 0)
        continue;
      if (!heu_argv_matches(s, h0, h1, h2))
        continue;
      int do_kill = 0;
      int trigger = 0;
      if (cfg->threshold == 1 && cfg->window_sec == 0) {
        trigger = 1;
        do_kill = (cfg->enabled == 2);
      } else {
        trigger = heu_sliding_window(pid, s, cfg->threshold, cfg->window_sec,
                                     &do_kill);
        do_kill = trigger && (cfg->enabled == 2);
      }
      if (trigger) {
        evt.action = do_kill ? 5 : 4;
        evt.heu_slot = s;
        __builtin_memcpy(evt.filename, "HEURISTIC", 10);
        events.perf_submit(args, &evt, sizeof(evt));
        if (do_kill)
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

/* ── openat: enforce blocked paths ──
 * When CLAWEDR_USE_LSM: only log; LSM file_open blocks with -EPERM (keeps
 * process alive). Otherwise: SIGKILL (kills process including OpenClaw when it
 * reads directly).
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u8 *is_tracked = tracked_pids.lookup(&pid);
  if (!is_tracked)
    return 0;

  const char *fname = args->filename;
  u64 h = simple_hash(fname, MAX_FILENAME_LEN);

  u8 *mode = blocked_path_hashes.lookup(&h);
  if (mode) {
    struct event_t evt = {};
    evt.pid = pid;
    evt.ns_pid = get_ns_pid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), fname);
    evt.action = (*mode == 2) ? 1 : 6;
    events.perf_submit(args, &evt, sizeof(evt));
#ifdef CLAWEDR_USE_LSM
    if (*mode == 2)
      /* LSM file_open will block with -EPERM; don't kill (keeps OpenClaw
       * intact) */
      ;
#else
    if (*mode == 2 && !protected_pids.lookup(&pid))
      bpf_send_signal(SIGKILL);
#endif
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

  u8 *mode = blocked_path_hashes.lookup(&h);
  if (mode) {
    struct event_t evt = {};
    evt.pid = pid;
    evt.ns_pid = get_ns_pid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), fname);
    evt.action = (*mode == 2) ? 1 : 6;
    events.perf_submit(args, &evt, sizeof(evt));
    if (*mode == 2 && !protected_pids.lookup(&pid))
      bpf_send_signal(SIGKILL);
  }

  return 0;
}

/* Helper: check blocked IP — value 1=alert, 2=enforce */
static __always_inline int _check_blocked_ip(void *ctx, u32 pid, u32 ip) {
  u8 *mode = blocked_ips.lookup(&ip);
  if (!mode)
    return 0;

  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));
  if (comm[0] == 's' && comm[1] == 'u' && comm[2] == 'd' && comm[3] == 'o' &&
      (comm[4] == '\0' || comm[4] == ' '))
    return 0;
  if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
      comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'c' && comm[7] == 't' &&
      comm[8] == 'l' && (comm[9] == '\0' || comm[9] == ' '))
    return 0;

  struct event_t evt = {};
  evt.pid = pid;
  evt.ns_pid = get_ns_pid();
  evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  __builtin_memcpy(&evt.comm, comm, sizeof(comm));
  evt.blocked_ip = ip;
  const char msg[] = "NETWORK_CONNECT";
  __builtin_memcpy((void *)evt.filename, msg, sizeof(msg));
  evt.action = (*mode == 2) ? 1 : 6;
  events.perf_submit(ctx, &evt, sizeof(evt));
  if (*mode == 2)
    bpf_send_signal(SIGKILL);
  return 1;
}

#ifdef CLAWEDR_USE_LSM
/* ── LSM socket_connect: block at kernel level (return -EPERM) ──
 * Tracepoints cannot prevent syscalls; LSM actually blocks the connect.
 * Requires CONFIG_BPF_LSM=y and lsm=...,bpf in kernel cmdline.
 */
LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address,
          int addrlen) {
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

  u8 *mode = blocked_ips.lookup(&ip);
  if (!mode)
    return 0;

  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));
  if (comm[0] == 's' && comm[1] == 'u' && comm[2] == 'd' && comm[3] == 'o' &&
      (comm[4] == '\0' || comm[4] == ' '))
    return 0;
  if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' && comm[3] == 't' &&
      comm[4] == 'e' && comm[5] == 'm' && comm[6] == 'c' && comm[7] == 't' &&
      comm[8] == 'l' && (comm[9] == '\0' || comm[9] == ' '))
    return 0;

  struct event_t evt = {};
  evt.pid = pid;
  evt.ns_pid = get_ns_pid();
  evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  __builtin_memcpy(&evt.comm, comm, sizeof(comm));
  evt.blocked_ip = ip;
  const char msg[] = "NETWORK_CONNECT";
  __builtin_memcpy((void *)evt.filename, msg, sizeof(msg));
  evt.action = (*mode == 2) ? 1 : 6;
  events.perf_submit(sock, &evt, sizeof(evt));
  if (*mode == 2)
    return -1; /* -EPERM */
  return 0;
}

/* ── LSM file_open: block file access at kernel level (return -EPERM) ──
 * When available, this replaces SIGKILL for openat blocked paths.
 * The process stays alive but the open() call fails with EPERM.
 * Requires CONFIG_BPF_LSM=y and lsm=...,bpf in kernel cmdline.
 */
LSM_PROBE(file_open, struct file *file) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u8 *is_tracked = tracked_pids.lookup(&pid);
  if (!is_tracked)
    return 0;

  /* Use per-CPU scratch buffers (stack limit 512 bytes; path+evt = 547) */
  u32 zero = 0;
  char *path_buf = scratch_path.lookup(&zero);
  struct event_t *evt = scratch_evt.lookup(&zero);
  if (!path_buf || !evt)
    return 0;

  struct path *fp = &file->f_path;
  int len = bpf_d_path(fp, path_buf, MAX_FILENAME_LEN);
  if (len < 0)
    return 0;

  u64 h = hash_path_buf(path_buf, MAX_FILENAME_LEN);
  u8 *mode = blocked_path_hashes.lookup(&h);
  if (!mode)
    return 0;

  /* Protected PIDs (gateway) get log-only */
  u8 *is_protected = protected_pids.lookup(&pid);

  __builtin_memset(evt, 0, sizeof(*evt));
  evt->pid = pid;
  evt->ns_pid = get_ns_pid();
  evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
  __builtin_memcpy(evt->filename, path_buf, MAX_FILENAME_LEN);
  evt->action = (*mode == 2 && !is_protected) ? 1 : 6;
  events.perf_submit(file, evt, sizeof(*evt));

  if (*mode == 2 && !is_protected)
    return -1; /* -EPERM: deny the file open */
  return 0;
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
    /* LSM does blocking; we only emit CONNECT_ATTEMPT for non-blocked IPs
     * (domain check) */
    u8 *is_blocked = blocked_ips.lookup(&ip);
    if (!is_blocked) {
#else
    /* Fallback: tracepoint + SIGKILL when LSM unavailable */
    if (_check_blocked_ip(args, pid, ip))
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
    _check_blocked_ip(args, pid, ip);
  }

  return 0;
}

/* ── fork: propagate tracking + HEU-SYS-001 (fork bomb) ── */
TRACEPOINT_PROBE(sched, sched_process_fork) {
  u32 parent_pid = args->parent_pid;
  u32 child_pid = args->child_pid;

  /* Check both the thread PID and the TGID (thread group leader).
   * tracked_pids is keyed by TGID, but sched_process_fork reports the
   * thread PID as parent_pid.  When a worker thread (libuv, etc.) forks
   * a child, parent_pid is the thread PID which may differ from the TGID. */
  u8 *tracked = tracked_pids.lookup(&parent_pid);
  if (!tracked) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    tracked = tracked_pids.lookup(&tgid);
  }
  if (tracked) {
    u8 one = 1;
    tracked_pids.update(&child_pid, &one);

    /* HEU-SYS-001: fork bomb */
    u32 fork_type = 1;
    u8 *slot_p = heu_syscall_slots.lookup(&fork_type);
    if (slot_p) {
      u8 slot = *slot_p;
      u32 slot32 = slot;
      struct heu_config_t *cfg = heu_configs.lookup(&slot32);
      if (cfg && cfg->enabled >= 1) {
        u64 key = (u64)parent_pid;
        u64 now = bpf_ktime_get_ns();
        u64 window_ns = (u64)cfg->window_sec * 1000000000ULL;
        struct heu_state_val_t *st = heu_fork_state.lookup(&key);
        struct heu_state_val_t newst = {};
        if (st) {
          if (now - st->window_start_ns > window_ns) {
            newst.count = 1;
            newst.window_start_ns = now;
          } else {
            newst.count = st->count + 1;
            newst.window_start_ns = st->window_start_ns;
          }
        } else {
          newst.count = 1;
          newst.window_start_ns = now;
        }
        heu_fork_state.update(&key, &newst);
        if (newst.count >= cfg->threshold) {
          struct event_t evt = {};
          evt.pid = parent_pid;
          evt.ns_pid = parent_pid;
          evt.action = (cfg->enabled == 2) ? 5 : 4;
          evt.heu_slot = slot;
          __builtin_memcpy(evt.filename, "HEURISTIC", 10);
          events.perf_submit(args, &evt, sizeof(evt));
          if (cfg->enabled == 2)
            bpf_send_signal(SIGKILL);
        }
      }
    }
  }

  return 0;
}

/* ── unlinkat: HEU-FS-001 (mass deletion) ── */
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u8 *is_tracked = tracked_pids.lookup(&pid);
  if (!is_tracked)
    return 0;

  u32 type = 2;
  u8 *slot_p = heu_syscall_slots.lookup(&type);
  if (!slot_p)
    return 0;
  u8 slot = *slot_p;
  u32 slot32 = slot;
  struct heu_config_t *cfg = heu_configs.lookup(&slot32);
  if (!cfg || cfg->enabled == 0)
    return 0;

  u64 key = ((u64)pid << 16) | slot;
  u64 now = bpf_ktime_get_ns();
  u64 window_ns = (u64)cfg->window_sec * 1000000000ULL;
  struct heu_state_val_t *st = heu_state.lookup(&key);
  struct heu_state_val_t newst = {};
  if (st) {
    if (now - st->window_start_ns > window_ns) {
      newst.count = 1;
      newst.window_start_ns = now;
    } else {
      newst.count = st->count + 1;
      newst.window_start_ns = st->window_start_ns;
    }
  } else {
    newst.count = 1;
    newst.window_start_ns = now;
  }
  heu_state.update(&key, &newst);
  if (newst.count >= cfg->threshold) {
    struct event_t evt = {};
    evt.pid = pid;
    evt.ns_pid = get_ns_pid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.filename, "HEURISTIC", 10);
    evt.action = (cfg->enabled == 2) ? 5 : 4;
    evt.heu_slot = slot;
    events.perf_submit(args, &evt, sizeof(evt));
    if (cfg->enabled == 2)
      bpf_send_signal(SIGKILL);
  }
  return 0;
}

/* ── chmod/fchmodat: HEU-FS-002 ── */
TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u8 *is_tracked = tracked_pids.lookup(&pid);
  if (!is_tracked)
    return 0;

  u32 type = 3;
  u8 *slot_p = heu_syscall_slots.lookup(&type);
  if (!slot_p)
    return 0;
  u8 slot = *slot_p;
  u32 slot32 = slot;
  struct heu_config_t *cfg = heu_configs.lookup(&slot32);
  if (!cfg || cfg->enabled == 0)
    return 0;

  u64 key = ((u64)pid << 16) | slot;
  u64 now = bpf_ktime_get_ns();
  u64 window_ns = (u64)cfg->window_sec * 1000000000ULL;
  struct heu_state_val_t *st = heu_state.lookup(&key);
  struct heu_state_val_t newst = {};
  if (st) {
    if (now - st->window_start_ns > window_ns) {
      newst.count = 1;
      newst.window_start_ns = now;
    } else {
      newst.count = st->count + 1;
      newst.window_start_ns = st->window_start_ns;
    }
  } else {
    newst.count = 1;
    newst.window_start_ns = now;
  }
  heu_state.update(&key, &newst);
  if (newst.count >= cfg->threshold) {
    struct event_t evt = {};
    evt.pid = pid;
    evt.ns_pid = get_ns_pid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.filename, "HEURISTIC", 10);
    evt.action = (cfg->enabled == 2) ? 5 : 4;
    evt.heu_slot = slot;
    events.perf_submit(args, &evt, sizeof(evt));
    if (cfg->enabled == 2)
      bpf_send_signal(SIGKILL);
  }
  return 0;
}

/* ── symlinkat: HEU-FS-004 ── */
TRACEPOINT_PROBE(syscalls, sys_enter_symlinkat) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  u8 *is_tracked = tracked_pids.lookup(&pid);
  if (!is_tracked)
    return 0;

  u32 type = 4;
  u8 *slot_p = heu_syscall_slots.lookup(&type);
  if (!slot_p)
    return 0;
  u8 slot = *slot_p;
  u32 slot32 = slot;
  struct heu_config_t *cfg = heu_configs.lookup(&slot32);
  if (!cfg || cfg->enabled == 0)
    return 0;

  u64 key = ((u64)pid << 16) | slot;
  u64 now = bpf_ktime_get_ns();
  u64 window_ns = (u64)cfg->window_sec * 1000000000ULL;
  struct heu_state_val_t *st = heu_state.lookup(&key);
  struct heu_state_val_t newst = {};
  if (st) {
    if (now - st->window_start_ns > window_ns) {
      newst.count = 1;
      newst.window_start_ns = now;
    } else {
      newst.count = st->count + 1;
      newst.window_start_ns = st->window_start_ns;
    }
  } else {
    newst.count = 1;
    newst.window_start_ns = now;
  }
  heu_state.update(&key, &newst);
  if (newst.count >= cfg->threshold) {
    struct event_t evt = {};
    evt.pid = pid;
    evt.ns_pid = get_ns_pid();
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.filename, "HEURISTIC", 10);
    evt.action = (cfg->enabled == 2) ? 5 : 4;
    evt.heu_slot = slot;
    events.perf_submit(args, &evt, sizeof(evt));
    if (cfg->enabled == 2)
      bpf_send_signal(SIGKILL);
  }
  return 0;
}

/* ── exit: clean up tracked set + heuristic state ── */
TRACEPOINT_PROBE(sched, sched_process_exit) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  tracked_pids.delete(&pid);
  heu_fork_state.delete(&pid);
  /* heu_state and heu_connect_state keys include pid; they'll age out or we
   * could delete by prefix — skip for now to avoid iteration */

  return 0;
}
