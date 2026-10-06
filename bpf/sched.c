// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
#include "common.h"
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  // Operational capacity is supplied by the Go loader.
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} runnable SEC(".maps");
static __always_inline void enqueue(struct task_struct *t) {
  __u32 pid = BPF_CORE_READ(t, pid);
  if (!pid)
    return;
  __u64 now = bpf_ktime_get_ns();
  // Repeated wakeups must not shorten an existing runnable wait.
  int rc = bpf_map_update_elem(&runnable, &pid, &now, BPF_NOEXIST);
  if (rc && rc != -17) {
    struct stats *s = get_stats();
    if (s)
      __sync_fetch_and_add(&s->tracking_failures, 1);
  }
}
SEC("raw_tp/sched_wakeup") int wakeup(struct bpf_raw_tracepoint_args *ctx) {
  enqueue((void *)ctx->args[0]);
  return 0;
}
SEC("raw_tp/sched_wakeup_new")
int wakeup_new(struct bpf_raw_tracepoint_args *ctx) {
  enqueue((void *)ctx->args[0]);
  return 0;
}
SEC("raw_tp/sched_switch")
int switch_task(struct bpf_raw_tracepoint_args *ctx) {
  struct task_struct *prev = (void *)ctx->args[1], *next = (void *)ctx->args[2];
  int preempt = ctx->args[0] != 0;
  long state = 0;
  if (bpf_core_field_exists(prev->__state))
    state = BPF_CORE_READ(prev, __state);
  else
    state = BPF_CORE_READ(prev, state);
  __u32 prev_pid = BPF_CORE_READ(prev, pid);
  if (prev_pid) {
    if (preempt || state == 0) {
      __u64 now = bpf_ktime_get_ns();
      // A switch-out starts a fresh wait, even after a wakeup while still on CPU.
      if (bpf_map_update_elem(&runnable, &prev_pid, &now, BPF_ANY)) {
        struct stats *s = get_stats();
        if (s)
          __sync_fetch_and_add(&s->tracking_failures, 1);
      }
    } else {
      // A blocked task has no runnable wait; discard any earlier wakeup.
      bpf_map_delete_elem(&runnable, &prev_pid);
    }
  }
  __u32 pid = BPF_CORE_READ(next, pid);
  if (!pid)
    return 0;
  __u64 *start = bpf_map_lookup_elem(&runnable, &pid);
  if (!start)
    return 0;
  __u64 latency = bpf_ktime_get_ns() - *start;
  struct stats *s = get_stats();
  if (s) {
    histogram(s, latency);
    if (latency >= threshold_ns) {
      __sync_fetch_and_add(&s->anomalies, 1);
      if (latency >= critical_threshold_ns)
        __sync_fetch_and_add(&s->critical, 1);
      struct event *e = reserve(s, 2, bpf_ktime_get_boot_ns(), 1,
                                latency >= critical_threshold_ns);
      if (e) {
        task_identity(e, next);
        e->latency_ns = latency;
        bpf_ringbuf_submit(e, 0);
      }
    }
  }
  bpf_map_delete_elem(&runnable, &pid);
  return 0;
}
SEC("raw_tp/sched_process_exit")
int exit_task(struct bpf_raw_tracepoint_args *ctx) {
  struct task_struct *t = (void *)ctx->args[0];
  __u32 pid = BPF_CORE_READ(t, pid);
  bpf_map_delete_elem(&runnable, &pid);
  return 0;
}
