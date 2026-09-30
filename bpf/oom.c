// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
#include "common.h"
// Set by the loader from the host tracepoint BTF signature.
const volatile __u32 victim_task_arg = 1;
SEC("raw_tp/mark_victim") int victim(struct bpf_raw_tracepoint_args *ctx) {
  struct stats *s = get_stats();
  if (!s)
    return 0;
  __sync_fetch_and_add(&s->count, 1);
  __sync_fetch_and_add(&s->anomalies, 1);
  struct event *e = reserve(s, 5, bpf_ktime_get_boot_ns(), 0);
  if (e) {
    if (victim_task_arg) {
      task_identity(e, (void *)ctx->args[0]);
    } else {
      e->pid = (__u32)ctx->args[0];
      e->operation = 1; // Only the victim PID is available on older kernels.
    }
    bpf_ringbuf_submit(e, 0);
  }
  return 0;
}
