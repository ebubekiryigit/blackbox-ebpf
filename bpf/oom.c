// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
#include "common.h"
SEC("raw_tp/mark_victim") int victim(struct bpf_raw_tracepoint_args *ctx) {
  struct stats *s = get_stats();
  if (!s)
    return 0;
  __sync_fetch_and_add(&s->count, 1);
  __sync_fetch_and_add(&s->anomalies, 1);
  struct event *e = reserve(s, 5, bpf_ktime_get_ns(), 0);
  if (e) {
    task_identity(e, (void *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
  }
  return 0;
}
