// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
#include "common.h"
struct gendisk {
  int major;
  int first_minor;
} CORE;
struct request_queue {
  struct gendisk *disk;
} CORE;
struct request {
  struct request_queue *q;
  struct gendisk *rq_disk;
  unsigned int __data_len;
  unsigned int cmd_flags;
} CORE;
struct inflight {
  __u64 start;
  struct event identity;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  // Operational capacity is supplied by the Go loader.
  __uint(max_entries, 1);
  __type(key, __u64);
  __type(value, struct inflight);
} starts SEC(".maps");
const volatile __u32 rq_arg_index = 0;
SEC("raw_tp/block_rq_issue") int issue(struct bpf_raw_tracepoint_args *ctx) {
  struct stats *s = get_stats();
  if (!s)
    return 0;
  struct request *rq = (void *)ctx->args[rq_arg_index ? 1 : 0];
  __u64 key = (__u64)rq;
  struct inflight v = {};
  v.start = bpf_ktime_get_ns();
  task_identity(&v.identity, (void *)bpf_get_current_task());
  struct gendisk *d = 0;
  if (bpf_core_field_exists(rq->rq_disk))
    d = BPF_CORE_READ(rq, rq_disk);
  else
    d = BPF_CORE_READ(rq, q, disk);
  if (d) {
    v.identity.major = BPF_CORE_READ(d, major);
    v.identity.minor = BPF_CORE_READ(d, first_minor);
  }
  v.identity.bytes = BPF_CORE_READ(rq, __data_len);
  v.identity.operation = BPF_CORE_READ(rq, cmd_flags) & 255;
  if (bpf_map_update_elem(&starts, &key, &v, BPF_ANY))
    __sync_fetch_and_add(&s->tracking_failures, 1);
  return 0;
}
SEC("raw_tp/block_rq_complete")
int complete(struct bpf_raw_tracepoint_args *ctx) {
  struct stats *s = get_stats();
  if (!s)
    return 0;
  struct request *rq = (void *)ctx->args[0];
  __u64 key = (__u64)rq;
  __u32 remaining = BPF_CORE_READ(rq, __data_len);
  __u32 completed = ctx->args[2];
  // The completion tracepoint can report a partial request. Count only the
  // final data completion, or the completion of an actual REQ_OP_FLUSH.
  if (completed < remaining)
    return 0;
  struct inflight *v = bpf_map_lookup_elem(&starts, &key);
  if (!v) {
    // Flush sequencing completes its original WRITE again after DATA has been
    // consumed, or completes a data-less logical WRITE without dispatching it.
    // Neither is another device I/O to time. A tracked dispatch is always timed,
    // even if empty. Zero-byte OP_FLUSH with a missing start remains unmatched:
    // unlike logical WRITE bookkeeping, it is a real device cache flush.
    if (!remaining && !completed &&
        (BPF_CORE_READ(rq, cmd_flags) & 255) == 1) {
      __sync_fetch_and_add(&s->bookkeeping_completions, 1);
      return 0;
    }
    __sync_fetch_and_add(&s->unmatched, 1);
    return 0;
  }
  __u64 now = bpf_ktime_get_ns();
  __u64 latency = now - v->start;
  histogram(s, latency);
  __sync_fetch_and_add(&s->bytes, v->identity.bytes);
  if (latency >= threshold_ns) {
    __sync_fetch_and_add(&s->anomalies, 1);
    if (latency >= critical_threshold_ns)
      __sync_fetch_and_add(&s->critical, 1);
    struct event *e = reserve(s, 1, now, 1);
    if (e) {
      *e = v->identity;
      e->mono_ns = now;
      e->kind = 1;
      e->cpu = bpf_get_smp_processor_id();
      e->latency_ns = latency;
      bpf_ringbuf_submit(e, 0);
    }
  }
  bpf_map_delete_elem(&starts, &key);
  return 0;
}
