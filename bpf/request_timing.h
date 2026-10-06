// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
#ifndef BLACKBOX_REQUEST_TIMING_H
#define BLACKBOX_REQUEST_TIMING_H
struct request_timing {
  __u64 start;
  __u64 generation;
  __u64 requeued;
};

static __always_inline int resume_request(struct request_timing *t,
                                           __u64 generation) {
  if (!t->requeued || t->generation != generation)
    return 0;
  t->requeued = 0;
  return 1;
}

static __always_inline void requeue_request(struct request_timing *t,
                                             __u64 generation) {
  if (t->generation != generation)
    return;
  t->requeued = 1;
  // start_time_ns identifies an allocation, not a dispatch attempt. With
  // request timestamping disabled it is zero; pointer reuse cannot be proven
  // safe. Exclude this ambiguous request instead of reporting a stale latency.
  if (!generation)
    t->start = 0;
}

static __always_inline int request_timing_valid(struct request_timing *t,
                                                __u64 generation) {
  return t->start && t->generation == generation;
}
#endif
