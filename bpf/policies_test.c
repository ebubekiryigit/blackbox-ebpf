// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// Test-only socket program: execute the same timing/quota helpers without
// manipulating a real disk or depending on scheduler timing.
#include "common.h"
#include "request_timing.h"
struct {
  __uint(type, 2);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct request_timing);
} timing SEC(".maps");
struct policy_input {
  __u64 action;
  __u64 generation;
  __u64 now;
  __u64 critical;
};
struct {
  __uint(type, 2);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct policy_input);
} test_input SEC(".maps");
SEC("socket") int policies(void *ctx) {
  __u32 zero = 0;
  struct policy_input *input = bpf_map_lookup_elem(&test_input, &zero);
  if (!input)
    return 0;
  if (input->action == 2) {
    struct stats *s = get_stats();
    return s && allowed(s, input->now, input->critical != 0);
  }
  struct request_timing *t = bpf_map_lookup_elem(&timing, &zero);
  if (!t)
    return 0;
  if (input->action == 3)
    return request_timing_valid(t, input->generation);
  if (input->action == 1) {
    requeue_request(t, input->generation);
    return 0;
  }
  if (resume_request(t, input->generation))
    return 1;
  t->start = input->now;
  t->generation = input->generation;
  t->requeued = 0;
  return 0;
}
