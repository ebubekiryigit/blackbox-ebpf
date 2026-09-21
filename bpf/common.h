// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
#ifndef BLACKBOX_COMMON_H
#define BLACKBOX_COMMON_H
#include "abi.h"
// Minimal CO-RE declarations: offsets are relocated against the host BTF.
// No kernel headers or libbpf shared library are needed on the target machine.
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#define CORE __attribute__((preserve_access_index))
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_ANY 0
#define BPF_NOEXIST 1
struct bpf_raw_tracepoint_args {
  __u64 args[0];
};
struct kernfs_node {
  __u64 id;
} CORE;
struct cgroup {
  struct kernfs_node *kn;
} CORE;
struct css_set {
  struct cgroup *dfl_cgrp;
} CORE;
struct task_struct {
  int pid;
  int tgid;
  char comm[16];
  __u64 start_boottime;
  long state;
  unsigned int __state;
  struct task_struct *group_leader;
  struct css_set *cgroups;
} CORE;
struct stats {
  __u64 histogram[BLACKBOX_HISTOGRAM_BUCKETS];
  __u64 count;
  __u64 anomalies;
  __u64 critical;
  __u64 bytes;
  __u64 retransmits;
  __u64 resets;
  __u64 ring_failures;
  __u64 suppressed;
  __u64 tracking_failures;
  __u64 unmatched;
  __u64 bookkeeping_completions;
  __u64 budget_second;
  __u64 budget_used;
};
// This wire structure is fixed-width and little-endian on supported hosts.
struct event {
  __u64 mono_ns;
  __u64 latency_ns;
  __u64 cgroup_id;
  __u64 process_start_ns;
  __u64 bytes;
  __u32 pid;
  __u32 tgid;
  __u32 cpu;
  __u32 major;
  __u32 minor;
  __u32 kind;
  __u32 state;
  __u16 source_port;
  __u16 destination_port;
  __u16 family;
  __u16 operation;
  char comm[16];
  __u8 source_ip[16];
  __u8 destination_ip[16];
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct stats);
} aggregates SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  // Operational capacity is supplied by the Go loader.
  __uint(max_entries, 1);
} details SEC(".maps");
const volatile __u64 threshold_ns = 0;
const volatile __u64 critical_threshold_ns = 0;
const volatile __u32 detail_rate = 0;
const volatile __u32 possible_cpus = 1;
static __always_inline struct stats *get_stats(void) {
  __u32 zero = 0;
  return bpf_map_lookup_elem(&aggregates, &zero);
}
static __always_inline void histogram(struct stats *s, __u64 ns) {
  __u32 bucket = 0;
  __u64 limit = BLACKBOX_HISTOGRAM_MIN_NS;
#pragma unroll
  for (int i = 0; i < BLACKBOX_HISTOGRAM_BUCKETS - 1; i++) {
    if (ns >= limit)
      bucket = i + 1;
    limit *= 2;
  }
  __sync_fetch_and_add(&s->histogram[bucket], 1);
  __sync_fetch_and_add(&s->count, 1);
}
static __always_inline int allowed(struct stats *s, __u64 ns) {
  __u64 sec = ns / 1000000000;
  if (s->budget_second != sec) {
    s->budget_second = sec;
    s->budget_used = 0;
  }
  __u32 n = possible_cpus;
  if (!n)
    n = 1;
  __u32 quota =
      detail_rate / n + (bpf_get_smp_processor_id() < detail_rate % n);
  __sync_fetch_and_add(&s->budget_used, 1);
  if (s->budget_used > quota) {
    __sync_fetch_and_add(&s->suppressed, 1);
    return 0;
  }
  return 1;
}
static __always_inline void task_identity(struct event *e,
                                          struct task_struct *t) {
  if (!t)
    return;
  e->pid = BPF_CORE_READ(t, pid);
  e->tgid = BPF_CORE_READ(t, tgid);
  bpf_core_read_str(e->comm, sizeof(e->comm), &t->comm);
  struct task_struct *leader = BPF_CORE_READ(t, group_leader);
  if (leader)
    e->process_start_ns = BPF_CORE_READ(leader, start_boottime);
  // cgroup v2 identity; on v1/unresolvable targets this remains unknown (zero).
  if (bpf_core_field_exists(((struct kernfs_node *)0)->id))
    e->cgroup_id = BPF_CORE_READ(t, cgroups, dfl_cgrp, kn, id);
}
static __always_inline struct event *reserve(struct stats *s, __u32 kind,
                                             __u64 now, int cap) {
  if (cap && !allowed(s, now))
    return 0;
  struct event *e = bpf_ringbuf_reserve(&details, sizeof(*e), 0);
  if (!e) {
    __sync_fetch_and_add(&s->ring_failures, 1);
    return 0;
  }
  __builtin_memset(e, 0, sizeof(*e));
  e->mono_ns = now;
  e->kind = kind;
  e->cpu = bpf_get_smp_processor_id();
  return e;
}
// The source license is defined by the SPDX header above. This separate ELF
// declaration permits the kernel to load programs using GPL-only BPF helpers.
char __license[] SEC("license") = "GPL";
#endif
