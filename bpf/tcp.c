// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
#include "common.h"
struct in6_addr {
  __u8 bytes[16];
} CORE;
struct sock_common {
  __u32 skc_daddr;
  __u32 skc_rcv_saddr;
  __u16 skc_dport;
  __u16 skc_num;
  __u16 skc_family;
  __u8 skc_state;
  struct in6_addr skc_v6_daddr;
  struct in6_addr skc_v6_rcv_saddr;
} CORE;
struct sock {
  struct sock_common __sk_common;
} CORE;
struct inet_sock {
  __be16 inet_sport;
} CORE;
struct sk_buff {
  unsigned char *head;
  unsigned char *data;
  unsigned int end;
  unsigned short network_header;
} CORE;

// TCP reuses the otherwise block-only operation field for metadata provenance.
// Keep the existing fixed-size detail wire format. Kind 6 means received reset;
// historical kind 4 with no metadata marker did not distinguish reset direction.
#define TCP_ENDPOINT_SOCKET 1
#define TCP_ENDPOINT_PACKET 2
#define TCP_SOCKET_PRESENT 4
#define TCP_METADATA_KNOWN 8

static __always_inline int socket_endpoints(struct event *e, struct sock *sk) {
  if (!sk)
    return 0;
  __u16 family = 0, local = 0, remote = 0;
  __u8 src[16] = {}, dst[16] = {};
  // Closing a socket can clear skc_num before the active-reset tracepoint.
  // inet_sport retains the wire port, also used by the kernel formatter.
  if (BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family) ||
      BPF_CORE_READ_INTO(&local, (struct inet_sock *)sk, inet_sport) ||
      BPF_CORE_READ_INTO(&remote, sk, __sk_common.skc_dport))
    return 0;
  if (family == 2) {
    if (bpf_core_read(src, 4, &sk->__sk_common.skc_rcv_saddr) ||
        bpf_core_read(dst, 4, &sk->__sk_common.skc_daddr))
      return 0;
  } else if (family == 10) {
    if (bpf_core_read(src, 16, &sk->__sk_common.skc_v6_rcv_saddr) ||
        bpf_core_read(dst, 16, &sk->__sk_common.skc_v6_daddr))
      return 0;
  } else {
    return 0;
  }
  e->family = family;
  e->source_port = bpf_ntohs(local);
  e->destination_port = bpf_ntohs(remote);
  __builtin_memcpy(e->source_ip, src, 16);
  __builtin_memcpy(e->destination_ip, dst, 16);
  return 1;
}

// For a socket-less response, tcp_send_reset supplies the INCOMING skb that
// caused the reset, not the outgoing reset packet. Read only IP addresses and
// TCP ports, then reverse the tuple. skb->data is the TCP header at this hook,
// including when IPv6 extension headers precede it. No payload is read or saved.
static __always_inline int response_endpoints(struct event *e,
                                             struct sk_buff *skb) {
  if (!skb)
    return 0;
  unsigned char *head = 0, *data = 0;
  __u32 end = 0;
  __u16 network = 0;
  if (BPF_CORE_READ_INTO(&head, skb, head) ||
      BPF_CORE_READ_INTO(&data, skb, data) ||
      BPF_CORE_READ_INTO(&end, skb, end) ||
      BPF_CORE_READ_INTO(&network, skb, network_header) || !head || !data)
    return 0;
  __u64 transport = (__u64)data - (__u64)head;
  if (end < 4 || transport > end - 4 || network >= end)
    return 0;
  __u8 version = 0;
  __be16 ports[2] = {};
  if (bpf_probe_read_kernel(&version, 1, head + network) ||
      bpf_probe_read_kernel(ports, sizeof(ports), data))
    return 0;
  __u8 ip[40] = {};
  if ((version >> 4) == 4) {
    if (end < 20 || network > end - 20 ||
        bpf_probe_read_kernel(ip, 20, head + network) ||
        (ip[0] & 15) < 5 || ip[9] != 6)
      return 0;
    e->family = 2;
    __builtin_memcpy(e->source_ip, ip + 16, 4);
    __builtin_memcpy(e->destination_ip, ip + 12, 4);
  } else if ((version >> 4) == 6) {
    if (end < 40 || network > end - 40 ||
        bpf_probe_read_kernel(ip, 40, head + network))
      return 0;
    e->family = 10;
    __builtin_memcpy(e->source_ip, ip + 24, 16);
    __builtin_memcpy(e->destination_ip, ip + 8, 16);
  } else {
    return 0;
  }
  e->source_port = bpf_ntohs(ports[1]);
  e->destination_port = bpf_ntohs(ports[0]);
  return 1;
}

static __always_inline int record(struct sock *sk, struct sk_buff *skb,
                                 __u32 kind) {
  struct stats *s = get_stats();
  if (!s)
    return 0;
  __sync_fetch_and_add(&s->count, 1);
  __sync_fetch_and_add(&s->anomalies, 1);
  if (kind != 3)
    __sync_fetch_and_add(&s->resets, 1);
  else
    __sync_fetch_and_add(&s->retransmits, 1);
  __u64 now = bpf_ktime_get_ns();
  struct event *e = reserve(s, kind, now, 1);
  if (!e)
    return 0;
  // IRQ/current-task context does not establish socket ownership. PID stays
  // unattributed even when a socket or packet tuple is available.
  e->operation = TCP_METADATA_KNOWN | (sk ? TCP_SOCKET_PRESENT : 0);
  if (sk)
    e->state = BPF_CORE_READ(sk, __sk_common.skc_state);
  // TIME_WAIT and request sockets are not full sockets. Like the kernel's
  // tracepoint formatter, use the incoming packet for their reset response.
  if (kind == 4 && (!sk || e->state == 6 || e->state == 12) &&
      response_endpoints(e, skb)) {
    e->operation |= TCP_ENDPOINT_PACKET;
  } else if (e->state != 6 && e->state != 12 && socket_endpoints(e, sk)) {
    e->operation |= TCP_ENDPOINT_SOCKET;
  } else if (kind == 4 && response_endpoints(e, skb)) {
    e->operation |= TCP_ENDPOINT_PACKET;
  }
  bpf_ringbuf_submit(e, 0);
  return 0;
}
SEC("raw_tp/tcp_retransmit_skb")
int retransmit(struct bpf_raw_tracepoint_args *ctx) {
  return record((void *)ctx->args[0], 0, 3);
}
SEC("raw_tp/tcp_send_reset")
int send_reset(struct bpf_raw_tracepoint_args *ctx) {
  return record((void *)ctx->args[0], (void *)ctx->args[1], 4);
}
SEC("raw_tp/tcp_receive_reset")
int receive_reset(struct bpf_raw_tracepoint_args *ctx) {
  return record((void *)ctx->args[0], 0, 6);
}
