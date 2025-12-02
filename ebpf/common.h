#ifndef __COMMON_H
#define __COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

// TCP flows indexed by four-tuple
struct flow_key {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
} __attribute__((packed));

// Flow events
struct flow_event {
    u8 event_type;  // 1=created, 2=closed
    u8 _pad[3];     // padding to align flow_key to 4-byte boundary
    struct flow_key flow;
    u32 init_cwnd;
    u32 mss;
} __attribute__((packed));


// Helper, extracts flow key from socket
static __always_inline void get_flow_key(struct sock *sk, struct flow_key *key) {
    key->saddr = sk->__sk_common.skc_rcv_saddr;
    key->daddr = sk->__sk_common.skc_daddr;
    key->sport = sk->__sk_common.skc_num;
    key->dport = __bpf_ntohs(sk->__sk_common.skc_dport);
}

// TAKEN FROM EBPFCCA (Bokai Bi, Edward Wibuwo)
static inline struct inet_connection_sock *inet_csk(const struct sock *sk) {
  return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk) {
  return (void *)inet_csk(sk)->icsk_ca_priv;
}

static inline struct tcp_sock *tcp_sk(const struct sock *sk) {
  return (struct tcp_sock *)sk;
}

static inline unsigned int tcp_left_out(const struct tcp_sock *tp) {
  return tp->sacked_out + tp->lost_out;
}

static inline unsigned int tcp_packets_in_flight(const struct tcp_sock *tp) {
  return tp->packets_out - tcp_left_out(tp) + tp->retrans_out;
}

#endif
