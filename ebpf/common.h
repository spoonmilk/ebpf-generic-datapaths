#ifndef __COMMON_H
#define __COMMON_H

// TCP flows indexed by four-tuple
struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
} __attribute__((packed));

// Measurements sent to userspace, taken from GenericCongAvoid
struct measurement {
    struct flow_key flow;
    __u32 acked;        // bytes acked
    __u32 sacked;       // selectively acked packets
    __u32 loss;         // lost packets
    __u32 rtt;          // microseconds
    __u32 inflight;     // packets
    __u8 was_timeout;   // reset on timeout
    __u8 _pad[3];
} __attribute__((packed));

// Flow events
struct flow_event {
    __u8 event_type;  // 1=created, 2=closed
    __u8 _pad[3];     // padding to align flow_key to 4-byte boundary
    struct flow_key flow;
    __u32 init_cwnd;
    __u32 mss;
} __attribute__((packed));

// For updates to cwnd from user CUBIC
struct cwnd_update {
    __u32 cwnd_bytes;
};

// Helper, extracts flow key from socket
static __always_inline void get_flow_key(struct sock *sk, struct flow_key *key) {
    key->saddr = sk->__sk_common.skc_rcv_saddr;
    key->daddr = sk->__sk_common.skc_daddr;
    key->sport = sk->__sk_common.skc_num;
    key->dport = __bpf_ntohs(sk->__sk_common.skc_dport);
}

#endif
