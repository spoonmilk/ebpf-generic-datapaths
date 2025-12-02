#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "datapath-cong-avoid.h"

char _license[] SEC("license") = "GPL";

#define tcp_sk(sk) ((struct tcp_sock *)(sk))

// Ring buffer for measurements
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} measurements SEC(".maps");

// Ring buffer for flow events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} flow_events SEC(".maps");

// Hash map for cwnd updates from userspace
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, struct user_update);
} cwnd_control SEC(".maps");

SEC("struct_ops/ebpf_bbr_init")
void BPF_PROG(ebpf_bbr_init, struct sock *sk)
{
    struct flow_event *e;
    
    e = bpf_ringbuf_reserve(&flow_events, sizeof(*e), 0);
    if (!e)
        return;
    
    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = 1; // CREATED
    get_flow_key(sk, &e->flow);
    e->init_cwnd = tcp_sk(sk)->snd_cwnd * tcp_sk(sk)->mss_cache;
    e->mss = tcp_sk(sk)->mss_cache;
    
    bpf_ringbuf_submit(e, 0);
}
