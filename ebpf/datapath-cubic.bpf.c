#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"

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
    __type(value, struct cwnd_update);
} cwnd_control SEC(".maps");

SEC("struct_ops/ebpf_cubic_init")
void BPF_PROG(ebpf_cubic_init, struct sock *sk)
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

SEC("struct_ops/ebpf_cubic_release")
void BPF_PROG(ebpf_cubic_release, struct sock *sk)
{
    struct flow_event *e;
    
    e = bpf_ringbuf_reserve(&flow_events, sizeof(*e), 0);
    if (!e)
        return;
    
    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = 2; // CLOSED
    get_flow_key(sk, &e->flow);
    
    bpf_ringbuf_submit(e, 0);
}

SEC("struct_ops/ebpf_cubic_cong_avoid")
void BPF_PROG(ebpf_cubic_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct measurement *m;
    struct flow_key key;
    struct cwnd_update *update;
    
    // Send measurement to userspace
    m = bpf_ringbuf_reserve(&measurements, sizeof(*m), 0);
    if (m) {
        __builtin_memset(m, 0, sizeof(*m));
        get_flow_key(sk, &key);
        m->flow = key;
        m->acked = acked;
        m->sacked = tp->sacked_out;
        m->loss = tp->lost_out;
        m->rtt = tp->srtt_us >> 3;
        m->inflight = tp->packets_out;
        m->was_timeout = 0;
        
        bpf_ringbuf_submit(m, 0);
    }
    
    // Apply cwnd update from userspace
    get_flow_key(sk, &key);
    update = bpf_map_lookup_elem(&cwnd_control, &key);
    if (update && update->cwnd_bytes > 0) {
        __u32 new_cwnd_pkts = update->cwnd_bytes / tp->mss_cache;
        if (new_cwnd_pkts > 0) {
            tp->snd_cwnd = new_cwnd_pkts;
        }
    }
}

SEC("struct_ops/ebpf_cubic_cwnd_event")
void BPF_PROG(ebpf_cubic_cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct measurement *m;
    
    if (event == CA_EVENT_LOSS || event == CA_EVENT_CWND_RESTART) {
        m = bpf_ringbuf_reserve(&measurements, sizeof(*m), 0);
        if (m) {
            __builtin_memset(m, 0, sizeof(*m));
            get_flow_key(sk, &m->flow);
            m->acked = 0;
            m->sacked = tp->sacked_out;
            m->loss = tp->lost_out;
            m->rtt = tp->srtt_us >> 3;
            m->inflight = tp->packets_out;
            m->was_timeout = (event == CA_EVENT_CWND_RESTART) ? 1 : 0;
            
            bpf_ringbuf_submit(m, 0);
        }
    }
}

SEC("struct_ops/ebpf_cubic_ssthresh")
__u32 BPF_PROG(ebpf_cubic_ssthresh, struct sock *sk)
{
    return tcp_sk(sk)->snd_cwnd;
}

SEC("struct_ops/ebpf_cubic_undo_cwnd")
__u32 BPF_PROG(ebpf_cubic_undo_cwnd, struct sock *sk)
{
    return tcp_sk(sk)->snd_cwnd;
}

SEC(".struct_ops")
struct tcp_congestion_ops ebpf_cubic = {
    .init = (void *)ebpf_cubic_init,
    .release = (void *)ebpf_cubic_release,
    .cong_avoid = (void *)ebpf_cubic_cong_avoid,
    .cwnd_event = (void *)ebpf_cubic_cwnd_event,
    .ssthresh = (void *)ebpf_cubic_ssthresh,
    .undo_cwnd = (void *)ebpf_cubic_undo_cwnd,
    .name = "ebpf_ccp_cubic",
};
