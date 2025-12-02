#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "datapath-generic.h"

u64 num_flows = 0;

// Map of all active dataflows - editable from userspace
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow);
} flow_map SEC(".maps");

// Flow lifecycle events (create/close)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} flow_events SEC(".maps");

// Flow and ACK statistics map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} measurements SEC(".maps");

// Flow rate info - measured outside struct_ops events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_rates);
} flow_rate_map SEC(".maps");

// Userspace → kernel: cwnd and rate updates
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct user_update);
} user_command_map SEC(".maps");

SEC("struct_ops/ebpf_generic_init")
void BPF_PROG(ebpf_generic_init, struct sock *sk) {
    struct flow_event *init_event;
    struct flow_key key;
    struct tcp_sock *tp = tcp_sk(sk);

    // Get flow key first
    get_flow_key(sk, &key);

    // Check if connection already exists
    if(bpf_map_lookup_elem(&flow_map, &key)) {
        return;
    }

    // Create and insert flow into map
    struct flow fl = {
        .key = key,
        .cwnd = tp->snd_cwnd * tp->mss_cache  // Store in bytes
    };
    bpf_map_update_elem(&flow_map, &key, &fl, BPF_ANY);
    num_flows++;

    // Setup/Send flow creation event to userspace
    init_event = bpf_ringbuf_reserve(&flow_events, sizeof(*init_event), 0);
    if(!init_event) { // -> should err probably?
        return;
    }

    __builtin_memset(init_event, 0, sizeof(*init_event));
    init_event->event_type = 1; // CREATED
    init_event->flow = key;
    init_event->init_cwnd = tp->snd_cwnd * tp->mss_cache;
    init_event->mss = tp->mss_cache;

    bpf_ringbuf_submit(init_event, 0);
}

SEC("struct_ops/ebpf_generic_release")
void BPF_PROG(ebpf_generic_release, struct sock *sk) {
    struct flow_event *release_event;
    struct flow_key key;

    // Remove from flow_map
    get_flow_key(sk, &key);
    bpf_map_delete_elem(&flow_map, &key);
    num_flows--;

    // Cleanup/Send flow close event to userspace
    release_event = bpf_ringbuf_reserve(&flow_events, sizeof(*release_event), 0);
    if(!release_event) { // -> Should err probably?
        return;
    }

    __builtin_memset(release_event, 0, sizeof(*release_event));
    release_event->event_type = 2; // CLOSED
    release_event->flow = key;

    bpf_ringbuf_submit(release_event, 0);
}

// Measure flow/ack signals ; separate from rates
static void measure_flack_signals(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct measurement *m;
    struct flow_key key;

    // Setup message and flow key
    m = bpf_ringbuf_reserve(&measurements, sizeof(*m), 0);
    if(!m) {
        return;
    }
    __builtin_memset(m, 0, sizeof(*m));
    get_flow_key(sk, &key);

    m->flow = key;
    

    

    



}





