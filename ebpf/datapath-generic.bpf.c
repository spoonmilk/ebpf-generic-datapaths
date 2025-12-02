#include "datapath-generic.h"
#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct ecn);
} ecns SEC(".maps");

SEC("struct_ops/ebpf_generic_init")
void BPF_PROG(ebpf_generic_init, struct sock *sk) {
    struct flow_event *init_event;
    struct flow_key key;
    struct tcp_sock *tp = tcp_sk(sk);

    // Get flow key first
    get_flow_key(sk, &key);

    // Check if connection already exists
    if (bpf_map_lookup_elem(&flow_map, &key)) {
        return;
    }

    // Create and insert flow into map
    struct flow fl = {.key = key,
                      .cwnd = tp->snd_cwnd * tp->mss_cache, // Store in bytes
                      .bytes_delivered_since_last = 0,
                      .bytes_sent_since_last = 0,
                      .last_rate_update_ns = bpf_ktime_get_ns()};
    bpf_map_update_elem(&flow_map, &key, &fl, BPF_ANY);
    num_flows++;

    // Setup/Send flow creation event to userspace
    init_event = bpf_ringbuf_reserve(&flow_events, sizeof(*init_event), 0);
    if (!init_event) { // -> should err probably?
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
    release_event =
        bpf_ringbuf_reserve(&flow_events, sizeof(*release_event), 0);
    if (!release_event) { // -> Should err probably?
        return;
    }

    __builtin_memset(release_event, 0, sizeof(*release_event));
    release_event->event_type = 2; // CLOSED
    release_event->flow = key;

    bpf_ringbuf_submit(release_event, 0);
}

static void fill_flow_stats(struct sock *sk, struct flow *fl,
                            struct flow_statistics *stats) {
    struct tcp_sock *tp = tcp_sk(sk);
    stats->packets_in_flight = tcp_packets_in_flight(tp);
    stats->bytes_in_flight = tp->packets_out * tp->mss_cache;
    stats->bytes_pending = sk->sk_wmem_queued;
    stats->rtt_sample_us = tp->srtt_us >> 3;
    stats->was_timeout = 0;
}

static void fill_ack_stats(struct sock *sk, u32 acked,
                           struct ack_statistics *stats) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct flow_key k;
    struct ecn *ecn;

    stats->bytes_acked = acked;
    stats->packets_acked = acked / tp->mss_cache;
    stats->bytes_misordered = tp->sacked_out * tp->mss_cache;
    stats->packets_misordered = tp->sacked_out;

    get_flow_key(sk, &k);
    ecn = bpf_map_lookup_elem(&ecns, &k);
    if (ecn) {
        stats->ecn_packets = ecn->ecn_packets;
        stats->ecn_bytes = ecn->ecn_bytes;
    } else {
        stats->ecn_packets = 0;
        stats->ecn_bytes = 0;
    }

    stats->lost_pckts_sample = tp->lost_out;
    stats->now = bpf_ktime_get_ns();
}

static void send_measurement(struct sock *sk, u32 acked, u8 was_timeout,
                             u8 meas_type) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct measurement *m;
    struct flow_key key;
    struct flow *fl;

    get_flow_key(sk, &key);
    fl = bpf_map_lookup_elem(&flow_map, &key);
    if (!fl) {
        return;
    }

    m = bpf_ringbuf_reserve(&measurements, sizeof(*m), 0);
    if (!m) {
        return;
    }

    __builtin_memset(m, 0, sizeof(*m));
    m->flow = key;

    fill_flow_stats(sk, fl, &m->flow_stats);
    fill_ack_stats(sk, acked, &m->ack_stats);
    m->flow_stats.was_timeout = was_timeout;
    m->snd_cwnd = tp->snd_cwnd;
    m->snd_ssthresh = tp->snd_ssthresh;
    m->pacing_rate = sk->sk_pacing_rate;
    m->measurement_type = meas_type;

    struct inet_connection_sock *icsk = inet_csk(sk);
    u8 ca_state_val;
    bpf_core_read(&ca_state_val, sizeof(ca_state_val), icsk->icsk_ca_state);
    m->ca_state = ca_state_val;

    bpf_ringbuf_submit(m, 0);

    fl->bytes_sent_since_last += acked;
}

static void apply_user_updates(struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct flow_key key;
    struct user_update *update;
    struct flow *fl;

    get_flow_key(sk, &key);
    update = bpf_map_lookup_elem(&user_command_map, &key);
    if (!update) {
        return;
    }

    fl = bpf_map_lookup_elem(&flow_map, &key);
    if (!fl) {
        return;
    }

    if (update->use_cwnd) {
        tp->snd_cwnd = update->cwnd_bytes / tp->mss_cache;
        fl->cwnd = update->cwnd_bytes;
    }

    if (update->use_pacing) {
        sk->sk_pacing_rate = update->pacing_rate;
        fl->pacing_rate = update->pacing_rate;
    }

    if (update->use_ssthresh) {
        tp->snd_ssthresh = update->ssthresh / tp->mss_cache;
    }

    bpf_map_update_elem(&flow_map, &key, fl, BPF_ANY);
}
