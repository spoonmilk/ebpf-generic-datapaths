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

/// Building/Initializing connections
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
                      .cwnd = tp->snd_cwnd * tp->mss_cache,
                      .pacing_rate = sk->sk_pacing_rate,
                      .bytes_delivered_since_last = 0,
                      .bytes_sent_since_last = 0,
                      .last_rate_sample_ns = bpf_ktime_get_ns()};
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

/// Teardown/Release of connections
SEC("struct_ops/ebpf_generic_release")
void BPF_PROG(ebpf_generic_release, struct sock *sk) {
    struct flow_event *release_event;
    struct flow_key key;

    // Remove from flow_map
    get_flow_key(sk, &key);
    if (bpf_map_lookup_elem(&flow_map, &key)) {
        bpf_map_delete_elem(&flow_map, &key);
        num_flows--;
    }

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
    stats->bytes_in_flight = (u64)tp->packets_out * tp->mss_cache;
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

    stats->lost_pkts_sample = tp->lost_out;
    stats->now = bpf_ktime_get_ns();
}

/// Send a whole measurement to userspace daemon
static void send_measurement(struct sock *sk, u32 acked, u8 was_timeout,
                             u8 meas_type) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct measurement *m;
    struct flow_key key;
    struct flow *fl;
    struct flow_rates *fr;

    get_flow_key(sk, &key);
    fl = bpf_map_lookup_elem(&flow_map, &key);
    if (!fl) {
        return;
    }

    m = bpf_ringbuf_reserve(&measurements, sizeof(*m), 0);
    if (!m) {
        return;
    }

    fr = bpf_map_lookup_elem(&flow_rate_map, &key);
    if(!fr) {
        return;
    }

    __builtin_memset(m, 0, sizeof(*m));
    m->flow = key;

    fill_flow_stats(sk, fl, &m->flow_stats);
    fill_ack_stats(sk, acked, &m->ack_stats);

    m->flow_stats.rates.rate_incoming = fr->rate_incoming;
    m->flow_stats.rates.rate_outgoing = fr->rate_outgoing;

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

    // Update flow state and persist
    fl->bytes_sent_since_last += acked;
    bpf_map_update_elem(&flow_map, &key, fl, BPF_ANY);
}

/// Apply cwnd/rate updates from daemon
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

SEC("struct_ops/ebpf_generic_cong_avoid")
void BPF_PROG(ebpf_generic_cong_avoid, struct sock *sk, __u32 ack,
              __u32 acked) {
    struct flow_key key;
    struct flow *fl;

    get_flow_key(sk, &key);
    fl = bpf_map_lookup_elem(&flow_map, &key);
    if (!fl) {
        return;
    }

    fl->bytes_delivered_since_last += acked;
    bpf_map_update_elem(&flow_map, &key, fl, BPF_ANY);

    send_measurement(sk, acked, 0, 0);
    apply_user_updates(sk);
}

SEC("struct_ops/ebpf_generic_cong_control")
void BPF_PROG(ebpf_generic_cong_control, struct sock *sk,
              const struct rate_sample *rs) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct flow_key key;
    struct flow *fl;
    u64 now;
    u64 elapsed_ns;

    get_flow_key(sk, &key);
    fl = bpf_map_lookup_elem(&flow_map, &key);
    if (!fl) {
        return;
    }

    fl->bytes_delivered_since_last += rs->delivered * tp->mss_cache;

    // Update rates
    now = bpf_ktime_get_ns();
    elapsed_ns = now - fl->last_rate_sample_ns;
    if (elapsed_ns >= 100000000) {
        u32 rate_incoming =
            (fl->bytes_delivered_since_last * 1000000000) / elapsed_ns;
        u32 rate_outgoing =
            (fl->bytes_sent_since_last * 1000000000) / elapsed_ns;

        struct flow_rates rates = {.rate_incoming = rate_incoming,
                                   .rate_outgoing = rate_outgoing};
        bpf_map_update_elem(&flow_rate_map, &key, &rates, BPF_ANY);

        fl->bytes_delivered_since_last = 0;
        fl->bytes_sent_since_last = 0;
        fl->last_rate_sample_ns = now;
    }

    bpf_map_update_elem(&flow_map, &key, fl, BPF_ANY);

    u32 acked = rs->acked_sacked;
    send_measurement(sk, acked, 0, 1);
    apply_user_updates(sk);
}

SEC("struct_ops/ebpf_generic_cwnd_event")
void BPF_PROG(ebpf_generic_cwnd_event, struct sock *sk,
              enum tcp_ca_event event) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct flow_key key;
    struct ecn *ecn_info;
    u8 was_timeout = 0;
    u32 acked = 0;

    get_flow_key(sk, &key);

    // Track ECN marks
    if (event == CA_EVENT_ECN_IS_CE || event == CA_EVENT_ECN_NO_CE) {
        ecn_info = bpf_map_lookup_elem(&ecns, &key);
        if (!ecn_info) {
            struct ecn new_ecn = {0};
            bpf_map_update_elem(&ecns, &key, &new_ecn, BPF_ANY);
            ecn_info = bpf_map_lookup_elem(&ecns, &key);
        }
        if (ecn_info && event == CA_EVENT_ECN_IS_CE) {
            ecn_info->ecn_packets++;
            ecn_info->ecn_bytes += tp->mss_cache;
            bpf_map_update_elem(&ecns, &key, ecn_info, BPF_ANY);
        }
    }

    // Detect timeout events
    if (event == CA_EVENT_CWND_RESTART || event == CA_EVENT_LOSS) {
        was_timeout = 1;
    }

    // Send measurement for significant events
    if (event == CA_EVENT_LOSS || event == CA_EVENT_CWND_RESTART ||
        event == CA_EVENT_ECN_IS_CE) {
        send_measurement(sk, acked, was_timeout, 2);
    }
}

SEC("struct_ops/ebpf_generic_ssthresh")
__u32 BPF_PROG(ebpf_generic_ssthresh, struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct flow_key key;
    struct user_update *update;

    get_flow_key(sk, &key);
    update = bpf_map_lookup_elem(&user_command_map, &key);

    // Apply userspace override if available
    if (update && update->use_ssthresh) {
        return update->ssthresh / tp->mss_cache;
    }

    // Default: half of current cwnd, minimum 2
    u32 ssthresh = tp->snd_cwnd >> 1;
    return ssthresh < 2 ? 2 : ssthresh;
}

SEC("struct_ops/ebpf_generic_undo_cwnd")
__u32 BPF_PROG(ebpf_generic_undo_cwnd, struct sock *sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct flow_key key;
    struct flow *fl;

    get_flow_key(sk, &key);
    fl = bpf_map_lookup_elem(&flow_map, &key);

    // Return last known cwnd from flow state, fallback to current
    if (fl) {
        return fl->cwnd / tp->mss_cache;
    }

    return tp->snd_cwnd;
}

SEC(".struct_ops")
struct tcp_congestion_ops ebpf_generic = {
    .init = (void *)ebpf_generic_init,
    .release = (void *)ebpf_generic_release,
    .cong_avoid = (void *)ebpf_generic_cong_avoid,
    .cong_control = (void *)ebpf_generic_cong_control,
    .cwnd_event = (void *)ebpf_generic_cwnd_event,
    .ssthresh = (void *)ebpf_generic_ssthresh,
    .undo_cwnd = (void *)ebpf_generic_undo_cwnd,
    .name = "ebpf_ccp_generic",
};
