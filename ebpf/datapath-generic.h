#ifndef __DATAPATH_GENERIC_H
#define __DATAPATH_GENERIC_H

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

#define MAX_FLOWS 1024

// Flow state tracked in flow_map
struct flow {
    struct flow_key key;
    // Congestion window // in bytes -> note that kernel
    // tp->snd_cwnd is in packets - translate by * (1/tp->mss)
    u32 cwnd;
    // Current pacing rate
    u32 pacing_rate;

    u64 bytes_delivered_since_last; // For rate_incoming calculation
    u64 bytes_sent_since_last;      // For rate_outgoing calculation
    u64 last_rate_update_ns;        // Timestamp of last rate update
};

struct ecn {
  // bytes corresponding to ecn-marked packets
  u32 ecn_bytes;
  // ecn-marked packets
  u32 ecn_packets;
} _ecn = {0};

// Flow rates - measured outside of struct_ops events
struct flow_rates {
    u32 rate_incoming; // Receive rate in bytes/sec
    u32 rate_outgoing; // Send rate in bytes/sec
    u64 last_updated;
};

// Per-flow statistics
struct flow_statistics {
    u32 packets_in_flight;
    u32 bytes_in_flight;
    u32 bytes_pending;
    u32 rtt_sample_us;
    u8 was_timeout;
    u8 _pad1[3];
} __attribute__((packed));

// Per-ACK statistics
struct ack_statistics {
    u32 packets_acked;
    u32 bytes_acked;
    u32 packets_misordered;
    u32 bytes_misordered;
    u32 ecn_packets;
    u32 ecn_bytes;
    u32 lost_pckts_sample;
    u32 now;
} __attribute__((packed));

struct measurement {
    struct flow_key flow;

    // Flow-level statistics
    struct flow_statistics flow_stats;

    // ACK-level statistics
    struct ack_statistics ack_stats;

    u32 snd_cwnd;        // current cwnd in packets
    u32 snd_ssthresh;    // slow start threshold
    u64 pacing_rate;     // current pacing rate
    u8 ca_state;         // TCP_CA_* state
    u8 measurement_type; // which callback generated this
    u8 _pad[2];
} __attribute__((packed));

struct user_update {
    u32 cwnd_bytes;  // For window-based algorithms
    u64 pacing_rate; // For rate-based algorithms (bytes/sec)
    u32 ssthresh;    // Optional ssthresh override
    u8 use_pacing;   // Whether to apply pacing_rate
    u8 use_cwnd;     // Whether to apply cwnd
    u8 use_ssthresh; // Whether to apply ssthresh
    u8 _pad;
    u32 flow_command;
};

#endif
