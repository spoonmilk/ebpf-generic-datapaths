#ifndef __DATAPATH_GENERIC_H
#define __DATAPATH_GENERIC_H

#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

#define MAX_FLOWS 1024

// Flow state tracked in flow_map
struct flow {
    struct flow_key key;
    // Congestion window // in bytes -> note that kernel
    // tp->snd_cwnd is in packets - translate by * (1/tp->mss)
    u32 cwnd;
};

// Flow rates - measured outside of struct_ops events
struct flow_rates {
    u32 rate_incoming; // Receive rate in bytes/sec
    u32 rate_outgoing; // Send rate in bytes/sec
};

// Per-flow statistics
struct flow_statistics {
    u32 packets_in_flight;
    u32 bytes_in_flight;
    u32 bytes_pending;
    u32 rtt_sample_us;
    u8 was_timeout;
};

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
};

#endif

