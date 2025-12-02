#ifndef __DATAPATH_CONG_AVOID_H
#define __DATAPATH_CONG_AVOID_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>
#include "common.h"

// Measurements sent to userspace, taken from GenericCongAvoid
struct measurement {
    struct flow_key flow;
    u32 acked;        // bytes acked
    u32 sacked;       // selectively acked packets
    u32 loss;         // lost packets
    u32 rtt;          // microseconds
    u32 inflight;     // packets
    u8 was_timeout;   // reset on timeout
    u8 _pad[3];
} __attribute__((packed));

// For updates to cwnd from user CUBIC
struct user_update {
    u32 cwnd_bytes;
    u32 flow_command;
};

#endif
