use std::collections::HashMap;

use crate::bpf::DatapathEvent;
use anyhow::anyhow;
use ebpf_ccp_cubic::{FlowKey, GenericAlgorithm, GenericFlow, Report};
use tracing::info;

use crate::algorithms::{AlgorithmRunner, CwndUpdate};

pub struct GenericRunner<A: GenericAlgorithm> {
    algorithm: A,
    flows: HashMap<u64, Box<dyn GenericFlow>>,
    init_cwnd: u32,
    mss: u32,
}

impl<A: GenericAlgorithm> GenericRunner<A> {
    pub fn new(algorithm: A, init_cwnd: u32, mss: u32) -> Self {
        Self {
            algorithm,
            flows: HashMap::new(),
            init_cwnd,
            mss: mss,
        }
    }
}

impl<A: GenericAlgorithm> AlgorithmRunner for GenericRunner<A> {
    fn name(&self) -> &str {
        self.algorithm.name()
    }

    fn ebpf_path(&self) -> &str {
        "ebpf/.output/generic.bpf.o"
    }

    fn struct_ops_name(&self) -> &str {
        "ebpf_ccp_generic"
    }

    fn handle_event(
        &mut self,
        event: crate::bpf::DatapathEvent,
    ) -> anyhow::Result<Option<super::CwndUpdate>> {
        match event {
            DatapathEvent::FlowCreated {
                flow_id,
                init_cwnd,
                mss,
            } => {
                info!(
                    "Flow created: {:016x}, init_cwnd={} bytes, mss={} bytes",
                    flow_id, init_cwnd, mss
                );
                let new_flow = self.algorithm.create_flow(init_cwnd, mss);
                self.flows.insert(flow_id, new_flow);
                Ok(None)
            }

            DatapathEvent::Measurement {
                flow_id,
                measurement,
            } => {
                let flow = self
                    .flows
                    .get_mut(&flow_id)
                    .ok_or_else(|| anyhow!("Unknown flow found"))?;

                let flow_key = FlowKey {
                    saddr: measurement.flow.saddr,
                    daddr: measurement.flow.daddr,
                    sport: measurement.flow.sport,
                    dport: measurement.flow.dport,
                };

                // Convert Measurement → Report
                let report = Report {
                    flow_key: flow_key,

                    // Flow statistics
                    packets_in_flight: measurement.flow_stats.packets_in_flight,
                    bytes_in_flight: measurement.flow_stats.bytes_in_flight,
                    bytes_pending: measurement.flow_stats.bytes_pending,
                    rtt_sample_us: measurement.flow_stats.rtt_sample_us,
                    was_timeout: measurement.flow_stats.was_timeout != 0,

                    // ACK statistics
                    bytes_acked: measurement.ack_stats.bytes_acked,
                    packets_acked: measurement.ack_stats.packets_acked,
                    bytes_misordered: measurement.ack_stats.bytes_misordered,
                    packets_misordered: measurement.ack_stats.packets_misordered,
                    ecn_bytes: measurement.ack_stats.ecn_bytes,
                    ecn_packets: measurement.ack_stats.ecn_packets,
                    lost_pkts_sample: measurement.ack_stats.lost_pkts_sample,

                    // Kernel context
                    snd_cwnd: measurement.snd_cwnd,
                    snd_ssthresh: measurement.snd_ssthresh,
                    pacing_rate: measurement.pacing_rate,
                    ca_state: measurement.ca_state,
                    now: measurement.ack_stats.now,
                    rate_incoming: measurement.rates.rate_incoming,
                    rate_outgoing: measurement.rates.rate_outgoing,
                };

                if report.was_timeout {
                    flow.reset();
                } else if report.lost_pkts_sample > 0 {
                    flow.reduction(&report);
                } else if report.bytes_acked > 0 {
                    flow.increase(&report);
                }

                // Return cwnd update
                Ok(Some(CwndUpdate {
                    flow_id,
                    cwnd_bytes: flow.curr_cwnd(),
                }))
            }

            DatapathEvent::FlowClosed { flow_id } => {
                info!("Flow closed: {:016x}", flow_id);
                self.flows.remove(&flow_id);
                Ok(None)
            }
        }
    }

    fn cleanup(&mut self) {
        info!("Cleaning up {} datapath flows", self.flows.len());
        self.flows.clear();
    }
}
