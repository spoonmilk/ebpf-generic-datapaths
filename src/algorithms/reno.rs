use super::{AlgorithmRunner, CwndUpdate};
use crate::bpf::DatapathEvent;
use anyhow::Result;
use ebpf_ccp_cubic::{GenericCongAvoidAlg, GenericCongAvoidFlow, GenericCongAvoidMeasurements};
use std::collections::HashMap;
use tracing::{debug, info, warn};

#[derive(Default)]
pub struct Reno {
    mss: u32,
    init_cwnd: f64,
    cwnd: f64,
}

impl GenericCongAvoidAlg for Reno {
    type Flow = Self;

    fn new_flow(&self, init_cwnd: u32, mss: u32) -> Self::Flow {
        Reno {
            mss,
            init_cwnd: f64::from(init_cwnd),
            cwnd: f64::from(init_cwnd),
        }
    }
}

impl GenericCongAvoidFlow for Reno {
    fn curr_cwnd(&self) -> u32 {
        self.cwnd as u32
    }

    fn set_cwnd(&mut self, cwnd: u32) {
        self.cwnd = f64::from(cwnd);
    }

    fn increase(&mut self, m: &GenericCongAvoidMeasurements) {
        // increase cwnd by 1 / cwnd per packet
        self.cwnd += f64::from(self.mss) * (f64::from(m.acked) / self.cwnd);
    }

    fn reduction(&mut self, _m: &GenericCongAvoidMeasurements) {
        self.cwnd /= 2.0;
        if self.cwnd <= self.init_cwnd {
            self.cwnd = self.init_cwnd;
        }
    }

    fn reset(&mut self) {
        self.cwnd = self.init_cwnd;
    }
}

struct FlowState {
    reno: Reno,
    mss: u32,
}

pub struct RenoRunner {
    reno_alg: Reno,
    flows: HashMap<u64, FlowState>,
}

impl RenoRunner {
    pub fn new(_init_cwnd_pkts: u32, _mss: u32) -> Self {
        Self {
            reno_alg: Reno::default(),
            flows: HashMap::new(),
        }
    }
}

impl AlgorithmRunner for RenoRunner {
    fn name(&self) -> &str {
        "ebpf_ccp_reno"
    }

    fn ebpf_path(&self) -> &str {
        "ebpf/.output/datapath-reno.bpf.o"
    }

    fn struct_ops_name(&self) -> &str {
        "ebpf_ccp_reno"
    }

    fn handle_event(&mut self, event: DatapathEvent) -> Result<Option<CwndUpdate>> {
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

                let reno = self.reno_alg.new_flow(init_cwnd, mss);
                self.flows.insert(flow_id, FlowState { reno, mss });
                Ok(None)
            }

            DatapathEvent::FlowClosed { flow_id } => {
                info!("Flow closed: {:016x}", flow_id);
                self.flows.remove(&flow_id);
                Ok(None)
            }

            DatapathEvent::Measurement {
                flow_id,
                measurement,
            } => {
                if let Some(flow) = self.flows.get_mut(&flow_id) {
                    // Handle timeout - reset RENO state
                    if measurement.was_timeout {
                        warn!("Timeout on flow {:016x} - resetting", flow_id);
                        flow.reno.reset();
                        let fallback_cwnd =
                            flow.reno.curr_cwnd().max(measurement.inflight * flow.mss);
                        flow.reno.set_cwnd(fallback_cwnd);

                        return Ok(Some(CwndUpdate {
                            flow_id,
                            cwnd_bytes: flow.reno.curr_cwnd(),
                        }));
                    }

                    let old_cwnd = flow.reno.curr_cwnd();
                    if measurement.loss > 0 || measurement.sacked > 0 {
                        flow.reno.reduction(&measurement);
                    } else if measurement.acked > 0 {
                        flow.reno.increase(&measurement);
                    }

                    let new_cwnd = flow.reno.curr_cwnd();
                    if old_cwnd != new_cwnd {
                        debug!(
                            "Flow {:016x}: cwnd {} -> {} bytes",
                            flow_id, old_cwnd, new_cwnd
                        );
                    }

                    // Return cwnd update
                    Ok(Some(CwndUpdate {
                        flow_id,
                        cwnd_bytes: new_cwnd,
                    }))
                } else {
                    warn!("Received measurement for unknown flow: {:016x}", flow_id);
                    Ok(None)
                }
            }
        }
    }

    fn cleanup(&mut self) {
        info!("Cleaning up {} active Reno flows", self.flows.len());
        self.flows.clear();
    }
}
