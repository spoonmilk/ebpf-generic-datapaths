use anyhow::{Context, Result};
use ebpf_ccp_cubic::GenericCongAvoidMeasurements;
use lazy_static::lazy_static;
use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder, RingBufferBuilder};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct FlowKey {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct Measurement {
    flow: FlowKey,
    acked: u32,
    sacked: u32,
    loss: u32,
    rtt: u32,
    inflight: u32,
    was_timeout: u8,
    _pad: [u8; 3],
}

#[repr(C)]
struct FlowEvent {
    event_type: u8,
    _pad: [u8; 3],
    flow: FlowKey,
    init_cwnd: u32,
    mss: u32,
}

#[repr(C)]
struct CwndUpdate {
    cwnd_bytes: u32,
}

pub enum DatapathEvent {
    FlowCreated {
        flow_id: u64,
        init_cwnd: u32,
        mss: u32,
    },
    FlowClosed {
        flow_id: u64,
    },
    Measurement {
        flow_id: u64,
        measurement: GenericCongAvoidMeasurements,
    },
}

pub struct EbpfDatapath {
    obj: Object,
    _link: Link, // Keep link alive
    events: Arc<Mutex<VecDeque<DatapathEvent>>>,
}

impl EbpfDatapath {
    pub fn new(ebpf_path: &str, struct_ops_name: &str) -> Result<Self> {
        info!("Loading eBPF object file: {}", ebpf_path);

        // Load the BPF object file
        let obj_path = Path::new(ebpf_path);
        if !obj_path.exists() {
            anyhow::bail!(
                "eBPF object file not found: {:?}. Run 'make ebpf' first.",
                obj_path
            );
        }

        let mut builder = ObjectBuilder::default();
        builder.debug(true);

        let open_obj = builder
            .open_file(obj_path)
            .context("Failed to open BPF object file")?;

        let mut obj = open_obj
            .load()
            .context("Failed to load BPF object into kernel")?;
        info!("BPF object loaded successfully, attempting to register with TCP");

        // Attach to tcp stack via struct_ops
        let mut struct_ops_map = obj
            .maps_mut()
            .find(|m| m.name() == struct_ops_name)
            .with_context(|| format!("Failed to find '{}' struct_ops map", struct_ops_name))?;

        let link = struct_ops_map
            .attach_struct_ops()
            .context("Failed to attach struct_ops to TCP stack")?;

        info!("struct_ops attached - '{}' registered with TCP", struct_ops_name);

        // Set up ring buffers
        let events = Arc::new(Mutex::new(VecDeque::new()));

        // Get measurements ring buffer map
        let measurements_map = obj
            .maps()
            .find(|m| m.name() == "measurements")
            .context("Failed to find 'measurements' map")?;

        let events_clone = events.clone();
        let mut rb_builder = RingBufferBuilder::new();

        rb_builder
            .add(&measurements_map, move |data: &[u8]| {
                let m = unsafe { &*(data.as_ptr() as *const Measurement) };
                let flow_id = flow_key_to_id(&m.flow);

                let measurement = GenericCongAvoidMeasurements {
                    acked: m.acked,
                    was_timeout: m.was_timeout != 0,
                    sacked: m.sacked,
                    loss: m.loss,
                    rtt: m.rtt,
                    inflight: m.inflight,
                };

                debug!(
                    "Measurement: flow={:016x}, acked={}, loss={}, rtt={}us",
                    flow_id, m.acked, m.loss, m.rtt
                );

                events_clone
                    .lock()
                    .unwrap()
                    .push_back(DatapathEvent::Measurement {
                        flow_id,
                        measurement,
                    });
                0
            })
            .context("Failed to add measurements ring buffer")?;

        // Get flow events ring buffer map
        let flow_events_map = obj
            .maps()
            .find(|m| m.name() == "flow_events")
            .context("Failed to find 'flow_events' map")?;

        let events_clone2 = events.clone();
        rb_builder
            .add(&flow_events_map, move |data: &[u8]| {
                let e = unsafe { &*(data.as_ptr() as *const FlowEvent) };
                let flow_id = flow_key_to_id(&e.flow);

                let event = match e.event_type {
                    1 => {
                        debug!("Flow created: {:016x}", flow_id);
                        DatapathEvent::FlowCreated {
                            flow_id,
                            init_cwnd: e.init_cwnd,
                            mss: e.mss,
                        }
                    }
                    2 => {
                        debug!("Flow closed: {:016x}", flow_id);
                        DatapathEvent::FlowClosed { flow_id }
                    }
                    _ => {
                        warn!("Unknown flow event type: {}", e.event_type);
                        return 0;
                    }
                };

                events_clone2.lock().unwrap().push_back(event);
                0
            })
            .context("Failed to add flow_events ring buffer")?;

        let rb = rb_builder.build().context("Failed to build ring buffers")?;
        info!("Ring buffers configured");

        // Thread polls ring buffers
        std::thread::spawn(move || {
            loop {
                if let Err(e) = rb.poll(std::time::Duration::from_millis(100)) {
                    warn!("Ring buffer poll error: {}", e);
                }
            }
        });

        Ok(Self {
            obj,
            _link: link,
            events,
        })
    }

    pub fn poll(&mut self, _timeout_ms: u64) -> Result<Vec<DatapathEvent>> {
        let mut events = self.events.lock().unwrap();
        let result: Vec<_> = events.drain(..).collect();
        Ok(result)
    }

    pub fn update_cwnd(&mut self, flow_id: u64, cwnd: u32) -> Result<()> {
        // Get the cwnd_control map
        let map = self
            .obj
            .maps()
            .find(|m| m.name() == "cwnd_control")
            .context("Failed to find cwnd_control map")?;

        let key = id_to_flow_key(flow_id);
        let value = CwndUpdate { cwnd_bytes: cwnd };

        let key_bytes = unsafe {
            std::slice::from_raw_parts(
                &key as *const _ as *const u8,
                std::mem::size_of::<FlowKey>(),
            )
        };

        let value_bytes = unsafe {
            std::slice::from_raw_parts(
                &value as *const _ as *const u8,
                std::mem::size_of::<CwndUpdate>(),
            )
        };

        map.update(key_bytes, value_bytes, MapFlags::ANY)
            .context("Failed to update cwnd_control map")?;

        debug!("Updated cwnd for flow {:016x}: {} bytes", flow_id, cwnd);
        Ok(())
    }

    pub fn cleanup_flow(&self, flow_id: u64) {
        cleanup_flow_key(flow_id);
    }
}

// Mapping from flow_id to flow_key for map lookups
lazy_static! {
    static ref FLOW_KEY_MAP: Mutex<HashMap<u64, FlowKey>> = Mutex::new(HashMap::new());
}

fn flow_key_to_id(key: &FlowKey) -> u64 {
    let id = ((key.saddr as u64) << 32) | (key.daddr as u64);
    FLOW_KEY_MAP.lock().unwrap().insert(id, *key);
    id
}

fn id_to_flow_key(id: u64) -> FlowKey {
    FLOW_KEY_MAP
        .lock()
        .unwrap()
        .get(&id)
        .copied()
        .unwrap_or_else(|| {
            warn!("Flow key not found for id {:016x}, using partial key", id);
            FlowKey {
                saddr: (id >> 32) as u32,
                daddr: id as u32,
                sport: 0,
                dport: 0,
            }
        })
}

fn cleanup_flow_key(id: u64) {
    FLOW_KEY_MAP.lock().unwrap().remove(&id);
}
