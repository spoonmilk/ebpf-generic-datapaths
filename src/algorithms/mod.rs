//! Provides a runner for any algorithm

pub mod cubic;
pub mod reno;

use crate::bpf::DatapathEvent;
use anyhow::Result;

pub trait AlgorithmRunner: Send {
    fn name(&self) -> &str;
    fn ebpf_path(&self) -> &str;

    #[allow(dead_code)]
    fn struct_ops_name(&self) -> &str;

    fn handle_event(&mut self, event: DatapathEvent) -> Result<Option<CwndUpdate>>;

    fn cleanup(&mut self) {}
}

#[derive(Debug, Clone)]
pub struct CwndUpdate {
    pub flow_id: u64,
    pub cwnd_bytes: u32,
}

pub struct AlgorithmRegistry;

impl AlgorithmRegistry {
    pub fn get(name: &str, init_cwnd_pkts: u32, mss: u32) -> Result<Box<dyn AlgorithmRunner>> {
        match name {
            "cubic" => Ok(Box::new(cubic::CubicRunner::new(init_cwnd_pkts, mss))),
            "reno" => Ok(Box::new(reno::RenoRunner::new(init_cwnd_pkts, mss))),
            _ => anyhow::bail!("Unknown algorithm: {}", name),
        }
    }

    /// List all available algorithms
    pub fn list() -> Vec<&'static str> {
        vec!["cubic", "reno"]
    }
}
