pub const DEFAULT_SS_THRESH: u32 = 0x7fff_ffff;

/// Flow key identifying a TCP connection
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub flow_key: FlowKey,

    // Flow-level statistics
    pub packets_in_flight: u32,
    pub bytes_in_flight: u32,
    pub bytes_pending: u32,
    pub rtt_sample_us: u32,
    pub was_timeout: bool,

    // ACK-level statistics
    pub bytes_acked: u32,
    pub packets_acked: u32,
    pub bytes_misordered: u32,
    pub packets_misordered: u32,
    pub ecn_bytes: u32,
    pub ecn_packets: u32,
    pub lost_pkts_sample: u32,

    // Rate statistics
    pub rate_incoming: u32,
    pub rate_outgoing: u32,

    // Kernel context
    pub snd_cwnd: u32,
    pub snd_ssthresh: u32,
    pub pacing_rate: u64,
    pub ca_state: u8,
    pub now: u64,
}
#[derive(Debug, Clone, Copy)]
pub struct FlowStatistics {
    pub packets_in_flight: u32,
    pub bytes_in_flight: u32,
    pub bytes_pending: u32,
    pub rtt_sample_us: u32,
    pub was_timeout: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct AckStatistics {
    pub bytes_acked: u32,
    pub packets_acked: u32,
    pub bytes_misordered: u32,
    pub packets_misordered: u32,
    pub ecn_bytes: u32,
    pub ecn_packets: u32,
    pub lost_pkts_sample: u32,
    pub now: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CwndUpdate {
    pub cwnd_bytes: Option<u32>,
    pub pacing_rate: Option<u64>,
    pub ssthresh: Option<u32>,
}

impl CwndUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cwnd(mut self, cwnd_bytes: u32) -> Self {
        self.cwnd_bytes = Some(cwnd_bytes);
        self
    }

    pub fn with_pacing_rate(mut self, pacing_rate: u64) -> Self {
        self.pacing_rate = Some(pacing_rate);
        self
    }

    pub fn with_ssthresh(mut self, ssthresh: u32) -> Self {
        self.ssthresh = Some(ssthresh);
        self
    }
}

pub trait GenericAlgorithm: Send {
    fn name(&self) -> &str;
    fn create_flow(&self, init_cwnd: u32, mss: u32) -> Box<dyn GenericFlow>;
}

pub trait GenericFlow: Send {
    /// Get current congestion window in bytes
    fn curr_cwnd(&self) -> u32;

    /// Set congestion window in bytes
    fn set_cwnd(&mut self, cwnd: u32);

    /// Increase cwnd on successful ACK without loss
    fn increase(&mut self, report: &Report);

    /// Reduce cwnd on congestion signal
    fn reduction(&mut self, report: &Report);

    /// Reset algorithm state (on timeout)
    fn reset(&mut self) {
        // Default is no-op
    }
}
