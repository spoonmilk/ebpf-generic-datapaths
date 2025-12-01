mod algorithms;
mod bpf;

use algorithms::AlgorithmRegistry;
use anyhow::Result;
use bpf::EbpfDatapath;
use clap::Parser;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "ebpf-ccp")]
#[command(about = "Congestion control with eBPF datapath")]
struct Args {
    /// Congestion control algorithm to use
    #[arg(short, long, default_value = "cubic")]
    algorithm: String,

    /// Initial congestion window in packets
    #[arg(long, default_value = "10")]
    init_cwnd_pkts: u32,

    /// Maximum segment size in bytes
    #[arg(long, default_value = "1448")]
    mss: u32,

    /// Enable verbose debug logging
    #[arg(short, long)]
    verbose: bool,

    /// List available algorithms and exit
    #[arg(long)]
    list_algorithms: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle --list-algorithms flag
    if args.list_algorithms {
        println!("Available congestion control algorithms:");
        for alg in AlgorithmRegistry::list() {
            println!("  - {}", alg);
        }
        return Ok(());
    }

    // Initialize logging
    let level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_max_level(level.parse::<tracing::Level>().unwrap())
        .init();

    // Get the algorithm implementation
    let mut algorithm = AlgorithmRegistry::get(&args.algorithm, args.init_cwnd_pkts, args.mss)?;

    info!("Starting eBPF congestion control");
    info!("  algorithm: {}", algorithm.name());
    info!("  init_cwnd: {} packets", args.init_cwnd_pkts);
    info!("  mss: {} bytes", args.mss);
    info!("  ebpf_path: {}", algorithm.ebpf_path());

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("Shutting down");
        r.store(false, Ordering::SeqCst);
    })?;

    // Load eBPF datapath
    let mut datapath = EbpfDatapath::new(algorithm.ebpf_path(), algorithm.struct_ops_name())?;
    info!("eBPF datapath loaded and attached");

    // Main event loop
    while running.load(Ordering::SeqCst) {
        let events = match datapath.poll(100) {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to poll datapath: {}", e);
                continue;
            }
        };

        for event in events {
            // Handle flow cleanup for closed flows
            if let bpf::DatapathEvent::FlowClosed { flow_id } = &event {
                datapath.cleanup_flow(*flow_id);
            }

            // Let the algorithm handle the event
            match algorithm.handle_event(event) {
                Ok(Some(update)) => {
                    // Send cwnd update back to eBPF
                    if let Err(e) = datapath.update_cwnd(update.flow_id, update.cwnd_bytes) {
                        error!(
                            "Failed to update cwnd for flow {:016x}: {}",
                            update.flow_id, e
                        );
                    }
                }
                Ok(None) => {
                    // No update needed
                }
                Err(e) => {
                    error!("Algorithm error: {}", e);
                }
            }
        }
    }

    info!("Shutting down eBPF daemon...");
    algorithm.cleanup();
    drop(datapath);
    info!(
        "eBPF datapath detached - '{}' unregistered from TCP",
        algorithm.name()
    );
    Ok(())
}
