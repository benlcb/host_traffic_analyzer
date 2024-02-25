use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;

use hnty_lib::TrafficCapture;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    let traffic_capture = TrafficCapture::new();

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
