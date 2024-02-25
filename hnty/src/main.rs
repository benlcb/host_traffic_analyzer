use eyre::Result;
use log::info;
use tokio::signal;

use hnty_lib::TrafficCapture;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    // When this is dropped, traffic is no longer captured
    let _traffic_capture = TrafficCapture::new()?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
