use aya::programs::TracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use eyre::Result;
use log::{debug, warn};

pub struct TrafficCapture {
    bpf: Bpf,
}

impl TrafficCapture {
    pub fn new() -> Result<Self> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        let mut traffic_capture = TrafficCapture {
            #[cfg(debug_assertions)]
            bpf: Bpf::load(include_bytes_aligned!(
                "../../target/bpfel-unknown-none/debug/hnty"
            ))?,
            #[cfg(not(debug_assertions))]
            bpf: Bpf::load(include_bytes_aligned!(
                "../../target/bpfel-unknown-none/release/hnty"
            ))?,
        };

        if let Err(e) = BpfLogger::init(&mut traffic_capture.bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        let program: &mut TracePoint = traffic_capture
            .bpf
            .program_mut("inet_sock_set_state")
            .unwrap()
            .try_into()?;
        program.load()?;
        program.attach("sock", "inet_sock_set_state")?;

        Ok(traffic_capture)
    }
}
