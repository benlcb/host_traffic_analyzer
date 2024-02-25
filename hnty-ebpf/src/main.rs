#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn hnty(ctx: TracePointContext) -> u32 {
    match try_hnty(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hnty(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint inet_sock_set_state called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
