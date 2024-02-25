#![no_std]
#![no_main]

use aya_bpf::{
    cty::{c_int, c_void}, macros::tracepoint, programs::TracePointContext
};
use aya_log_ebpf::info;

struct InetSockSetStateCtx {
    skaddr: c_void,
    oldstate: c_int,
    newstate: c_int,
    sport: u16,
    dport: u16,
    family: u16,
    protocol: u8,
    saddr: [u8; 4],
    daddr: [u8; 4],
    saddr_v6: [u8; 16],
    daddr_v6: [u8; 16],
}

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_inet_sock_set_state(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<u32, u32> {
    let parsed : InetSockSetStateCtx = unsafe { ctx.read_at(0).unwrap() };
    info!(&ctx, "state: {} --> {}", i32::from_be(parsed.oldstate), parsed.newstate);
    info!(&ctx, "src port: {} dst port: {}", u16::from_be(parsed.sport), u16::from_be(parsed.dport));
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
