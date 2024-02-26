#![no_std]
#![no_main]

use aya_bpf::{
    cty::{c_int, c_void}, macros::tracepoint, programs::TracePointContext
};
use aya_log_ebpf::info;

// macro_rules! ipv4_bytes2str {
//     ($($arr:ident).+) => {
//         format!("{}.{}.{}.{}", $($arr).+[0], $($arr).+[1], $($arr).+[2], $($arr).+[3])
//     };
// }

struct InetSockSetStateCtx {
    _skaddr: [u8; 16], 
    oldstate: c_int,
    newstate: c_int,
    sport: u16,
    dport: u16,
    family: u16,
    protocol: u16,
    saddr: [u8; 4],
    daddr: [u8; 4], 
    _saddr_v6: [u8; 16],
    _daddr_v6: [u8; 16],
}

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_inet_sock_set_state(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_inet_sock_set_state(ctx: TracePointContext) -> Result<u32, u32> {
    let parsed = InetSockSetStateCtx {
        _skaddr: unsafe { ctx.read_at(0).unwrap() },
        oldstate: unsafe { ctx.read_at(16).unwrap() },
        newstate: unsafe { ctx.read_at(20).unwrap() },
        sport: unsafe { ctx.read_at(24).unwrap() },
        dport: unsafe { ctx.read_at(26).unwrap() },
        family: unsafe { ctx.read_at(28).unwrap() },
        protocol: unsafe { ctx.read_at(30).unwrap() },
        saddr: unsafe { ctx.read_at(32).unwrap() },
        daddr: unsafe { ctx.read_at(36).unwrap() },
        _saddr_v6: unsafe { ctx.read_at(40).unwrap() },
        _daddr_v6: unsafe { ctx.read_at(40).unwrap() },
    };
    info!(&ctx, "state: {} --> {}", parsed.oldstate, parsed.newstate);
    info!(&ctx, "src port: {} dst port: {}", parsed.sport, parsed.dport);
    if parsed.family == 2 { // AF_INET (IPv4)
        info!(&ctx, "src ip: {}.{}.{}.{} dst ip: {}.{}.{}.{}", parsed.saddr[0], parsed.saddr[1], parsed.saddr[2], parsed.saddr[3], parsed.daddr[0], parsed.daddr[0], parsed.daddr[0], parsed.daddr[0]);
    } else if parsed.family == 10 { // AF_INET6 (IPv6)
        info!(&ctx, "IPv6 support not yet implemented");
    } else {
        info!(&ctx, "Unknown family with identifier {}", parsed.family);
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
