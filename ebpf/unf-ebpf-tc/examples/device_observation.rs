#![no_std]
#![no_main]
// Isolated diagnostic only: never installed as the production packet program.
// All packets are dropped. No kernel pointer is exported in the result map.
#![allow(unsafe_code)]

use aya_ebpf::{
    EbpfContext,
    bindings::TC_ACT_SHOT,
    helpers::bpf_probe_read_kernel,
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};

// schema=2, skb.dev u64-word index, dev.ifindex, dev.nd_net.net, net.net_cookie,
// aligned netdev-private peer-pointer offset, expected ingress index, reserved.
// The isolated loader must derive and validate offsets from the running BTF.
#[map]
static P9DEVCFG: Array<[u32; 8]> = Array::with_max_entries(1, 0);
// serial probe count, context index, read-back index, namespace cookie,
// peer index, peer namespace cookie, failure stage, EtherType. Never authority.
#[map]
static P9DEVOBS: Array<[u64; 8]> = Array::with_max_entries(1, 0);

#[classifier]
pub fn device_observation(ctx: TcContext) -> i32 {
    let Ok(protocol) = ctx.load::<u16>(12).map(u16::from_be) else {
        return TC_ACT_SHOT;
    };
    let selected = match protocol {
        0x0800 => {
            ctx.load::<u8>(14) == Ok(0x45)
                && ctx.load::<u8>(23) == Ok(17)
                && ctx.load::<u16>(36).map(u16::from_be) == Ok(17778)
        }
        0x86dd => {
            ctx.load::<u8>(20) == Ok(17) && ctx.load::<u16>(56).map(u16::from_be) == Ok(17778)
        }
        _ => false,
    };
    if !selected {
        return TC_ACT_SHOT;
    }
    let Some(config) = P9DEVCFG.get(0).copied() else {
        return TC_ACT_SHOT;
    };
    let Some(output) = P9DEVOBS.get_ptr_mut(0) else {
        return TC_ACT_SHOT;
    };
    // SAFETY: this diagnostic array entry exists for the attached program's
    // lifetime. The isolated qualifier sends/readbacks one probe at a time;
    // these counters deliberately make no concurrent or lossless claim.
    let previous = unsafe { (*output)[0] };
    let mut result = [0_u64; 8];
    result[0] = previous.saturating_add(1);
    result[1] = u64::from(ifindex(&ctx));
    result[7] = u64::from(protocol);
    if let Err(stage) = observe(&ctx, &config, &mut result) {
        result[6] = stage;
    }
    // SAFETY: same live private array entry as above; no pointer escapes.
    unsafe {
        *output = result;
    }
    TC_ACT_SHOT
}

#[inline(always)]
fn observe(ctx: &TcContext, config: &[u32; 8], result: &mut [u64; 8]) -> Result<(), u64> {
    if config[0] != 2
        || config[1] > 7
        || config[2] > 8192
        || config[3] > 8192
        || config[4] > 65536
        || config[5] > 8192
        || config[5] < 64
        || config[5] % 8 != 0
        || config[6] != ifindex(ctx)
        || config[7] != 0
    {
        return Err(1);
    }
    // SAFETY: the helper safely copies the fixed skb prefix from the actual
    // kernel context, returning an error on an unreadable address. BTF-derived
    // offset selection happens only within this bounded local copy; no variable
    // pointer arithmetic is performed on the verifier's context pointer.
    let prefix =
        unsafe { bpf_probe_read_kernel::<[u64; 8]>(ctx.as_ptr().cast()) }.map_err(|_| 2_u64)?;
    let device = prefix[config[1] as usize];
    result[2] = u64::from(read::<u32>(device, config[2]).map_err(|_| 3_u64)?);
    if result[2] != result[1] {
        return Err(10);
    }
    let namespace = read::<u64>(device, config[3]).map_err(|_| 4_u64)?;
    result[3] = read::<u64>(namespace, config[4]).map_err(|_| 5_u64)?;
    let peer = read::<u64>(device, config[5]).map_err(|_| 6_u64)?;
    result[4] = u64::from(read::<u32>(peer, config[2]).map_err(|_| 7_u64)?);
    let peer_namespace = read::<u64>(peer, config[3]).map_err(|_| 8_u64)?;
    result[5] = read::<u64>(peer_namespace, config[4]).map_err(|_| 9_u64)?;
    if result[3] == 0 || result[4] == 0 || result[5] == 0 {
        return Err(11);
    }
    Ok(())
}

#[inline(always)]
fn read<T: Copy>(base: u64, offset: u32) -> Result<T, ()> {
    if base == 0 || base % 8 != 0 {
        return Err(());
    }
    let address = base.checked_add(u64::from(offset)).ok_or(())?;
    // SAFETY: probe_read_kernel bounds/fault-checks the copy; no raw pointer is
    // dereferenced by Rust. Layout correctness is an independent loader gate.
    unsafe { bpf_probe_read_kernel(address as *const T) }.map_err(|_| ())
}

#[inline(always)]
fn ifindex(ctx: &TcContext) -> u32 {
    // SAFETY: normal verifier-translated __sk_buff context access, independent
    // of the diagnostic raw-kernel-prefix copy and its BTF-derived offsets.
    unsafe { (*ctx.skb.skb).ifindex }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
