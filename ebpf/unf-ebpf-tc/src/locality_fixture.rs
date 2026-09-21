#![no_std]
#![no_main]
#![allow(unsafe_code)]
//! Isolated bank qualification ONLY. This fabricates trusted runtime input and
//! must never be packaged in, attached by, or treated as the production agent.

use aya_ebpf::{
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::{Array, PerCpuArray, ProgramArray},
    programs::TcContext,
};
use unf_ebpf_common::locality::{PacketInput, PlacementFence};

#[map]
static UL_INPUT_V1: PerCpuArray<PacketInput> = PerCpuArray::with_max_entries(1, 0);
#[map]
static UL_FENCE_V1: Array<PlacementFence> = Array::with_max_entries(1, 128);
#[map]
static UL_RESUME_V1: ProgramArray = ProgramArray::with_max_entries(4, 0);
#[map]
static UL_DISPATCH_V1: ProgramArray = ProgramArray::with_max_entries(1, 0);
#[map]
static UL_FIXTURE_V1: Array<PacketInput> = Array::with_max_entries(1, 128);

#[classifier]
pub fn unf_locality_fixture(ctx: TcContext) -> i32 {
    if let (Some(input), Some(fixture)) = (UL_INPUT_V1.get_ptr_mut(0), UL_FIXTURE_V1.get(0)) {
        // Every invocation starts with an explicit complete fixed-width input.
        // Real policy/Service integration must supply its own actual context.
        unsafe {
            *input = *fixture;
            UL_DISPATCH_V1.tail_call(&ctx, 0);
        }
    }
    TC_ACT_SHOT
}

// Retain the continuation map in the fixture ELF without providing any allow
// continuation. Missing tails must drop; this fixture never asserts policy.
#[classifier]
pub fn unf_locality_fixture_resume(ctx: TcContext) -> i32 {
    unsafe {
        UL_RESUME_V1.tail_call(&ctx, 0);
    }
    TC_ACT_SHOT
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
