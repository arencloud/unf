#![no_std]

//! Versioned, fixed-layout data shared by eBPF programs and userspace.

use unf_common::{IdentityId, PolicyId, RuleId, Verdict};

pub const FLOW_ABI_VERSION: u16 = 1;
pub const IDENTITY_MAP_ABI_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressFamily {
    Ipv4 = 4,
    Ipv6 = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    Ingress = 1,
    Egress = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReasonCode {
    Observed = 0,
    AllowExplicit = 1,
    DenyExplicit = 2,
    DenyDefault = 3,
    IdentityUnknown = 4,
}

/// Network-byte-order flow tuple. IPv4 addresses occupy the first four bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FlowKey {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub source_port: [u8; 2],
    pub destination_port: [u8; 2],
    pub protocol: u8,
    pub address_family: u8,
    pub reserved: [u8; 2],
}

/// A compact event emitted from a ring buffer and enriched in userspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FlowEvent {
    pub timestamp_ns: u64,
    pub flow: FlowKey,
    pub policy_id: PolicyId,
    pub rule_id: RuleId,
    pub interface_index: u32,
    pub version: u16,
    pub size: u16,
    pub verdict: Verdict,
    pub direction: u8,
    pub reason: u8,
    pub reserved: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4IdentityKey {
    /// IPv4 address in network byte order.
    pub address: [u8; 4],
}

impl Ipv4IdentityKey {
    #[must_use]
    pub const fn new(address: [u8; 4]) -> Self {
        Self { address }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IdentityMapValue {
    pub identity_id: IdentityId,
    pub schema_version: u16,
    pub flags: u16,
    pub revision: u64,
}

impl IdentityMapValue {
    #[must_use]
    pub const fn new(identity_id: IdentityId, revision: u64) -> Self {
        Self {
            identity_id,
            schema_version: IDENTITY_MAP_ABI_VERSION,
            flags: 0,
            revision,
        }
    }
}

const _: () = assert!(core::mem::size_of::<FlowKey>() == 48);
const _: () = assert!(core::mem::size_of::<FlowEvent>() == 80);
const _: () = assert!(core::mem::size_of::<Ipv4IdentityKey>() == 4);
const _: () = assert!(core::mem::size_of::<IdentityMapValue>() == 16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_layout_is_stable() {
        assert_eq!(core::mem::align_of::<FlowKey>(), 4);
        assert_eq!(core::mem::align_of::<FlowEvent>(), 8);
        assert_eq!(core::mem::size_of::<FlowEvent>(), 80);
        assert_eq!(core::mem::align_of::<IdentityMapValue>(), 8);
        assert_eq!(core::mem::size_of::<IdentityMapValue>(), 16);
    }
}
