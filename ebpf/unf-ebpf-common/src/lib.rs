#![no_std]

//! Versioned, fixed-layout data shared by eBPF programs and userspace.

use unf_common::{IdentityId, PolicyId, RuleId, Verdict};

pub const FLOW_ABI_VERSION: u16 = 2;
pub const IDENTITY_MAP_ABI_VERSION: u16 = 1;
pub const POLICY_MAP_ABI_VERSION: u16 = 1;
pub const POLICY_BANK_COUNT: u8 = 2;
pub const POLICY_FLAG_HAS_POLICY: u16 = 1 << 0;
pub const POLICY_FLAG_HAS_RULE: u16 = 1 << 1;
pub const POLICY_FLAG_HAS_SHADOW: u16 = 1 << 2;
pub const POLICY_FLAG_SHADOW_HAS_POLICY: u16 = 1 << 3;
pub const POLICY_FLAG_SHADOW_HAS_RULE: u16 = 1 << 4;

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
    AllowDefault = 5,
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
    pub policy_revision: u64,
    pub policy_id: PolicyId,
    pub rule_id: RuleId,
    pub shadow_policy_id: PolicyId,
    pub shadow_rule_id: RuleId,
    pub interface_index: u32,
    pub version: u16,
    pub size: u16,
    pub verdict: Verdict,
    pub direction: u8,
    pub reason: u8,
    pub shadow_verdict: u8,
    pub shadow_reason: u8,
    pub reserved: [u8; 3],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyMapKey {
    pub source_identity: IdentityId,
    pub destination_identity: IdentityId,
    /// Destination port in network byte order; zero means wildcard fallback.
    pub destination_port: [u8; 2],
    /// IP protocol number; zero means wildcard fallback.
    pub protocol: u8,
    pub bank: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyMapValue {
    pub policy_id: PolicyId,
    pub rule_id: RuleId,
    pub shadow_policy_id: PolicyId,
    pub shadow_rule_id: RuleId,
    pub revision: u64,
    pub schema_version: u16,
    pub flags: u16,
    pub verdict: u8,
    pub reason: u8,
    pub shadow_verdict: u8,
    pub shadow_reason: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PolicyMapConfig {
    pub source_epoch: u64,
    pub revision: u64,
    pub entry_count: u32,
    pub schema_version: u16,
    pub active_bank: u8,
    pub flags: u8,
}

const _: () = assert!(core::mem::size_of::<FlowKey>() == 48);
const _: () = assert!(core::mem::size_of::<FlowEvent>() == 96);
const _: () = assert!(core::mem::size_of::<Ipv4IdentityKey>() == 4);
const _: () = assert!(core::mem::size_of::<IdentityMapValue>() == 16);
const _: () = assert!(core::mem::size_of::<PolicyMapKey>() == 12);
const _: () = assert!(core::mem::size_of::<PolicyMapValue>() == 32);
const _: () = assert!(core::mem::size_of::<PolicyMapConfig>() == 24);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_layout_is_stable() {
        assert_eq!(core::mem::align_of::<FlowKey>(), 4);
        assert_eq!(core::mem::align_of::<FlowEvent>(), 8);
        assert_eq!(core::mem::size_of::<FlowEvent>(), 96);
        assert_eq!(core::mem::align_of::<IdentityMapValue>(), 8);
        assert_eq!(core::mem::size_of::<IdentityMapValue>(), 16);
        assert_eq!(core::mem::align_of::<PolicyMapKey>(), 4);
        assert_eq!(core::mem::size_of::<PolicyMapKey>(), 12);
        assert_eq!(core::mem::align_of::<PolicyMapValue>(), 8);
        assert_eq!(core::mem::size_of::<PolicyMapValue>(), 32);
        assert_eq!(core::mem::align_of::<PolicyMapConfig>(), 8);
        assert_eq!(core::mem::size_of::<PolicyMapConfig>(), 24);
    }
}
