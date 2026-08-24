#![no_std]

//! Versioned, fixed-layout data shared by eBPF programs and userspace.

use unf_common::{IdentityId, PolicyId, RuleId, Verdict};

pub const FLOW_ABI_VERSION: u16 = 2;
pub const IDENTITY_MAP_ABI_VERSION: u16 = 1;
pub const POLICY_MAP_ABI_VERSION: u16 = 2;
pub const POLICY_BANK_COUNT: u8 = 2;
pub const POLICY_FLAG_HAS_POLICY: u16 = 1 << 0;
pub const POLICY_FLAG_HAS_RULE: u16 = 1 << 1;
pub const POLICY_FLAG_HAS_SHADOW: u16 = 1 << 2;
pub const POLICY_FLAG_SHADOW_HAS_POLICY: u16 = 1 << 3;
pub const POLICY_FLAG_SHADOW_HAS_RULE: u16 = 1 << 4;
pub const IPV6_EXTENSION_HEADER_LIMIT: u8 = 6;
pub const IPV6_EXTENSION_BYTE_LIMIT: usize = 256;

pub const IPV6_NEXT_HEADER_HOP_BY_HOP: u8 = 0;
pub const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
pub const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
pub const IPV6_NEXT_HEADER_ESP: u8 = 50;
pub const IPV6_NEXT_HEADER_AUTHENTICATION: u8 = 51;
pub const IPV6_NEXT_HEADER_NONE: u8 = 59;
pub const IPV6_NEXT_HEADER_DESTINATION_OPTIONS: u8 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6ExtensionStep {
    Transport,
    Continue { next_header: u8, length: usize },
    Unsupported,
}

/// Decodes one IPv6 extension-header boundary from its first eight bytes.
///
/// Transport protocols are returned without inspecting `header`. Opaque,
/// terminal, malformed, and non-initial-fragment headers are unsupported.
#[must_use]
pub const fn ipv6_extension_step(next_header: u8, header: [u8; 8]) -> Ipv6ExtensionStep {
    match next_header {
        6 | 17 | 132 => Ipv6ExtensionStep::Transport,
        IPV6_NEXT_HEADER_HOP_BY_HOP
        | IPV6_NEXT_HEADER_ROUTING
        | IPV6_NEXT_HEADER_DESTINATION_OPTIONS => Ipv6ExtensionStep::Continue {
            next_header: header[0],
            length: (header[1] as usize + 1) * 8,
        },
        IPV6_NEXT_HEADER_FRAGMENT => {
            let fragment = u16::from_be_bytes([header[2], header[3]]);
            if fragment & 0xfff8 == 0 {
                Ipv6ExtensionStep::Continue {
                    next_header: header[0],
                    length: 8,
                }
            } else {
                Ipv6ExtensionStep::Unsupported
            }
        }
        IPV6_NEXT_HEADER_AUTHENTICATION if header[1] >= 1 => Ipv6ExtensionStep::Continue {
            next_header: header[0],
            length: (header[1] as usize + 2) * 4,
        },
        IPV6_NEXT_HEADER_ESP | IPV6_NEXT_HEADER_NONE | IPV6_NEXT_HEADER_AUTHENTICATION => {
            Ipv6ExtensionStep::Unsupported
        }
        _ => Ipv6ExtensionStep::Unsupported,
    }
}

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
pub struct Ipv6IdentityKey {
    /// IPv6 address in network byte order.
    pub address: [u8; 16],
}

impl Ipv6IdentityKey {
    #[must_use]
    pub const fn new(address: [u8; 16]) -> Self {
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
    /// Destination port in network byte order; zero means protocol/global wildcard.
    pub destination_port: [u8; 2],
    /// IP protocol number; zero means global wildcard fallback.
    pub protocol: u8,
    pub bank: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4PolicyMapKey {
    /// Exact source IPv4 address in network byte order; zero is a fallback.
    pub source_address: [u8; 4],
    pub destination_identity: IdentityId,
    /// Destination port in network byte order; zero means protocol/global wildcard.
    pub destination_port: [u8; 2],
    /// IP protocol number; zero means global wildcard fallback.
    pub protocol: u8,
    pub bank: u8,
}

/// The first 64 bits are exact policy dimensions; the final 128 bits are the
/// source address matched by an LPM trie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv6PolicyMapData {
    pub destination_identity: IdentityId,
    pub destination_port: [u8; 2],
    pub protocol: u8,
    pub bank: u8,
    pub source_address: [u8; 16],
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
const _: () = assert!(core::mem::size_of::<Ipv6IdentityKey>() == 16);
const _: () = assert!(core::mem::size_of::<IdentityMapValue>() == 16);
const _: () = assert!(core::mem::size_of::<PolicyMapKey>() == 12);
const _: () = assert!(core::mem::size_of::<Ipv4PolicyMapKey>() == 12);
const _: () = assert!(core::mem::size_of::<Ipv6PolicyMapData>() == 24);
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
        assert_eq!(core::mem::align_of::<Ipv6IdentityKey>(), 1);
        assert_eq!(core::mem::size_of::<Ipv6IdentityKey>(), 16);
        assert_eq!(core::mem::align_of::<PolicyMapKey>(), 4);
        assert_eq!(core::mem::size_of::<PolicyMapKey>(), 12);
        assert_eq!(core::mem::align_of::<Ipv4PolicyMapKey>(), 4);
        assert_eq!(core::mem::size_of::<Ipv4PolicyMapKey>(), 12);
        assert_eq!(core::mem::align_of::<Ipv6PolicyMapData>(), 4);
        assert_eq!(core::mem::size_of::<Ipv6PolicyMapData>(), 24);
        assert_eq!(core::mem::align_of::<PolicyMapValue>(), 8);
        assert_eq!(core::mem::size_of::<PolicyMapValue>(), 32);
        assert_eq!(core::mem::align_of::<PolicyMapConfig>(), 8);
        assert_eq!(core::mem::size_of::<PolicyMapConfig>(), 24);
    }

    #[test]
    fn ipv6_extension_steps_validate_lengths_and_fragments() {
        assert_eq!(ipv6_extension_step(6, [0; 8]), Ipv6ExtensionStep::Transport);
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_HOP_BY_HOP, [17, 1, 0, 0, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Continue {
                next_header: 17,
                length: 16,
            }
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_ROUTING, [6, 2, 0, 0, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Continue {
                next_header: 6,
                length: 24,
            }
        );
        assert_eq!(
            ipv6_extension_step(
                IPV6_NEXT_HEADER_DESTINATION_OPTIONS,
                [17, 0, 0, 0, 0, 0, 0, 0]
            ),
            Ipv6ExtensionStep::Continue {
                next_header: 17,
                length: 8,
            }
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_FRAGMENT, [132, 0, 0, 1, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Continue {
                next_header: 132,
                length: 8,
            }
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_FRAGMENT, [6, 0, 0, 8, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Unsupported
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_AUTHENTICATION, [6, 1, 0, 0, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Continue {
                next_header: 6,
                length: 12,
            }
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_AUTHENTICATION, [6, 0, 0, 0, 0, 0, 0, 0]),
            Ipv6ExtensionStep::Unsupported
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_ESP, [0; 8]),
            Ipv6ExtensionStep::Unsupported
        );
        assert_eq!(
            ipv6_extension_step(IPV6_NEXT_HEADER_NONE, [0; 8]),
            Ipv6ExtensionStep::Unsupported
        );
    }
}
