//! Immutable locality-bank ABI. These values are data, not authentication.
//!
//! Admission additionally requires replayed placement, the current journal,
//! frozen kernel device references, an exact live incarnation map and policy-
//! first packet invocation. No existing persistent map ABI is reinterpreted.

pub const ABI_VERSION: u16 = 1;
pub const MAX_ENDPOINTS: u32 = 65_536;
pub const MAX_ADDRESSES: u32 = MAX_ENDPOINTS * 2;
pub const ALIAS_BYTES: usize = 104;
pub const MAX_ALIAS_LENGTH: usize = 96;
pub const PACKET_DSR_PENDING: u32 = 1;

/// Private-bank geometry discovered from current native BTF, not hard-coded
/// offsets selected from a kernel release string. All offsets are BYTES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DeviceGeometry {
    pub skb_device: u32,
    pub device_index: u32,
    pub device_net: u32,
    pub net_cookie: u32,
    pub device_peer: u32,
    pub device_flags: u32,
    pub device_alias: u32,
    pub alias_data: u32,
}

impl DeviceGeometry {
    #[must_use]
    #[cfg_attr(target_arch = "bpf", inline(always))]
    pub const fn valid(self) -> bool {
        self.skb_device <= 56
            && self.skb_device.is_multiple_of(8)
            && self.device_index <= 8192
            && self.device_index.is_multiple_of(4)
            && self.device_net <= 8192
            && self.device_net.is_multiple_of(8)
            && self.net_cookie <= 65_536
            && self.net_cookie.is_multiple_of(8)
            && self.device_peer >= 64
            && self.device_peer <= 8192
            && self.device_peer.is_multiple_of(8)
            && self.device_flags <= 8192
            && self.device_flags.is_multiple_of(4)
            && self.device_alias <= 8192
            && self.device_alias.is_multiple_of(8)
            && self.alias_data >= 8
            && self.alias_data <= 256
    }
}

/// One immutable bank, never an identity-pair matrix. A zero-endpoint cut is
/// represented by withdrawing dispatch, not by publishing an empty permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BankConfig {
    pub identity_epoch: u64,
    pub identity_revision: u64,
    pub routing_revision: u64,
    pub host_cookie: u64,
    pub endpoints: u32,
    pub addresses: u32,
    pub schema_version: u16,
    pub flags: u16,
    pub reserved: u32,
    pub geometry: DeviceGeometry,
    pub placement_digest: [u8; 32],
}

impl BankConfig {
    #[must_use]
    #[cfg_attr(target_arch = "bpf", inline(always))]
    pub fn valid(&self) -> bool {
        self.schema_version == ABI_VERSION
            && self.flags == 0
            && self.reserved == 0
            && self.identity_epoch != 0
            && self.identity_revision != 0
            && self.routing_revision != 0
            && self.host_cookie != 0
            && self.endpoints != 0
            && self.endpoints <= MAX_ENDPOINTS
            && self.addresses >= self.endpoints
            && self.addresses <= self.endpoints * 2
            && self.geometry.valid()
    }
}

/// Mutable, program-read-only applied-placement fence shared by all banks.
/// Userspace withdraws this BEFORE changing identity/routing authority; an old
/// frozen bank cannot rearm itself by retaining yesterday's revision numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PlacementFence {
    pub identity_epoch: u64,
    pub identity_revision: u64,
    pub routing_revision: u64,
    pub schema_version: u16,
    pub reserved: [u8; 6],
}

impl PlacementFence {
    #[must_use]
    #[cfg_attr(target_arch = "bpf", inline(always))]
    pub fn matches(&self, config: &BankConfig) -> bool {
        config.valid()
            && self.schema_version == ABI_VERSION
            && self.reserved == [0; 6]
            && self.identity_epoch == config.identity_epoch
            && self.identity_revision == config.identity_revision
            && self.routing_revision == config.routing_revision
    }
}

/// One canonical family/address key. IPv4 occupies the first four bytes,
/// matching UNF's existing packet ABI; its remaining twelve bytes are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct AddressKey {
    pub address: [u8; 16],
    pub family: u32,
}

impl AddressKey {
    #[must_use]
    #[cfg_attr(target_arch = "bpf", inline(always))]
    pub fn valid(&self) -> bool {
        match self.family {
            4 => self.address[4..].iter().all(|byte| *byte == 0),
            6 => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct AddressOwner {
    pub endpoint: u32,
    pub identity: u32,
}

impl AddressOwner {
    #[must_use]
    #[cfg_attr(target_arch = "bpf", inline(always))]
    pub const fn valid(self, endpoints: u32) -> bool {
        endpoints != 0
            && endpoints <= MAX_ENDPOINTS
            && self.endpoint < endpoints
            && self.identity != 0
    }
}

/// Shared by all addresses of one attachment. Device slots 2*n and 2*n+1
/// retain its host and peer respectively; peer indexes are namespace-relative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Endpoint {
    pub nonce: [u8; 32],
    pub serial: u64,
    pub host_cookie: u64,
    pub peer_cookie: u64,
    pub host_index: u32,
    pub peer_index: u32,
    pub host_mac: [u8; 6],
    pub peer_mac: [u8; 6],
    pub reserved: u32,
    pub host_alias: [u8; ALIAS_BYTES],
    pub peer_alias: [u8; ALIAS_BYTES],
}

impl Endpoint {
    /// Userspace seal validation, not a substitute for actual per-packet
    /// device/alias, namespace and nonce/serial comparisons.
    #[must_use]
    pub fn valid(&self, host_cookie: u64) -> bool {
        self.nonce != [0; 32]
            && self.serial != 0
            && host_cookie != 0
            && self.host_cookie == host_cookie
            && self.peer_cookie != 0
            && self.peer_cookie != host_cookie
            && (2..=i32::MAX as u32).contains(&self.host_index)
            && (2..=i32::MAX as u32).contains(&self.peer_index)
            && self.host_mac != [0; 6]
            && self.peer_mac != [0; 6]
            && self.host_mac[0] & 1 == 0
            && self.peer_mac[0] & 1 == 0
            && self.reserved == 0
            && valid_alias(&self.host_alias)
            && valid_alias(&self.peer_alias)
    }
}

#[must_use]
pub fn valid_alias(alias: &[u8; ALIAS_BYTES]) -> bool {
    let Some(end) = alias.iter().position(|byte| *byte == 0) else {
        return false;
    };
    end != 0 && end <= MAX_ALIAS_LENGTH && alias[end..].iter().all(|byte| *byte == 0)
}

/// A trusted policy/Service/egress continuation initializes this CPU-local
/// record for EVERY invocation. It is never read from a packet or CNI request.
/// Packet consumers additionally compare actual addresses/ports/device to it.
/// Source identity/address remain pre-Service-SNAT; destination is final backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PacketInput {
    pub identity_epoch: u64,
    pub identity_revision: u64,
    pub routing_revision: u64,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub source_identity: u32,
    pub destination_identity: u32,
    pub ingress_index: u32,
    pub schema_version: u16,
    pub family: u8,
    pub protocol: u8,
    pub source_port: [u8; 2],
    pub destination_port: [u8; 2],
    pub flags: u32,
}

impl PacketInput {
    #[must_use]
    #[cfg_attr(target_arch = "bpf", inline(always))]
    pub fn matches(&self, config: &BankConfig) -> bool {
        config.valid()
            && self.schema_version == ABI_VERSION
            && self.flags & !PACKET_DSR_PENDING == 0
            && self.identity_epoch == config.identity_epoch
            && self.identity_revision == config.identity_revision
            && self.routing_revision == config.routing_revision
            && self.source_identity != 0
            && self.destination_identity != 0
            && self.ingress_index > 1
            && i32::try_from(self.ingress_index).is_ok()
            && matches!(self.protocol, 6 | 17 | 132)
            && AddressKey {
                address: self.source_address,
                family: self.family.into(),
            }
            .valid()
            && AddressKey {
                address: self.destination_address,
                family: self.family.into(),
            }
            .valid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn locality_abi_has_explicit_padding_free_layouts() {
        assert_eq!(
            (size_of::<DeviceGeometry>(), align_of::<DeviceGeometry>()),
            (32, 4)
        );
        assert_eq!(
            (size_of::<BankConfig>(), align_of::<BankConfig>()),
            (112, 8)
        );
        assert_eq!(offset_of!(BankConfig, geometry), 48);
        assert_eq!(offset_of!(BankConfig, placement_digest), 80);
        assert_eq!(
            (size_of::<PlacementFence>(), align_of::<PlacementFence>()),
            (32, 8)
        );
        assert_eq!(offset_of!(PlacementFence, schema_version), 24);
        assert_eq!(offset_of!(PlacementFence, reserved), 26);
        assert_eq!((size_of::<AddressKey>(), align_of::<AddressKey>()), (20, 4));
        assert_eq!(offset_of!(AddressKey, family), 16);
        assert_eq!(size_of::<AddressOwner>(), 8);
        assert_eq!((size_of::<Endpoint>(), align_of::<Endpoint>()), (288, 8));
        assert_eq!(offset_of!(Endpoint, serial), 32);
        assert_eq!(offset_of!(Endpoint, host_index), 56);
        assert_eq!(offset_of!(Endpoint, host_alias), 80);
        assert_eq!(offset_of!(Endpoint, peer_alias), 184);
        assert_eq!(
            (size_of::<PacketInput>(), align_of::<PacketInput>()),
            (80, 8)
        );
        assert_eq!(offset_of!(PacketInput, source_address), 24);
        assert_eq!(offset_of!(PacketInput, source_identity), 56);
        assert_eq!(offset_of!(PacketInput, schema_version), 68);
        assert_eq!(offset_of!(PacketInput, flags), 76);
    }

    fn config() -> BankConfig {
        BankConfig {
            identity_epoch: 1,
            identity_revision: 2,
            routing_revision: 3,
            host_cookie: 4,
            endpoints: 2,
            addresses: 4,
            schema_version: ABI_VERSION,
            flags: 0,
            reserved: 0,
            geometry: DeviceGeometry {
                skb_device: 16,
                device_index: 224,
                device_net: 256,
                net_cookie: 128,
                device_peer: 2048,
                device_flags: 96,
                device_alias: 320,
                alias_data: 16,
            },
            placement_digest: [7; 32],
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One mutation matrix for this closed ABI.
    fn bank_geometry_and_capacity_fail_closed() {
        let good = config();
        assert!(good.valid());
        for (endpoints, addresses) in [
            (0, 0),
            (1, 0),
            (2, 1),
            (1, 3),
            (MAX_ENDPOINTS + 1, 2),
            (u32::MAX, u32::MAX),
        ] {
            assert!(
                !BankConfig {
                    endpoints,
                    addresses,
                    ..good
                }
                .valid()
            );
        }
        assert!(
            BankConfig {
                endpoints: MAX_ENDPOINTS,
                addresses: MAX_ADDRESSES,
                ..good
            }
            .valid()
        );
        assert!(
            !BankConfig {
                identity_epoch: 0,
                ..good
            }
            .valid()
        );
        assert!(
            !BankConfig {
                identity_revision: 0,
                ..good
            }
            .valid()
        );
        assert!(
            !BankConfig {
                routing_revision: 0,
                ..good
            }
            .valid()
        );
        assert!(
            !BankConfig {
                host_cookie: 0,
                ..good
            }
            .valid()
        );
        assert!(!BankConfig { flags: 1, ..good }.valid());
        assert!(
            !BankConfig {
                reserved: 1,
                ..good
            }
            .valid()
        );
        assert!(
            !BankConfig {
                schema_version: ABI_VERSION + 1,
                ..good
            }
            .valid()
        );
        for geometry in [
            DeviceGeometry {
                skb_device: 64,
                ..good.geometry
            },
            DeviceGeometry {
                skb_device: 1,
                ..good.geometry
            },
            DeviceGeometry {
                device_index: 8196,
                ..good.geometry
            },
            DeviceGeometry {
                device_net: 3,
                ..good.geometry
            },
            DeviceGeometry {
                net_cookie: 65_544,
                ..good.geometry
            },
            DeviceGeometry {
                device_peer: 63,
                ..good.geometry
            },
            DeviceGeometry {
                device_flags: 3,
                ..good.geometry
            },
            DeviceGeometry {
                device_alias: 1,
                ..good.geometry
            },
            DeviceGeometry {
                alias_data: 257,
                ..good.geometry
            },
        ] {
            assert!(!BankConfig { geometry, ..good }.valid());
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Keep each independent field rejection visible.
    fn canonical_address_and_exact_cut_are_required() {
        let config = config();
        let packet = PacketInput {
            identity_epoch: 1,
            identity_revision: 2,
            routing_revision: 3,
            source_address: [0; 16],
            destination_address: [0; 16],
            source_identity: 1,
            destination_identity: 2,
            ingress_index: 3,
            schema_version: ABI_VERSION,
            family: 4,
            protocol: 17,
            source_port: [1, 2],
            destination_port: [3, 4],
            flags: 0,
        };
        assert!(packet.matches(&config));
        assert!(
            PacketInput {
                family: 6,
                ..packet
            }
            .matches(&config)
        );
        assert!(
            !PacketInput {
                family: 0,
                ..packet
            }
            .matches(&config)
        );
        assert!(
            !PacketInput {
                protocol: 0,
                ..packet
            }
            .matches(&config)
        );
        assert!(
            !PacketInput {
                identity_epoch: 2,
                ..packet
            }
            .matches(&config)
        );
        assert!(
            !PacketInput {
                identity_revision: 3,
                ..packet
            }
            .matches(&config)
        );
        assert!(
            !PacketInput {
                routing_revision: 4,
                ..packet
            }
            .matches(&config)
        );
        assert!(
            !PacketInput {
                source_identity: 0,
                ..packet
            }
            .matches(&config)
        );
        assert!(
            !PacketInput {
                destination_identity: 0,
                ..packet
            }
            .matches(&config)
        );
        assert!(
            !PacketInput {
                ingress_index: 1,
                ..packet
            }
            .matches(&config)
        );
        assert!(!PacketInput { flags: 2, ..packet }.matches(&config));
        assert!(
            PacketInput {
                flags: PACKET_DSR_PENDING,
                ..packet
            }
            .matches(&config)
        );
        let mut noncanonical = packet;
        noncanonical.source_address[15] = 1;
        assert!(!noncanonical.matches(&config));
        assert!(
            PacketInput {
                family: 6,
                ..noncanonical
            }
            .matches(&config)
        );
        assert!(
            !AddressOwner {
                endpoint: 2,
                identity: 1
            }
            .valid(2)
        );
        assert!(
            !AddressOwner {
                endpoint: 0,
                identity: 0
            }
            .valid(2)
        );
        assert!(
            AddressOwner {
                endpoint: 1,
                identity: 1
            }
            .valid(2)
        );
    }

    #[test]
    fn aliases_are_complete_zero_padded_strings_not_prefixes() {
        assert!(!valid_alias(&[0; ALIAS_BYTES]));
        assert!(!valid_alias(&[1; ALIAS_BYTES]));
        let mut alias = [0; ALIAS_BYTES];
        alias[..MAX_ALIAS_LENGTH].fill(b'a');
        assert!(valid_alias(&alias));
        alias[MAX_ALIAS_LENGTH] = b'b';
        assert!(!valid_alias(&alias));
        alias[MAX_ALIAS_LENGTH] = 0;
        alias[ALIAS_BYTES - 1] = 1;
        assert!(!valid_alias(&alias));
    }

    #[test]
    fn endpoint_requires_full_nonce_serial_and_namespace_coordinates() {
        let mut alias = [0; ALIAS_BYTES];
        alias[..3].copy_from_slice(b"own");
        let good = Endpoint {
            nonce: [1; 32],
            serial: 1,
            host_cookie: 4,
            peer_cookie: 5,
            host_index: 2,
            peer_index: 2,
            host_mac: [2, 0, 0, 0, 0, 1],
            peer_mac: [2, 0, 0, 0, 0, 2],
            reserved: 0,
            host_alias: alias,
            peer_alias: alias,
        };
        // Host/peer indexes may coincide in DIFFERENT namespaces.
        assert!(good.valid(4));
        assert!(!good.valid(0));
        assert!(!good.valid(3));
        for invalid in [
            Endpoint {
                nonce: [0; 32],
                ..good
            },
            Endpoint { serial: 0, ..good },
            Endpoint {
                peer_cookie: 0,
                ..good
            },
            Endpoint {
                peer_cookie: 4,
                ..good
            },
            Endpoint {
                host_index: 1,
                ..good
            },
            Endpoint {
                peer_index: u32::MAX,
                ..good
            },
            Endpoint {
                host_mac: [0; 6],
                ..good
            },
            Endpoint {
                peer_mac: [1; 6],
                ..good
            },
            Endpoint {
                reserved: 1,
                ..good
            },
            Endpoint {
                host_alias: [0; ALIAS_BYTES],
                ..good
            },
        ] {
            assert!(!invalid.valid(4));
        }
    }

    #[test]
    fn mutable_fence_cannot_rearm_an_old_bank_by_shape_alone() {
        let config = config();
        let fence = PlacementFence {
            identity_epoch: 1,
            identity_revision: 2,
            routing_revision: 3,
            schema_version: ABI_VERSION,
            reserved: [0; 6],
        };
        assert!(fence.matches(&config));
        for changed in [
            PlacementFence {
                identity_epoch: 0,
                ..fence
            },
            PlacementFence {
                identity_revision: 3,
                ..fence
            },
            PlacementFence {
                routing_revision: 4,
                ..fence
            },
            PlacementFence {
                schema_version: 0,
                ..fence
            },
            PlacementFence {
                reserved: [1; 6],
                ..fence
            },
        ] {
            assert!(!changed.matches(&config));
        }
        assert!(!fence.matches(&BankConfig {
            reserved: 1,
            ..config
        }));
    }
}
