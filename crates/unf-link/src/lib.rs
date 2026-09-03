//! Portable, ownership-safe veth lifecycle for one UNF CNI attachment.

use std::collections::BTreeSet;
use std::fs::File;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

use futures::TryStreamExt;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::{
    InfoData, InfoKind, InfoVeth, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage,
};
use rtnetlink::{Handle, LinkDummy, LinkMessageBuilder, LinkUnspec, LinkVeth, new_connection};
use rustix::fs::{Mode, OFlags, open};
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};
use thiserror::Error;
use unf_cni_state::AttachmentRecord;

const LINUX_INTERFACE_NAME_MAX: usize = 15;
const MIN_DUAL_STACK_MTU: u32 = 1_280;
const MAX_MTU: u32 = 65_535;
const OWNER_PREFIX: &str = "unf:cni:v1:";
const EGRESS_OWNER_PREFIX: &str = "unf:egress-address:v1:";
pub const EGRESS_GATEWAY_INTERFACE: &str = "unf-egress0";
const MAX_GATEWAY_ADDRESSES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AssignedAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VethPlan {
    host_name: String,
    temporary_peer_name: String,
    container_name: String,
    host_alias: String,
    peer_alias: String,
    host_address: [u8; 6],
    peer_address: [u8; 6],
    netns: PathBuf,
    mtu: u32,
    addresses: [AssignedAddress; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkReadback {
    pub host_index: u32,
    pub peer_index: u32,
    pub host_name: String,
    pub peer_name: String,
    pub host_address: [u8; 6],
    pub peer_address: [u8; 6],
    pub mtu: u32,
    pub addresses: BTreeSet<AssignedAddress>,
}

/// Exact, Node-UID-bound ownership plan for egress addresses. The addresses
/// live on a dedicated dummy interface as host prefixes; reachability is an
/// independent provider concern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAddressPlan {
    node_uid: String,
    interface_name: String,
    owner_alias: String,
    mtu: u32,
    addresses: BTreeSet<AssignedAddress>,
    ipv6_proxy_uplink: Option<GatewayProxyUplink>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayProxyUplink {
    interface_name: String,
    interface_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAddressReadback {
    pub node_uid: String,
    pub interface_name: String,
    pub interface_index: u32,
    pub mtu: u32,
    pub addresses: BTreeSet<AssignedAddress>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteOutcome {
    Deleted,
    AlreadyAbsent,
}

#[derive(Debug, Error)]
pub enum LinkError {
    #[error("invalid veth plan: {0}")]
    InvalidPlan(String),
    #[error("network namespace {path:?} is unavailable: {source}")]
    OpenNamespace {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("refusing network namespace path {0:?}: the final component is a symbolic link")]
    SymbolicLinkNamespace(PathBuf),
    #[error("netlink {operation} failed: {source}")]
    Netlink {
        operation: &'static str,
        #[source]
        source: rtnetlink::Error,
    },
    #[error("netlink {operation} failed: {source}")]
    OpenNetlink {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("could not configure IPv6 proxy ownership through {path:?}: {source}")]
    ConfigureIpv6Proxy {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("link {name:?} conflicts with the expected UNF ownership or shape: {reason}")]
    LinkConflict { name: String, reason: String },
    #[error("veth lifecycle readback failed: {0}")]
    Readback(String),
    #[error("could not enter network namespace: {0}")]
    EnterNamespace(rustix::io::Errno),
    #[error("network namespace worker panicked")]
    NamespaceWorkerPanicked,
    #[error("network namespace worker could not be joined: {0}")]
    NamespaceJoin(String),
    #[error("could not construct the namespace-local Tokio runtime: {0}")]
    NamespaceRuntime(std::io::Error),
}

impl VethPlan {
    /// Builds the veth plan persisted by the durable attachment transaction.
    ///
    /// # Errors
    ///
    /// Rejects names, namespace paths, MTUs, or prefixes that Linux cannot
    /// apply safely.
    pub fn from_attachment(record: &AttachmentRecord) -> Result<Self, LinkError> {
        Self::new(
            record.host_interface.clone(),
            record.spec.key.ifname.clone(),
            PathBuf::from(&record.spec.netns),
            record.spec.mtu,
            [
                AssignedAddress {
                    address: IpAddr::V4(record.lease.ipv4.address),
                    prefix_len: 32,
                },
                AssignedAddress {
                    address: IpAddr::V6(record.lease.ipv6.address),
                    prefix_len: 128,
                },
            ],
        )
    }

    /// Creates a deterministic plan from explicit attachment inputs.
    ///
    /// # Errors
    ///
    /// Rejects names, namespace paths, MTUs, or prefixes that Linux cannot
    /// apply safely.
    pub fn new(
        host_name: String,
        container_name: String,
        netns: PathBuf,
        mtu: u32,
        addresses: [AssignedAddress; 2],
    ) -> Result<Self, LinkError> {
        validate_interface_name(&host_name, "host")?;
        validate_interface_name(&container_name, "container")?;
        if host_name == container_name {
            return Err(LinkError::InvalidPlan(
                "host and container interface names must differ".to_string(),
            ));
        }
        if !netns.is_absolute() {
            return Err(LinkError::InvalidPlan(
                "network namespace path must be absolute".to_string(),
            ));
        }
        if !(MIN_DUAL_STACK_MTU..=MAX_MTU).contains(&mtu) {
            return Err(LinkError::InvalidPlan(format!(
                "MTU must be between {MIN_DUAL_STACK_MTU} and {MAX_MTU}"
            )));
        }
        validate_addresses(addresses)?;

        let suffix = host_name.strip_prefix("unf").unwrap_or(&host_name);
        let suffix = &suffix[..suffix.len().min(11)];
        let temporary_peer_name = format!("unfp{suffix}");
        validate_interface_name(&temporary_peer_name, "temporary peer")?;
        if temporary_peer_name == host_name || temporary_peer_name == container_name {
            return Err(LinkError::InvalidPlan(
                "derived temporary peer name collides with an attachment interface".to_string(),
            ));
        }

        let host_alias = format!("{OWNER_PREFIX}{host_name}:host");
        let peer_alias = format!("{OWNER_PREFIX}{host_name}:peer");
        let (host_address, peer_address) = ownership_addresses(&host_name);
        Ok(Self {
            host_name,
            temporary_peer_name,
            container_name,
            host_alias,
            peer_alias,
            host_address,
            peer_address,
            netns,
            mtu,
            addresses,
        })
    }

    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    #[must_use]
    pub fn temporary_peer_name(&self) -> &str {
        &self.temporary_peer_name
    }

    #[must_use]
    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    #[must_use]
    pub fn netns(&self) -> &Path {
        &self.netns
    }

    /// Creates or resumes the exact owned veth, then verifies kernel state.
    ///
    /// # Errors
    ///
    /// Fails closed on foreign links, inaccessible namespaces, netlink
    /// failures, or state that differs from the durable plan.
    pub async fn apply(&self) -> Result<LinkReadback, LinkError> {
        let namespace = open_namespace(&self.netns)?;
        let (connection, handle, _) =
            new_connection().map_err(|source| LinkError::OpenNetlink {
                operation: "open host connection",
                source,
            })?;
        tokio::spawn(connection);
        self.ensure_host(&handle).await?;
        self.move_temporary_peer(&handle, &namespace).await?;
        let peer = self.configure_and_read_peer(namespace).await?;
        let host = require_link(&handle, &self.host_name).await?;
        validate_ready_link(
            &host,
            &self.host_name,
            &self.host_alias,
            self.mtu,
            self.host_address,
        )?;
        Ok(LinkReadback {
            host_index: host.header.index,
            peer_index: peer.index,
            host_name: self.host_name.clone(),
            peer_name: self.container_name.clone(),
            host_address: self.host_address,
            peer_address: self.peer_address,
            mtu: self.mtu,
            addresses: peer.addresses,
        })
    }

    async fn ensure_host(&self, handle: &Handle) -> Result<(), LinkError> {
        let host = find_link(handle, &self.host_name).await?;
        if let Some(ref link) = host {
            validate_recoverable_link(
                link,
                &self.host_name,
                &self.host_alias,
                self.mtu,
                self.host_address,
            )?;
        } else {
            if find_link(handle, &self.temporary_peer_name)
                .await?
                .is_some()
            {
                return Err(LinkError::LinkConflict {
                    name: self.temporary_peer_name.clone(),
                    reason: "temporary peer exists without its owned host endpoint".to_string(),
                });
            }
            let peer = LinkMessageBuilder::<LinkUnspec>::new()
                .name(&self.temporary_peer_name)
                .mtu(self.mtu)
                .address(self.peer_address.to_vec())
                .alias(&self.peer_alias)
                .build();
            handle
                .link()
                .add(
                    LinkVeth::new(&self.host_name, &self.temporary_peer_name)
                        .mtu(self.mtu)
                        .address(self.host_address.to_vec())
                        .alias(&self.host_alias)
                        .set_info_data(InfoData::Veth(InfoVeth::Peer(peer)))
                        .build(),
                )
                .execute()
                .await
                .map_err(|source| LinkError::Netlink {
                    operation: "create veth",
                    source,
                })?;
        }

        let host = require_link(handle, &self.host_name).await?;
        validate_recoverable_link(
            &host,
            &self.host_name,
            &self.host_alias,
            self.mtu,
            self.host_address,
        )?;
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(host.header.index)
                    .mtu(self.mtu)
                    .alias(&self.host_alias)
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(|source| LinkError::Netlink {
                operation: "configure host endpoint",
                source,
            })
    }

    async fn move_temporary_peer(
        &self,
        handle: &Handle,
        namespace: &File,
    ) -> Result<(), LinkError> {
        let Some(peer) = find_link(handle, &self.temporary_peer_name).await? else {
            return Ok(());
        };
        validate_recoverable_link(
            &peer,
            &self.temporary_peer_name,
            &self.peer_alias,
            self.mtu,
            self.peer_address,
        )?;
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(peer.header.index)
                    .mtu(self.mtu)
                    .alias(&self.peer_alias)
                    .setns_by_fd(namespace.as_raw_fd())
                    .build(),
            )
            .execute()
            .await
            .map_err(|source| LinkError::Netlink {
                operation: "move peer into network namespace",
                source,
            })
    }

    /// Reads and verifies both endpoints without mutating them.
    ///
    /// # Errors
    ///
    /// Returns a conflict/readback error when either endpoint is missing or
    /// does not match the plan.
    pub async fn readback(&self) -> Result<LinkReadback, LinkError> {
        let namespace = open_namespace(&self.netns)?;
        let (connection, handle, _) =
            new_connection().map_err(|source| LinkError::OpenNetlink {
                operation: "open host connection",
                source,
            })?;
        tokio::spawn(connection);
        let host = require_link(&handle, &self.host_name).await?;
        validate_ready_link(
            &host,
            &self.host_name,
            &self.host_alias,
            self.mtu,
            self.host_address,
        )?;
        let plan = self.clone();
        let peer = run_in_namespace(namespace, move || async move {
            let (connection, handle, _) =
                new_connection().map_err(|source| LinkError::OpenNetlink {
                    operation: "open container connection",
                    source,
                })?;
            tokio::spawn(connection);
            read_peer(&handle, &plan).await
        })
        .await?;
        Ok(LinkReadback {
            host_index: host.header.index,
            peer_index: peer.index,
            host_name: self.host_name.clone(),
            peer_name: self.container_name.clone(),
            host_address: self.host_address,
            peer_address: self.peer_address,
            mtu: self.mtu,
            addresses: peer.addresses,
        })
    }

    /// Reads ownership and interface indexes for exact route-first cleanup.
    ///
    /// Unlike strict CHECK readback, this accepts absent endpoints and missing
    /// managed addresses. It still rejects same-named foreign links, MAC/alias
    /// drift, and MTU drift before returning indexes (zero means absent).
    ///
    /// # Errors
    ///
    /// Returns an ownership conflict or netlink error when cleanup cannot
    /// safely distinguish managed from foreign link state.
    pub async fn cleanup_readback(&self) -> Result<LinkReadback, LinkError> {
        let (connection, handle, _) =
            new_connection().map_err(|source| LinkError::OpenNetlink {
                operation: "open host cleanup connection",
                source,
            })?;
        tokio::spawn(connection);
        let host_index = if let Some(host) = find_link(&handle, &self.host_name).await? {
            validate_recoverable_link(
                &host,
                &self.host_name,
                &self.host_alias,
                self.mtu,
                self.host_address,
            )?;
            host.header.index
        } else {
            0
        };

        let peer_index = match open_namespace(&self.netns) {
            Ok(namespace) => {
                let plan = self.clone();
                run_in_namespace(namespace, move || async move {
                    let (connection, handle, _) =
                        new_connection().map_err(|source| LinkError::OpenNetlink {
                            operation: "open container cleanup connection",
                            source,
                        })?;
                    tokio::spawn(connection);
                    let Some(peer) = find_link(&handle, &plan.container_name).await? else {
                        return Ok(0);
                    };
                    validate_recoverable_link(
                        &peer,
                        &plan.container_name,
                        &plan.peer_alias,
                        plan.mtu,
                        plan.peer_address,
                    )?;
                    Ok(peer.header.index)
                })
                .await?
            }
            Err(LinkError::OpenNamespace { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                0
            }
            Err(error) => return Err(error),
        };

        Ok(LinkReadback {
            host_index,
            peer_index,
            host_name: self.host_name.clone(),
            peer_name: self.container_name.clone(),
            host_address: self.host_address,
            peer_address: self.peer_address,
            mtu: self.mtu,
            addresses: BTreeSet::from(self.addresses),
        })
    }

    /// Deletes only the endpoint pair bearing this plan's ownership aliases.
    ///
    /// # Errors
    ///
    /// Fails closed rather than deleting a same-named foreign interface.
    pub async fn delete(&self) -> Result<DeleteOutcome, LinkError> {
        let (connection, handle, _) =
            new_connection().map_err(|source| LinkError::OpenNetlink {
                operation: "open host connection",
                source,
            })?;
        tokio::spawn(connection);
        if let Some(host) = find_link(&handle, &self.host_name).await? {
            validate_recoverable_link(
                &host,
                &self.host_name,
                &self.host_alias,
                self.mtu,
                self.host_address,
            )?;
            handle
                .link()
                .del(host.header.index)
                .execute()
                .await
                .map_err(|source| LinkError::Netlink {
                    operation: "delete host endpoint",
                    source,
                })?;
            return Ok(DeleteOutcome::Deleted);
        }

        let namespace = match open_namespace(&self.netns) {
            Ok(namespace) => namespace,
            Err(LinkError::OpenNamespace { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(DeleteOutcome::AlreadyAbsent);
            }
            Err(error) => return Err(error),
        };
        let plan = self.clone();
        run_in_namespace(namespace, move || async move {
            let (connection, handle, _) =
                new_connection().map_err(|source| LinkError::OpenNetlink {
                    operation: "open container connection",
                    source,
                })?;
            tokio::spawn(connection);
            let Some(peer) = find_link(&handle, &plan.container_name).await? else {
                return Ok(DeleteOutcome::AlreadyAbsent);
            };
            validate_recoverable_link(
                &peer,
                &plan.container_name,
                &plan.peer_alias,
                plan.mtu,
                plan.peer_address,
            )?;
            handle
                .link()
                .del(peer.header.index)
                .execute()
                .await
                .map_err(|source| LinkError::Netlink {
                    operation: "delete orphaned container endpoint",
                    source,
                })?;
            Ok(DeleteOutcome::Deleted)
        })
        .await
    }

    async fn configure_and_read_peer(&self, namespace: File) -> Result<PeerReadback, LinkError> {
        let plan = self.clone();
        run_in_namespace(namespace, move || async move {
            let (connection, handle, _) =
                new_connection().map_err(|source| LinkError::OpenNetlink {
                    operation: "open container connection",
                    source,
                })?;
            tokio::spawn(connection);

            let peer = if let Some(peer) = find_link(&handle, &plan.container_name).await? {
                validate_recoverable_link(
                    &peer,
                    &plan.container_name,
                    &plan.peer_alias,
                    plan.mtu,
                    plan.peer_address,
                )?;
                peer
            } else {
                let peer = require_link(&handle, &plan.temporary_peer_name).await?;
                validate_recoverable_link(
                    &peer,
                    &plan.temporary_peer_name,
                    &plan.peer_alias,
                    plan.mtu,
                    plan.peer_address,
                )?;
                peer
            };
            handle
                .link()
                .set(
                    LinkUnspec::new_with_index(peer.header.index)
                        .name(&plan.container_name)
                        .mtu(plan.mtu)
                        .alias(&plan.peer_alias)
                        .up()
                        .build(),
                )
                .execute()
                .await
                .map_err(|source| LinkError::Netlink {
                    operation: "configure container endpoint",
                    source,
                })?;
            let peer = require_link(&handle, &plan.container_name).await?;
            for assigned in plan.addresses {
                handle
                    .address()
                    .add(peer.header.index, assigned.address, assigned.prefix_len)
                    .replace()
                    .execute()
                    .await
                    .map_err(|source| LinkError::Netlink {
                        operation: "assign container address",
                        source,
                    })?;
            }
            read_peer(&handle, &plan).await
        })
        .await
    }
}

impl GatewayAddressPlan {
    /// Builds a canonical ownership plan. Addresses are always represented as
    /// IPv4 /32 or IPv6 /128 so no connected pool route is invented.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Node UID, MTU, oversized set, duplicates, and
    /// addresses unsafe for external source ownership.
    pub fn new(node_uid: String, mtu: u32, addresses: Vec<IpAddr>) -> Result<Self, LinkError> {
        if node_uid.is_empty()
            || node_uid.len() > 128
            || !node_uid.is_ascii()
            || node_uid.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(LinkError::InvalidPlan(
                "gateway Node UID must contain 1..=128 printable ASCII bytes".to_string(),
            ));
        }
        if !(MIN_DUAL_STACK_MTU..=MAX_MTU).contains(&mtu) {
            return Err(LinkError::InvalidPlan(format!(
                "MTU must be between {MIN_DUAL_STACK_MTU} and {MAX_MTU}"
            )));
        }
        if addresses.len() > MAX_GATEWAY_ADDRESSES {
            return Err(LinkError::InvalidPlan(format!(
                "gateway address set must contain 0..={MAX_GATEWAY_ADDRESSES} entries"
            )));
        }
        let address_count = addresses.len();
        let addresses = addresses
            .into_iter()
            .map(|address| AssignedAddress {
                prefix_len: if address.is_ipv4() { 32 } else { 128 },
                address,
            })
            .collect::<BTreeSet<_>>();
        if addresses.len() != address_count {
            return Err(LinkError::InvalidPlan(
                "gateway addresses must be unique".to_string(),
            ));
        }
        if addresses
            .iter()
            .any(|assigned| !valid_gateway_address(assigned.address))
        {
            return Err(LinkError::InvalidPlan(
                "gateway addresses cannot be unspecified, loopback, multicast, or link-local"
                    .to_string(),
            ));
        }
        Ok(Self {
            owner_alias: format!("{EGRESS_OWNER_PREFIX}{node_uid}"),
            node_uid,
            interface_name: EGRESS_GATEWAY_INTERFACE.to_string(),
            mtu,
            addresses,
            ipv6_proxy_uplink: None,
        })
    }

    /// Publishes owned IPv6 host addresses through an exact proxy-NDP set on
    /// the provider uplink. IPv4 ownership is announced by Linux ARP directly;
    /// IPv6 addresses held on a dummy link require an explicit neighbour proxy
    /// when the address pool is reachable on-link.
    ///
    /// # Errors
    ///
    /// Rejects unsafe interface names or a zero interface index.
    pub fn with_ipv6_proxy_uplink(
        mut self,
        interface_name: String,
        interface_index: u32,
    ) -> Result<Self, LinkError> {
        validate_interface_name(&interface_name, "IPv6 proxy uplink")?;
        if interface_name == "lo" || interface_index == 0 {
            return Err(LinkError::InvalidPlan(
                "IPv6 proxy uplink must identify a non-loopback interface".to_string(),
            ));
        }
        self.ipv6_proxy_uplink = Some(GatewayProxyUplink {
            interface_name,
            interface_index,
        });
        Ok(self)
    }

    #[must_use]
    pub fn addresses(&self) -> &BTreeSet<AssignedAddress> {
        &self.addresses
    }

    /// Preflights the whole host for collisions, creates or resumes the exact
    /// owned dummy interface, applies missing host prefixes, and independently
    /// reads back the complete managed set. A partial add is rolled back.
    ///
    /// # Errors
    ///
    /// Fails closed on foreign link/address ownership or any kernel mismatch.
    pub async fn apply(&self) -> Result<GatewayAddressReadback, LinkError> {
        let (connection, handle, _) =
            new_connection().map_err(|source| LinkError::OpenNetlink {
                operation: "open gateway-address connection",
                source,
            })?;
        tokio::spawn(connection);
        let existing = find_link(&handle, &self.interface_name).await?;
        if let Some(link) = &existing {
            validate_gateway_link(link, self)?;
        }
        preflight_gateway_address_collisions(
            &handle,
            existing.as_ref().map(|link| link.header.index),
            &self.addresses,
        )
        .await?;

        let created = existing.is_none();
        if created {
            handle
                .link()
                .add(
                    LinkDummy::new(&self.interface_name)
                        .mtu(self.mtu)
                        .alias(&self.owner_alias)
                        .up()
                        .build(),
                )
                .execute()
                .await
                .map_err(|source| LinkError::Netlink {
                    operation: "create gateway-address interface",
                    source,
                })?;
        }
        let link = require_link(&handle, &self.interface_name).await?;
        if created {
            validate_gateway_link_kind(&link, &self.interface_name)?;
        } else {
            validate_gateway_link(&link, self)?;
        }
        let link = self.configure_gateway_link(&handle, &link, created).await?;

        let current = addresses_on_link(&handle, link.header.index).await?;
        let missing = self
            .addresses
            .difference(&current)
            .copied()
            .collect::<Vec<_>>();
        let mut added = Vec::new();
        for assigned in missing {
            if let Err(source) = handle
                .address()
                .add(link.header.index, assigned.address, assigned.prefix_len)
                .execute()
                .await
            {
                rollback_gateway_addresses(&handle, link.header.index, &added).await;
                if created {
                    let _ = handle.link().del(link.header.index).execute().await;
                }
                return Err(LinkError::Netlink {
                    operation: "assign gateway address",
                    source,
                });
            }
            added.push(assigned);
        }
        let added_proxies = match self.apply_ipv6_proxy_ownership(&handle).await {
            Ok(added) => added,
            Err(error) => {
                rollback_gateway_addresses(&handle, link.header.index, &added).await;
                if created {
                    let _ = handle.link().del(link.header.index).execute().await;
                }
                return Err(error);
            }
        };
        match self.readback_with_handle(&handle).await {
            Ok(readback) => Ok(readback),
            Err(error) => {
                rollback_gateway_proxies(&handle, &added_proxies).await;
                rollback_gateway_addresses(&handle, link.header.index, &added).await;
                if created {
                    let _ = handle.link().del(link.header.index).execute().await;
                }
                Err(error)
            }
        }
    }

    async fn apply_ipv6_proxy_ownership(
        &self,
        handle: &Handle,
    ) -> Result<Vec<NeighbourMessage>, LinkError> {
        let desired = self.ipv6_proxy_addresses();
        if desired.is_empty() {
            return Ok(Vec::new());
        }
        let uplink = self.ipv6_proxy_uplink.as_ref().ok_or_else(|| {
            LinkError::InvalidPlan(
                "IPv6 gateway addresses require an explicit proxy-NDP uplink".to_string(),
            )
        })?;
        validate_gateway_proxy_uplink(handle, uplink).await?;
        enable_ipv6_proxy_ndp(&uplink.interface_name)?;
        let existing = gateway_proxy_entries(handle, &desired).await?;
        if let Some(entry) = existing
            .iter()
            .find(|entry| entry.header.ifindex != uplink.interface_index)
        {
            return Err(LinkError::LinkConflict {
                name: uplink.interface_name.clone(),
                reason: format!(
                    "IPv6 gateway proxy {:?} already exists on foreign interface index {}",
                    neighbour_address(entry),
                    entry.header.ifindex
                ),
            });
        }
        let present = existing
            .iter()
            .filter_map(neighbour_address)
            .collect::<BTreeSet<_>>();
        let mut added = Vec::new();
        for address in desired.difference(&present).copied() {
            if let Err(source) = handle
                .neighbours()
                .add(uplink.interface_index, address)
                .flags(NeighbourFlags::Proxy)
                .execute()
                .await
            {
                rollback_gateway_proxies(handle, &added).await;
                return Err(LinkError::Netlink {
                    operation: "publish IPv6 gateway proxy",
                    source,
                });
            }
            let entry = match gateway_proxy_entries(handle, &BTreeSet::from([address])).await {
                Ok(entries) => entries
                    .into_iter()
                    .find(|entry| entry.header.ifindex == uplink.interface_index),
                Err(error) => {
                    let _ =
                        remove_gateway_proxies(handle, &BTreeSet::from([address]), Some(uplink))
                            .await;
                    rollback_gateway_proxies(handle, &added).await;
                    return Err(error);
                }
            };
            let Some(entry) = entry else {
                let _ =
                    remove_gateway_proxies(handle, &BTreeSet::from([address]), Some(uplink)).await;
                rollback_gateway_proxies(handle, &added).await;
                return Err(LinkError::Readback(format!(
                    "IPv6 gateway proxy {address} was not readable after publication"
                )));
            };
            added.push(entry);
        }
        Ok(added)
    }

    fn ipv6_proxy_addresses(&self) -> BTreeSet<IpAddr> {
        self.addresses
            .iter()
            .filter_map(|assigned| assigned.address.is_ipv6().then_some(assigned.address))
            .collect()
    }

    async fn configure_gateway_link(
        &self,
        handle: &Handle,
        link: &LinkMessage,
        created: bool,
    ) -> Result<LinkMessage, LinkError> {
        if let Err(source) = handle
            .link()
            .set(
                LinkUnspec::new_with_index(link.header.index)
                    .mtu(self.mtu)
                    .alias(&self.owner_alias)
                    .up()
                    .build(),
            )
            .execute()
            .await
        {
            if created {
                let _ = handle.link().del(link.header.index).execute().await;
            }
            return Err(LinkError::Netlink {
                operation: "configure gateway-address interface",
                source,
            });
        }
        let link = require_link(handle, &self.interface_name).await?;
        if let Err(error) = validate_gateway_link(&link, self) {
            if created {
                let _ = handle.link().del(link.header.index).execute().await;
            }
            return Err(error);
        }
        Ok(link)
    }

    /// Independently verifies exact ownership and that every planned address
    /// remains present. Extra host-prefix addresses are rejected because they
    /// cannot be attributed to this transaction.
    ///
    /// # Errors
    ///
    /// Rejects missing, foreign, down, or otherwise mismatched kernel state.
    pub async fn readback(&self) -> Result<GatewayAddressReadback, LinkError> {
        let (connection, handle, _) =
            new_connection().map_err(|source| LinkError::OpenNetlink {
                operation: "open gateway-address readback connection",
                source,
            })?;
        tokio::spawn(connection);
        self.readback_with_handle(&handle).await
    }

    /// Applies an explicitly authorized monotonic subset transition.
    ///
    /// The previous plan is independently read back before any removal. The
    /// desired plan must retain the same Node ownership and may only remove
    /// addresses. Exact replay is idempotent; a partial failure restores every
    /// address already removed.
    ///
    /// # Errors
    ///
    /// Rejects ownership changes, additions, ambiguous current state, netlink
    /// failures, or an inexact final readback.
    pub async fn transition_from(
        &self,
        previous: &Self,
    ) -> Result<GatewayAddressReadback, LinkError> {
        if self.node_uid != previous.node_uid
            || self.interface_name != previous.interface_name
            || self.owner_alias != previous.owner_alias
            || self.mtu != previous.mtu
            || self.ipv6_proxy_uplink != previous.ipv6_proxy_uplink
            || !self.addresses.is_subset(&previous.addresses)
        {
            return Err(LinkError::InvalidPlan(
                "gateway address transition must be a same-owner monotonic subset".to_string(),
            ));
        }
        let (connection, handle, _) =
            new_connection().map_err(|source| LinkError::OpenNetlink {
                operation: "open gateway-address transition connection",
                source,
            })?;
        tokio::spawn(connection);
        if let Ok(readback) = self.readback_with_handle(&handle).await {
            return Ok(readback);
        }
        let prior = previous.readback_with_handle(&handle).await?;
        let removing = previous
            .addresses
            .difference(&self.addresses)
            .copied()
            .collect::<BTreeSet<_>>();
        let removed_proxies = remove_gateway_proxies(
            &handle,
            &removing
                .iter()
                .filter_map(|assigned| assigned.address.is_ipv6().then_some(assigned.address))
                .collect(),
            previous.ipv6_proxy_uplink.as_ref(),
        )
        .await?;
        let mut removed = Vec::new();
        let mut stream = handle
            .address()
            .get()
            .set_link_index_filter(prior.interface_index)
            .execute();
        while let Some(message) = stream
            .try_next()
            .await
            .map_err(|source| LinkError::Netlink {
                operation: "read gateway addresses for authorized transition",
                source,
            })?
        {
            let Some(address) = address_from_message(&message) else {
                continue;
            };
            let assigned = AssignedAddress {
                address,
                prefix_len: message.header.prefix_len,
            };
            if !removing.contains(&assigned) {
                continue;
            }
            if let Err(source) = handle.address().del(message).execute().await {
                restore_gateway_addresses(&handle, prior.interface_index, &removed).await;
                restore_gateway_proxies(&handle, &removed_proxies).await;
                return Err(LinkError::Netlink {
                    operation: "remove authorized gateway address",
                    source,
                });
            }
            removed.push(assigned);
        }
        match self.readback_with_handle(&handle).await {
            Ok(readback) => Ok(readback),
            Err(error) => {
                restore_gateway_addresses(&handle, prior.interface_index, &removed).await;
                restore_gateway_proxies(&handle, &removed_proxies).await;
                Err(error)
            }
        }
    }

    /// Deletes the exact owned interface only after strict readback. Callers
    /// must supply the distributed source-fence barrier; this primitive never
    /// infers release authority from elapsed time or controller leadership.
    ///
    /// # Errors
    ///
    /// Refuses deletion when ownership or the complete address set differs.
    pub async fn release(&self) -> Result<DeleteOutcome, LinkError> {
        let (connection, handle, _) =
            new_connection().map_err(|source| LinkError::OpenNetlink {
                operation: "open gateway-address release connection",
                source,
            })?;
        tokio::spawn(connection);
        let Some(link) = find_link(&handle, &self.interface_name).await? else {
            return Ok(DeleteOutcome::AlreadyAbsent);
        };
        self.readback_with_handle(&handle).await?;
        let removed_proxies = remove_gateway_proxies(
            &handle,
            &self.ipv6_proxy_addresses(),
            self.ipv6_proxy_uplink.as_ref(),
        )
        .await?;
        if let Err(source) = handle.link().del(link.header.index).execute().await {
            restore_gateway_proxies(&handle, &removed_proxies).await;
            return Err(LinkError::Netlink {
                operation: "release gateway-address interface",
                source,
            });
        }
        Ok(DeleteOutcome::Deleted)
    }

    async fn readback_with_handle(
        &self,
        handle: &Handle,
    ) -> Result<GatewayAddressReadback, LinkError> {
        let link = require_link(handle, &self.interface_name).await?;
        validate_gateway_link(&link, self)?;
        if !link.header.flags.contains(LinkFlags::Up) {
            return Err(conflict(
                &self.interface_name,
                "gateway-address interface is not administratively up",
            ));
        }
        let observed = addresses_on_link(handle, link.header.index).await?;
        let managed = observed
            .into_iter()
            .filter(|assigned| valid_gateway_address(assigned.address))
            .collect::<BTreeSet<_>>();
        if managed != self.addresses {
            return Err(LinkError::Readback(format!(
                "gateway interface {:?} address mismatch; expected {:?}, observed {:?}",
                self.interface_name, self.addresses, managed
            )));
        }
        self.readback_ipv6_proxy_ownership(handle).await?;
        Ok(GatewayAddressReadback {
            node_uid: self.node_uid.clone(),
            interface_name: self.interface_name.clone(),
            interface_index: link.header.index,
            mtu: self.mtu,
            addresses: managed,
        })
    }

    async fn readback_ipv6_proxy_ownership(&self, handle: &Handle) -> Result<(), LinkError> {
        let desired = self.ipv6_proxy_addresses();
        if desired.is_empty() {
            return Ok(());
        }
        let uplink = self.ipv6_proxy_uplink.as_ref().ok_or_else(|| {
            LinkError::Readback(
                "IPv6 gateway addresses have no proxy-NDP uplink ownership".to_string(),
            )
        })?;
        validate_gateway_proxy_uplink(handle, uplink).await?;
        let proxy_ndp = ipv6_proxy_ndp_enabled(&uplink.interface_name)?;
        if !proxy_ndp {
            return Err(LinkError::Readback(format!(
                "IPv6 proxy NDP is disabled on {:?}",
                uplink.interface_name
            )));
        }
        let observed = gateway_proxy_entries(handle, &desired)
            .await?
            .into_iter()
            .filter(|entry| entry.header.ifindex == uplink.interface_index)
            .filter_map(|entry| neighbour_address(&entry))
            .collect::<BTreeSet<_>>();
        if observed != desired {
            return Err(LinkError::Readback(format!(
                "IPv6 gateway proxy mismatch on {:?}; expected {desired:?}, observed {observed:?}",
                uplink.interface_name
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PeerReadback {
    index: u32,
    addresses: BTreeSet<AssignedAddress>,
}

async fn read_peer(handle: &Handle, plan: &VethPlan) -> Result<PeerReadback, LinkError> {
    let peer = require_link(handle, &plan.container_name).await?;
    validate_ready_link(
        &peer,
        &plan.container_name,
        &plan.peer_alias,
        plan.mtu,
        plan.peer_address,
    )?;
    let mut stream = handle
        .address()
        .get()
        .set_link_index_filter(peer.header.index)
        .execute();
    let mut addresses = BTreeSet::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|source| LinkError::Netlink {
            operation: "read container addresses",
            source,
        })?
    {
        if let Some(address) = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(address) | AddressAttribute::Address(address) => {
                    Some(*address)
                }
                _ => None,
            })
        {
            addresses.insert(AssignedAddress {
                address,
                prefix_len: message.header.prefix_len,
            });
        }
    }
    let expected = BTreeSet::from(plan.addresses);
    if !expected.is_subset(&addresses) {
        return Err(LinkError::Readback(format!(
            "container endpoint {:?} is missing managed addresses; expected {expected:?}, observed {addresses:?}",
            plan.container_name
        )));
    }
    Ok(PeerReadback {
        index: peer.header.index,
        addresses: expected,
    })
}

async fn addresses_on_link(
    handle: &Handle,
    interface_index: u32,
) -> Result<BTreeSet<AssignedAddress>, LinkError> {
    let mut stream = handle
        .address()
        .get()
        .set_link_index_filter(interface_index)
        .execute();
    let mut addresses = BTreeSet::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|source| LinkError::Netlink {
            operation: "read gateway addresses",
            source,
        })?
    {
        if let Some(address) = address_from_message(&message) {
            addresses.insert(AssignedAddress {
                address,
                prefix_len: message.header.prefix_len,
            });
        }
    }
    Ok(addresses)
}

async fn preflight_gateway_address_collisions(
    handle: &Handle,
    owned_interface_index: Option<u32>,
    desired: &BTreeSet<AssignedAddress>,
) -> Result<(), LinkError> {
    let mut stream = handle.address().get().execute();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|source| LinkError::Netlink {
            operation: "preflight gateway address ownership",
            source,
        })?
    {
        let Some(address) = address_from_message(&message) else {
            continue;
        };
        if desired.iter().any(|assigned| assigned.address == address)
            && Some(message.header.index) != owned_interface_index
        {
            return Err(LinkError::LinkConflict {
                name: EGRESS_GATEWAY_INTERFACE.to_string(),
                reason: format!(
                    "address {address} is already owned by foreign interface index {}",
                    message.header.index
                ),
            });
        }
    }
    Ok(())
}

async fn rollback_gateway_addresses(
    handle: &Handle,
    interface_index: u32,
    added: &[AssignedAddress],
) {
    if added.is_empty() {
        return;
    }
    let mut stream = handle
        .address()
        .get()
        .set_link_index_filter(interface_index)
        .execute();
    while let Ok(Some(message)) = stream.try_next().await {
        let Some(address) = address_from_message(&message) else {
            continue;
        };
        if added.iter().any(|assigned| {
            assigned.address == address && assigned.prefix_len == message.header.prefix_len
        }) {
            let _ = handle.address().del(message).execute().await;
        }
    }
}

async fn restore_gateway_addresses(
    handle: &Handle,
    interface_index: u32,
    removed: &[AssignedAddress],
) {
    for assigned in removed {
        let _ = handle
            .address()
            .add(interface_index, assigned.address, assigned.prefix_len)
            .execute()
            .await;
    }
}

fn ipv6_proxy_ndp_path(interface_name: &str) -> PathBuf {
    Path::new("/proc/sys/net/ipv6/conf")
        .join(interface_name)
        .join("proxy_ndp")
}

fn enable_ipv6_proxy_ndp(interface_name: &str) -> Result<(), LinkError> {
    let path = ipv6_proxy_ndp_path(interface_name);
    if ipv6_proxy_ndp_enabled(interface_name)? {
        return Ok(());
    }
    std::fs::write(&path, b"1\n").map_err(|source| LinkError::ConfigureIpv6Proxy {
        path: path.clone(),
        source,
    })?;
    if !ipv6_proxy_ndp_enabled(interface_name)? {
        return Err(LinkError::Readback(format!(
            "IPv6 proxy NDP remained disabled after writing {}",
            path.display()
        )));
    }
    Ok(())
}

fn ipv6_proxy_ndp_enabled(interface_name: &str) -> Result<bool, LinkError> {
    let path = ipv6_proxy_ndp_path(interface_name);
    let value = std::fs::read_to_string(&path).map_err(|source| LinkError::ConfigureIpv6Proxy {
        path: path.clone(),
        source,
    })?;
    Ok(value.trim() == "1")
}

async fn validate_gateway_proxy_uplink(
    handle: &Handle,
    uplink: &GatewayProxyUplink,
) -> Result<(), LinkError> {
    let link = require_link(handle, &uplink.interface_name).await?;
    if link.header.index != uplink.interface_index {
        return Err(LinkError::LinkConflict {
            name: uplink.interface_name.clone(),
            reason: format!(
                "IPv6 proxy uplink index changed from {} to {}",
                uplink.interface_index, link.header.index
            ),
        });
    }
    if !link.header.flags.contains(LinkFlags::Up) {
        return Err(conflict(
            &uplink.interface_name,
            "IPv6 proxy uplink is not administratively up",
        ));
    }
    Ok(())
}

async fn gateway_proxy_entries(
    handle: &Handle,
    addresses: &BTreeSet<IpAddr>,
) -> Result<Vec<NeighbourMessage>, LinkError> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    let mut stream = handle.neighbours().get().proxies().execute();
    let mut entries = Vec::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|source| LinkError::Netlink {
            operation: "read IPv6 gateway proxies",
            source,
        })?
    {
        if message.header.flags.contains(NeighbourFlags::Proxy)
            && neighbour_address(&message).is_some_and(|address| addresses.contains(&address))
        {
            entries.push(message);
        }
    }
    Ok(entries)
}

fn neighbour_address(message: &NeighbourMessage) -> Option<IpAddr> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(address)) => {
                Some(IpAddr::V4(*address))
            }
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(address)) => {
                Some(IpAddr::V6(*address))
            }
            _ => None,
        })
}

async fn remove_gateway_proxies(
    handle: &Handle,
    addresses: &BTreeSet<IpAddr>,
    uplink: Option<&GatewayProxyUplink>,
) -> Result<Vec<NeighbourMessage>, LinkError> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }
    let uplink = uplink.ok_or_else(|| {
        LinkError::InvalidPlan(
            "cannot remove IPv6 gateway ownership without a proxy-NDP uplink".to_string(),
        )
    })?;
    validate_gateway_proxy_uplink(handle, uplink).await?;
    let entries = gateway_proxy_entries(handle, addresses)
        .await?
        .into_iter()
        .filter(|entry| entry.header.ifindex == uplink.interface_index)
        .collect::<Vec<_>>();
    let mut removed = Vec::new();
    for entry in entries {
        if let Err(source) = handle.neighbours().del(entry.clone()).execute().await {
            restore_gateway_proxies(handle, &removed).await;
            return Err(LinkError::Netlink {
                operation: "withdraw IPv6 gateway proxy",
                source,
            });
        }
        removed.push(entry);
    }
    Ok(removed)
}

async fn rollback_gateway_proxies(handle: &Handle, entries: &[NeighbourMessage]) {
    for entry in entries.iter().rev() {
        let _ = handle.neighbours().del(entry.clone()).execute().await;
    }
}

async fn restore_gateway_proxies(handle: &Handle, entries: &[NeighbourMessage]) {
    for entry in entries {
        if let Some(address) = neighbour_address(entry) {
            let _ = handle
                .neighbours()
                .add(entry.header.ifindex, address)
                .flags(NeighbourFlags::Proxy)
                .execute()
                .await;
        }
    }
}

fn address_from_message(
    message: &rtnetlink::packet_route::address::AddressMessage,
) -> Option<IpAddr> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            AddressAttribute::Local(address) | AddressAttribute::Address(address) => Some(*address),
            _ => None,
        })
}

fn validate_gateway_link(link: &LinkMessage, plan: &GatewayAddressPlan) -> Result<(), LinkError> {
    if link_name(link) != Some(plan.interface_name.as_str())
        || link_alias(link) != Some(plan.owner_alias.as_str())
        || link_mtu(link) != Some(plan.mtu)
    {
        return Err(conflict(
            &plan.interface_name,
            &format!(
                "expected name {:?}, alias {:?}, MTU {}; observed name {:?}, alias {:?}, MTU {:?}",
                plan.interface_name,
                plan.owner_alias,
                plan.mtu,
                link_name(link),
                link_alias(link),
                link_mtu(link)
            ),
        ));
    }
    validate_gateway_link_kind(link, &plan.interface_name)
}

fn validate_gateway_link_kind(link: &LinkMessage, name: &str) -> Result<(), LinkError> {
    let dummy = link.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            LinkAttribute::LinkInfo(infos)
                if infos.iter().any(|info| matches!(info, LinkInfo::Kind(InfoKind::Dummy)))
        )
    });
    if !dummy {
        return Err(conflict(name, "interface is not a dummy link"));
    }
    Ok(())
}

fn valid_gateway_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_link_local()
                && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
    }
}

async fn run_in_namespace<F, Fut, T>(namespace: File, operation: F) -> Result<T, LinkError>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, LinkError>> + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        std::thread::spawn(move || {
            move_into_link_name_space(namespace.as_fd(), Some(LinkNameSpaceType::Network))
                .map_err(LinkError::EnterNamespace)?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(LinkError::NamespaceRuntime)?
                .block_on(operation())
        })
        .join()
        .map_err(|_| LinkError::NamespaceWorkerPanicked)?
    })
    .await
    .map_err(|error| LinkError::NamespaceJoin(error.to_string()))?
}

fn open_namespace(path: &Path) -> Result<File, LinkError> {
    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|source| {
        if source == rustix::io::Errno::LOOP {
            LinkError::SymbolicLinkNamespace(path.to_path_buf())
        } else {
            LinkError::OpenNamespace {
                path: path.to_path_buf(),
                source: source.into(),
            }
        }
    })
}

async fn find_link(handle: &Handle, name: &str) -> Result<Option<LinkMessage>, LinkError> {
    let mut links = handle.link().get().execute();
    while let Some(link) = links
        .try_next()
        .await
        .map_err(|source| LinkError::Netlink {
            operation: "list links",
            source,
        })?
    {
        if link_name(&link) == Some(name) {
            return Ok(Some(link));
        }
    }
    Ok(None)
}

async fn require_link(handle: &Handle, name: &str) -> Result<LinkMessage, LinkError> {
    find_link(handle, name)
        .await?
        .ok_or_else(|| LinkError::Readback(format!("required interface {name:?} is absent")))
}

fn validate_owned_link(
    link: &LinkMessage,
    expected_name: &str,
    expected_alias: &str,
    expected_mtu: u32,
    expected_address: [u8; 6],
) -> Result<(), LinkError> {
    validate_veth_kind(link, expected_name)?;
    if link_name(link) != Some(expected_name) {
        return Err(conflict(
            expected_name,
            "kernel returned a different interface name",
        ));
    }
    if link_alias(link) != Some(expected_alias) {
        return Err(conflict(
            expected_name,
            &format!(
                "expected alias {expected_alias:?}, observed {:?}",
                link_alias(link)
            ),
        ));
    }
    if link_mtu(link) != Some(expected_mtu) {
        return Err(conflict(
            expected_name,
            &format!("expected MTU {expected_mtu}, observed {:?}", link_mtu(link)),
        ));
    }
    if link_address(link) != Some(expected_address.as_slice()) {
        return Err(conflict(
            expected_name,
            &format!(
                "expected hardware address {expected_address:02x?}, observed {:?}",
                link_address(link)
            ),
        ));
    }
    Ok(())
}

fn validate_recoverable_link(
    link: &LinkMessage,
    expected_name: &str,
    expected_alias: &str,
    expected_mtu: u32,
    expected_address: [u8; 6],
) -> Result<(), LinkError> {
    validate_veth_kind(link, expected_name)?;
    if link_name(link) != Some(expected_name)
        || link_mtu(link) != Some(expected_mtu)
        || link_address(link) != Some(expected_address.as_slice())
    {
        return Err(conflict(
            expected_name,
            "interface does not carry the deterministic UNF creation identity",
        ));
    }
    if link_alias(link).is_some_and(|alias| alias != expected_alias) {
        return Err(conflict(
            expected_name,
            &format!("unexpected ownership alias {:?}", link_alias(link)),
        ));
    }
    Ok(())
}

fn validate_ready_link(
    link: &LinkMessage,
    expected_name: &str,
    expected_alias: &str,
    expected_mtu: u32,
    expected_address: [u8; 6],
) -> Result<(), LinkError> {
    validate_owned_link(
        link,
        expected_name,
        expected_alias,
        expected_mtu,
        expected_address,
    )?;
    if !link.header.flags.contains(LinkFlags::Up) {
        return Err(conflict(
            expected_name,
            "interface is not administratively up",
        ));
    }
    Ok(())
}

fn validate_veth_kind(link: &LinkMessage, name: &str) -> Result<(), LinkError> {
    let is_veth = link.attributes.iter().any(|attribute| {
        matches!(
            attribute,
            LinkAttribute::LinkInfo(infos)
                if infos.iter().any(|info| matches!(info, LinkInfo::Kind(InfoKind::Veth)))
        )
    });
    if !is_veth {
        return Err(conflict(name, "interface is not a veth"));
    }
    Ok(())
}

fn link_name(link: &LinkMessage) -> Option<&str> {
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfName(value) => Some(value.as_str()),
            _ => None,
        })
}

fn link_alias(link: &LinkMessage) -> Option<&str> {
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::IfAlias(value) => Some(value.as_str()),
            _ => None,
        })
}

fn link_mtu(link: &LinkMessage) -> Option<u32> {
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::Mtu(value) => Some(*value),
            _ => None,
        })
}

fn link_address(link: &LinkMessage) -> Option<&[u8]> {
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::Address(value) => Some(value.as_slice()),
            _ => None,
        })
}

fn ownership_addresses(host_name: &str) -> ([u8; 6], [u8; 6]) {
    let hash = host_name
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    let bytes = hash.to_be_bytes();
    (
        [0x02, bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]],
        [0x06, bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]],
    )
}

fn conflict(name: &str, reason: &str) -> LinkError {
    LinkError::LinkConflict {
        name: name.to_string(),
        reason: reason.to_string(),
    }
}

fn validate_interface_name(name: &str, role: &str) -> Result<(), LinkError> {
    if name.is_empty() || name.len() > LINUX_INTERFACE_NAME_MAX {
        return Err(LinkError::InvalidPlan(format!(
            "{role} interface name must contain 1..={LINUX_INTERFACE_NAME_MAX} bytes"
        )));
    }
    if !name.is_ascii()
        || name == "."
        || name == ".."
        || name
            .bytes()
            .any(|byte| matches!(byte, 0 | b'/' | b':') || byte.is_ascii_whitespace())
    {
        return Err(LinkError::InvalidPlan(format!(
            "{role} interface name contains a forbidden byte"
        )));
    }
    Ok(())
}

fn validate_addresses(addresses: [AssignedAddress; 2]) -> Result<(), LinkError> {
    let mut ipv4 = 0;
    let mut ipv6 = 0;
    for assigned in addresses {
        match assigned.address {
            IpAddr::V4(_) if assigned.prefix_len <= 32 => ipv4 += 1,
            IpAddr::V6(_) if assigned.prefix_len <= 128 => ipv6 += 1,
            IpAddr::V4(_) => {
                return Err(LinkError::InvalidPlan(
                    "IPv4 prefix exceeds /32".to_string(),
                ));
            }
            IpAddr::V6(_) => {
                return Err(LinkError::InvalidPlan(
                    "IPv6 prefix exceeds /128".to_string(),
                ));
            }
        }
    }
    if ipv4 != 1 || ipv6 != 1 {
        return Err(LinkError::InvalidPlan(
            "exactly one IPv4 and one IPv6 address are required".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use unf_cni_state::{AttachmentKey, AttachmentPhase, AttachmentSpec};
    use unf_ipam::{DualStackLease, Ipv4Lease, Ipv6Lease};

    use super::*;

    fn plan() -> VethPlan {
        VethPlan::new(
            "unf01234567890".to_string(),
            "eth0".to_string(),
            PathBuf::from("/run/netns/unf-test"),
            1_400,
            [
                AssignedAddress {
                    address: IpAddr::V4(Ipv4Addr::new(10, 44, 0, 2)),
                    prefix_len: 24,
                },
                AssignedAddress {
                    address: IpAddr::V6(Ipv6Addr::new(0xfd44, 0, 0, 1, 0, 0, 0, 2)),
                    prefix_len: 64,
                },
            ],
        )
        .expect("valid plan")
    }

    #[test]
    fn plan_derives_bounded_stable_ownership() {
        let first = plan();
        let second = plan();
        assert_eq!(first, second);
        assert_eq!(first.temporary_peer_name(), "unfp01234567890");
        assert!(first.temporary_peer_name().len() <= LINUX_INTERFACE_NAME_MAX);
        assert_eq!(first.host_alias, "unf:cni:v1:unf01234567890:host");
        assert_eq!(first.peer_alias, "unf:cni:v1:unf01234567890:peer");
        assert_ne!(first.host_address, first.peer_address);
        assert_eq!(first.host_address[0] & 0x03, 0x02);
        assert_eq!(first.peer_address[0] & 0x03, 0x02);
    }

    #[test]
    fn plan_requires_absolute_namespace_and_dual_stack() {
        let mut addresses = plan().addresses;
        addresses[1] = addresses[0];
        assert!(matches!(
            VethPlan::new(
                "unf01234567890".to_string(),
                "eth0".to_string(),
                PathBuf::from("relative"),
                1_400,
                addresses,
            ),
            Err(LinkError::InvalidPlan(_))
        ));
        assert!(matches!(
            VethPlan::new(
                "unf01234567890".to_string(),
                "eth0".to_string(),
                PathBuf::from("/run/netns/test"),
                1_400,
                addresses,
            ),
            Err(LinkError::InvalidPlan(_))
        ));
    }

    #[test]
    fn plan_rejects_kernel_invalid_names_and_mtu() {
        for name in [
            "",
            "this-name-is-too-long",
            "bad/name",
            "bad:name",
            "bad name",
            "bad\tname",
            "éth0",
        ] {
            assert!(matches!(
                VethPlan::new(
                    "unf01234567890".to_string(),
                    name.to_string(),
                    PathBuf::from("/run/netns/test"),
                    1_400,
                    plan().addresses,
                ),
                Err(LinkError::InvalidPlan(_))
            ));
        }
        assert!(matches!(
            VethPlan::new(
                "unf01234567890".to_string(),
                "eth0".to_string(),
                PathBuf::from("/run/netns/test"),
                1_200,
                plan().addresses,
            ),
            Err(LinkError::InvalidPlan(_))
        ));
    }

    #[test]
    fn durable_node_block_lease_becomes_routed_host_prefixes() {
        let record = AttachmentRecord {
            spec: AttachmentSpec {
                key: AttachmentKey {
                    network: "unf-test".to_string(),
                    container_id: "container-1".to_string(),
                    ifname: "eth0".to_string(),
                },
                netns: "/run/netns/pod-1".to_string(),
                mtu: 1_400,
            },
            host_interface: "unf01234567890".to_string(),
            lease: DualStackLease {
                ipv4: Ipv4Lease {
                    address: Ipv4Addr::new(10, 44, 0, 2),
                    gateway: Ipv4Addr::new(10, 44, 0, 1),
                    prefix_len: 24,
                },
                ipv6: Ipv6Lease {
                    address: Ipv6Addr::new(0xfd44, 0, 0, 1, 0, 0, 0, 2),
                    gateway: Ipv6Addr::new(0xfd44, 0, 0, 1, 0, 0, 0, 1),
                    prefix_len: 64,
                },
            },
            phase: AttachmentPhase::Preparing,
        };
        let plan = VethPlan::from_attachment(&record).expect("durable record is valid");
        assert_eq!(plan.addresses[0].prefix_len, 32);
        assert_eq!(plan.addresses[1].prefix_len, 128);
    }

    #[test]
    fn gateway_address_plan_is_canonical_dual_stack_and_node_bound() {
        let plan = GatewayAddressPlan::new(
            "node-uid-a".to_string(),
            1_500,
            vec![
                IpAddr::V6("2001:db8:100::20".parse().unwrap()),
                IpAddr::V4("192.0.2.20".parse().unwrap()),
            ],
        )
        .expect("valid gateway address plan")
        .with_ipv6_proxy_uplink("eth0".to_string(), 2)
        .expect("valid IPv6 proxy uplink");
        assert_eq!(plan.interface_name, EGRESS_GATEWAY_INTERFACE);
        assert_eq!(plan.owner_alias, "unf:egress-address:v1:node-uid-a");
        assert_eq!(
            plan.ipv6_proxy_uplink,
            Some(GatewayProxyUplink {
                interface_name: "eth0".to_string(),
                interface_index: 2,
            })
        );
        assert_eq!(
            plan.addresses,
            BTreeSet::from([
                AssignedAddress {
                    address: IpAddr::V4("192.0.2.20".parse().unwrap()),
                    prefix_len: 32,
                },
                AssignedAddress {
                    address: IpAddr::V6("2001:db8:100::20".parse().unwrap()),
                    prefix_len: 128,
                },
            ])
        );
    }

    #[test]
    fn gateway_address_plan_rejects_ambiguous_or_unsafe_ownership() {
        for addresses in [
            vec!["192.0.2.20".parse().unwrap(), "192.0.2.20".parse().unwrap()],
            vec!["127.0.0.2".parse().unwrap()],
            vec!["fe80::20".parse().unwrap()],
            vec!["ff02::1".parse().unwrap()],
        ] {
            assert!(GatewayAddressPlan::new("node-uid-a".to_string(), 1_500, addresses).is_err());
        }
        assert!(GatewayAddressPlan::new("node-uid-a".to_string(), 1_500, Vec::new()).is_ok());
        assert!(
            GatewayAddressPlan::new(String::new(), 1_500, vec!["192.0.2.20".parse().unwrap()])
                .is_err()
        );
        assert!(
            GatewayAddressPlan::new(
                "node-uid-a".to_string(),
                1_200,
                vec!["192.0.2.20".parse().unwrap()]
            )
            .is_err()
        );
        assert!(
            GatewayAddressPlan::new(
                "node-uid-a".to_string(),
                1_500,
                vec!["2001:db8:100::20".parse().unwrap()]
            )
            .unwrap()
            .with_ipv6_proxy_uplink("../eth0".to_string(), 2)
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated network namespace with CAP_NET_ADMIN"]
    async fn privileged_gateway_address_transaction_is_exact_and_collision_safe() {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        handle
            .link()
            .add(LinkDummy::new("uplink0").up().build())
            .execute()
            .await
            .unwrap();
        let uplink = require_link(&handle, "uplink0").await.unwrap();
        let addresses = vec![
            "192.0.2.20".parse().unwrap(),
            "2001:db8:100::20".parse().unwrap(),
        ];
        let plan = GatewayAddressPlan::new("node-uid-a".to_string(), 1_500, addresses)
            .unwrap()
            .with_ipv6_proxy_uplink("uplink0".to_string(), uplink.header.index)
            .unwrap();
        let applied = plan.apply().await.expect("apply gateway addresses");
        assert_eq!(
            applied,
            plan.readback().await.expect("independent readback")
        );
        assert_eq!(
            plan.apply().await.expect("idempotent apply"),
            applied,
            "restart must reproduce exact ownership"
        );
        let retained = GatewayAddressPlan::new(
            "node-uid-a".to_string(),
            1_500,
            vec!["192.0.2.20".parse().unwrap()],
        )
        .unwrap()
        .with_ipv6_proxy_uplink("uplink0".to_string(), uplink.header.index)
        .unwrap();
        assert_eq!(
            retained
                .transition_from(&plan)
                .await
                .expect("authorized subset transition")
                .addresses,
            retained.addresses
        );
        plan.apply().await.expect("restore full desired ownership");

        handle
            .link()
            .add(LinkDummy::new("foreign0").up().build())
            .execute()
            .await
            .unwrap();
        let foreign = require_link(&handle, "foreign0").await.unwrap();
        handle
            .address()
            .add(foreign.header.index, "192.0.2.30".parse().unwrap(), 32)
            .execute()
            .await
            .unwrap();
        let conflict = GatewayAddressPlan::new(
            "node-uid-a".to_string(),
            1_500,
            vec!["192.0.2.30".parse().unwrap()],
        )
        .unwrap()
        .apply()
        .await
        .expect_err("foreign address collision must fail before mutation");
        assert!(matches!(conflict, LinkError::LinkConflict { .. }));
        let empty = GatewayAddressPlan::new("node-uid-a".to_string(), 1_500, Vec::new())
            .unwrap()
            .with_ipv6_proxy_uplink("uplink0".to_string(), uplink.header.index)
            .unwrap();
        assert!(
            empty
                .transition_from(&plan)
                .await
                .expect("release every authorized address")
                .addresses
                .is_empty()
        );
        assert_eq!(
            empty.release().await.expect("release exact empty plan"),
            DeleteOutcome::Deleted
        );
        assert_eq!(
            empty.release().await.expect("idempotent release"),
            DeleteOutcome::AlreadyAbsent
        );
    }
}
