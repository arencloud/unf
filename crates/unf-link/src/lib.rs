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
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec, LinkVeth, new_connection};
use rustix::fs::{Mode, OFlags, open};
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};
use thiserror::Error;
use unf_cni_state::AttachmentRecord;

const LINUX_INTERFACE_NAME_MAX: usize = 15;
const MIN_DUAL_STACK_MTU: u32 = 1_280;
const MAX_MTU: u32 = 65_535;
const OWNER_PREFIX: &str = "unf:cni:v1:";

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
}
