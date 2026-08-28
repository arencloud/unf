//! Routing-provider plans kept separate from IP allocation and link mutation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use thiserror::Error;
use unf_cni_state::AttachmentRecord;
use unf_link::{AssignedAddress, LinkReadback};

pub const MIN_DUAL_STACK_MTU: u32 = 1_280;
pub const MAX_WORKLOAD_MTU: u32 = 65_535;
pub const MAIN_ROUTE_TABLE: u32 = 254;
/// Private route-protocol marker used to distinguish UNF-owned native routes.
/// Standard Linux protocol assignments, including BGP at 186, are not reused.
pub const UNF_ROUTE_PROTOCOL: u8 = 99;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkNamespace {
    Host,
    Container,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RouteScope {
    Universe,
    Link,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteSpec {
    pub namespace: NetworkNamespace,
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub gateway: Option<IpAddr>,
    pub output_interface: u32,
    pub onlink: bool,
    pub protocol: u8,
    pub table: u32,
    pub scope: RouteScope,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NeighborSpec {
    pub namespace: NetworkNamespace,
    pub destination: IpAddr,
    pub output_interface: u32,
    pub link_address: [u8; 6],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtuProfile {
    pub underlay_mtu: u32,
    pub encapsulation_overhead: u32,
}

impl MtuProfile {
    /// Derives the workload MTU after a routing provider's declared overhead.
    ///
    /// # Errors
    ///
    /// Rejects arithmetic underflow and values outside Linux's dual-stack
    /// workload boundary.
    pub fn workload_mtu(self) -> Result<u32, RouteError> {
        let mtu = self
            .underlay_mtu
            .checked_sub(self.encapsulation_overhead)
            .ok_or(RouteError::InvalidMtu {
                underlay: self.underlay_mtu,
                overhead: self.encapsulation_overhead,
            })?;
        if !(MIN_DUAL_STACK_MTU..=MAX_WORKLOAD_MTU).contains(&mtu) {
            return Err(RouteError::InvalidMtu {
                underlay: self.underlay_mtu,
                overhead: self.encapsulation_overhead,
            });
        }
        Ok(mtu)
    }
}

pub trait RoutingProvider {
    type Plan;

    /// Returns this provider's derived workload MTU.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider input cannot support dual stack.
    fn workload_mtu(&self) -> Result<u32, RouteError>;

    /// Builds an exact routing plan from durable and kernel-read-back state.
    ///
    /// # Errors
    ///
    /// Rejects mismatched attachment/link state or invalid provider inputs.
    fn plan(
        &self,
        attachment: &AttachmentRecord,
        links: &LinkReadback,
    ) -> Result<Self::Plan, RouteError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRoutingProvider {
    profile: MtuProfile,
}

impl NativeRoutingProvider {
    #[must_use]
    pub const fn new(underlay_mtu: u32) -> Self {
        Self {
            profile: MtuProfile {
                underlay_mtu,
                encapsulation_overhead: 0,
            },
        }
    }

    #[must_use]
    pub const fn profile(self) -> MtuProfile {
        self.profile
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRoutePlan {
    host_name: String,
    container_name: String,
    netns: PathBuf,
    mtu: u32,
    host_routes: [RouteSpec; 2],
    container_routes: [RouteSpec; 4],
    host_neighbors: [NeighborSpec; 2],
    container_neighbors: [NeighborSpec; 2],
}

impl NativeRoutePlan {
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    #[must_use]
    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    #[must_use]
    pub fn netns(&self) -> &Path {
        &self.netns
    }

    #[must_use]
    pub const fn mtu(&self) -> u32 {
        self.mtu
    }

    #[must_use]
    pub const fn host_routes(&self) -> &[RouteSpec; 2] {
        &self.host_routes
    }

    #[must_use]
    pub const fn container_routes(&self) -> &[RouteSpec; 4] {
        &self.container_routes
    }

    #[must_use]
    pub const fn host_neighbors(&self) -> &[NeighborSpec; 2] {
        &self.host_neighbors
    }

    #[must_use]
    pub const fn container_neighbors(&self) -> &[NeighborSpec; 2] {
        &self.container_neighbors
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RouteError {
    #[error(
        "underlay MTU {underlay} minus routing overhead {overhead} is outside the dual-stack workload boundary"
    )]
    InvalidMtu { underlay: u32, overhead: u32 },
    #[error("durable attachment MTU {attachment} differs from provider MTU {provider}")]
    AttachmentMtuMismatch { attachment: u32, provider: u32 },
    #[error("link readback does not match the durable attachment: {0}")]
    LinkMismatch(String),
    #[error("invalid {family} lease route inputs: workload {workload}, gateway {gateway}")]
    InvalidLease {
        family: &'static str,
        workload: IpAddr,
        gateway: IpAddr,
    },
}

impl RoutingProvider for NativeRoutingProvider {
    type Plan = NativeRoutePlan;

    fn workload_mtu(&self) -> Result<u32, RouteError> {
        self.profile.workload_mtu()
    }

    fn plan(
        &self,
        attachment: &AttachmentRecord,
        links: &LinkReadback,
    ) -> Result<Self::Plan, RouteError> {
        let mtu = self.workload_mtu()?;
        if attachment.spec.mtu != mtu {
            return Err(RouteError::AttachmentMtuMismatch {
                attachment: attachment.spec.mtu,
                provider: mtu,
            });
        }
        validate_links(attachment, links, mtu)?;

        let workload_v4 = attachment.lease.ipv4.address;
        let gateway_v4 = attachment.lease.ipv4.gateway;
        let workload_v6 = attachment.lease.ipv6.address;
        let gateway_v6 = attachment.lease.ipv6.gateway;
        validate_family(workload_v4, gateway_v4, "IPv4")?;
        validate_family(workload_v6, gateway_v6, "IPv6")?;

        Ok(NativeRoutePlan {
            host_name: attachment.host_interface.clone(),
            container_name: attachment.spec.key.ifname.clone(),
            netns: PathBuf::from(&attachment.spec.netns),
            mtu,
            host_routes: [
                host_route(workload_v4, links.host_index),
                host_route(workload_v6, links.host_index),
            ],
            container_routes: [
                gateway_route(gateway_v4, links.peer_index),
                default_route(gateway_v4, links.peer_index),
                gateway_route(gateway_v6, links.peer_index),
                default_route(gateway_v6, links.peer_index),
            ],
            host_neighbors: [
                neighbor(
                    NetworkNamespace::Host,
                    workload_v4,
                    links.host_index,
                    links.peer_address,
                ),
                neighbor(
                    NetworkNamespace::Host,
                    workload_v6,
                    links.host_index,
                    links.peer_address,
                ),
            ],
            container_neighbors: [
                neighbor(
                    NetworkNamespace::Container,
                    gateway_v4,
                    links.peer_index,
                    links.host_address,
                ),
                neighbor(
                    NetworkNamespace::Container,
                    gateway_v6,
                    links.peer_index,
                    links.host_address,
                ),
            ],
        })
    }
}

fn validate_links(
    attachment: &AttachmentRecord,
    links: &LinkReadback,
    mtu: u32,
) -> Result<(), RouteError> {
    if links.host_name != attachment.host_interface {
        return Err(RouteError::LinkMismatch(
            "host interface name differs".to_string(),
        ));
    }
    if links.peer_name != attachment.spec.key.ifname {
        return Err(RouteError::LinkMismatch(
            "container interface name differs".to_string(),
        ));
    }
    if links.mtu != mtu {
        return Err(RouteError::LinkMismatch(format!(
            "link MTU {} differs from planned MTU {mtu}",
            links.mtu
        )));
    }
    if links.host_index == 0 || links.peer_index == 0 {
        return Err(RouteError::LinkMismatch(
            "kernel interface indexes must be nonzero".to_string(),
        ));
    }
    let expected = [
        AssignedAddress {
            address: IpAddr::V4(attachment.lease.ipv4.address),
            prefix_len: 32,
        },
        AssignedAddress {
            address: IpAddr::V6(attachment.lease.ipv6.address),
            prefix_len: 128,
        },
    ];
    if expected
        .iter()
        .any(|address| !links.addresses.contains(address))
    {
        return Err(RouteError::LinkMismatch(
            "container endpoint lacks its routed /32 or /128 address".to_string(),
        ));
    }
    Ok(())
}

fn validate_family<T>(workload: T, gateway: T, family: &'static str) -> Result<(), RouteError>
where
    T: Copy + Eq + Into<IpAddr>,
{
    if workload == gateway || workload.into().is_unspecified() || gateway.into().is_unspecified() {
        return Err(RouteError::InvalidLease {
            family,
            workload: workload.into(),
            gateway: gateway.into(),
        });
    }
    Ok(())
}

fn host_route<T>(workload: T, output_interface: u32) -> RouteSpec
where
    T: Into<IpAddr>,
{
    let destination = workload.into();
    RouteSpec {
        namespace: NetworkNamespace::Host,
        destination,
        prefix_len: full_prefix(destination),
        gateway: None,
        output_interface,
        onlink: false,
        protocol: UNF_ROUTE_PROTOCOL,
        table: MAIN_ROUTE_TABLE,
        scope: RouteScope::Link,
    }
}

fn gateway_route<T>(gateway: T, output_interface: u32) -> RouteSpec
where
    T: Into<IpAddr>,
{
    let destination = gateway.into();
    RouteSpec {
        namespace: NetworkNamespace::Container,
        destination,
        prefix_len: full_prefix(destination),
        gateway: None,
        output_interface,
        onlink: false,
        protocol: UNF_ROUTE_PROTOCOL,
        table: MAIN_ROUTE_TABLE,
        scope: RouteScope::Link,
    }
}

fn default_route<T>(gateway: T, output_interface: u32) -> RouteSpec
where
    T: Into<IpAddr>,
{
    let gateway = gateway.into();
    RouteSpec {
        namespace: NetworkNamespace::Container,
        destination: match gateway {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        },
        prefix_len: 0,
        gateway: Some(gateway),
        output_interface,
        onlink: true,
        protocol: UNF_ROUTE_PROTOCOL,
        table: MAIN_ROUTE_TABLE,
        scope: RouteScope::Universe,
    }
}

fn neighbor<T>(
    namespace: NetworkNamespace,
    destination: T,
    output_interface: u32,
    link_address: [u8; 6],
) -> NeighborSpec
where
    T: Into<IpAddr>,
{
    NeighborSpec {
        namespace,
        destination: destination.into(),
        output_interface,
        link_address,
    }
}

const fn full_prefix(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use unf_cni_state::{AttachmentKey, AttachmentPhase, AttachmentSpec};
    use unf_ipam::{DualStackLease, Ipv4Lease, Ipv6Lease};

    use super::*;

    fn attachment() -> AttachmentRecord {
        AttachmentRecord {
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
        }
    }

    fn links() -> LinkReadback {
        let attachment = attachment();
        LinkReadback {
            host_index: 41,
            peer_index: 7,
            host_name: attachment.host_interface,
            peer_name: attachment.spec.key.ifname,
            host_address: [0x02, 1, 2, 3, 4, 5],
            peer_address: [0x06, 1, 2, 3, 4, 5],
            mtu: 1_400,
            addresses: BTreeSet::from([
                AssignedAddress {
                    address: IpAddr::V4(attachment.lease.ipv4.address),
                    prefix_len: 32,
                },
                AssignedAddress {
                    address: IpAddr::V6(attachment.lease.ipv6.address),
                    prefix_len: 128,
                },
            ]),
        }
    }

    #[test]
    fn native_plan_is_directional_dual_stack_and_exact() {
        let plan = NativeRoutingProvider::new(1_400)
            .plan(&attachment(), &links())
            .expect("valid native plan");
        assert_eq!(plan.mtu(), 1_400);
        assert_eq!(plan.host_routes().len(), 2);
        assert_eq!(plan.container_routes().len(), 4);
        assert_eq!(plan.host_neighbors().len(), 2);
        assert_eq!(plan.container_neighbors().len(), 2);
        assert!(plan.host_routes().iter().all(|route| {
            route.namespace == NetworkNamespace::Host
                && route.gateway.is_none()
                && matches!(route.prefix_len, 32 | 128)
                && route.protocol == UNF_ROUTE_PROTOCOL
                && route.table == MAIN_ROUTE_TABLE
                && route.scope == RouteScope::Link
        }));
        assert!(
            plan.container_routes()
                .iter()
                .filter(|route| route.onlink)
                .all(|route| route.prefix_len == 0
                    && route.gateway.is_some()
                    && route.namespace == NetworkNamespace::Container
                    && route.scope == RouteScope::Universe)
        );
        assert!(
            plan.host_neighbors()
                .iter()
                .all(|neighbor| neighbor.link_address == links().peer_address)
        );
        assert!(
            plan.container_neighbors()
                .iter()
                .all(|neighbor| neighbor.link_address == links().host_address)
        );
    }

    #[test]
    fn native_mtu_has_zero_overhead_and_dual_stack_bounds() {
        let provider = NativeRoutingProvider::new(1_500);
        assert_eq!(provider.profile().encapsulation_overhead, 0);
        assert_eq!(provider.workload_mtu(), Ok(1_500));
        assert!(matches!(
            NativeRoutingProvider::new(1_279).workload_mtu(),
            Err(RouteError::InvalidMtu { .. })
        ));
        assert!(matches!(
            MtuProfile {
                underlay_mtu: 1_500,
                encapsulation_overhead: 221,
            }
            .workload_mtu(),
            Err(RouteError::InvalidMtu { .. })
        ));
    }

    #[test]
    fn plan_rejects_mtu_and_link_readback_drift() {
        let mut drifted_links = links();
        drifted_links.mtu = 1_300;
        assert!(matches!(
            NativeRoutingProvider::new(1_400).plan(&attachment(), &drifted_links),
            Err(RouteError::LinkMismatch(_))
        ));

        let mut attachment = attachment();
        attachment.spec.mtu = 1_300;
        assert!(matches!(
            NativeRoutingProvider::new(1_400).plan(&attachment, &links()),
            Err(RouteError::AttachmentMtuMismatch { .. })
        ));
    }
}
