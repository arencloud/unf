use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsFd;
use std::path::Path;

use futures::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState,
};
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteProtocol,
    RouteScope as KernelRouteScope, RouteType,
};
use rtnetlink::{Handle, RouteMessageBuilder, new_connection};
use rustix::fs::{Mode, OFlags, open};
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};

use super::{
    NativeRoutePlan, NeighborSpec, NetworkNamespace, RouteDeleteOutcome, RouteError, RouteReadback,
    RouteScope, RouteSpec,
};

#[derive(Debug)]
struct ObservedState {
    routes: Vec<Option<RouteMessage>>,
    neighbors: Vec<Option<NeighbourMessage>>,
}

impl ObservedState {
    fn is_absent(&self) -> bool {
        self.routes.iter().all(Option::is_none) && self.neighbors.iter().all(Option::is_none)
    }

    fn is_complete(&self) -> bool {
        self.routes.iter().all(Option::is_some) && self.neighbors.iter().all(Option::is_some)
    }
}

impl NativeRoutePlan {
    /// Applies or replays all exact host and container routing state.
    ///
    /// # Errors
    ///
    /// Fails before mutation on a foreign key conflict. A partial netlink
    /// failure triggers exact scoped rollback; rollback failure is reported
    /// alongside the original cause.
    pub async fn apply(&self) -> Result<RouteReadback, RouteError> {
        self.apply_with_checkpoint(|| Ok(())).await
    }

    async fn apply_with_checkpoint<F>(
        &self,
        after_container: F,
    ) -> Result<RouteReadback, RouteError>
    where
        F: FnOnce() -> Result<(), RouteError>,
    {
        let namespace = open_namespace(&self.netns)?;
        let host = connect("open host route connection")?;
        inspect_local(&host, &self.host_routes, &self.host_neighbors).await?;
        let plan = self.clone();
        run_in_namespace(
            clone_namespace(&namespace, &self.netns)?,
            move || async move {
                let handle = connect("open container route connection")?;
                inspect_local(&handle, &plan.container_routes, &plan.container_neighbors).await?;
                Ok(())
            },
        )
        .await?;

        let plan = self.clone();
        let container_apply = run_in_namespace(
            clone_namespace(&namespace, &self.netns)?,
            move || async move {
                let handle = connect("open container route connection")?;
                apply_local(&handle, &plan.container_routes, &plan.container_neighbors).await
            },
        )
        .await;
        if let Err(cause) = container_apply {
            let rollback = self.rollback_container(&namespace).await;
            return Err(with_rollback(cause, [rollback]));
        }

        if let Err(cause) = after_container() {
            let rollback = self.rollback_container(&namespace).await;
            return Err(with_rollback(cause, [rollback]));
        }

        if let Err(cause) = apply_local(&host, &self.host_routes, &self.host_neighbors).await {
            let host_rollback = delete_local(&host, &self.host_routes, &self.host_neighbors).await;
            let container_rollback = self.rollback_container(&namespace).await;
            return Err(with_rollback(cause, [host_rollback, container_rollback]));
        }

        self.readback().await
    }

    /// Strictly reads both namespace roles and returns the planned state.
    ///
    /// # Errors
    ///
    /// Returns an error for missing or conflicting state.
    pub async fn readback(&self) -> Result<RouteReadback, RouteError> {
        let namespace = open_namespace(&self.netns)?;
        let host = connect("open host route connection")?;
        let host_state = inspect_local(&host, &self.host_routes, &self.host_neighbors).await?;
        require_complete(&host_state, NetworkNamespace::Host)?;

        let plan = self.clone();
        let container_state = run_in_namespace(namespace, move || async move {
            let handle = connect("open container route connection")?;
            inspect_local(&handle, &plan.container_routes, &plan.container_neighbors).await
        })
        .await?;
        require_complete(&container_state, NetworkNamespace::Container)?;

        Ok(RouteReadback {
            routes: self
                .host_routes
                .iter()
                .chain(self.container_routes.iter())
                .copied()
                .collect(),
            neighbors: self
                .host_neighbors
                .iter()
                .chain(self.container_neighbors.iter())
                .copied()
                .collect(),
        })
    }

    /// Removes only exact route and neighbor entries from both namespace roles.
    ///
    /// # Errors
    ///
    /// Refuses foreign state sharing an owned key. A missing namespace is
    /// treated as absent because its namespace-local routing state no longer
    /// exists.
    pub async fn delete(&self) -> Result<RouteDeleteOutcome, RouteError> {
        let host = connect("open host route connection")?;
        let host_state = inspect_local(&host, &self.host_routes, &self.host_neighbors).await?;
        let namespace = match open_namespace(&self.netns) {
            Ok(namespace) => Some(namespace),
            Err(RouteError::OpenNamespace {
                kind: std::io::ErrorKind::NotFound,
                ..
            }) => None,
            Err(error) => return Err(error),
        };

        let container_state = if let Some(namespace) = namespace.as_ref() {
            let plan = self.clone();
            Some(
                run_in_namespace(
                    clone_namespace(namespace, &self.netns)?,
                    move || async move {
                        let handle = connect("open container route connection")?;
                        inspect_local(&handle, &plan.container_routes, &plan.container_neighbors)
                            .await
                    },
                )
                .await?,
            )
        } else {
            None
        };
        let any_present = !host_state.is_absent()
            || container_state
                .as_ref()
                .is_some_and(|state| !state.is_absent());

        if let Some(namespace) = namespace {
            let plan = self.clone();
            run_in_namespace(namespace, move || async move {
                let handle = connect("open container route connection")?;
                delete_local(&handle, &plan.container_routes, &plan.container_neighbors).await
            })
            .await?;
        }
        delete_local(&host, &self.host_routes, &self.host_neighbors).await?;

        Ok(if any_present {
            RouteDeleteOutcome::Deleted
        } else {
            RouteDeleteOutcome::AlreadyAbsent
        })
    }

    async fn rollback_container(&self, namespace: &File) -> Result<bool, RouteError> {
        let plan = self.clone();
        run_in_namespace(
            clone_namespace(namespace, &self.netns)?,
            move || async move {
                let handle = connect("open container rollback connection")?;
                delete_local(&handle, &plan.container_routes, &plan.container_neighbors).await
            },
        )
        .await
    }
}

fn require_complete(state: &ObservedState, namespace: NetworkNamespace) -> Result<(), RouteError> {
    if state.is_complete() {
        Ok(())
    } else {
        Err(RouteError::Readback(format!(
            "{namespace:?} state is incomplete: {} of {} routes and {} of {} neighbors exist",
            state.routes.iter().filter(|entry| entry.is_some()).count(),
            state.routes.len(),
            state
                .neighbors
                .iter()
                .filter(|entry| entry.is_some())
                .count(),
            state.neighbors.len()
        )))
    }
}

fn with_rollback<const N: usize>(
    cause: RouteError,
    rollbacks: [Result<bool, RouteError>; N],
) -> RouteError {
    let failures: Vec<String> = rollbacks
        .into_iter()
        .filter_map(Result::err)
        .map(|error| error.to_string())
        .collect();
    if failures.is_empty() {
        cause
    } else {
        RouteError::Rollback {
            cause: cause.to_string(),
            rollback: failures.join("; "),
        }
    }
}

async fn apply_local(
    handle: &Handle,
    routes: &[RouteSpec],
    neighbors: &[NeighborSpec],
) -> Result<(), RouteError> {
    let observed = inspect_local(handle, routes, neighbors).await?;
    for (spec, message) in neighbors.iter().zip(observed.neighbors) {
        if message.is_none() {
            handle
                .neighbours()
                .add(spec.output_interface, spec.destination)
                .link_layer_address(&spec.link_address)
                .execute()
                .await
                .map_err(|error| netlink("add permanent neighbor", &error))?;
        }
    }
    for (spec, message) in routes.iter().zip(observed.routes) {
        if message.is_none() {
            handle
                .route()
                .add(build_route(*spec))
                .execute()
                .await
                .map_err(|error| netlink("add route", &error))?;
        }
    }
    Ok(())
}

async fn delete_local(
    handle: &Handle,
    routes: &[RouteSpec],
    neighbors: &[NeighborSpec],
) -> Result<bool, RouteError> {
    let observed = inspect_local(handle, routes, neighbors).await?;
    let existed = !observed.is_absent();
    for message in observed.routes.into_iter().rev().flatten() {
        handle
            .route()
            .del(message)
            .execute()
            .await
            .map_err(|error| netlink("delete route", &error))?;
    }
    for message in observed.neighbors.into_iter().rev().flatten() {
        handle
            .neighbours()
            .del(message)
            .execute()
            .await
            .map_err(|error| netlink("delete permanent neighbor", &error))?;
    }
    Ok(existed)
}

async fn inspect_local(
    handle: &Handle,
    routes: &[RouteSpec],
    neighbors: &[NeighborSpec],
) -> Result<ObservedState, RouteError> {
    let route_messages = list_routes(handle).await?;
    let neighbor_messages = list_neighbors(handle).await?;
    let mut observed_routes = Vec::with_capacity(routes.len());
    for spec in routes {
        let matching: Vec<&RouteMessage> = route_messages
            .iter()
            .filter(|message| route_key_matches(message, spec))
            .collect();
        match matching.as_slice() {
            [] => observed_routes.push(None),
            [message] if route_exact(message, spec) => {
                observed_routes.push(Some((*message).clone()));
            }
            _ => {
                return Err(RouteError::Conflict {
                    namespace: spec.namespace,
                    resource: "route",
                    message: format!(
                        "key {}/{} in table {} has non-UNF state",
                        spec.destination, spec.prefix_len, spec.table
                    ),
                });
            }
        }
    }

    let mut observed_neighbors = Vec::with_capacity(neighbors.len());
    for spec in neighbors {
        let matching: Vec<&NeighbourMessage> = neighbor_messages
            .iter()
            .filter(|message| neighbor_key_matches(message, spec))
            .collect();
        match matching.as_slice() {
            [] => observed_neighbors.push(None),
            [message] if neighbor_exact(message, spec) => {
                observed_neighbors.push(Some((*message).clone()));
            }
            _ => {
                return Err(RouteError::Conflict {
                    namespace: spec.namespace,
                    resource: "neighbor",
                    message: format!(
                        "destination {} on interface {} has non-UNF state",
                        spec.destination, spec.output_interface
                    ),
                });
            }
        }
    }
    Ok(ObservedState {
        routes: observed_routes,
        neighbors: observed_neighbors,
    })
}

async fn list_routes(handle: &Handle) -> Result<Vec<RouteMessage>, RouteError> {
    let mut messages = Vec::new();
    let requests = [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ];
    for request in requests {
        let mut stream = handle.route().get(request).execute();
        while let Some(message) = stream
            .try_next()
            .await
            .map_err(|error| netlink("list routes", &error))?
        {
            messages.push(message);
        }
    }
    Ok(messages)
}

async fn list_neighbors(handle: &Handle) -> Result<Vec<NeighbourMessage>, RouteError> {
    let mut stream = handle.neighbours().get().execute();
    let mut messages = Vec::new();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|error| netlink("list neighbors", &error))?
    {
        messages.push(message);
    }
    Ok(messages)
}

fn build_route(spec: RouteSpec) -> RouteMessage {
    match spec.destination {
        IpAddr::V4(destination) => {
            let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
                .output_interface(spec.output_interface)
                .table_id(spec.table)
                .protocol(RouteProtocol::from(spec.protocol))
                .scope(kernel_scope(spec.scope));
            if spec.prefix_len != 0 {
                builder = builder.destination_prefix(destination, spec.prefix_len);
            }
            if let Some(IpAddr::V4(gateway)) = spec.gateway {
                builder = builder.gateway(gateway);
            }
            if spec.onlink {
                builder = builder.onlink();
            }
            builder.build()
        }
        IpAddr::V6(destination) => {
            let mut builder = RouteMessageBuilder::<Ipv6Addr>::new()
                .output_interface(spec.output_interface)
                .table_id(spec.table)
                .protocol(RouteProtocol::from(spec.protocol))
                .scope(kernel_scope(spec.scope));
            if spec.prefix_len != 0 {
                builder = builder.destination_prefix(destination, spec.prefix_len);
            }
            if let Some(IpAddr::V6(gateway)) = spec.gateway {
                builder = builder.gateway(gateway);
            }
            if spec.onlink {
                builder = builder.onlink();
            }
            builder.build()
        }
    }
}

const fn kernel_scope(scope: RouteScope) -> KernelRouteScope {
    match scope {
        RouteScope::Universe => KernelRouteScope::Universe,
        RouteScope::Link => KernelRouteScope::Link,
    }
}

fn route_key_matches(message: &RouteMessage, spec: &RouteSpec) -> bool {
    route_destination(message) == spec.destination
        && message.header.destination_prefix_length == spec.prefix_len
        && route_table(message) == spec.table
}

fn route_exact(message: &RouteMessage, spec: &RouteSpec) -> bool {
    route_key_matches(message, spec)
        && route_output_interface(message) == Some(spec.output_interface)
        && route_gateway(message) == spec.gateway
        && u8::from(message.header.protocol) == spec.protocol
        && message.header.scope == kernel_scope(spec.scope)
        && message.header.kind == RouteType::Unicast
        && message.header.flags.contains(RouteFlags::Onlink) == spec.onlink
}

fn route_destination(message: &RouteMessage) -> IpAddr {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(address) => route_address(address),
            _ => None,
        })
        .unwrap_or(match message.header.address_family {
            AddressFamily::Inet6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        })
}

fn route_gateway(message: &RouteMessage) -> Option<IpAddr> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Gateway(address) => route_address(address),
            _ => None,
        })
}

const fn route_address(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(address) => Some(IpAddr::V4(*address)),
        RouteAddress::Inet6(address) => Some(IpAddr::V6(*address)),
        _ => None,
    }
}

fn route_output_interface(message: &RouteMessage) -> Option<u32> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
}

fn route_table(message: &RouteMessage) -> u32 {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(message.header.table))
}

fn neighbor_key_matches(message: &NeighbourMessage, spec: &NeighborSpec) -> bool {
    message.header.ifindex == spec.output_interface
        && neighbor_destination(message) == Some(spec.destination)
}

fn neighbor_exact(message: &NeighbourMessage, spec: &NeighborSpec) -> bool {
    neighbor_key_matches(message, spec)
        && message.header.state == NeighbourState::Permanent
        && neighbor_link_address(message) == Some(spec.link_address.as_slice())
}

fn neighbor_destination(message: &NeighbourMessage) -> Option<IpAddr> {
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

fn neighbor_link_address(message: &NeighbourMessage) -> Option<&[u8]> {
    message
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            NeighbourAttribute::LinkLayerAddress(address) => Some(address.as_slice()),
            _ => None,
        })
}

fn connect(operation: &'static str) -> Result<Handle, RouteError> {
    let (connection, handle, _) = new_connection().map_err(|error| RouteError::Netlink {
        operation,
        message: error.to_string(),
    })?;
    tokio::spawn(connection);
    Ok(handle)
}

fn netlink(operation: &'static str, error: &rtnetlink::Error) -> RouteError {
    RouteError::Netlink {
        operation,
        message: error.to_string(),
    }
}

fn open_namespace(path: &Path) -> Result<File, RouteError> {
    open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            RouteError::SymbolicLinkNamespace(path.to_path_buf())
        } else {
            let source = std::io::Error::from(error);
            RouteError::OpenNamespace {
                path: path.to_path_buf(),
                kind: source.kind(),
                message: source.to_string(),
            }
        }
    })
}

fn clone_namespace(namespace: &File, path: &Path) -> Result<File, RouteError> {
    namespace
        .try_clone()
        .map_err(|error| RouteError::OpenNamespace {
            path: path.to_path_buf(),
            kind: error.kind(),
            message: format!("could not duplicate namespace descriptor: {error}"),
        })
}

async fn run_in_namespace<F, Fut, T>(namespace: File, operation: F) -> Result<T, RouteError>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, RouteError>> + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        std::thread::spawn(move || {
            move_into_link_name_space(namespace.as_fd(), Some(LinkNameSpaceType::Network))
                .map_err(|error| RouteError::EnterNamespace(error.to_string()))?;
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| RouteError::NamespaceRuntime(error.to_string()))?
                .block_on(operation())
        })
        .join()
        .map_err(|_| RouteError::NamespaceWorkerPanicked)?
    })
    .await
    .map_err(|error| RouteError::NamespaceJoin(error.to_string()))?
}

#[cfg(test)]
mod tests {
    use std::env;

    use unf_cni_state::{AttachmentKey, AttachmentPhase, AttachmentRecord, AttachmentSpec};
    use unf_ipam::{DualStackLease, Ipv4Lease, Ipv6Lease};
    use unf_link::{DeleteOutcome, VethPlan};

    use super::*;
    use crate::{NativeRoutingProvider, RouteDeleteOutcome, RoutingProvider};

    #[test]
    fn route_lowering_preserves_ownership_fields() {
        let spec = RouteSpec {
            namespace: NetworkNamespace::Container,
            destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix_len: 0,
            gateway: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            output_interface: 7,
            onlink: true,
            protocol: super::super::UNF_ROUTE_PROTOCOL,
            table: 254,
            scope: RouteScope::Universe,
        };
        let message = build_route(spec);
        assert!(route_exact(&message, &spec));
    }

    #[test]
    fn rollback_reports_only_cleanup_failure() {
        let cause = RouteError::Readback("cause".to_string());
        assert_eq!(with_rollback(cause.clone(), [Ok(false)]), cause);
        assert!(matches!(
            with_rollback(cause, [Err(RouteError::Readback("cleanup".to_string()))]),
            RouteError::Rollback { .. }
        ));
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN and UNF_ROUTE_TEST_NETNS"]
    async fn privileged_failure_after_container_rolls_back_exact_state() {
        let netns = env::var("UNF_ROUTE_TEST_NETNS").expect("test namespace path");
        let host_name = env::var("UNF_ROUTE_TEST_HOST_IF").expect("test host interface");
        let attachment = AttachmentRecord {
            spec: AttachmentSpec {
                key: AttachmentKey {
                    network: "unf-route-rollback".to_string(),
                    container_id: "rollback-container".to_string(),
                    ifname: "eth0".to_string(),
                },
                netns,
                mtu: 1_400,
            },
            host_interface: host_name,
            lease: DualStackLease {
                ipv4: Ipv4Lease {
                    address: Ipv4Addr::new(10, 244, 44, 2),
                    gateway: Ipv4Addr::new(10, 244, 44, 1),
                    prefix_len: 24,
                },
                ipv6: Ipv6Lease {
                    address: Ipv6Addr::new(0xfd44, 0, 0, 0x44, 0, 0, 0, 2),
                    gateway: Ipv6Addr::new(0xfd44, 0, 0, 0x44, 0, 0, 0, 1),
                    prefix_len: 64,
                },
            },
            phase: AttachmentPhase::Preparing,
        };
        let links = VethPlan::from_attachment(&attachment).expect("valid link plan");
        let link_state = links.apply().await.expect("link apply");
        let routes = NativeRoutingProvider::new(1_400)
            .plan(&attachment, &link_state)
            .expect("route plan");

        let error = routes
            .apply_with_checkpoint(|| {
                Err(RouteError::Readback(
                    "injected failure after container apply".to_string(),
                ))
            })
            .await
            .expect_err("injected failure must escape");
        assert!(matches!(error, RouteError::Readback(_)));
        assert_eq!(
            routes.delete().await.expect("rollback readback"),
            RouteDeleteOutcome::AlreadyAbsent
        );
        links.readback().await.expect("rollback preserves links");
        assert_eq!(
            links.delete().await.expect("link cleanup"),
            DeleteOutcome::Deleted
        );
    }
}
