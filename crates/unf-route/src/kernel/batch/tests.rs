use super::*;
use crate::kernel::{
    AddressFamily, NeighbourAddress, NeighbourAttribute, NeighbourState, build_route,
};
use crate::{NetworkNamespace, RouteScope};

fn plan() -> NativeRoutePlan {
    let v4: IpAddr = "192.0.2.2".parse().unwrap();
    let v6: IpAddr = "2001:db8::2".parse().unwrap();
    let g4: IpAddr = "192.0.2.1".parse().unwrap();
    let g6: IpAddr = "2001:db8::1".parse().unwrap();
    NativeRoutePlan {
        host_name: "unf-test".into(),
        container_name: "eth0".into(),
        netns: "/not-opened-by-model-test".into(),
        mtu: 1400,
        host_routes: [crate::host_route(v4, 7), crate::host_route(v6, 7)],
        host_neighbors: [
            crate::neighbor(NetworkNamespace::Host, v4, 7, [2; 6]),
            crate::neighbor(NetworkNamespace::Host, v6, 7, [2; 6]),
        ],
        container_routes: [
            crate::gateway_route(g4, 8),
            crate::default_route(g4, 8),
            crate::gateway_route(g6, 8),
            crate::default_route(g6, 8),
        ],
        container_neighbors: [
            crate::neighbor(NetworkNamespace::Container, g4, 8, [3; 6]),
            crate::neighbor(NetworkNamespace::Container, g6, 8, [3; 6]),
        ],
    }
}

fn message(spec: NeighborSpec) -> NeighbourMessage {
    let mut message = NeighbourMessage::default();
    message.header.ifindex = spec.output_interface;
    message.header.state = NeighbourState::Permanent;
    message.header.family = match spec.destination {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    message.attributes = vec![
        NeighbourAttribute::Destination(match spec.destination {
            IpAddr::V4(address) => NeighbourAddress::Inet(address),
            IpAddr::V6(address) => NeighbourAddress::Inet6(address),
        }),
        NeighbourAttribute::LinkLayerAddress(spec.link_address.to_vec()),
    ];
    message
}

#[test]
fn dual_stack_complete_snapshot_and_missing_entry_detection() {
    let plan = plan();
    let mut selected = SelectedState::new(std::iter::once(&plan)).unwrap();
    assert!(selected.complete().is_err());
    for route in plan.host_routes {
        selected.route(&build_route(route)).unwrap();
    }
    assert!(selected.complete().is_err());
    selected.neighbor(&message(plan.host_neighbors[0])).unwrap();
    assert!(selected.complete().is_err());
    selected.neighbor(&message(plan.host_neighbors[1])).unwrap();
    assert!(selected.complete().is_ok());
    assert_eq!(selected.messages, 4);
    let mut peer = SelectedState::new(std::iter::empty()).unwrap();
    peer.add(plan.container_routes, plan.container_neighbors)
        .unwrap();
    for route in plan.container_routes {
        peer.route(&build_route(route)).unwrap();
    }
    for neighbor in plan.container_neighbors {
        peer.neighbor(&message(neighbor)).unwrap();
    }
    assert!(peer.complete().is_ok());
}

#[test]
fn duplicate_expected_or_observed_keys_fail_even_if_bytes_match() {
    let plan = plan();
    assert!(SelectedState::new([&plan, &plan].into_iter()).is_err());
    let mut selected = SelectedState::new(std::iter::once(&plan)).unwrap();
    let route = build_route(plan.host_routes[0]);
    selected.route(&route).unwrap();
    assert!(selected.route(&route).is_err());
    let mut selected = SelectedState::new(std::iter::once(&plan)).unwrap();
    let neighbor = message(plan.host_neighbors[0]);
    selected.neighbor(&neighbor).unwrap();
    assert!(selected.neighbor(&neighbor).is_err());
}

#[test]
fn wrong_owner_and_interface_cannot_satisfy_selected_route_or_neighbor() {
    let plan = plan();
    for mutation in 0..4 {
        let mut selected = SelectedState::new(std::iter::once(&plan)).unwrap();
        let mut route = plan.host_routes[0];
        match mutation {
            0 => route.output_interface += 1,
            1 => route.protocol += 1,
            2 => route.gateway = Some("192.0.2.9".parse().unwrap()),
            3 => route.scope = RouteScope::Universe,
            _ => unreachable!(),
        }
        assert!(selected.route(&build_route(route)).is_err());
    }
    let mut selected = SelectedState::new(std::iter::once(&plan)).unwrap();
    let mut wrong = message(plan.host_neighbors[0]);
    wrong.header.state = NeighbourState::Reachable;
    assert!(selected.neighbor(&wrong).is_err());
    let mut selected = SelectedState::new(std::iter::once(&plan)).unwrap();
    let mut wrong = plan.host_neighbors[0];
    wrong.link_address[5] ^= 1;
    assert!(selected.neighbor(&message(wrong)).is_err());
}

#[test]
fn unrelated_host_tables_are_streamed_without_retaining_their_messages() {
    let plan = plan();
    let mut selected = SelectedState::new(std::iter::once(&plan)).unwrap();
    let mut route = plan.host_routes[0];
    let mut neighbor = plan.host_neighbors[0];
    for index in 0..20_000 {
        let address = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + index));
        route.destination = address;
        neighbor.destination = address;
        selected.route(&build_route(route)).unwrap();
        selected.neighbor(&message(neighbor)).unwrap();
        assert_eq!(selected.routes.len(), 2);
        assert_eq!(selected.neighbors.len(), 2);
    }
    assert!(selected.complete().is_err());
    assert_eq!(selected.messages, 40_000);
    selected.messages = MAX_MESSAGES;
    assert!(selected.route(&build_route(plan.host_routes[0])).is_err());
    assert!(selected.neighbor(&message(plan.host_neighbors[0])).is_err());
    assert!(selected.routes.values().all(|(_, seen)| !seen));
}
