//! Exercise the actual DSR continuation with sockets and reversible reply state.
use super::*;

#[allow(clippy::too_many_arguments)] // One existing fixture, no second runtime or authority.
pub(super) async fn exercise(
    services: &mut ServiceSynchronizer,
    encryption: &mut encryption_maps::EncryptionMaps,
    state: &AgentState,
    publisher: &mut crate::locality_publisher::BankPublisher,
    plan: &AdmittedNodeLocalPlan,
    evidence: &VerifiedEncryptionLocality,
    object: &Ebpf,
    records: &[AttachmentRecord],
    sockets: &mut sockets::Sockets,
) {
    let mut snapshot = dual_stack_dsr_load_balancer_snapshot(
        2,
        records[1].lease.ipv4.address,
        records[1].lease.ipv6.address,
    );
    snapshot.services[0]
        .load_balancer
        .as_mut()
        .unwrap()
        .source_ranges = vec![
        "10.244.46.0/24".parse().unwrap(),
        "fd46::/120".parse().unwrap(),
    ];
    let snapshot = snapshot.validate_and_normalize().unwrap();
    let node = node_port_node_snapshot(1);
    let contract = NetworkBehaviorContract::compile(
        &snapshot,
        Revision::new(1),
        Revision::new(1),
        local_selection_node(&node, Some("zone-a".into())),
    )
    .unwrap();
    activate_service_snapshot_with_contract(
        services,
        &snapshot,
        Some(&node),
        Some(&contract),
        true,
        state,
    )
    .unwrap();
    let reachability = dual_stack_load_balancer_node_snapshot(
        &snapshot,
        1,
        "192.0.2.60".parse().unwrap(),
        "2001:db8:ffff::60".parse().unwrap(),
    );
    activate_load_balancer_snapshot(services, &reachability, state).unwrap();
    transport(encryption, 3, 2);
    sockets.dsr_frontends();
    // The application binds only its PodIP, never the VIP. A successful exchange
    // requires the actual continuation's reversible NAT and reply translation.
    let first_ports = sockets.matrix("dsr-local-reversible", true, true);
    let guard = crate::locality_runtime::begin(state, LocalityApplyComponent::Identity).unwrap();
    sockets.matrix("dsr-withdrawn", true, false);
    crate::locality_runtime::complete(guard, 7, 3).unwrap();
    let mut plan = plan.clone();
    plan.snapshot.service_revision = Revision::new(2);
    plan.admitted_digest = AdmittedNodeLocalPlanDigest([3; 32]);
    publish(publisher, state, &plan, evidence, object).await;
    let second_ports = sockets.matrix("dsr-republished", true, true);
    let positive_ports = first_ports.chain(second_ports).collect::<Vec<_>>();
    let connections = services
        .connections
        .iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut reversible = 0;
    for (key, value) in connections {
        let source_port = u16::from_be_bytes(key[32..34].try_into().unwrap());
        let target_port = u16::from_be_bytes(key[34..36].try_into().unwrap());
        if !positive_ports.contains(&source_port) && !positive_ports.contains(&target_port) {
            continue;
        }
        let flags = u16::from_ne_bytes(value[98..100].try_into().unwrap());
        assert_eq!(
            flags & unf_ebpf_common::SERVICE_CONNECTION_FLAG_DSR,
            0,
            "local DSR retained VIP-only state"
        );
        if flags & unf_ebpf_common::SERVICE_CONNECTION_FLAG_ENCRYPTED_NAT != 0 {
            reversible += 1;
        }
    }
    assert_eq!(
        reversible, 16,
        "missing eight bidirectional DSR connection pairs"
    );
    println!(
        "main-locality-dsr: PASS socket-exchanges=8 withdrawn-denials=4 reversible-pairs=true backend-vip-bound=false"
    );
}
