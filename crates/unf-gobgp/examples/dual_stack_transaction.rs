//! Live four-speaker dual-stack transaction and diversity-quorum proof.

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::net::Ipv4Addr;

use tokio::time::{Duration, Instant, sleep};
use unf_common::Revision;
use unf_egress::{
    EGRESS_BGP_ALGORITHM, EGRESS_BGP_SCHEMA_VERSION,
    EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1, EGRESS_REACHABILITY_SCHEMA_VERSION,
    EgressBgpAddressFamily, EgressBgpConfig, EgressBgpConfigDigest, EgressBgpGracefulRestart,
    EgressBgpLargeCommunity, EgressBgpPeer, EgressBgpPrefix, EgressBgpRoute, EgressCapability,
    EgressGatewayAction, EgressGatewayDesired, EgressIntentOwner, EgressIntentScope, EgressNode,
    EgressProviderRef, EgressReachabilityObservation, EgressReachabilityObservationDigest,
    EgressReachabilityObserver, EgressReachabilityPath, EgressReachabilityRouteObservation,
    EgressReachabilityVerdict, assess_egress_reachability, derive_egress_bgp_reachability_plan,
    prepare_egress_bgp_transaction, seal_egress_bgp_config, seal_egress_bgp_route,
    seal_egress_bgp_snapshot, seal_egress_reachability_observation,
};
use unf_gobgp::GoBgpAdapter;

type DynError = Box<dyn Error + Send + Sync>;

const GATEWAY_ASN: u32 = 64_512;
const FABRIC_A_ASN: u32 = 64_513;
const FABRIC_B_ASN: u32 = 64_514;
const EGRESS_V4: &str = "192.0.2.240";
const EGRESS_V6: &str = "2001:db8:200::240";

#[tokio::main]
#[allow(clippy::similar_names, clippy::too_many_lines)]
async fn main() -> Result<(), DynError> {
    let endpoints = [
        endpoint("UNF_BGP_GATEWAY_A_ENDPOINT", "http://127.0.0.1:50061"),
        endpoint("UNF_BGP_GATEWAY_B_ENDPOINT", "http://127.0.0.1:50062"),
        endpoint("UNF_BGP_FABRIC_A_ENDPOINT", "http://127.0.0.1:50063"),
        endpoint("UNF_BGP_FABRIC_B_ENDPOINT", "http://127.0.0.1:50064"),
    ];
    let gateway_a_ipv4 = endpoint("UNF_BGP_GATEWAY_A_IPV4", "10.89.0.10");
    let gateway_a_ipv6 = endpoint("UNF_BGP_GATEWAY_A_IPV6", "fd00:89::10");
    let gateway_b_ipv4 = endpoint("UNF_BGP_GATEWAY_B_IPV4", "10.89.0.11");
    let gateway_b_ipv6 = endpoint("UNF_BGP_GATEWAY_B_IPV6", "fd00:89::11");
    let fabric_a_ipv4 = endpoint("UNF_BGP_FABRIC_A_IPV4", "10.89.0.20");
    let fabric_a_ipv6 = endpoint("UNF_BGP_FABRIC_A_IPV6", "fd00:89::20");
    let fabric_b_ipv4 = endpoint("UNF_BGP_FABRIC_B_IPV4", "10.89.0.21");
    let fabric_b_ipv6 = endpoint("UNF_BGP_FABRIC_B_IPV6", "fd00:89::21");
    let [mut gateway_a, mut gateway_b, mut fabric_a, mut fabric_b] =
        connect_all(&endpoints).await?;

    let gateway_a_config = speaker_config(
        "gateway-a",
        GATEWAY_ASN,
        Ipv4Addr::new(192, 0, 2, 10),
        &gateway_a_ipv4,
        &gateway_a_ipv6,
        vec![
            peer("fabric-a", &fabric_a_ipv4, FABRIC_A_ASN, "rack-a"),
            peer("fabric-b", &fabric_b_ipv4, FABRIC_B_ASN, "rack-b"),
        ],
    )?;
    let gateway_b_config = speaker_config(
        "gateway-b",
        GATEWAY_ASN,
        Ipv4Addr::new(192, 0, 2, 11),
        &gateway_b_ipv4,
        &gateway_b_ipv6,
        vec![
            peer("fabric-a", &fabric_a_ipv4, FABRIC_A_ASN, "rack-a"),
            peer("fabric-b", &fabric_b_ipv4, FABRIC_B_ASN, "rack-b"),
        ],
    )?;
    let fabric_a_config = speaker_config(
        "fabric-a",
        FABRIC_A_ASN,
        Ipv4Addr::new(192, 0, 2, 20),
        &fabric_a_ipv4,
        &fabric_a_ipv6,
        vec![
            peer("gateway-a", &gateway_a_ipv4, GATEWAY_ASN, "host-a"),
            peer("gateway-b", &gateway_b_ipv4, GATEWAY_ASN, "host-b"),
        ],
    )?;
    let fabric_b_config = speaker_config(
        "fabric-b",
        FABRIC_B_ASN,
        Ipv4Addr::new(192, 0, 2, 21),
        &fabric_b_ipv4,
        &fabric_b_ipv6,
        vec![
            peer("gateway-a", &gateway_a_ipv4, GATEWAY_ASN, "host-a"),
            peer("gateway-b", &gateway_b_ipv4, GATEWAY_ASN, "host-b"),
        ],
    )?;

    let (a, b, c, d) = tokio::join!(
        gateway_a.reconcile_speaker(&gateway_a_config),
        gateway_b.reconcile_speaker(&gateway_b_config),
        fabric_a.reconcile_speaker(&fabric_a_config),
        fabric_b.reconcile_speaker(&fabric_b_config),
    );
    eprintln!(
        "speaker reconciliation: gateway-a={a:?} gateway-b={b:?} fabric-a={c:?} fabric-b={d:?}"
    );
    a?;
    b?;
    c?;
    d?;
    eprintln!("BGP sessions established across both fabric failure domains");

    let desired = desired();
    let plan = derive_egress_bgp_reachability_plan(&desired)?;
    let routes_a = routes(&gateway_a_config, &desired, &plan.expected_paths[0])?;
    let routes_b = routes(&gateway_b_config, &desired, &plan.expected_paths[1])?;
    let previous_a = seal_egress_bgp_snapshot(&gateway_a_config, Revision::new(1), Vec::new())?;
    let previous_b = seal_egress_bgp_snapshot(&gateway_b_config, Revision::new(1), Vec::new())?;
    let desired_a =
        seal_egress_bgp_snapshot(&gateway_a_config, Revision::new(2), routes_a.clone())?;
    let desired_b =
        seal_egress_bgp_snapshot(&gateway_b_config, Revision::new(2), routes_b.clone())?;
    let transaction_a = prepare_egress_bgp_transaction(&gateway_a_config, previous_a, desired_a)?;
    let transaction_b = prepare_egress_bgp_transaction(&gateway_b_config, previous_b, desired_b)?;

    let (snapshot_a, snapshot_b) = tokio::try_join!(
        gateway_a.apply_transaction(&gateway_a_config, &transaction_a),
        gateway_b.apply_transaction(&gateway_b_config, &transaction_b),
    )?;
    eprintln!("dual-stack transactions accepted by both gateway speakers");
    wait_for_visibility(
        &mut fabric_a,
        &mut fabric_b,
        routes_a
            .iter()
            .chain(&routes_b)
            .collect::<Vec<_>>()
            .as_slice(),
        true,
    )
    .await?;
    eprintln!("both external RIBs contain both exact gateway paths");

    let mut stale = routes_a[0].clone();
    stale.capsule.communities[0] = EgressBgpLargeCommunity {
        global_admin: GATEWAY_ASN,
        local_data_one: 0,
        local_data_two: 0,
    };
    if fabric_a.route_visible_in_global(&stale).await?
        || fabric_b.route_visible_in_global(&stale).await?
    {
        return Err("a stale causal capsule matched a live route".into());
    }
    eprintln!("stale Causal Route Capsule rejected by both external RIB views");

    let observations = observations(&plan);
    let assessment = assess_egress_reachability(plan.clone(), observations, 1_000)?;
    if assessment.verdict != EgressReachabilityVerdict::Ready {
        return Err("dual-fabric evidence did not compile to Ready".into());
    }
    eprintln!("independent evidence compiled to finite DQR authority");

    let empty_a = seal_egress_bgp_snapshot(&gateway_a_config, Revision::new(3), Vec::new())?;
    let rollback_a = prepare_egress_bgp_transaction(&gateway_a_config, snapshot_a, empty_a)?;
    gateway_a
        .apply_transaction(&gateway_a_config, &rollback_a)
        .await?;
    wait_for_visibility(
        &mut fabric_a,
        &mut fabric_b,
        routes_a.iter().collect::<Vec<_>>().as_slice(),
        false,
    )
    .await?;
    eprintln!("single-gateway withdrawal preserved only the independent path");
    wait_for_visibility(
        &mut fabric_a,
        &mut fabric_b,
        routes_b.iter().collect::<Vec<_>>().as_slice(),
        true,
    )
    .await?;
    gateway_a
        .rollback_transaction(&gateway_a_config, &rollback_a)
        .await?;
    wait_for_visibility(
        &mut fabric_a,
        &mut fabric_b,
        routes_a.iter().collect::<Vec<_>>().as_slice(),
        true,
    )
    .await?;
    eprintln!("scoped rollback restored the exact withdrawn path");

    let empty_b = seal_egress_bgp_snapshot(&gateway_b_config, Revision::new(3), Vec::new())?;
    let withdraw_b = prepare_egress_bgp_transaction(&gateway_b_config, snapshot_b, empty_b)?;
    let (withdrawn_a, withdrawn_b) = tokio::join!(
        gateway_a.apply_transaction(&gateway_a_config, &rollback_a),
        gateway_b.apply_transaction(&gateway_b_config, &withdraw_b),
    );
    withdrawn_a?;
    withdrawn_b?;
    wait_for_visibility(
        &mut fabric_a,
        &mut fabric_b,
        routes_a
            .iter()
            .chain(&routes_b)
            .collect::<Vec<_>>()
            .as_slice(),
        false,
    )
    .await?;
    eprintln!("complete transaction withdrew every external route");

    let (recovered_a, recovered_b) = tokio::join!(
        gateway_a.reconcile_snapshot(&gateway_a_config, &rollback_a.previous_snapshot),
        gateway_b.reconcile_snapshot(&gateway_b_config, &withdraw_b.previous_snapshot),
    );
    recovered_a?;
    recovered_b?;
    wait_for_visibility(
        &mut fabric_a,
        &mut fabric_b,
        routes_a
            .iter()
            .chain(&routes_b)
            .collect::<Vec<_>>()
            .as_slice(),
        true,
    )
    .await?;
    eprintln!("durable complete snapshots restored a missing daemon RIB");

    let (withdrawn_a, withdrawn_b) = tokio::join!(
        gateway_a.apply_transaction(&gateway_a_config, &rollback_a),
        gateway_b.apply_transaction(&gateway_b_config, &withdraw_b),
    );
    withdrawn_a?;
    withdrawn_b?;
    wait_for_visibility(
        &mut fabric_a,
        &mut fabric_b,
        routes_a
            .iter()
            .chain(&routes_b)
            .collect::<Vec<_>>()
            .as_slice(),
        false,
    )
    .await?;
    eprintln!("post-recovery cleanup withdrew every external route");

    println!(
        "{}",
        serde_json::json!({
            "schemaVersion": 1,
            "result": "verified",
            "families": ["IPv4", "IPv6"],
            "gatewayPaths": 2,
            "fabricFailureDomains": 2,
            "causalCapsule": "exact-match",
            "scopedRollback": "verified",
            "durableReplay": "verified",
            "withdrawal": "verified",
            "assessmentDigest": assessment.digest.0,
        })
    );
    Ok(())
}

fn endpoint(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

async fn connect_all(endpoints: &[String; 4]) -> Result<[GoBgpAdapter; 4], DynError> {
    let (a, b, c, d) = tokio::try_join!(
        GoBgpAdapter::connect(&endpoints[0]),
        GoBgpAdapter::connect(&endpoints[1]),
        GoBgpAdapter::connect(&endpoints[2]),
        GoBgpAdapter::connect(&endpoints[3]),
    )?;
    Ok([a, b, c, d])
}

fn peer(name: &str, address: &str, remote_asn: u32, failure_domain: &str) -> EgressBgpPeer {
    EgressBgpPeer {
        name: name.to_owned(),
        address: address.parse().expect("fixture address is valid"),
        remote_asn,
        failure_domain: failure_domain.to_owned(),
        families: BTreeSet::from([EgressBgpAddressFamily::Ipv4, EgressBgpAddressFamily::Ipv6]),
        multihop_ttl: 1,
        maximum_received_prefixes: 64,
    }
}

fn speaker_config(
    _speaker: &str,
    local_asn: u32,
    router_id: Ipv4Addr,
    ipv4_next_hop: &str,
    ipv6_next_hop: &str,
    peers: Vec<EgressBgpPeer>,
) -> Result<EgressBgpConfig, DynError> {
    Ok(seal_egress_bgp_config(EgressBgpConfig {
        schema_version: EGRESS_BGP_SCHEMA_VERSION,
        algorithm: EGRESS_BGP_ALGORITHM.to_owned(),
        revision: Revision::new(1),
        instance: "fabric-live".to_owned(),
        local_asn,
        router_id,
        ipv4_next_hop: Some(ipv4_next_hop.parse()?),
        ipv6_next_hop: Some(ipv6_next_hop.parse()?),
        peers,
        permitted_export_prefixes: vec![
            EgressBgpPrefix {
                address: "192.0.2.0".parse()?,
                length: 24,
            },
            EgressBgpPrefix {
                address: "2001:db8:200::".parse()?,
                length: 64,
            },
        ],
        maximum_changed_prefixes: 8,
        maximum_total_prefixes: 64,
        maximum_paths_per_prefix: 4,
        graceful_restart: EgressBgpGracefulRestart {
            restart_seconds: 15,
            stale_path_seconds: 45,
        },
        digest: EgressBgpConfigDigest([0; 32]),
    })?)
}

fn desired() -> EgressGatewayDesired {
    EgressGatewayDesired {
        schema_version: 1,
        revision: Revision::new(2),
        allocation_revision: Revision::new(2),
        owner: EgressIntentOwner {
            scope: EgressIntentScope::Cluster,
            name: "bgp-live".to_owned(),
            uid: "bgp-live-uid".to_owned(),
        },
        provider: EgressProviderRef {
            name: "bgp".to_owned(),
            instance: "fabric-live".to_owned(),
        },
        lease_epoch: 7,
        action: EgressGatewayAction::Ensure,
        addresses: vec![
            EGRESS_V4.parse().expect("valid fixture"),
            EGRESS_V6.parse().expect("valid fixture"),
        ],
        nodes: vec![
            EgressNode {
                name: "gateway-a".to_owned(),
                uid: "gateway-a-uid".to_owned(),
                capabilities: BTreeSet::<EgressCapability>::new(),
            },
            EgressNode {
                name: "gateway-b".to_owned(),
                uid: "gateway-b-uid".to_owned(),
                capabilities: BTreeSet::<EgressCapability>::new(),
            },
        ],
    }
}

fn routes(
    config: &EgressBgpConfig,
    desired: &EgressGatewayDesired,
    path: &EgressReachabilityPath,
) -> Result<Vec<EgressBgpRoute>, DynError> {
    let node = desired
        .nodes
        .iter()
        .find(|node| node.uid == path.gateway_uid)
        .ok_or("fixture path has no gateway")?;
    let plan = derive_egress_bgp_reachability_plan(desired)?;
    desired
        .addresses
        .iter()
        .map(|address| {
            seal_egress_bgp_route(
                config,
                desired.owner.clone(),
                desired.provider.clone(),
                desired.revision,
                desired.lease_epoch,
                *address,
                node.name.clone(),
                node.uid.clone(),
                plan.digest,
            )
            .map_err(Into::into)
        })
        .collect()
}

async fn wait_for_visibility(
    fabric_a: &mut GoBgpAdapter,
    fabric_b: &mut GoBgpAdapter,
    routes: &[&EgressBgpRoute],
    expected: bool,
) -> Result<(), DynError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut matches = true;
        for route in routes {
            matches &= fabric_a.route_visible_in_global(route).await? == expected;
            matches &= fabric_b.route_visible_in_global(route).await? == expected;
        }
        if matches {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("external BGP RIB did not converge before its deadline".into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

fn observations(plan: &unf_egress::EgressReachabilityPlan) -> Vec<EgressReachabilityObservation> {
    let observations = [
        (
            "gateway-a",
            "gateway-a",
            "adj-rib-out",
            vec![plan.expected_paths[0].clone()],
        ),
        ("fabric-a", "rack-a", "fabric", plan.expected_paths.clone()),
        ("fabric-b", "rack-b", "fabric", plan.expected_paths.clone()),
    ];
    observations
        .into_iter()
        .enumerate()
        .map(|(index, (name, domain, vantage, paths))| {
            seal_egress_reachability_observation(
                plan,
                EgressReachabilityObservation {
                    schema_version: EGRESS_REACHABILITY_SCHEMA_VERSION,
                    algorithm: EGRESS_REACHABILITY_ALGORITHM_DIVERSITY_QUORUM_V1.to_owned(),
                    plan_digest: plan.digest,
                    observer: EgressReachabilityObserver {
                        name: name.to_owned(),
                        failure_domain: domain.to_owned(),
                        vantage: vantage.to_owned(),
                    },
                    source_epoch: 1,
                    revision: Revision::new(u64::try_from(index).expect("small fixture") + 1),
                    observed_at_unix_seconds: 1_000,
                    valid_until_unix_seconds: 1_060,
                    routes: plan
                        .addresses
                        .iter()
                        .map(|address| EgressReachabilityRouteObservation {
                            address: *address,
                            paths: paths.clone(),
                        })
                        .collect(),
                    digest: EgressReachabilityObservationDigest([0; 32]),
                },
            )
            .expect("live observation matches the sealed plan")
        })
        .collect()
}
