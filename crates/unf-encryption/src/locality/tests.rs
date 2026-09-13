use super::*;
use crate::{
    KubernetesEncryptionNodeSnapshot, KubernetesEncryptionWorkloadSnapshot,
    project_kubernetes_encryption_placement,
};
use std::fmt::Write as _;

fn prefix(address: &str, prefix_len: u8) -> IpPrefix {
    IpPrefix {
        address: address.parse().unwrap(),
        prefix_len,
    }
}

fn context() -> EncryptionLocalityContext {
    EncryptionLocalityContext {
        cluster_id: "cluster-a".to_owned(),
        recipient: EncryptionGenerationRecipient {
            node_name: "worker-a".to_owned(),
            node_uid: "node-a".to_owned(),
        },
        membership_revision: Revision::new(3),
        identity_epoch: 7,
        identity_revision: Revision::new(5),
        routing_revision: Revision::new(9),
    }
}

fn nodes() -> Vec<KubernetesEncryptionNodeSnapshot> {
    ["a", "b"]
        .into_iter()
        .enumerate()
        .map(|(index, suffix)| KubernetesEncryptionNodeSnapshot {
            name: format!("worker-{suffix}"),
            uid: format!("node-{suffix}"),
            ready: true,
            managed: true,
            pod_cidrs: vec![
                prefix(&format!("10.42.{}.0", index + 1), 24),
                prefix(&format!("fd42:{}::", index + 1), 64),
            ],
            underlay_addresses: vec![format!("192.0.2.{}", index + 1).parse().unwrap()],
        })
        .collect()
}

fn workloads() -> Vec<KubernetesEncryptionWorkloadSnapshot> {
    ["a", "b"]
        .into_iter()
        .enumerate()
        .flat_map(|(index, suffix)| {
            [("source", 11, 8), ("backend", 21, 9)].into_iter().map(
                move |(role, identity, host)| KubernetesEncryptionWorkloadSnapshot {
                    workload_uid: format!("{role}-{suffix}"),
                    identity: IdentityId::new(identity),
                    node_name: format!("worker-{suffix}"),
                    host_network: false,
                    addresses: vec![
                        format!("10.42.{}.{host}", index + 1).parse().unwrap(),
                        format!("fd42:{}::{host}", index + 1).parse().unwrap(),
                    ],
                },
            )
        })
        .collect()
}

fn placement(
    workloads: Vec<KubernetesEncryptionWorkloadSnapshot>,
) -> KubernetesEncryptionPlacement {
    project_kubernetes_encryption_placement("cluster-a", nodes(), workloads).unwrap()
}

fn certificate() -> EncryptionLocalityCertificate {
    EncryptionLocalityCertificate::issue(context(), &placement(workloads())).unwrap()
}

#[test]
fn locality_matches_both_exact_local_owners_not_replicated_identity_alone() {
    let placement = placement(workloads());
    let certificate = certificate();
    let verified = certificate.verify_against(&context(), &placement).unwrap();
    assert_eq!(verified.certificate(), &certificate);
    assert_eq!(certificate.addresses().len(), 4);
    for (source, local, remote) in [
        ("10.42.1.8", "10.42.1.9", "10.42.2.9"),
        ("fd42:1::8", "fd42:1::9", "fd42:2::9"),
    ] {
        let lookup = |source: &str, destination: &str, identity| {
            verified
                .local_tuple(
                    &context(),
                    IdentityId::new(11),
                    source.parse().unwrap(),
                    IdentityId::new(identity),
                    destination.parse().unwrap(),
                )
                .unwrap()
        };
        let tuple = lookup(source, local, 21).unwrap();
        assert_eq!(tuple.source.workload_uid, "source-a");
        assert_eq!(tuple.destination.workload_uid, "backend-a");
        assert!(lookup(source, remote, 21).is_none());
        assert!(lookup(source, local, 22).is_none());
        assert!(lookup(remote, local, 21).is_none());
    }
    assert!(
        verified
            .local_tuple(
                &context(),
                IdentityId::new(11),
                "10.42.1.8".parse().unwrap(),
                IdentityId::new(21),
                "fd42:1::9".parse().unwrap(),
            )
            .unwrap()
            .is_none()
    );
    // A Service VIP or an unallocated address inside the local Pod CIDR is
    // not evidence for a local backend, even when the identity matches.
    for address in ["172.30.0.8", "10.42.1.10", "fd42:1::10"] {
        let source = if address.contains(':') {
            "fd42:1::8"
        } else {
            "10.42.1.8"
        };
        assert!(
            verified
                .local_tuple(
                    &context(),
                    IdentityId::new(11),
                    source.parse().unwrap(),
                    IdentityId::new(21),
                    address.parse().unwrap()
                )
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn locality_rejects_every_stale_context_coordinate() {
    let placement = placement(workloads());
    let certificate = certificate();
    let verified = certificate.verify_against(&context(), &placement).unwrap();
    let mut changed = Vec::new();
    let mut value = context();
    value.cluster_id = "foreign-cluster".to_owned();
    changed.push(value);
    let mut value = context();
    value.recipient.node_name = "worker-b".to_owned();
    changed.push(value);
    let mut value = context();
    value.recipient.node_uid = "replacement-uid".to_owned();
    changed.push(value);
    let mut value = context();
    value.membership_revision = Revision::new(4);
    changed.push(value);
    let mut value = context();
    value.identity_epoch = 8;
    changed.push(value);
    let mut value = context();
    value.identity_revision = Revision::new(6);
    changed.push(value);
    let mut value = context();
    value.routing_revision = Revision::new(10);
    changed.push(value);
    for expected in changed {
        assert!(certificate.verify_against(&expected, &placement).is_err());
        assert_eq!(
            verified.local_tuple(
                &expected,
                IdentityId::new(11),
                "10.42.1.8".parse().unwrap(),
                IdentityId::new(21),
                "10.42.1.9".parse().unwrap(),
            ),
            Err(EncryptionLocalityError::InvalidContext)
        );
    }
}

#[test]
fn locality_replay_rejects_move_deletion_uid_reuse_and_identity_changes() {
    let certificate = certificate();
    let mut variants = Vec::new();
    let mut moved = workloads();
    moved[1].node_name = "worker-b".to_owned();
    moved[1].addresses = vec!["10.42.2.10".parse().unwrap(), "fd42:2::10".parse().unwrap()];
    variants.push(moved);
    let mut deleted = workloads();
    deleted.remove(1);
    variants.push(deleted);
    let mut replacement = workloads();
    replacement[1].workload_uid = "new-pod-same-ip-and-identity".to_owned();
    variants.push(replacement);
    let mut new_identity = workloads();
    new_identity[1].identity = IdentityId::new(22);
    variants.push(new_identity);
    for changed in variants {
        assert_eq!(
            certificate.verify_against(&context(), &placement(changed)),
            Err(EncryptionLocalityError::PlacementMismatch)
        );
    }
    let mut replacement_nodes = nodes();
    replacement_nodes[0].uid = "new-node-same-name".to_owned();
    let replacement =
        project_kubernetes_encryption_placement("cluster-a", replacement_nodes, workloads())
            .unwrap();
    assert_eq!(
        certificate.verify_against(&context(), &replacement),
        Err(EncryptionLocalityError::InvalidContext)
    );
}

#[test]
fn locality_checksum_is_not_authentication_or_placement_authority() {
    let original = certificate();
    let mut forged = original.clone();
    for owner in &mut forged.addresses {
        if owner.workload_uid == "backend-a" {
            owner.identity = IdentityId::new(99);
        }
    }
    assert_eq!(
        forged.verify_integrity(),
        Err(EncryptionLocalityError::IntegrityMismatch)
    );
    forged.certificate_digest = forged.digest().unwrap();
    forged.verify_integrity().unwrap();
    assert_eq!(
        forged.verify_against(&context(), &placement(workloads())),
        Err(EncryptionLocalityError::PlacementMismatch)
    );
    let mut incomplete = original;
    incomplete.addresses.pop();
    incomplete.certificate_digest = incomplete.digest().unwrap();
    incomplete.verify_integrity().unwrap();
    assert_eq!(
        incomplete.verify_against(&context(), &placement(workloads())),
        Err(EncryptionLocalityError::PlacementMismatch)
    );
}

#[test]
fn locality_rejects_noncanonical_or_foreign_shape_even_after_rehashing() {
    let original = certificate();
    let mut variants = Vec::new();
    let mut value = original.clone();
    value.schema_version += 1;
    variants.push(value);
    let mut value = original.clone();
    value.addresses.reverse();
    variants.push(value);
    let mut value = original.clone();
    value.addresses.insert(0, value.addresses[0].clone());
    variants.push(value);
    let mut value = original.clone();
    value.addresses[0].node_uid = "node-b".to_owned();
    variants.push(value);
    let mut value = original.clone();
    value.addresses[0].identity = IdentityId::new(0);
    variants.push(value);
    let mut value = original.clone();
    value.addresses[0].identity = IdentityId::new(99); // one UID, two identities
    variants.push(value);
    let mut value = original.clone();
    value.addresses[0].workload_uid.clear();
    variants.push(value);
    let mut value = original.clone();
    value.pod_cidrs.clear();
    variants.push(value);
    let mut value = original.clone();
    value.pod_cidrs[0].prefix_len = 33;
    variants.push(value);
    let mut value = original;
    value.addresses[0].address = "10.42.2.8".parse().unwrap();
    value.addresses.sort_unstable_by_key(|owner| owner.address);
    variants.push(value);
    for mut value in variants {
        value.certificate_digest = value.digest().unwrap();
        assert_eq!(
            value.verify_integrity(),
            Err(EncryptionLocalityError::InvalidShape)
        );
    }
}

#[test]
fn locality_context_zero_and_control_characters_are_rejected() {
    for field in [
        "membershipRevision",
        "identityEpoch",
        "identityRevision",
        "routingRevision",
    ] {
        let mut value = serde_json::to_value(context()).unwrap();
        value[field] = serde_json::json!(0);
        let invalid = serde_json::from_value(value).unwrap();
        assert_eq!(
            EncryptionLocalityCertificate::issue(invalid, &placement(workloads())),
            Err(EncryptionLocalityError::InvalidContext)
        );
    }
    let mut invalid = context();
    invalid.cluster_id = "cluster-a\n".to_owned();
    assert_eq!(
        EncryptionLocalityCertificate::issue(invalid, &placement(workloads())),
        Err(EncryptionLocalityError::InvalidContext)
    );
}

#[test]
fn locality_serialization_is_strict_and_permutation_canonical() {
    let original = certificate();
    let wire = serde_json::to_value(&original).unwrap();
    let decoded: EncryptionLocalityCertificate = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(decoded, original);
    decoded
        .verify_against(&context(), &placement(workloads()))
        .unwrap();
    let mut top = wire.clone();
    top["nativeFallback"] = serde_json::json!(true);
    let mut nested = wire.clone();
    nested["context"]["foreignAuthority"] = serde_json::json!(true);
    let mut owner = wire;
    owner["addresses"][0]["permit"] = serde_json::json!(true);
    for invalid in [top, nested, owner] {
        assert!(serde_json::from_value::<EncryptionLocalityCertificate>(invalid).is_err());
    }
    let mut workloads = workloads();
    workloads.reverse();
    for workload in &mut workloads {
        workload.addresses.reverse();
    }
    let mut nodes = nodes();
    nodes.reverse();
    for node in &mut nodes {
        node.pod_cidrs.reverse();
    }
    let reversed = project_kubernetes_encryption_placement("cluster-a", nodes, workloads).unwrap();
    assert_eq!(
        EncryptionLocalityCertificate::issue(context(), &reversed).unwrap(),
        original
    );
}

#[test]
fn locality_empty_or_host_network_only_cut_proves_no_local_tuple() {
    let mut host = workloads()[0].clone();
    host.host_network = true;
    host.addresses = vec!["192.0.2.1".parse().unwrap()];
    for workloads in [vec![], vec![host]] {
        let placement = placement(workloads);
        let empty = EncryptionLocalityCertificate::issue(context(), &placement).unwrap();
        assert!(empty.addresses().is_empty());
        let verified = empty.verify_against(&context(), &placement).unwrap();
        assert!(
            verified
                .local_tuple(
                    &context(),
                    IdentityId::new(11),
                    "10.42.1.8".parse().unwrap(),
                    IdentityId::new(21),
                    "10.42.1.9".parse().unwrap()
                )
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn locality_rejects_non_workload_address_classes() {
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "169.254.1.1",
        "255.255.255.255",
        "::",
        "::1",
        "ff02::1",
        "fe80::1",
        "::ffff:10.42.1.8",
    ] {
        assert!(
            !valid_workload_address(address.parse().unwrap()),
            "{address}"
        );
    }
    for address in ["10.42.1.8", "fd42:1::8"] {
        assert!(valid_workload_address(address.parse().unwrap()));
    }
}

#[test]
fn locality_v1_digest_is_frozen() {
    let digest = certificate().certificate_digest().0;
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").unwrap();
    }
    assert_eq!(
        hex,
        "a748225a38d3e68a34a60601e5dd9cf07a6b9bd1dc5e656eab9b575d0824cc50"
    );
}

#[test]
fn locality_streamed_digest_matches_independent_buffered_encoding() {
    let certificate = certificate();
    let payload = serde_json::to_vec(&(
        1_u16,
        certificate.context(),
        &certificate.pod_cidrs,
        certificate.addresses(),
    ))
    .unwrap();
    let mut bytes = b"unf.encryption-locality-certificate.v1\0".to_vec();
    bytes.extend(payload);
    let expected: [u8; 32] = Sha256::digest(bytes).into();
    assert_eq!(certificate.certificate_digest().0, expected);
}

#[test]
fn locality_storage_is_address_linear_at_the_endpoint_budget() {
    let mut nodes = nodes();
    nodes[0].pod_cidrs[0] = prefix("10.20.0.0", 16);
    let workloads = (0..MAX_ENCRYPTION_ENDPOINTS)
        .map(|index| {
            let ordinal = u16::try_from(index + 8).unwrap();
            let [high, low] = ordinal.to_be_bytes();
            KubernetesEncryptionWorkloadSnapshot {
                workload_uid: format!("pod-{index}"),
                identity: IdentityId::new(u32::try_from(index + 1).unwrap()),
                node_name: "worker-a".to_owned(),
                host_network: false,
                addresses: vec![
                    format!("10.20.{high}.{low}").parse().unwrap(),
                    format!("fd42:1::{ordinal:x}").parse().unwrap(),
                ],
            }
        })
        .collect();
    let placement = project_kubernetes_encryption_placement("cluster-a", nodes, workloads).unwrap();
    let certificate = EncryptionLocalityCertificate::issue(context(), &placement).unwrap();
    assert_eq!(certificate.addresses().len(), 2 * MAX_ENCRYPTION_ENDPOINTS);
    let verified = certificate.verify_against(&context(), &placement).unwrap();
    for (first, second) in [
        (0, 1),
        (17, 1024),
        (MAX_ENCRYPTION_ENDPOINTS - 2, MAX_ENCRYPTION_ENDPOINTS - 1),
    ] {
        let ip = |index| {
            let ordinal = u16::try_from(index + 8).unwrap();
            let [high, low] = ordinal.to_be_bytes();
            format!("10.20.{high}.{low}").parse().unwrap()
        };
        assert!(
            verified
                .local_tuple(
                    &context(),
                    IdentityId::new(u32::try_from(first + 1).unwrap()),
                    ip(first),
                    IdentityId::new(u32::try_from(second + 1).unwrap()),
                    ip(second)
                )
                .unwrap()
                .is_some()
        );
    }
}
