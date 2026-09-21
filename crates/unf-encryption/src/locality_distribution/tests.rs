use super::*;
use crate::{EncryptionGenerationRecipient, IpPrefix};
use unf_common::{IdentityId, Revision};

fn context() -> EncryptionLocalityContext {
    EncryptionLocalityContext {
        cluster_id: "cluster-a".into(),
        recipient: EncryptionGenerationRecipient {
            node_name: "worker-a".into(),
            node_uid: "node-a".into(),
        },
        membership_revision: Revision::new(2),
        identity_epoch: 3,
        identity_revision: Revision::new(4),
        routing_revision: Revision::new(5),
    }
}

fn source() -> (
    Vec<KubernetesEncryptionNodeSnapshot>,
    Vec<KubernetesEncryptionWorkloadSnapshot>,
) {
    (
        vec![KubernetesEncryptionNodeSnapshot {
            name: "worker-a".into(),
            uid: "node-a".into(),
            ready: true,
            managed: true,
            pod_cidrs: vec![
                IpPrefix {
                    address: "10.42.0.0".parse().unwrap(),
                    prefix_len: 24,
                },
                IpPrefix {
                    address: "fd42::".parse().unwrap(),
                    prefix_len: 64,
                },
            ],
            underlay_addresses: vec!["192.0.2.10".parse().unwrap()],
        }],
        [11, 21]
            .into_iter()
            .map(|id| KubernetesEncryptionWorkloadSnapshot {
                workload_uid: format!("pod-{id}"),
                identity: IdentityId::new(id),
                node_name: "worker-a".into(),
                host_network: false,
                addresses: vec![
                    format!("10.42.0.{id}").parse().unwrap(),
                    format!("fd42::{id}").parse().unwrap(),
                ],
            })
            .collect(),
    )
}

fn response(request: &EncryptionLocalityRequest) -> EncryptionLocalityResponse {
    let (nodes, workloads) = source();
    EncryptionLocalityResponse::issue(request, &context(), nodes, workloads).unwrap()
}

#[test]
fn private_checkpoint_replays_source_and_requires_the_entire_current_cut() {
    let request = EncryptionLocalityRequest::issue(context()).unwrap();
    let wire = serde_json::to_vec(&response(&request)).unwrap();
    let (captured, original) =
        EncryptionLocalityResponse::capture_authenticated(&wire, &request, &context()).unwrap();
    let checkpoint = serde_json::to_vec(&captured).unwrap();
    assert_eq!(
        CapturedEncryptionLocality::replay_private_checkpoint(&checkpoint, &context()).unwrap(),
        original
    );
    for field in 0..7 {
        let mut changed = context();
        match field {
            0 => changed.cluster_id.push('x'),
            1 => changed.recipient.node_name.push('x'),
            2 => changed.recipient.node_uid.push('x'),
            3 => changed.membership_revision = Revision::new(99),
            4 => changed.identity_epoch += 1,
            5 => changed.identity_revision = Revision::new(99),
            _ => changed.routing_revision = Revision::new(99),
        }
        assert!(
            CapturedEncryptionLocality::replay_private_checkpoint(&checkpoint, &changed).is_err()
        );
    }
    let valid = serde_json::to_value(captured).unwrap();
    for (pointer, value) in [
        ("/schemaVersion", serde_json::json!(2)),
        ("/request/schemaVersion", serde_json::json!(2)),
        (
            "/request/nonce/0",
            serde_json::json!(request.nonce[0].wrapping_add(1)),
        ),
        (
            "/response/workloads/0/workloadUid",
            serde_json::json!("substitution"),
        ),
        (
            "/response/workloads/0/addresses/0",
            serde_json::json!("10.42.0.99"),
        ),
        (
            "/response/nodes/0/uid",
            serde_json::json!("replacement-node"),
        ),
        (
            "/response/certificate/context/identityEpoch",
            serde_json::json!(99),
        ),
    ] {
        let mut changed = valid.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            CapturedEncryptionLocality::replay_private_checkpoint(
                &serde_json::to_vec(&changed).unwrap(),
                &context()
            )
            .is_err(),
            "{pointer}"
        );
    }
    for pointer in ["", "/request", "/response", "/response/workloads/0"] {
        let mut changed = valid.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unrecognized".into(), serde_json::json!(true));
        assert!(
            CapturedEncryptionLocality::replay_private_checkpoint(
                &serde_json::to_vec(&changed).unwrap(),
                &context()
            )
            .is_err(),
            "{pointer}"
        );
    }
    assert!(matches!(
        CapturedEncryptionLocality::replay_private_checkpoint(
            &vec![0; MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES + 1],
            &context()
        ),
        Err(EncryptionLocalityDistributionError::Capacity)
    ));
    // An archive is not an HTTP response, including when its original nonce
    // is known. It must use the distinct trusted-file replay boundary.
    assert!(
        EncryptionLocalityResponse::decode_authenticated(&checkpoint, &request, &context())
            .is_err()
    );
}

#[test]
fn nonce_bound_replay_yields_only_exact_dual_stack_placement() {
    let request = EncryptionLocalityRequest::issue(context()).unwrap();
    let wire = serde_json::to_vec(&response(&request)).unwrap();
    let verified =
        EncryptionLocalityResponse::decode_authenticated(&wire, &request, &context()).unwrap();
    for (source, destination) in [("10.42.0.11", "10.42.0.21"), ("fd42::11", "fd42::21")] {
        assert!(
            verified
                .local_tuple(
                    &context(),
                    IdentityId::new(11),
                    source.parse().unwrap(),
                    IdentityId::new(21),
                    destination.parse().unwrap()
                )
                .unwrap()
                .is_some()
        );
    }
    let other = EncryptionLocalityRequest::issue(context()).unwrap();
    assert_ne!(request.nonce, other.nonce);
    assert!(EncryptionLocalityResponse::decode_authenticated(&wire, &other, &context()).is_err());
}

#[test]
fn every_request_coordinate_and_applied_cut_is_fenced() {
    let request = EncryptionLocalityRequest::issue(context()).unwrap();
    let wire = serde_json::to_vec(&response(&request)).unwrap();
    let mut contexts = vec![context(); 7];
    contexts[0].cluster_id.push('x');
    contexts[1].recipient.node_name.push('x');
    contexts[2].recipient.node_uid.push('x');
    contexts[3].membership_revision = Revision::new(22);
    contexts[4].identity_epoch += 1;
    contexts[5].identity_revision = Revision::new(44);
    contexts[6].routing_revision = Revision::new(55);
    for current in contexts {
        assert!(
            EncryptionLocalityResponse::decode_authenticated(&wire, &request, &current).is_err()
        );
        let changed = EncryptionLocalityRequest::issue(current.clone()).unwrap();
        assert!(
            EncryptionLocalityResponse::decode_authenticated(&wire, &changed, &current).is_err()
        );
        let (nodes, workloads) = source();
        assert!(EncryptionLocalityResponse::issue(&request, &current, nodes, workloads).is_err());
    }
}

#[test]
fn replay_rejects_source_substitution_even_with_intact_certificate() {
    let request = EncryptionLocalityRequest::issue(context()).unwrap();
    let valid = serde_json::to_value(response(&request)).unwrap();
    for (pointer, value) in [
        ("/schemaVersion", serde_json::json!(2)),
        (
            "/requestNonce/0",
            serde_json::json!(request.nonce[0].wrapping_add(1)),
        ),
        ("/nodes/0/uid", serde_json::json!("replacement-node")),
        ("/nodes/0/ready", serde_json::json!(false)),
        ("/nodes/0/managed", serde_json::json!(false)),
        (
            "/workloads/0/workloadUid",
            serde_json::json!("replacement-pod"),
        ),
        ("/workloads/0/identity", serde_json::json!(99)),
        ("/workloads/0/nodeName", serde_json::json!("foreign-node")),
        ("/workloads/0/hostNetwork", serde_json::json!(true)),
        ("/workloads/0/addresses/0", serde_json::json!("10.42.0.21")),
        ("/certificate/context/identityEpoch", serde_json::json!(99)),
    ] {
        let mut altered = valid.clone();
        *altered.pointer_mut(pointer).unwrap() = value;
        assert!(
            EncryptionLocalityResponse::decode_authenticated(
                &serde_json::to_vec(&altered).unwrap(),
                &request,
                &context()
            )
            .is_err(),
            "{pointer}"
        );
    }
    for pointer in ["", "/nodes/0", "/workloads/0", "/certificate"] {
        let mut altered = valid.clone();
        altered
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), true.into());
        assert!(
            EncryptionLocalityResponse::decode_authenticated(
                &serde_json::to_vec(&altered).unwrap(),
                &request,
                &context()
            )
            .is_err()
        );
    }
}

#[test]
fn malformed_requests_and_oversized_wire_fail_before_admission() {
    let request = EncryptionLocalityRequest::issue(context()).unwrap();
    let mut invalid = request.clone();
    invalid.nonce = [0; 32];
    assert!(invalid.verify().is_err());
    invalid = request.clone();
    invalid.schema_version += 1;
    assert!(invalid.verify().is_err());
    invalid = request.clone();
    invalid.context.identity_epoch = 0;
    assert!(invalid.verify().is_err());
    for wire in [b"null".as_slice(), b"{}", b"[", b""] {
        assert!(
            EncryptionLocalityResponse::decode_authenticated(wire, &request, &context()).is_err()
        );
    }
    let oversized = vec![b' '; MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES + 1];
    assert!(matches!(
        EncryptionLocalityResponse::decode_authenticated(&oversized, &request, &context()),
        Err(EncryptionLocalityDistributionError::Capacity)
    ));
    let mut sink = WireBudget(3);
    assert_eq!(sink.write(b"abc").unwrap(), 3);
    assert!(sink.write(b"x").is_err());
    let (nodes, mut workloads) = source();
    workloads[0].workload_uid = "x".repeat(MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES);
    assert!(matches!(
        EncryptionLocalityResponse::issue(&request, &context(), nodes, workloads),
        Err(EncryptionLocalityDistributionError::Capacity)
    ));
}

#[test]
fn explicit_empty_cut_is_replayed_not_confused_with_unavailable() {
    let request = EncryptionLocalityRequest::issue(context()).unwrap();
    let (nodes, _) = source();
    let response = EncryptionLocalityResponse::issue(&request, &context(), nodes, vec![]).unwrap();
    let verified = EncryptionLocalityResponse::decode_authenticated(
        &serde_json::to_vec(&response).unwrap(),
        &request,
        &context(),
    )
    .unwrap();
    assert!(verified.certificate().addresses().is_empty());
}
