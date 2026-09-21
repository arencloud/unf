use super::*;
use unf_cni_state::{AttachmentKey, AttachmentSpec};
use unf_common::Revision;
use unf_encryption::{
    EncryptionGenerationRecipient, EncryptionLocalityCertificate, IpPrefix,
    KubernetesEncryptionNodeSnapshot, KubernetesEncryptionWorkloadSnapshot,
    project_kubernetes_encryption_placement,
};
use unf_ipam::{DualStackLease, Ipv4Lease, Ipv6Lease};

pub(crate) fn record() -> AttachmentRecord {
    AttachmentRecord {
        spec: AttachmentSpec {
            key: AttachmentKey {
                network: "test".into(),
                container_id: "sandbox".into(),
                ifname: "eth0".into(),
            },
            netns: "/not-an-observed-namespace".into(),
            mtu: 1400,
            workload_uid: Some("pod-a".into()),
        },
        host_interface: "unf-test".into(),
        phase: AttachmentPhase::Ready,
        creation_token: Some([17; 32]),
        lease: DualStackLease {
            ipv4: Ipv4Lease {
                address: "10.42.0.2".parse().unwrap(),
                gateway: "10.42.0.1".parse().unwrap(),
                prefix_len: 32,
            },
            ipv6: Ipv6Lease {
                address: "fd42::2".parse().unwrap(),
                gateway: "fd42::1".parse().unwrap(),
                prefix_len: 128,
            },
        },
    }
}

pub(crate) fn evidence(dual: bool) -> (VerifiedEncryptionLocality, EncryptionLocalityContext) {
    let context = EncryptionLocalityContext {
        cluster_id: "cluster-a".into(),
        recipient: EncryptionGenerationRecipient {
            node_name: "worker-a".into(),
            node_uid: "node-a".into(),
        },
        membership_revision: Revision::new(1),
        identity_epoch: 2,
        identity_revision: Revision::new(3),
        routing_revision: Revision::new(4),
    };
    let node = KubernetesEncryptionNodeSnapshot {
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
                prefix_len: 120,
            },
        ],
        underlay_addresses: vec!["192.0.2.10".parse().unwrap()],
    };
    let mut addresses = vec!["10.42.0.2".parse().unwrap()];
    if dual {
        addresses.push("fd42::2".parse().unwrap());
    }
    let workload = KubernetesEncryptionWorkloadSnapshot {
        workload_uid: "pod-a".into(),
        identity: IdentityId::new(17),
        node_name: "worker-a".into(),
        host_network: false,
        addresses,
    };
    let placement =
        project_kubernetes_encryption_placement("cluster-a", vec![node], vec![workload]).unwrap();
    let certificate = EncryptionLocalityCertificate::issue(context.clone(), &placement).unwrap();
    (
        certificate.verify_against(&context, &placement).unwrap(),
        context,
    )
}

#[test]
fn metadata_join_never_invents_an_unpublished_address_family() {
    let (dual, _) = evidence(true);
    let owners = exact_owners(&record(), &dual).unwrap();
    assert_eq!(owners.iter().flatten().count(), 2);
    assert!(
        owners
            .iter()
            .flatten()
            .all(|(_, identity)| *identity == IdentityId::new(17))
    );
    let (single, _) = evidence(false);
    let owners = exact_owners(&record(), &single).unwrap();
    assert!(owners[0].is_some());
    assert!(owners[1].is_none());
}

#[test]
fn metadata_cannot_replace_ready_uid_nonce_and_exact_address_ownership() {
    let (evidence, _) = evidence(true);
    for mutation in 0..8 {
        let mut record = record();
        match mutation {
            0 => record.spec.workload_uid = None,
            1 => record.spec.workload_uid = Some("other-pod".into()),
            2 => record.creation_token = None,
            3 => record.creation_token = Some([0; 32]),
            4 => record.phase = AttachmentPhase::Preparing,
            5 => record.phase = AttachmentPhase::Deleting,
            6 => record.phase = AttachmentPhase::Aborting,
            7 => {
                record.lease.ipv4.address = "10.42.0.9".parse().unwrap();
                record.lease.ipv6.address = "fd42::9".parse().unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            exact_owners(&record, &evidence).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn empty_kernel_inventory_never_acquires_placement_addresses_and_rejects_foreign_cut() {
    let (evidence, context) = evidence(true);
    let bank = ObservedLocalityBank::join(&evidence, &context, Vec::new()).unwrap();
    assert!(bank.addresses().unwrap().is_empty());
    assert!(bank.endpoints().unwrap().is_empty());
    assert_eq!(bank.context(), &context);
    assert_eq!(
        bank.placement_digest(),
        evidence.certificate().certificate_digest()
    );
    let mut foreign = context;
    foreign.identity_revision = Revision::new(99);
    assert!(ObservedLocalityBank::join(&evidence, &foreign, Vec::new()).is_err());
}
