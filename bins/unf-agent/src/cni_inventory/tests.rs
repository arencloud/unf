use super::*;
use unf_cni_state::{
    AttachmentKey, AttachmentSpec, CNI_TRANSACTION_SCHEMA_VERSION, TransactionOperation,
    TransactionRequest,
};
use unf_common::Revision;
use unf_encryption::{
    EncryptionGenerationRecipient, EncryptionLocalityCertificate, IpPrefix,
    KubernetesEncryptionNodeSnapshot, KubernetesEncryptionWorkloadSnapshot,
    project_kubernetes_encryption_placement,
};
use unf_ipam::NodeBlockProvider;

fn spec(uid: Option<&str>) -> AttachmentSpec {
    AttachmentSpec {
        key: AttachmentKey {
            network: "unf-test".into(),
            container_id: "sandbox-a".into(),
            ifname: "eth0".into(),
        },
        netns: "/run/netns/sandbox-a".into(),
        mtu: 1500,
        workload_uid: uid.map(Into::into),
    }
}

fn apply(journal: &mut AttachmentJournal, operation: TransactionOperation) {
    journal
        .apply(TransactionRequest::new(
            CNI_TRANSACTION_SCHEMA_VERSION,
            operation,
        ))
        .unwrap();
}

fn inventory(uid: Option<&str>) -> (tempfile::TempDir, CniAttachmentInventory) {
    let directory = tempfile::tempdir().unwrap();
    let provider = NodeBlockProvider::new(
        "10.42.0.0/24".parse().unwrap(),
        "fd42::/120".parse().unwrap(),
    );
    let mut journal =
        AttachmentJournal::open(directory.path().join("attachments.json"), provider).unwrap();
    apply(
        &mut journal,
        TransactionOperation::Prepare {
            attachment: spec(uid),
        },
    );
    (
        directory,
        CniAttachmentInventory::new(Arc::new(Mutex::new(journal))),
    )
}

pub(crate) fn placement(
    uid: &str,
    identity: u32,
    dual_stack: bool,
) -> (VerifiedEncryptionLocality, EncryptionLocalityContext) {
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
    if dual_stack {
        addresses.push("fd42::2".parse().unwrap());
    }
    let workloads = vec![KubernetesEncryptionWorkloadSnapshot {
        workload_uid: uid.into(),
        identity: IdentityId::new(identity),
        node_name: "worker-a".into(),
        host_network: false,
        addresses,
    }];
    let placement =
        project_kubernetes_encryption_placement("cluster-a", vec![node], workloads).unwrap();
    let certificate = EncryptionLocalityCertificate::issue(context.clone(), &placement).unwrap();
    (
        certificate.verify_against(&context, &placement).unwrap(),
        context,
    )
}

#[tokio::test]
async fn joins_only_ready_bound_exact_owners_and_reuses_unchanged_cut() {
    let (_directory, inventory) = inventory(Some("pod-a"));
    let (evidence, context) = placement("pod-a", 17, true);
    let mut selected = None;
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    assert_eq!(selected.as_ref().unwrap().counts(), (0, 0, 0));
    apply(
        &mut *inventory.journal.lock().await,
        TransactionOperation::Commit {
            key: spec(Some("pod-a")).key,
        },
    );
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    let first = selected.as_ref().unwrap();
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.addresses, 2);
    assert_eq!(first.records[0].1, [Some(IdentityId::new(17)); 2]);
    let allocation = first.records.as_ptr();
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    assert_eq!(selected.as_ref().unwrap().records.as_ptr(), allocation);
    apply(
        &mut *inventory.journal.lock().await,
        TransactionOperation::BeginDelete {
            key: spec(Some("pod-a")).key,
        },
    );
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    assert_eq!(selected.as_ref().unwrap().counts(), (0, 0, 0));
}

#[tokio::test]
async fn legacy_or_unplaced_addresses_never_become_bound_candidates() {
    let (_directory, inventory) = inventory(None);
    apply(
        &mut *inventory.journal.lock().await,
        TransactionOperation::Commit {
            key: spec(None).key,
        },
    );
    let (evidence, context) = placement("pod-a", 17, true);
    let mut selected = None;
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    assert_eq!(selected.as_ref().unwrap().counts(), (0, 0, 0));
    let mut unplaced = inventory
        .journal
        .lock()
        .await
        .iter()
        .next()
        .unwrap()
        .clone();
    unplaced.spec.workload_uid = Some("pod-a".into());
    unplaced.creation_token = Some([7; 32]);
    unplaced.lease.ipv4.address = "10.42.0.99".parse().unwrap();
    unplaced.lease.ipv6.address = "fd42::99".parse().unwrap();
    assert!(matching_owners(&unplaced, &evidence).unwrap().is_none());
}

pub(crate) async fn ready_inventory(uid: &str) -> (tempfile::TempDir, CniAttachmentInventory) {
    let (directory, inventory) = inventory(Some(uid));
    apply(
        &mut *inventory.journal.lock().await,
        TransactionOperation::Commit {
            key: spec(Some(uid)).key,
        },
    );
    (directory, inventory)
}

#[tokio::test]
async fn uid_or_context_mismatch_clears_previous_and_changed_digest_is_rejoined() {
    let (_directory, inventory) = inventory(Some("pod-a"));
    apply(
        &mut *inventory.journal.lock().await,
        TransactionOperation::Commit {
            key: spec(Some("pod-a")).key,
        },
    );
    let (evidence, context) = placement("pod-a", 17, true);
    let mut selected = None;
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    let (foreign, _) = placement("pod-b", 17, true);
    assert!(
        inventory
            .refresh(&mut selected, &foreign, &context)
            .await
            .is_err()
    );
    assert!(selected.is_none());
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    let mut changed = context.clone();
    changed.recipient.node_uid.push('x');
    assert!(
        inventory
            .refresh(&mut selected, &evidence, &changed)
            .await
            .is_err()
    );
    assert!(selected.is_none());
    let (changed, _) = placement("pod-a", 29, false);
    inventory
        .refresh(&mut selected, &changed, &context)
        .await
        .unwrap();
    assert_eq!(
        selected.as_ref().unwrap().records[0].1,
        [Some(IdentityId::new(29)), None]
    );
    assert_eq!(selected.as_ref().unwrap().addresses, 1);
}

#[tokio::test]
async fn cancellation_waiting_for_journal_lock_cannot_retain_previous_selection() {
    let (_directory, inventory) = inventory(Some("pod-a"));
    let (evidence, context) = placement("pod-a", 17, true);
    let mut selected = None;
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    let _locked = inventory.journal.lock().await;
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1),
            inventory.refresh(&mut selected, &evidence, &context)
        )
        .await
        .is_err()
    );
    assert!(selected.is_none());
}

#[tokio::test]
async fn uncertain_persistence_rejects_selection_until_durable_recovery() {
    let (directory, inventory) = inventory(Some("pod-a"));
    let (evidence, context) = placement("pod-a", 17, true);
    let mut selected = None;
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    let temporary = directory.path().join("attachments.json.tmp");
    std::fs::create_dir(&temporary).unwrap();
    assert!(
        inventory
            .journal
            .lock()
            .await
            .apply(TransactionRequest::new(
                CNI_TRANSACTION_SCHEMA_VERSION,
                TransactionOperation::Commit {
                    key: spec(Some("pod-a")).key
                }
            ))
            .is_err()
    );
    assert!(
        inventory
            .refresh(&mut selected, &evidence, &context)
            .await
            .is_err()
    );
    assert!(selected.is_none());
    std::fs::remove_dir(&temporary).unwrap();
    apply(
        &mut *inventory.journal.lock().await,
        TransactionOperation::Commit {
            key: spec(Some("pod-a")).key,
        },
    );
    inventory
        .refresh(&mut selected, &evidence, &context)
        .await
        .unwrap();
    assert_eq!(selected.as_ref().unwrap().addresses, 2);
}

#[test]
fn payload_budget_accepts_exact_limit_and_rejects_overflow() {
    assert_eq!(
        charge_payload(MAX_RETAINED_BYTES - 1, 1).unwrap(),
        MAX_RETAINED_BYTES
    );
    assert!(charge_payload(MAX_RETAINED_BYTES, 1).is_err());
    assert!(charge_payload(usize::MAX, 1).is_err());
}
