//! Disposable real-journal/link/route/placement join, never a packet program.
use std::future::Future as _;
use std::path::Path;

use unf_cni_state::{
    AttachmentJournal, AttachmentKey, AttachmentRecord, AttachmentSpec,
    CNI_TRANSACTION_SCHEMA_VERSION, TransactionOperation, TransactionRequest,
};
use unf_common::{IdentityId, Revision};
use unf_encryption::{
    EncryptionGenerationRecipient, EncryptionLocalityCertificate, EncryptionLocalityContext,
    IpPrefix, KubernetesEncryptionNodeSnapshot, KubernetesEncryptionWorkloadSnapshot,
    VerifiedEncryptionLocality, project_kubernetes_encryption_placement,
};
use unf_ipam::NodeBlockProvider;
use unf_link::VethPlan;
use unf_locality::{IncarnationGate, LocalityObservationWorker, ObservedLocalityBank};
use unf_route::{NativeRoutePlan, NativeRoutingProvider, RoutingProvider};

#[path = "support/journal_floor.rs"]
mod journal_floor;
#[path = "support/kernel_bank.rs"]
mod kernel_bank;
#[path = "support/runtime_owner.rs"]
mod runtime_owner;

fn request(operation: TransactionOperation) -> TransactionRequest {
    TransactionRequest::new(CNI_TRANSACTION_SCHEMA_VERSION, operation)
}

async fn create(
    journal: &mut AttachmentJournal,
    provider: NativeRoutingProvider,
    name: &str,
    namespace: &str,
) -> NativeRoutePlan {
    let spec = AttachmentSpec {
        key: AttachmentKey {
            network: "observed-bank-test".into(),
            container_id: name.into(),
            ifname: "eth0".into(),
        },
        netns: namespace.into(),
        mtu: 1400,
        workload_uid: Some(name.into()),
    };
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: spec.clone(),
        }))
        .unwrap();
    let preparing = journal.get(&spec.key).unwrap();
    let links = VethPlan::from_attachment(preparing)
        .unwrap()
        .apply()
        .await
        .unwrap();
    let plan = provider.plan(preparing, &links).unwrap();
    plan.apply().await.unwrap();
    journal
        .apply(request(TransactionOperation::Commit { key: spec.key }))
        .unwrap();
    plan
}

fn evidence(
    records: &[AttachmentRecord],
) -> (VerifiedEncryptionLocality, EncryptionLocalityContext) {
    let context = EncryptionLocalityContext {
        cluster_id: "isolated-bank".into(),
        recipient: EncryptionGenerationRecipient {
            node_name: "fabric".into(),
            node_uid: "fabric-uid".into(),
        },
        membership_revision: Revision::new(1),
        identity_epoch: 2,
        identity_revision: Revision::new(3),
        routing_revision: Revision::new(4),
    };
    let node = KubernetesEncryptionNodeSnapshot {
        name: "fabric".into(),
        uid: "fabric-uid".into(),
        ready: true,
        managed: true,
        pod_cidrs: vec![
            IpPrefix {
                address: "10.244.45.0".parse().unwrap(),
                prefix_len: 24,
            },
            IpPrefix {
                address: "fd45::".parse().unwrap(),
                prefix_len: 120,
            },
        ],
        underlay_addresses: vec!["192.0.2.10".parse().unwrap()],
    };
    let workloads = records
        .iter()
        .map(|record| KubernetesEncryptionWorkloadSnapshot {
            workload_uid: record.spec.workload_uid.as_deref().unwrap().into(),
            identity: IdentityId::new(17),
            node_name: "fabric".into(),
            host_network: false,
            addresses: vec![
                record.lease.ipv4.address.into(),
                record.lease.ipv6.address.into(),
            ],
        })
        .collect();
    let placement =
        project_kubernetes_encryption_placement("isolated-bank", vec![node], workloads).unwrap();
    let certificate = EncryptionLocalityCertificate::issue(context.clone(), &placement).unwrap();
    (
        certificate.verify_against(&context, &placement).unwrap(),
        context,
    )
}

fn cookie(hex: &str) -> u64 {
    assert_eq!(hex.len(), 16);
    let mut bytes = [0; 8];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    u64::from_le_bytes(bytes)
}

async fn prepare(
    provider: NativeRoutingProvider,
    records: &[AttachmentRecord],
    evidence: &VerifiedEncryptionLocality,
    context: &EncryptionLocalityContext,
) -> ObservedLocalityBank {
    LocalityObservationWorker::default()
        .try_observe(
            provider,
            records.to_vec(),
            evidence.clone(),
            context.clone(),
        )
        .unwrap()
        .unwrap()
        .finish()
        .await
        .unwrap()
}

async fn verify_failure_retirement(
    provider: NativeRoutingProvider,
    records: &[AttachmentRecord],
    evidence: &VerifiedEncryptionLocality,
    context: &EncryptionLocalityContext,
    plan: &NativeRoutePlan,
) {
    let mut bank = prepare(provider, records, evidence, context).await;
    plan.delete().await.unwrap();
    assert!(bank.recheck().await.is_err());
    assert!(bank.endpoints().is_none());
    assert!(bank.addresses().is_none());
    plan.apply().await.unwrap();
    assert!(
        bank.recheck().await.is_err(),
        "restoring routes cannot rearm a failed preparation"
    );
    let mut fresh = prepare(provider, records, evidence, context).await;
    fresh.recheck().await.unwrap();
}

#[tokio::main(flavor = "current_thread")]
#[allow(clippy::too_many_lines)] // One ordered disposable journal/namespace lifecycle.
async fn main() {
    assert_eq!(
        std::env::var("UNF_OBSERVED_BANK_ISOLATED_CONTAINER").as_deref(),
        Ok("yes")
    );
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        5,
        "peer namespace paths, independent host/peer UDP socket cookies"
    );
    for path in &args[..2] {
        assert!(Path::new(path).is_absolute());
        assert!(path.starts_with("/var/run/netns/unf-ob-p-"));
    }
    let directory = tempfile::tempdir().unwrap();
    let mut journal = AttachmentJournal::open(
        directory.path().join("journal.json"),
        NodeBlockProvider::new(
            "10.244.45.0/24".parse().unwrap(),
            "fd45::/120".parse().unwrap(),
        ),
    )
    .unwrap();
    let provider = NativeRoutingProvider::new(1400);
    let first_plan = create(&mut journal, provider, "first", &args[0]).await;
    let second_plan = create(&mut journal, provider, "second", &args[1]).await;
    let records = journal.records();
    let (evidence, context) = evidence(&records);
    if std::env::var("UNF_LOCALITY_RUNTIME_OWNER_TEST").as_deref() == Ok("yes") {
        runtime_owner::verify(
            Path::new(&std::env::var("UNF_KERNEL_BANK_BPFFS").unwrap()),
            &context,
        )
        .unwrap();
    }
    if std::env::var("UNF_LOCALITY_AGENT_STARTUP_TEST").as_deref() == Ok("yes") {
        runtime_owner::verify_agent_startup(
            Path::new(&std::env::var("UNF_KERNEL_BANK_BPFFS").unwrap()),
            &context,
        )
        .unwrap();
    }
    let gate = IncarnationGate::install(&mut journal, 8).unwrap();
    if std::env::var("UNF_LOCALITY_JOURNAL_FLOOR_TEST").as_deref() == Ok("yes") {
        journal_floor::verify(
            &directory.path().join("journal.json"),
            NodeBlockProvider::new(
                "10.244.45.0/24".parse().unwrap(),
                "fd45::/120".parse().unwrap(),
            ),
        )
        .unwrap();
    }
    let cut = journal.cut().unwrap();
    let mut bank = prepare(provider, &records, &evidence, &context).await;
    assert_eq!(bank.endpoints().unwrap().len(), 2);
    assert_eq!(bank.addresses().unwrap().len(), 4);
    for (index, endpoint) in bank.endpoints().unwrap().iter().enumerate() {
        assert_eq!(endpoint.attachment(), &records[index]);
        let cookies = endpoint.namespace_cookies().unwrap();
        assert_eq!(cookies.host(), cookie(&args[2]));
        assert_eq!(cookies.peer(), cookie(&args[3 + index]));
        let plan = VethPlan::from_attachment(&records[index]).unwrap();
        assert_eq!(endpoint.ownership_aliases(), plan.ownership_aliases());
        assert!(endpoint.namespace_descriptors().is_some());
    }
    bank.recheck().await.unwrap();
    let leased = bank.bind(&journal, &cut, &gate, &context).unwrap();
    assert_eq!(leased.observed().addresses().unwrap().len(), 4);
    assert_eq!(leased.leases().len(), 2);
    assert!(
        leased
            .leases()
            .iter()
            .all(|lease| gate.is_current(lease).unwrap())
    );
    verify_failure_retirement(provider, &records, &evidence, &context, &first_plan).await;
    verify_cancellation(provider, &records, &evidence, &context).await;
    let mut foreign = context.clone();
    foreign.identity_revision = Revision::new(99);
    let foreign_bank = prepare(provider, &records, &evidence, &context).await;
    assert!(foreign_bank.bind(&journal, &cut, &gate, &foreign).is_err());
    let pending = prepare(provider, &records, &evidence, &context).await;
    if std::env::var("UNF_KERNEL_BANK_ISOLATED_CONTAINER").as_deref() == Ok("yes") {
        let bank = prepare(provider, &records, &evidence, &context).await;
        let leased = bank.bind(&journal, &cut, &gate, &context).unwrap();
        kernel_bank::verify(leased, &mut journal, &gate, &context, &second_plan)
            .await
            .unwrap();
    }
    journal
        .apply(request(TransactionOperation::BeginDelete {
            key: records[0].spec.key.clone(),
        }))
        .unwrap();
    assert!(pending.bind(&journal, &cut, &gate, &context).is_err());
    assert!(!gate.is_current(&leased.leases()[0]).unwrap());
    assert!(gate.is_current(&leased.leases()[1]).unwrap());
    for (record, plan) in records.iter().zip([first_plan, second_plan]) {
        journal
            .apply(request(TransactionOperation::BeginDelete {
                key: record.spec.key.clone(),
            }))
            .unwrap();
        plan.delete().await.unwrap();
        VethPlan::from_attachment(record)
            .unwrap()
            .delete()
            .await
            .unwrap();
        journal
            .apply(request(TransactionOperation::CompleteDelete {
                key: record.spec.key.clone(),
            }))
            .unwrap();
    }
    assert!(journal.is_empty());
    assert!(
        leased
            .leases()
            .iter()
            .all(|lease| !gate.is_current(lease).unwrap())
    );
    drop((leased, gate, journal));
    directory.close().unwrap();
    println!(
        "observed-locality-bank: PASS schema=1 endpoints=2 addresses=4 independent-cookie-parity=true route-drift-retired=true cancellation-retired=true stale-context-rejected=true stale-journal-rejected=true scoped-revocation=true cleanup=true kernel-admitted=false packet-delivery-tested=false"
    );
}

async fn verify_cancellation(
    provider: NativeRoutingProvider,
    records: &[AttachmentRecord],
    evidence: &VerifiedEncryptionLocality,
    context: &EncryptionLocalityContext,
) {
    let mut bank = prepare(provider, records, evidence, context).await;
    let mut check = Box::pin(bank.recheck());
    std::future::poll_fn(|cx| {
        assert!(
            check.as_mut().poll(cx).is_pending(),
            "recheck did not suspend"
        );
        std::task::Poll::Ready(())
    })
    .await;
    drop(check);
    assert!(bank.endpoints().is_none());
    assert!(bank.addresses().is_none());
    assert!(bank.recheck().await.is_err());
}
