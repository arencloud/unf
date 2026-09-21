//! Private-network composition of the real publisher/main hook. The placement
//! input is a local fixture, not authenticated controller/disaster-recovery proof.
use super::*;
use std::os::fd::AsFd as _;
use unf_cni_state::{
    AttachmentJournal, AttachmentKey, AttachmentRecord, AttachmentSpec,
    CNI_TRANSACTION_SCHEMA_VERSION, TransactionOperation, TransactionRequest,
};
use unf_encryption::{
    AdmittedNodeLocalPlan, AdmittedNodeLocalPlanDigest, EncryptionGenerationRecipient,
    EncryptionLocalityCertificate, EncryptionLocalityContext, IpPrefix,
    KubernetesEncryptionNodeSnapshot, KubernetesEncryptionWorkloadSnapshot, NodeLocalPlanMode,
    NodeLocalPlanSnapshot, NodeLocalPlanSnapshotDigest, VerifiedEncryptionLocality,
    project_kubernetes_encryption_placement,
};
use unf_ipam::NodeBlockProvider;
use unf_link::VethPlan;
use unf_route::{NativeRoutePlan, NativeRoutingProvider, RoutingProvider as _};

mod dsr;
mod sockets;

fn apply(journal: &mut AttachmentJournal, operation: TransactionOperation) {
    journal
        .apply(TransactionRequest::new(
            CNI_TRANSACTION_SCHEMA_VERSION,
            operation,
        ))
        .unwrap();
}

async fn create(journal: &mut AttachmentJournal, index: usize) -> NativeRoutePlan {
    let name = format!("main-locality-{index}");
    let namespace = std::env::var(format!("UNF_MAIN_PEER_{index}")).unwrap();
    assert!(namespace.starts_with("/var/run/netns/unf-main-p-"));
    let spec = AttachmentSpec {
        key: AttachmentKey {
            network: "main-locality".into(),
            container_id: name.clone(),
            ifname: "eth0".into(),
        },
        netns: namespace,
        mtu: 1400,
        workload_uid: Some(name.into()),
    };
    apply(
        journal,
        TransactionOperation::Prepare {
            attachment: spec.clone(),
        },
    );
    let record = journal.get(&spec.key).unwrap();
    let links = VethPlan::from_attachment(record)
        .unwrap()
        .apply()
        .await
        .unwrap();
    let route = NativeRoutingProvider::new(1400)
        .plan(record, &links)
        .unwrap();
    route.apply().await.unwrap();
    apply(journal, TransactionOperation::Commit { key: spec.key });
    route
}

fn evidence(records: &[AttachmentRecord]) -> (VerifiedEncryptionLocality, AdmittedNodeLocalPlan) {
    let recipient = EncryptionGenerationRecipient {
        node_name: "worker-a".into(),
        node_uid: "private-main-node".into(),
    };
    let context = EncryptionLocalityContext {
        cluster_id: "private-main-fixture".into(),
        recipient: recipient.clone(),
        membership_revision: Revision::new(1),
        identity_epoch: 7,
        identity_revision: Revision::new(3),
        routing_revision: Revision::new(9),
    };
    let node = KubernetesEncryptionNodeSnapshot {
        name: recipient.node_name.clone(),
        uid: recipient.node_uid.clone(),
        ready: true,
        managed: true,
        pod_cidrs: vec![
            IpPrefix {
                address: "10.244.46.0".parse().unwrap(),
                prefix_len: 24,
            },
            IpPrefix {
                address: "fd46::".parse().unwrap(),
                prefix_len: 120,
            },
        ],
        underlay_addresses: vec!["192.0.2.10".parse().unwrap()],
    };
    let workloads = records
        .iter()
        .zip([11, 22])
        .map(|(record, id)| KubernetesEncryptionWorkloadSnapshot {
            workload_uid: record.spec.workload_uid.as_deref().unwrap().into(),
            identity: IdentityId::new(id),
            node_name: recipient.node_name.clone(),
            host_network: false,
            addresses: vec![
                record.lease.ipv4.address.into(),
                record.lease.ipv6.address.into(),
            ],
        })
        .collect();
    let placement =
        project_kubernetes_encryption_placement(&context.cluster_id, vec![node], workloads)
            .unwrap();
    let verified = EncryptionLocalityCertificate::issue(context.clone(), &placement)
        .unwrap()
        .verify_against(&context, &placement)
        .unwrap();
    // Typed admitted-plan coordinates are fixture input, not cryptographic
    // admission coverage. Real journal, observations, publisher and BPF follow.
    let plan = AdmittedNodeLocalPlan {
        schema_version: 1,
        controller_epoch: 7,
        admitted_digest: AdmittedNodeLocalPlanDigest([1; 32]),
        snapshot: NodeLocalPlanSnapshot {
            schema_version: 1,
            membership_revision: Revision::new(1),
            generation: Revision::new(1),
            recipient,
            mode: NodeLocalPlanMode::Active,
            policy_revision: Revision::new(1),
            service_revision: Revision::new(1),
            egress_revision: Revision::new(1),
            listen_port: 51820,
            persistent_keepalive_seconds: 25,
            epochs: vec![],
            decisions: vec![],
            snapshot_digest: NodeLocalPlanSnapshotDigest([2; 32]),
        },
    };
    (verified, plan)
}

fn transport(maps: &mut encryption_maps::EncryptionMaps, revision: u64, service_revision: u64) {
    // Structurally admitted empty cut allows exact locality preparation only.
    // No Native or Required remote decision exists: a bank miss MUST drop.
    let config = unf_ebpf_common::EncryptionMapConfig {
        generation: 1,
        policy_revision: revision,
        service_revision,
        egress_revision: 1,
        decision_count: 0,
        transport_count: 0,
        schema_version: unf_ebpf_common::ENCRYPTION_MAP_ABI_VERSION,
        active_bank: 0,
        epoch_count: 0,
        path_count: 0,
    };
    maps.config
        .set(0, encryption_maps::encode_map_config(&config), 0)
        .unwrap();
}

async fn publish(
    publisher: &mut crate::locality_publisher::BankPublisher,
    state: &AgentState,
    plan: &AdmittedNodeLocalPlan,
    evidence: &VerifiedEncryptionLocality,
    _object: &Ebpf,
) {
    let inventory = state.cni_inventory.get().unwrap();
    let mut selection = None;
    inventory
        .refresh(&mut selection, evidence, evidence.certificate().context())
        .await
        .unwrap();
    assert_eq!(selection.as_ref().unwrap().counts().0, 2);
    for _ in 0..300 {
        publisher
            .synchronize(state, plan, evidence, selection.as_ref().unwrap())
            .await
            .unwrap();
        if publisher
            .selected_for_test(evidence.certificate().context())
            .unwrap()
        {
            // Exercise actual reuse/readback too, not only first publication.
            publisher
                .synchronize(state, plan, evidence, selection.as_ref().unwrap())
                .await
                .unwrap();
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("actual publisher failed to select a sealed bank within deadline");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires isolated fabric/peer namespaces, private bpffs and actual main ELF"]
#[allow(clippy::too_many_lines)] // Ordered real ownership, delivery, retirement and cleanup.
async fn privileged_publisher_main_hook_delivers_and_revokes_dual_stack() {
    assert_eq!(
        std::env::var("UNF_MAIN_COMPOSITION_ISOLATED").as_deref(),
        Ok("yes")
    );
    let root = PathBuf::from(std::env::var("UNF_MAIN_COMPOSITION_ROOT").unwrap());
    assert!(
        root.to_str()
            .unwrap()
            .starts_with("/tmp/unf-main-composition.")
    );
    let mut args = Args::try_parse_from(["unf-agent"]).unwrap();
    args.node_name = "worker-a".into();
    args.bpf_pin_path = root.join("bpffs/v15");
    args.cni_state_path = root.join("journal/attachments.json");
    let state = test_agent_state();
    crate::locality_runtime::initialize(&args, &state, true).unwrap();
    let runtime = state.locality_runtime.get().unwrap();
    let main = PathBuf::from(std::env::var("UNF_EBPF_OBJECT").unwrap());
    runtime.initialize_bank(&main).unwrap();
    let mut journal = AttachmentJournal::open(
        &args.cni_state_path,
        NodeBlockProvider::new(
            "10.244.46.0/24".parse().unwrap(),
            "fd46::/120".parse().unwrap(),
        ),
    )
    .unwrap();
    runtime.install_journal(&mut journal).unwrap();
    let routing = crate::locality_runtime::begin(&state, LocalityApplyComponent::Routing).unwrap();
    let first = create(&mut journal, 0).await;
    let second = create(&mut journal, 1).await;
    crate::locality_runtime::complete(routing, 7, 9).unwrap();
    let records = journal.records();
    let (evidence, plan) = evidence(&records);
    assert!(
        state
            .cni_inventory
            .set(crate::cni_inventory::CniAttachmentInventory::new(Arc::new(
                tokio::sync::Mutex::new(journal)
            )))
            .is_ok()
    );
    let mut loader = EbpfLoader::new();
    runtime.admission.configure_loader(&mut loader).unwrap();
    let mut object = loader.load_file(&main).unwrap();
    runtime.admission.verify_loaded(&object).unwrap();
    load_dataplane_tail_programs(&mut object).unwrap();
    load_dataplane_program(&mut object, Direction::Ingress).unwrap();
    let identity =
        crate::locality_runtime::begin(&state, LocalityApplyComponent::Identity).unwrap();
    let (mut ids4, mut ids6, mut config) = take_identity_maps(&mut object).unwrap();
    for (record, id) in records.iter().zip([11, 22]) {
        let value = encode_identity_value(IdentityMapValue::new(IdentityId::new(id), 3));
        ids4[0]
            .insert(record.lease.ipv4.address.octets(), value, 0)
            .unwrap();
        ids6[0]
            .insert(record.lease.ipv6.address.octets(), value, 0)
            .unwrap();
    }
    config
        .set(0, encode_identity_config(7, 3, 4, 0).unwrap(), 0)
        .unwrap();
    crate::locality_runtime::complete(identity, 7, 3).unwrap();
    for epoch in [
        &state.desired_identity_epoch,
        &state.applied_identity_epoch,
        &state.desired_remote_route_epoch,
        &state.applied_remote_route_epoch,
    ] {
        epoch.store(7, Ordering::Release);
    }
    for revision in [
        &state.desired_identity_revision,
        &state.applied_identity_revision,
    ] {
        revision.store(3, Ordering::Release);
    }
    for revision in [
        &state.desired_remote_route_revision,
        &state.applied_remote_route_revision,
    ] {
        revision.store(9, Ordering::Release);
    }
    let mut services = test_service_synchronizer(&mut object, root.join("services.json"));
    activate_service_snapshot(
        &mut services,
        &dual_stack_service_snapshot(
            1,
            records[1].lease.ipv4.address,
            records[1].lease.ipv6.address,
            true,
        ),
        None,
        false,
        &state,
    )
    .unwrap();
    let (mut policies, _, _, _, _, mut policy_config) = take_policy_maps(&mut object).unwrap();
    policy_config
        .set(0, encode_policy_config(7, 1, 0, 0).unwrap(), 0)
        .unwrap();
    let mut encryption = take_encryption_maps(&mut object).unwrap();
    transport(&mut encryption, 1, 1);
    sockets::attach(&records, &mut object).await;
    let mut sockets = sockets::Sockets::new(&records);
    sockets.matrix("unpublished", false, false);
    let mut publisher = crate::locality_publisher::BankPublisher::default();
    publish(&mut publisher, &state, &plan, &evidence, &object).await;
    sockets.matrix("published-podip", false, true);
    sockets.matrix("published-service", true, true);
    // The real writer boundary withdraws the same selected main runtime.
    let guard = crate::locality_runtime::begin(&state, LocalityApplyComponent::Routing).unwrap();
    sockets.matrix("writer-pending", false, false);
    crate::locality_runtime::complete(guard, 7, 9).unwrap();
    sockets.matrix("writer-complete-not-republished", false, false);
    publish(&mut publisher, &state, &plan, &evidence, &object).await;
    sockets.matrix("republished", true, true);
    for protocol in [6, 17] {
        let entry = PolicyMapEntry {
            key: unf_state::PolicyMapKey {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(22),
                protocol,
                destination_port: if protocol == 6 { 8080 } else { 5353 },
            },
            decision: PolicyDecisionRecord {
                verdict: Verdict::Deny,
                reason: PolicyReason::ExplicitRule,
                policy_id: Some(PolicyId::new(1)),
                rule_id: Some(RuleId::new(1)),
            },
            shadow: None,
        };
        policies
            .insert(
                encode_policy_key(&entry, 0),
                encode_policy_value(&entry, 2),
                0,
            )
            .unwrap();
    }
    policy_config
        .set(0, encode_policy_config(7, 2, 2, 0).unwrap(), 0)
        .unwrap();
    transport(&mut encryption, 2, 1);
    sockets.matrix("policy-deny-before-locality", true, false);
    policy_config
        .set(0, encode_policy_config(7, 3, 0, 0).unwrap(), 0)
        .unwrap();
    transport(&mut encryption, 3, 1);
    sockets.matrix("policy-restored", false, true);
    dsr::exercise(
        &mut services,
        &mut encryption,
        &state,
        &mut publisher,
        &plan,
        &evidence,
        &object,
        &records,
        &mut sockets,
    )
    .await;
    let mut journal = state.cni_inventory.get().unwrap().journal.lock().await;
    apply(
        &mut journal,
        TransactionOperation::BeginDelete {
            key: records[0].spec.key.clone(),
        },
    );
    sockets.matrix("retired-source-live-links", false, false);
    publisher.clear().unwrap();
    drop(object); // actual Aya-owned TC links detach before private device deletion.
    for (record, route) in records.iter().zip([first, second]) {
        apply(
            &mut journal,
            TransactionOperation::BeginDelete {
                key: record.spec.key.clone(),
            },
        );
        route.delete().await.unwrap();
        VethPlan::from_attachment(record)
            .unwrap()
            .delete()
            .await
            .unwrap();
        apply(
            &mut journal,
            TransactionOperation::CompleteDelete {
                key: record.spec.key.clone(),
            },
        );
    }
    assert!(journal.is_empty());
    sockets.finish();
    drop(journal);
    drop(publisher);
    drop(state);
    // Only this test's four exact runtime pins, after all bank/owner lifetime
    // guards have drained. Unexpected preparation residue fails rmdir below.
    let locality = root.join("bpffs/locality");
    for name in [
        "UL_INPUT_V1",
        "UL_FENCE_V1",
        "UL_RESUME_V1",
        "UL_DISPATCH_V1",
    ] {
        fs::remove_file(locality.join("v1").join(name)).unwrap();
    }
    fs::remove_dir(locality.join("v1")).unwrap();
    fs::remove_dir(locality.join("preparations")).unwrap();
    fs::remove_dir(locality).unwrap();
    println!(
        "main-publisher-composition: PASS actual-publisher=true actual-main=true synthetic-packet-input=false controller-admission-tested=false"
    );
}
