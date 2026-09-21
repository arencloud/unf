use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unf_common::IdentityId;
use unf_encryption::{
    EncryptionGenerationRecipient, NodeLocalDecisionPlan, NodeLocalPlanMode, NodeLocalPlanSnapshot,
    NodeLocalPlanSnapshotDigest,
};

// This is a placement-coordinate fixture, not a valid cryptographic plan.
// Production receives plans only through the existing durable admission path.
fn plan() -> AdmittedNodeLocalPlan {
    AdmittedNodeLocalPlan {
        schema_version: 1,
        controller_epoch: 7,
        admitted_digest: AdmittedNodeLocalPlanDigest([1; 32]),
        snapshot: NodeLocalPlanSnapshot {
            schema_version: 1,
            membership_revision: Revision::new(2),
            generation: Revision::new(3),
            recipient: EncryptionGenerationRecipient {
                node_name: "worker-a".into(),
                node_uid: "node-a".into(),
            },
            mode: NodeLocalPlanMode::Active,
            policy_revision: Revision::new(4),
            service_revision: Revision::new(5),
            egress_revision: Revision::new(6),
            listen_port: 51820,
            persistent_keepalive_seconds: 25,
            epochs: vec![],
            decisions: vec![NodeLocalDecisionPlan {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(21),
                disposition: EncryptionDisposition::Required,
                contract_epoch: Some(1),
                plan_index: Some(0),
            }],
            snapshot_digest: NodeLocalPlanSnapshotDigest([2; 32]),
        },
    }
}

fn state() -> AgentState {
    let state = crate::tests::test_agent_state();
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
        &state.desired_remote_route_revision,
        &state.applied_remote_route_revision,
    ] {
        revision.store(9, Ordering::Release);
    }
    state
}

#[test]
fn locality_fetch_requires_required_demand_and_matching_applied_epochs() {
    let mut plan = plan();
    let state = state();
    let context = applied_context(&plan, "cluster-a", &state).unwrap();
    assert_eq!(context.identity_epoch, 7);
    assert_eq!(context.routing_revision, Revision::new(9));
    for coordinate in [
        &state.desired_identity_epoch,
        &state.applied_identity_epoch,
        &state.desired_remote_route_epoch,
        &state.applied_remote_route_epoch,
        &state.desired_identity_revision,
        &state.applied_identity_revision,
        &state.desired_remote_route_revision,
        &state.applied_remote_route_revision,
    ] {
        let old = coordinate.swap(0, Ordering::AcqRel);
        assert!(applied_context(&plan, "cluster-a", &state).is_none());
        coordinate.store(old + 1, Ordering::Release);
        assert!(applied_context(&plan, "cluster-a", &state).is_none());
        coordinate.store(old, Ordering::Release);
    }
    plan.snapshot.decisions[0].disposition = EncryptionDisposition::Native;
    assert!(applied_context(&plan, "cluster-a", &state).is_none());
    plan.snapshot.decisions[0].disposition = EncryptionDisposition::Required;
    plan.controller_epoch += 1;
    assert!(applied_context(&plan, "cluster-a", &state).is_none());
    plan.controller_epoch -= 1;
    plan.snapshot.recipient.node_name.push('x');
    assert!(applied_context(&plan, "cluster-a", &state).is_none());
}

#[test]
fn stream_budget_accepts_exact_bound_and_rejects_before_append() {
    let mut bytes = vec![7; MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES - 1];
    append_bounded(&mut bytes, &[8]).unwrap();
    assert_eq!(bytes.len(), MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES);
    assert!(append_bounded(&mut bytes, &[9]).is_err());
    assert_eq!(bytes.len(), MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES);
    assert_eq!(bytes.last(), Some(&8));
}

#[test]
fn placement_cache_is_cut_and_plan_bound_and_explicitly_clearable() {
    let plan = plan();
    let context = applied_context(&plan, "cluster-a", &state()).unwrap();
    let request = EncryptionLocalityRequest::issue(context.clone()).unwrap();
    let node = unf_encryption::KubernetesEncryptionNodeSnapshot {
        name: "worker-a".into(),
        uid: "node-a".into(),
        ready: true,
        managed: true,
        pod_cidrs: vec![unf_encryption::IpPrefix {
            address: "10.42.0.0".parse().unwrap(),
            prefix_len: 24,
        }],
        underlay_addresses: vec!["192.0.2.10".parse().unwrap()],
    };
    let response =
        EncryptionLocalityResponse::issue(&request, &context, vec![node], vec![]).unwrap();
    let verified = EncryptionLocalityResponse::decode_authenticated(
        &serde_json::to_vec(&response).unwrap(),
        &request,
        &context,
    )
    .unwrap();
    let mut cache = PlacementCache {
        candidate: Some((plan.admitted_digest, verified)),
        ..PlacementCache::default()
    };
    assert!(cache.matches(&plan, &context));
    let observed_state = state();
    record_observation(&cache, &observed_state, false);
    let report = status_for(&observed_state);
    assert_eq!(report.observation.phase, PlacementPhase::Replayed);
    assert!(report.matches_reported_identity_and_routing);
    assert!(!report.kernel_admitted && !report.observed_delivery);
    observed_state
        .applied_remote_route_revision
        .store(99, Ordering::Release);
    let stale = status_for(&observed_state);
    assert!(!stale.matches_reported_identity_and_routing);
    assert_eq!(stale.observation.phase, PlacementPhase::Replayed);
    let mut changed = plan.clone();
    changed.admitted_digest.0[0] ^= 1;
    assert!(!cache.matches(&changed, &context));
    let mut changed = context.clone();
    changed.routing_revision = changed.routing_revision.next();
    assert!(!cache.matches(&plan, &changed));
    cache.clear().unwrap();
    assert!(!cache.matches(&plan, &context));
}

#[tokio::test]
async fn locality_status_is_observational_and_never_kernel_or_delivery_authority() {
    let state = std::sync::Arc::new(state());
    let report = status(axum::extract::State(state.clone())).await.0;
    let wire = serde_json::to_value(report).unwrap();
    assert_eq!(wire["schemaVersion"], 1);
    assert_eq!(wire["scope"], "localityPlacementCandidate");
    assert_eq!(wire["observation"]["phase"], "absent");
    assert_eq!(wire["kernelAdmitted"], false);
    assert_eq!(wire["observedDelivery"], false);
    assert_eq!(wire["matchesReportedIdentityAndRouting"], false);
    record_observation(&PlacementCache::default(), &state, true);
    let report = status_for(&state);
    assert_eq!(report.observation.phase, PlacementPhase::Failed);
    assert!(report.observation.observed_at_unix_ms > 0);
    assert!(!report.kernel_admitted && !report.observed_delivery);
}

#[tokio::test]
async fn journal_selection_counts_remain_observational_and_clear_with_candidate() {
    let (_directory, inventory) = crate::cni_inventory::tests::ready_inventory("pod-a").await;
    let (evidence, context) = crate::cni_inventory::tests::placement("pod-a", 17, true);
    let state = state();
    let mut plan = plan();
    plan.controller_epoch = context.identity_epoch;
    plan.snapshot.membership_revision = context.membership_revision;
    for epoch in [
        &state.desired_identity_epoch,
        &state.applied_identity_epoch,
        &state.desired_remote_route_epoch,
        &state.applied_remote_route_epoch,
    ] {
        epoch.store(context.identity_epoch, Ordering::Release);
    }
    for revision in [
        &state.desired_identity_revision,
        &state.applied_identity_revision,
    ] {
        revision.store(context.identity_revision.get(), Ordering::Release);
    }
    for revision in [
        &state.desired_remote_route_revision,
        &state.applied_remote_route_revision,
    ] {
        revision.store(context.routing_revision.get(), Ordering::Release);
    }
    assert!(state.cni_inventory.set(inventory).is_ok());
    let mut cache = PlacementCache {
        candidate: Some((plan.admitted_digest, evidence)),
        ..PlacementCache::default()
    };
    refresh_attachments(&mut cache, &state, &plan, &context)
        .await
        .unwrap();
    record_observation(&cache, &state, false);
    let report = status_for(&state);
    assert_eq!(report.observation.journal_selected_attachments, 1);
    assert_eq!(report.observation.journal_selected_addresses, 2);
    assert!(report.observation.journal_selected_payload_bytes > 0);
    assert!(!report.kernel_admitted && !report.observed_delivery);
    state
        .desired_remote_route_revision
        .store(99, Ordering::Release);
    assert!(
        refresh_attachments(&mut cache, &state, &plan, &context)
            .await
            .is_err()
    );
    assert!(cache.attachments.is_none());
    record_observation(&cache, &state, true);
    assert_eq!(status_for(&state).observation.journal_selected_addresses, 0);
    cache.clear().unwrap();
    assert!(cache.attachments.is_none());
    record_observation(&cache, &state, false);
    let report = status_for(&state);
    assert_eq!(report.observation.phase, PlacementPhase::Absent);
    assert_eq!(report.observation.journal_selected_attachments, 0);
    assert_eq!(report.observation.journal_selected_addresses, 0);
    assert_eq!(report.observation.journal_selected_payload_bytes, 0);
    assert!(!report.kernel_admitted && !report.observed_delivery);
}

async fn http_response(
    headers: &'static str,
    chunks: usize,
) -> (reqwest::Response, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let _ = stream.read(&mut request).await.unwrap();
        stream.write_all(headers.as_bytes()).await.unwrap();
        let chunk = vec![b'x'; 1024 * 1024];
        for _ in 0..chunks {
            if stream.write_all(b"100000\r\n").await.is_err()
                || stream.write_all(&chunk).await.is_err()
                || stream.write_all(b"\r\n").await.is_err()
            {
                return;
            }
        }
        let _ = stream.write_all(b"0\r\n\r\n").await;
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    (
        client
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap(),
        server,
    )
}

#[tokio::test]
async fn actual_http_stream_rejects_oversize_without_content_length() {
    let (response, server) = http_response(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        17,
    )
    .await;
    assert!(collect_response(response).await.is_err());
    server.await.unwrap();
    let (response, server) = http_response(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        1,
    )
    .await;
    assert_eq!(collect_response(response).await.unwrap().len(), 1024 * 1024);
    server.await.unwrap();
}

#[tokio::test]
async fn actual_http_rejects_oversize_headers_status_and_truncation() {
    for header in [
        "HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 302 Found\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n",
    ] {
        let (response, server) = http_response(header, 0).await;
        assert!(collect_response(response).await.is_err(), "{header}");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_replay_keeps_the_single_worker_slot_until_real_completion() {
    let plan = plan();
    let context = applied_context(&plan, "cluster-a", &state()).unwrap();
    let mut cache = PlacementCache::default();
    let slot = cache.work_slot.clone().try_acquire_owned().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let work = tokio::task::spawn_blocking(move || -> Result<VerifiedEncryptionLocality> {
        let _slot = slot;
        started_tx.send(()).unwrap();
        release_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        bail!("test replay completed without a candidate")
    });
    cache.pending = Some(PendingPlacement {
        context,
        plan_digest: plan.admitted_digest,
        task: tokio::spawn(async move { work.await.unwrap() }),
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), started_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(!cache.pending.as_ref().unwrap().task.is_finished());
    let observed_state = state();
    record_observation(&cache, &observed_state, false);
    assert_eq!(
        status_for(&observed_state).observation.phase,
        PlacementPhase::Fetching
    );
    cache.clear().unwrap();
    assert!(cache.pending.is_none());
    assert!(cache.work_slot.clone().try_acquire_owned().is_err());
    release_tx.send(()).unwrap();
    let slot = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        cache.work_slot.clone().acquire_owned(),
    )
    .await
    .unwrap()
    .unwrap();
    drop(slot);
    assert_eq!(cache.work_slot.available_permits(), 1);
}
