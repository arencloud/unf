use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use unf_encryption::{CapturedEncryptionLocality, IpPrefix, KubernetesEncryptionNodeSnapshot};

fn captured() -> (CapturedEncryptionLocality, VerifiedEncryptionLocality) {
    let plan = plan();
    let context = applied_context(&plan, "cluster-a", &state()).unwrap();
    let request = EncryptionLocalityRequest::issue(context.clone()).unwrap();
    let response = EncryptionLocalityResponse::issue(
        &request,
        &context,
        vec![KubernetesEncryptionNodeSnapshot {
            name: context.recipient.node_name.clone(),
            uid: context.recipient.node_uid.clone(),
            ready: true,
            managed: true,
            pod_cidrs: vec![IpPrefix {
                address: "10.42.0.0".parse().unwrap(),
                prefix_len: 24,
            }],
            underlay_addresses: vec!["192.0.2.10".parse().unwrap()],
        }],
        vec![],
    )
    .unwrap();
    EncryptionLocalityResponse::capture_authenticated(
        &serde_json::to_vec(&response).unwrap(),
        &request,
        &context,
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires root-owned private checkpoint filesystem in isolated diagnostic"]
#[allow(clippy::too_many_lines)] // Explicit ordered file-shape/ownership and offline-worker negatives.
async fn privileged_private_checkpoint_replay_is_bounded_and_offline() {
    assert_eq!(
        std::env::var("UNF_MAIN_COMPOSITION_ISOLATED").as_deref(),
        Ok("yes")
    );
    let directory = tempfile::Builder::new()
        .prefix("unf-private-placement-")
        .tempdir()
        .unwrap();
    let path = super::super::checkpoint::path(&directory.path().join("plan.json"));
    let (captured, original) = captured();
    let context = captured.context().clone();
    assert!(super::super::checkpoint::load(&path).unwrap().is_none());
    super::super::checkpoint::save(&path, &captured, &context).unwrap();
    let bytes = super::super::checkpoint::load(&path).unwrap().unwrap();
    assert_eq!(
        CapturedEncryptionLocality::replay_private_checkpoint(&bytes, &context).unwrap(),
        original
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(super::super::checkpoint::load(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = directory.path().join("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(super::super::checkpoint::load(&alias).is_err());
    assert!(super::super::checkpoint::load(&path).is_err());
    fs::remove_file(&alias).unwrap();
    symlink(&path, &alias).unwrap();
    assert!(super::super::checkpoint::load(&alias).is_err());
    fs::remove_file(&alias).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &alias,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let before = std::time::Instant::now();
    assert!(super::super::checkpoint::load(&alias).is_err());
    assert!(
        before.elapsed() < std::time::Duration::from_secs(1),
        "FIFO open blocked"
    );
    fs::remove_file(&alias).unwrap();
    let oversized = fs::File::create(&alias).unwrap();
    oversized
        .set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    oversized
        .set_len(unf_encryption::MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES as u64 + 1)
        .unwrap();
    assert!(super::super::checkpoint::load(&alias).is_err());
    drop(oversized);
    fs::remove_file(&alias).unwrap();
    let mut foreign = context.clone();
    foreign.recipient.node_uid.push('x');
    assert!(super::super::checkpoint::save(&path, &captured, &foreign).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let original_wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for pointer in ["/schemaVersion", "/request/context/recipient/nodeUid"] {
        let mut altered = original_wire.clone();
        *altered.pointer_mut(pointer).unwrap() = if pointer == "/schemaVersion" {
            serde_json::json!(2)
        } else {
            serde_json::json!("foreign-node")
        };
        fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(super::super::checkpoint::save(&path, &captured, &context).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "foreign source was overwritten"
        );
    }
    fs::write(&path, &bytes).unwrap(); // Restore only this disposable test's file.
    let temporary = directory.path().join(".locality-placement-source.tmp");
    fs::write(&temporary, b"partial").unwrap();
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
    super::super::checkpoint::save(&path, &captured, &context).unwrap();
    assert!(!temporary.exists());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let unsafe_parent = directory.path().join("unsafe");
    fs::create_dir(&unsafe_parent).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(super::super::checkpoint::load(&unsafe_parent.join("absent")).is_err());
    let mut plans = EncryptionPlanSynchronizer::recover(
        None,
        crate::ReloadingControllerClient::without_custom_trust(
            crate::Counter::default(),
            crate::Counter::default(),
        )
        .unwrap(),
        directory.path().join("absent-token"),
        std::time::Duration::from_secs(1),
        "worker-a".into(),
        directory.path().join("plan.json"),
    )
    .unwrap();
    let slot = plans
        .locality
        .work_slot
        .clone()
        .try_acquire_owned()
        .unwrap();
    start_recovery(&mut plans, context.clone(), plan().admitted_digest, slot);
    let mut pending = plans.locality.pending.take().unwrap();
    let result = (&mut pending.task).await.unwrap().unwrap().unwrap();
    assert_eq!(result.evidence, original);
    assert!(matches!(result.source, PlacementSource::PrivateCheckpoint) && result.durable);
    assert_eq!(plans.locality.work_slot.available_permits(), 1);
    assert!(plans.controller_url.is_none() && !plans.agent_token_path.exists());
    println!(
        "locality-checkpoint: PASS offline-worker=true full-source-replay=true private-file=true symlink-hardlink-fifo-oversize-denied=true foreign-preserved=true bounded-worker=true kernel-authority=false"
    );
}
