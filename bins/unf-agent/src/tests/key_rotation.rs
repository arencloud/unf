//! Exercise independently progressing members against the actual durable key API.
use super::*;
use unf_encryption::{
    AuthenticatedNodeIdentity, EncryptionGenerationRecipient, NodeKeyTransparencyLedger,
};

fn publication(keys: &EncryptionKeySynchronizer) -> NodeKeyPublication {
    keys.authority
        .as_ref()
        .unwrap()
        .authority()
        .publication()
        .unwrap()
}

fn transparency(
    members: &[EncryptionGenerationRecipient],
    keys: &[EncryptionKeySynchronizer; 2],
) -> NodeKeyTransparencyLedger {
    let mut ledger = NodeKeyTransparencyLedger::default();
    ledger
        .replace_membership("cluster-a".into(), Revision::new(7), members.to_vec())
        .unwrap();
    for (member, keys) in members.iter().zip(keys) {
        ledger
            .observe(
                &AuthenticatedNodeIdentity {
                    cluster_id: "cluster-a".into(),
                    node_name: member.node_name.clone(),
                    node_uid: member.node_uid.clone(),
                },
                publication(keys),
            )
            .unwrap();
    }
    ledger
}

fn retire(keys: &mut EncryptionKeySynchronizer, epoch: u64, now: u64) {
    let proof = EpochDrainProof::issue(
        publication(keys).node_uid,
        epoch,
        Revision::new(7),
        now,
        0,
        0,
    )
    .unwrap();
    keys.authority
        .as_mut()
        .unwrap()
        .retire_drained_epoch(&proof, now)
        .unwrap();
}

fn setup(
    root: &Path,
) -> (
    [EncryptionKeySynchronizer; 2],
    Vec<EncryptionGenerationRecipient>,
    [EncryptionKeyBootstrap; 2],
    u64,
) {
    let members: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|suffix| EncryptionGenerationRecipient {
            node_name: format!("worker-{suffix}"),
            node_uid: format!("uid-{suffix}"),
        })
        .collect();
    let bootstraps = std::array::from_fn(|index| {
        EncryptionKeyBootstrap::issue(
            11,
            "cluster-a".into(),
            Revision::new(7),
            1,
            members[index].clone(),
            members.clone(),
        )
        .unwrap()
    });
    let keys = std::array::from_fn(|index| {
        let mut keys = EncryptionKeySynchronizer::new(
            None,
            test_controller_client(),
            root.join("token"),
            Duration::from_secs(2),
            members[index].node_name.clone(),
            root.join(&members[index].node_name).join("authority.json"),
        )
        .unwrap()
        .with_rotation_timing(
            Duration::from_secs(10),
            Duration::from_secs(8),
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .unwrap();
        keys.bind_bootstrap(&bootstraps[index]).unwrap();
        keys
    });
    (
        keys,
        members,
        bootstraps,
        current_unix_time_milliseconds().max(1),
    )
}

fn cuts(
    members: &[EncryptionGenerationRecipient],
    keys: &[EncryptionKeySynchronizer; 2],
    now: u64,
) -> [NodeKeyAttestationCut; 2] {
    let publications = [publication(&keys[0]), publication(&keys[1])];
    [
        complete_reciprocal_attestation_cut(members, publications.clone(), now),
        complete_reciprocal_attestation_cut(
            &[members[1].clone(), members[0].clone()],
            publications,
            now,
        ),
    ]
}

#[test]
fn viable_attested_transition_can_finish_behind_a_faster_members_floor() {
    let directory = tempdir().unwrap();
    let (mut keys, members, bootstraps, now) = setup(directory.path());
    let first = cuts(&members, &keys, now + 1);
    for (keys, cut) in keys.iter_mut().zip(first) {
        assert!(keys.bind_attestation_cut(&cut, now + 1).unwrap());
    }
    for (keys, bootstrap) in keys.iter_mut().zip(&bootstraps) {
        assert!(prepare_due_encryption_rotation(keys, bootstrap, now + 2_500).unwrap());
    }
    let second = cuts(&members, &keys, now + 2_501);
    // Both rows exist, but only B has consumed its complete cut so far.
    assert!(
        keys[1]
            .bind_attestation_cut(&second[1], now + 2_502)
            .unwrap()
    );
    retire(&mut keys[1], 1, now + 3_503);
    assert!(prepare_due_encryption_rotation(&mut keys[1], &bootstraps[1], now + 5_000).unwrap());
    let ledger = transparency(&members, &keys);
    assert_eq!(ledger.epoch_floor(), 3);
    let advanced = EncryptionKeyBootstrap::issue(
        11,
        "cluster-a".into(),
        Revision::new(7),
        ledger.epoch_floor(),
        members[0].clone(),
        members.clone(),
    )
    .unwrap();
    let before = publication(&keys[0]);
    let checkpoint = fs::read(&keys[0].state_path).unwrap();
    // Floor is an issuance frontier, not a revocation of the retained valid
    // epoch. Reconciliation must let the existing exact cut be consumed.
    for _ in 0..64 {
        assert!(
            !keys[0]
                .reconcile_bootstrap_epoch_floor(&advanced, now + 5_001)
                .unwrap()
        );
    }
    assert_eq!(publication(&keys[0]), before);
    assert_eq!(fs::read(&keys[0].state_path).unwrap(), checkpoint);
    // A higher floor is not a substitute for complete attestation, and does
    // not make expired evidence usable. Neither rejection changes key state.
    let mut incomplete = second[0].clone();
    incomplete.acknowledgements.clear();
    assert!(
        keys[0]
            .bind_attestation_cut(&incomplete, now + 5_002)
            .is_err()
    );
    assert!(
        keys[0]
            .bind_attestation_cut(&second[0], now + 13_000)
            .is_err()
    );
    assert_eq!(publication(&keys[0]), before);
    assert_eq!(fs::read(&keys[0].state_path).unwrap(), checkpoint);
    assert!(
        keys[0]
            .bind_attestation_cut(&second[0], now + 5_002)
            .unwrap()
    );
    retire(&mut keys[0], 1, now + 6_003);
    assert!(
        keys[0]
            .reconcile_bootstrap_epoch_floor(&advanced, now + 6_004)
            .unwrap()
    );
    let third = cuts(&members, &keys, now + 6_005);
    for (keys, cut) in keys.iter_mut().zip(third) {
        assert!(keys.bind_attestation_cut(&cut, now + 6_006).unwrap());
        let publication = publication(keys);
        assert_eq!(publication.revoked_through_epoch, 0);
        assert_eq!(publication.retired_through_epoch, 1);
        assert_eq!(publication.epochs[1].epoch, 3);
        assert_eq!(publication.epochs[1].phase, KeyEpochPhase::Active);
    }
}

#[test]
fn expired_shorter_successor_cannot_bypass_floor_or_revoke_a_viable_predecessor() {
    let directory = tempdir().unwrap();
    let (mut keys, members, _, now) = setup(directory.path());
    let first = cuts(&members, &keys, now + 1);
    for (keys, cut) in keys.iter_mut().zip(first) {
        assert!(keys.bind_attestation_cut(&cut, now + 1).unwrap());
    }
    // A changed rotation configuration after restart could give the successor
    // less remaining lifetime than the already-issued predecessor.
    keys[0]
        .authority
        .as_mut()
        .unwrap()
        .prepare_epoch(
            Revision::new(7),
            BTreeSet::from([members[1].node_uid.clone()]),
            now + 2_000,
            now + 3_000,
        )
        .unwrap();
    let advanced = EncryptionKeyBootstrap::issue(
        11,
        "cluster-a".into(),
        Revision::new(7),
        3,
        members[0].clone(),
        members,
    )
    .unwrap();
    let before = publication(&keys[0]);
    let checkpoint = fs::read(&keys[0].state_path).unwrap();
    let error = keys[0]
        .reconcile_bootstrap_epoch_floor(&advanced, now + 4_000)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("expired encryption transition epoch 2")
    );
    assert_eq!(publication(&keys[0]), before);
    assert_eq!(fs::read(&keys[0].state_path).unwrap(), checkpoint);
}

#[test]
fn delayed_successor_activation_caps_drain_at_the_predecessors_sealed_expiry() {
    for lateness in [-500_i64, 0, 1] {
        let directory = tempdir().unwrap();
        let (mut keys, members, bootstraps, now) = setup(directory.path());
        let first = cuts(&members, &keys, now + 1);
        for (keys, cut) in keys.iter_mut().zip(first) {
            assert!(keys.bind_attestation_cut(&cut, now + 1).unwrap());
        }
        let expiry = publication(&keys[0]).epochs[0].valid_until_unix_ms;
        for (keys, bootstrap) in keys.iter_mut().zip(&bootstraps) {
            assert!(prepare_due_encryption_rotation(keys, bootstrap, expiry - 5_000).unwrap());
        }
        let second = cuts(&members, &keys, expiry - 4_999);
        let delayed = expiry.checked_add_signed(lateness).unwrap();
        assert!(keys[0].bind_attestation_cut(&second[0], delayed).unwrap());
        let published = publication(&keys[0]);
        assert_eq!(published.revoked_through_epoch, 0);
        assert_eq!(published.retired_through_epoch, 0);
        assert_eq!(published.epochs[0].phase, KeyEpochPhase::Draining);
        assert_eq!(published.epochs[0].drain_deadline_unix_ms, Some(expiry));
        assert_eq!(published.epochs[0].valid_until_unix_ms, expiry);
        assert_eq!(published.epochs[1].phase, KeyEpochPhase::Active);
        let restored = FileNodeKeyStateStore::new(keys[0].state_path.clone())
            .restore("cluster-a", "worker-a", "uid-a")
            .unwrap();
        assert_eq!(restored.publication().unwrap(), published);
        assert_eq!(
            restored
                .drained_epoch_ready_for_retirement(expiry - 1)
                .unwrap(),
            None
        );
        assert_eq!(
            restored.drained_epoch_ready_for_retirement(expiry).unwrap(),
            Some(1)
        );
        // Expiry makes retirement due, not authorized: live flows or routes
        // must still prevent removal and leave the durable checkpoint intact.
        let checkpoint = fs::read(&keys[0].state_path).unwrap();
        for (flows, routes) in [(1, 0), (0, 1)] {
            let proof = EpochDrainProof::issue(
                "uid-a".into(),
                1,
                Revision::new(7),
                expiry + 2,
                flows,
                routes,
            )
            .unwrap();
            assert!(
                keys[0]
                    .authority
                    .as_mut()
                    .unwrap()
                    .retire_drained_epoch(&proof, expiry + 2)
                    .is_err()
            );
            assert_eq!(publication(&keys[0]), published);
            assert_eq!(fs::read(&keys[0].state_path).unwrap(), checkpoint);
        }
        retire(&mut keys[0], 1, expiry + 2);
        let retired = publication(&keys[0]);
        assert_eq!(retired.retired_through_epoch, 1);
        assert_eq!(retired.revoked_through_epoch, 0);
        assert_eq!(retired.epochs.len(), 1);
        assert_eq!(retired.epochs[0].epoch, 2);
    }
}
