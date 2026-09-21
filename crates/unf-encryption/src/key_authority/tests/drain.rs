use super::*;

fn prepared_rotation() -> NodeKeyAuthority {
    let mut authority = authority();
    let mut generator = FixedGenerator { next: 1 };
    let first = prepare_and_attest(&mut authority, &mut generator);
    authority
        .activate_epoch(first, Revision::new(4), NOW + 2, 1_000)
        .unwrap();
    authority
        .prepare_epoch(
            Revision::new(4),
            peers(),
            NOW + 90_000,
            NOW + 190_000,
            &mut generator,
        )
        .unwrap();
    for peer in peers() {
        let ack = acknowledgement(&authority.epochs[1], &peer, NOW + 90_001);
        authority
            .acknowledge_epoch(&peer, ack, NOW + 90_001)
            .unwrap();
    }
    authority
}

#[test]
fn clipped_drain_is_bounded_by_requested_window_and_original_key_lifetime() {
    let prepared = prepared_rotation();
    let expiry = NOW + 100_000;
    for now in [expiry - 5_000, expiry - 1, expiry, expiry + 1] {
        for window in [1, 500, 1_000, MAX_EPOCH_DRAIN_MS] {
            let mut authority = prepared.clone();
            let old_key = authority.epochs[0].public_key;
            authority
                .activate_epoch(2, Revision::new(4), now, window)
                .unwrap();
            let deadline = expiry.min(now + window);
            let publication = authority.publication().unwrap();
            assert_eq!(publication.epochs[0].phase, KeyEpochPhase::Draining);
            assert_eq!(publication.epochs[0].drain_deadline_unix_ms, Some(deadline));
            assert_eq!(publication.epochs[0].valid_until_unix_ms, expiry);
            assert_eq!(publication.epochs[0].public_key, old_key);
            assert_eq!(publication.epochs[1].phase, KeyEpochPhase::Active);
            assert_eq!(publication.revoked_through_epoch, 0);
            assert_eq!(publication.retired_through_epoch, 0);
            assert_eq!(
                authority.drained_epoch_ready_for_retirement(now).unwrap(),
                (now >= deadline).then_some(1)
            );
        }
    }
}

#[test]
fn expiry_clipping_does_not_accept_invalid_requested_drain_windows() {
    for window in [0, MAX_EPOCH_DRAIN_MS + 1] {
        let mut authority = prepared_rotation();
        let before = authority.publication().unwrap();
        assert!(matches!(
            authority.activate_epoch(2, Revision::new(4), NOW + 100_001, window),
            Err(KeyAuthorityError::InvalidDrainWindow)
        ));
        assert_eq!(authority.publication().unwrap(), before);
    }
}

#[test]
fn expiry_clipping_cannot_activate_unready_expired_or_foreign_topology_successors() {
    for (now, revision, remove_attestation) in [
        (NOW + 190_000, Revision::new(4), false),
        (NOW + 89_999, Revision::new(4), false),
        (NOW + 100_001, Revision::new(5), false),
        (NOW + 100_001, Revision::new(4), true),
    ] {
        let mut authority = prepared_rotation();
        if remove_attestation {
            authority.epochs[1].phase = KeyEpochPhase::Prepared;
            authority.epochs[1].readiness = None;
            authority.epochs[1].acknowledgements.clear();
        }
        let before = authority.publication().unwrap();
        assert!(matches!(
            authority.activate_epoch(2, revision, now, 1_000),
            Err(KeyAuthorityError::ActivationBarrierNotSatisfied)
        ));
        assert_eq!(authority.publication().unwrap(), before);
    }
}

#[test]
fn expiry_capped_activation_keeps_original_durable_authority_on_write_failure() {
    let mut durable = DurableNodeKeyAuthority::create(
        prepared_rotation(),
        FailingStore::default(),
        FixedGenerator { next: 3 },
    )
    .unwrap();
    let before = durable.authority().publication().unwrap();
    let writes = durable.store.writes.get();
    durable.store.fail.set(true);
    assert!(matches!(
        durable.activate_epoch(2, Revision::new(4), NOW + 100_001, 1_000),
        Err(KeyAuthorityError::Io(_))
    ));
    assert_eq!(durable.authority().publication().unwrap(), before);
    assert_eq!(durable.store.writes.get(), writes);
    durable.store.fail.set(false);
    durable
        .activate_epoch(2, Revision::new(4), NOW + 100_001, 1_000)
        .unwrap();
    let published = durable.authority().publication().unwrap();
    assert_eq!(
        published.epochs[0].drain_deadline_unix_ms,
        Some(NOW + 100_000)
    );
    assert_eq!(published.epochs[1].phase, KeyEpochPhase::Active);
    assert_eq!(durable.store.writes.get(), writes + 1);
}
