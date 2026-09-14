use super::*;

#[test]
fn cuts_track_durable_changes_but_not_reads_or_idempotent_replays() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let empty = journal.cut().unwrap();
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: spec("pod"),
        }))
        .unwrap();
    assert!(!journal.is_current(&empty));
    let preparing = journal.cut().unwrap();
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: spec("pod"),
        }))
        .unwrap();
    assert!(journal.is_current(&preparing));
    journal
        .apply(request(TransactionOperation::Commit { key: key("pod") }))
        .unwrap();
    assert!(!journal.is_current(&preparing));
    let ready = journal.cut().unwrap();
    let durable = fs::read(&path).unwrap();
    for operation in [
        TransactionOperation::Status,
        TransactionOperation::Inspect { key: key("pod") },
        TransactionOperation::List {
            network: "unf-test".into(),
            after: None,
            limit: 8,
        },
        TransactionOperation::Check {
            attachment: spec("pod"),
        },
        TransactionOperation::Commit { key: key("pod") },
    ] {
        journal.apply(request(operation)).unwrap();
        assert!(journal.is_current(&ready));
        assert_eq!(fs::read(&path).unwrap(), durable);
    }
    assert_eq!(journal.iter().count(), 1);
    assert_eq!(
        journal.iter().next().unwrap(),
        journal.get(&key("pod")).unwrap()
    );
    journal
        .apply(request(TransactionOperation::BeginDelete {
            key: key("pod"),
        }))
        .unwrap();
    assert!(!journal.is_current(&ready));
    let deleting = journal.cut().unwrap();
    journal
        .apply(request(TransactionOperation::CompleteDelete {
            key: key("pod"),
        }))
        .unwrap();
    assert!(!journal.is_current(&deleting));
    assert!(journal.is_empty());
    assert!(
        !journal.is_current(&empty),
        "restoring equal contents must not restore the cut"
    );
}

#[test]
fn cuts_are_bound_to_one_open_instance_even_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let journal = AttachmentJournal::open(&path, provider()).unwrap();
    let cut = journal.cut().unwrap();
    let duplicate = cut.clone();
    assert!(journal.is_current(&duplicate));
    let other = AttachmentJournal::open(directory.path().join("other.json"), provider()).unwrap();
    assert!(!other.is_current(&cut));
    drop(journal);
    let reopened = AttachmentJournal::open(&path, provider()).unwrap();
    assert!(!reopened.is_current(&cut));
    assert!(!reopened.is_current(&duplicate));
    assert!(reopened.is_current(&reopened.cut().unwrap()));
}

#[test]
fn failed_persistence_revokes_cuts_and_exhaustion_preserves_known_state() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: spec("pod"),
        }))
        .unwrap();
    let before = journal.records();
    let durable = fs::read(&path).unwrap();
    let cut = journal.cut().unwrap();
    let temporary = temporary_path(&path);
    fs::create_dir(&temporary).unwrap();
    assert!(
        journal
            .apply(request(TransactionOperation::Commit { key: key("pod") }))
            .is_err()
    );
    assert!(!journal.is_current(&cut));
    assert!(journal.cut().is_none());
    assert_eq!(journal.records(), before);
    assert_eq!(fs::read(&path).unwrap(), durable);
    fs::remove_dir(&temporary).unwrap();
    journal
        .apply(request(TransactionOperation::Status))
        .unwrap();
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: spec("pod"),
        }))
        .unwrap();
    assert!(
        journal.cut().is_none(),
        "reads and no-op replay cannot restore a fence"
    );
    journal
        .apply(request(TransactionOperation::Commit { key: key("pod") }))
        .unwrap();
    let recovered = journal.cut().unwrap();
    assert!(journal.is_current(&recovered));
    assert!(!journal.is_current(&cut));
    let before = journal.records();
    let durable = fs::read(&path).unwrap();
    journal.revision = u64::MAX;
    let exhausted = journal.cut().unwrap();
    let error = journal
        .apply(request(TransactionOperation::BeginDelete {
            key: key("pod"),
        }))
        .unwrap_err();
    assert!(error.to_string().contains("revision exhausted"));
    assert!(journal.is_current(&exhausted));
    assert_eq!(journal.records(), before);
    assert_eq!(fs::read(&path).unwrap(), durable);
    journal
        .apply(request(TransactionOperation::Status))
        .unwrap();
    journal
        .apply(request(TransactionOperation::Commit { key: key("pod") }))
        .unwrap();
    assert!(
        journal.is_current(&exhausted),
        "no-op operations need no new revision"
    );
}

#[test]
fn seek_pagination_matches_original_filter_for_cross_network_and_absent_cursors() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal =
        AttachmentJournal::open(directory.path().join("attachments.json"), provider()).unwrap();
    for network in ["aaa", "unf-test", "zzz"] {
        for index in 0..12 {
            let mut attachment = spec(&format!("pod-{index:02}"));
            attachment.key.network = network.into();
            journal
                .apply(request(TransactionOperation::Prepare { attachment }))
                .unwrap();
        }
    }
    let records = journal.records();
    let cut = journal.cut().unwrap();
    let mut cursors: Vec<_> = std::iter::once(None)
        .chain(records.iter().map(|record| Some(record.spec.key.clone())))
        .collect();
    cursors.push(Some(key("absent")));
    cursors.push(Some(key("pod-05-suffix")));
    for network in ["aaa", "middle-absent", "unf-test", "zzz", "zzzz"] {
        for after in &cursors {
            for limit in [1, 3, MAX_ATTACHMENT_LIST_RECORDS] {
                let expected: Vec<_> = records
                    .iter()
                    .filter(|record| record.spec.key.network == network)
                    .filter(|record| {
                        after
                            .as_ref()
                            .is_none_or(|cursor| record.spec.key > *cursor)
                    })
                    .take(usize::from(limit))
                    .cloned()
                    .collect();
                let response = journal
                    .apply(request(TransactionOperation::List {
                        network: network.into(),
                        after: after.clone(),
                        limit,
                    }))
                    .unwrap();
                let TransactionOutcome::Ok {
                    attachments,
                    attachment_count,
                    ..
                } = response.outcome
                else {
                    panic!("list rejected")
                };
                assert_eq!(
                    attachments, expected,
                    "network={network} cursor={after:?} limit={limit}"
                );
                assert_eq!(attachment_count, records.len());
                assert!(journal.is_current(&cut));
            }
        }
    }
}
