use super::*;

#[test]
fn incarnation_survives_restart_and_rejects_replacement_or_omission() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let mut bound = spec("container-1");
    bound.workload_uid = Some("pod-uid-a".into());
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: bound.clone(),
        }))
        .unwrap();
    journal
        .apply(request(TransactionOperation::Commit {
            key: bound.key.clone(),
        }))
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    assert_eq!(journal.get(&bound.key).unwrap().spec, bound);
    journal
        .apply(request(TransactionOperation::Check {
            attachment: bound.clone(),
        }))
        .unwrap();
    for uid in [None, Some("pod-uid-b".into())] {
        let mut other = bound.clone();
        other.workload_uid = uid;
        for operation in [
            TransactionOperation::Check {
                attachment: other.clone(),
            },
            TransactionOperation::Prepare {
                attachment: other.clone(),
            },
        ] {
            assert!(matches!(
                journal.apply(request(operation)),
                Err(JournalError::Conflict(_))
            ));
            assert_eq!(fs::read(&path).unwrap(), bytes);
            assert_eq!(journal.get(&bound.key).unwrap().spec, bound);
        }
    }
}

#[test]
fn schema_two_cannot_observe_or_mutate_bound_attachments() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let mut bound = spec("container-1");
    bound.workload_uid = Some("pod-uid-a".into());
    assert!(
        journal
            .apply(TransactionRequest::new(
                2,
                TransactionOperation::Prepare {
                    attachment: bound.clone()
                }
            ))
            .is_err()
    );
    assert!(!path.exists());
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: bound.clone(),
        }))
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    for operation in [
        TransactionOperation::Prepare {
            attachment: spec("container-1"),
        },
        TransactionOperation::Check {
            attachment: spec("container-1"),
        },
        TransactionOperation::Inspect {
            key: bound.key.clone(),
        },
        TransactionOperation::Commit {
            key: bound.key.clone(),
        },
        TransactionOperation::BeginAbort {
            key: bound.key.clone(),
        },
        TransactionOperation::CompleteAbort {
            key: bound.key.clone(),
        },
        TransactionOperation::BeginDelete {
            key: bound.key.clone(),
        },
        TransactionOperation::CompleteDelete {
            key: bound.key.clone(),
        },
        TransactionOperation::List {
            network: bound.key.network.clone(),
            after: None,
            limit: 8,
        },
    ] {
        assert!(matches!(
            journal.apply(TransactionRequest::new(2, operation)),
            Err(JournalError::IncompatibleSchema { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            journal.get(&bound.key).unwrap().phase,
            AttachmentPhase::Preparing
        );
    }
    assert_eq!(
        journal
            .apply(TransactionRequest::new(2, TransactionOperation::Status))
            .unwrap()
            .schema_version,
        2
    );
}

#[test]
fn legacy_replay_never_invents_or_persists_workload_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let prepared = journal
        .apply(TransactionRequest::new(
            2,
            TransactionOperation::Prepare {
                attachment: spec("container-1"),
            },
        ))
        .unwrap();
    assert_eq!(prepared.schema_version, 2);
    let record = journal.get(&key("container-1")).unwrap().clone();
    let mut document = serde_json::to_value(JournalDocument {
        schema_version: 2,
        provider: provider(),
        attachments: vec![record.clone()],
    })
    .unwrap();
    assert!(
        document["attachments"][0]["spec"]
            .get("workloadUid")
            .is_none()
    );
    fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let bytes = fs::read(&path).unwrap();
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    assert_eq!(
        fs::read(&path).unwrap(),
        bytes,
        "opening schema 2 must not rewrite it"
    );
    let mut requested = spec("container-1");
    requested.workload_uid = Some("new-runtime-pod-uid".into());
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: requested.clone(),
        }))
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    journal
        .apply(request(TransactionOperation::Commit {
            key: requested.key.clone(),
        }))
        .unwrap();
    journal
        .apply(request(TransactionOperation::Check {
            attachment: requested,
        }))
        .unwrap();
    let restarted = AttachmentJournal::open(&path, provider()).unwrap();
    assert!(
        restarted
            .get(&record.spec.key)
            .unwrap()
            .spec
            .workload_uid
            .is_none()
    );
    assert_eq!(restarted.get(&record.spec.key).unwrap().lease, record.lease);
    document["attachments"][0]["spec"]["workloadUid"] = "forged-uid".into();
    fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(matches!(
        AttachmentJournal::open(&path, provider()),
        Err(JournalError::Invalid(_))
    ));
}

#[test]
fn malformed_uid_is_rejected_before_allocating_or_persisting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    for uid in [
        String::new(),
        "a".repeat(129),
        "pod/uid".to_owned(),
        "pod\nuid".to_owned(),
        "pod\0uid".to_owned(),
    ] {
        let mut bound = spec("container-1");
        bound.workload_uid = Some(uid.into());
        assert!(matches!(
            journal.apply(request(TransactionOperation::Prepare { attachment: bound })),
            Err(JournalError::Invalid(_))
        ));
        assert!(journal.is_empty());
        assert!(!path.exists());
    }
}

#[test]
fn failed_binding_write_does_not_reserve_an_address() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let mut bound = spec("container-1");
    bound.workload_uid = Some("pod-uid-a".into());
    let temporary = temporary_path(&path);
    fs::create_dir(&temporary).unwrap();
    assert!(
        journal
            .apply(request(TransactionOperation::Prepare {
                attachment: bound.clone()
            }))
            .is_err()
    );
    assert!(journal.is_empty());
    assert!(!path.exists());
    fs::remove_dir(temporary).unwrap();
    journal
        .apply(request(TransactionOperation::Prepare { attachment: bound }))
        .unwrap();
    assert_eq!(journal.len(), 1);
}
