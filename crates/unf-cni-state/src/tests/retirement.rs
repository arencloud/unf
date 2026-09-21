use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

type Calls = Arc<Mutex<Vec<[u8; 32]>>>;

struct Observer {
    path: PathBuf,
    calls: Calls,
    fail: Arc<AtomicBool>,
}

impl AttachmentRetirement for Observer {
    fn retire(&self, token: &[u8; 32]) -> io::Result<()> {
        // The durable record must still be Ready at the actual callback, not
        // merely when the test last inspected it before apply().
        let document: JournalDocument = serde_json::from_slice(&fs::read(&self.path)?)?;
        assert!(document.attachments.iter().any(|record| {
            record.creation_token.as_ref() == Some(token) && record.phase == AttachmentPhase::Ready
        }));
        self.calls.lock().unwrap().push(*token);
        if self.fail.load(Ordering::Acquire) {
            return Err(io::Error::other("injected retirement failure"));
        }
        Ok(())
    }
}

fn observer(path: &Path) -> (Observer, Calls, Arc<AtomicBool>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    (
        Observer {
            path: path.into(),
            calls: Arc::clone(&calls),
            fail: Arc::clone(&fail),
        },
        calls,
        fail,
    )
}

#[test]
fn required_hook_persists_reader_floor_and_preserves_all_attachment_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    ready(&mut journal, "bound");
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: spec("legacy"),
        }))
        .unwrap();
    let old_cut = journal.cut().unwrap();
    let records = journal.records();
    let before: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let (hook, calls, _) = observer(&path);
    let registration = journal.install_required_retirement(Box::new(hook)).unwrap();
    let bytes = fs::read(&path).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(after["schemaVersion"], 5);
    assert_eq!(after["attachments"], before["attachments"]);
    assert_eq!(after["provider"], before["provider"]);
    assert_eq!(journal.records(), records);
    assert!(journal.retirement_required());
    assert!(calls.lock().unwrap().is_empty());
    assert!(!journal.is_current(&old_cut));
    assert!(journal.retirement_matches(&registration));
    let installed_cut = journal.cut().unwrap();
    drop(journal);
    let mut reopened = AttachmentJournal::open(&path, provider()).unwrap();
    assert!(reopened.retirement_required());
    assert!(reopened.cut().is_none());
    assert!(!reopened.is_current(&installed_cut));
    assert!(!reopened.retirement_matches(&registration));
    for operation in [
        TransactionOperation::Status,
        TransactionOperation::Prepare {
            attachment: bound_spec("new"),
        },
        TransactionOperation::BeginDelete { key: key("bound") },
    ] {
        assert!(reopened.apply(request(operation)).is_err());
        assert_eq!(reopened.records(), records);
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    let (hook, calls, _) = observer(&path);
    let new_registration = reopened
        .install_required_retirement(Box::new(hook))
        .unwrap();
    assert!(reopened.cut().is_some());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(reopened.retirement_matches(&new_registration));
    assert!(!reopened.retirement_matches(&registration));
    reopened
        .apply(request(TransactionOperation::BeginDelete {
            key: key("bound"),
        }))
        .unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn required_reader_floor_survives_empty_inventory_and_unbound_records() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let (hook, _, _) = observer(&path);
    journal.install_required_retirement(Box::new(hook)).unwrap();
    for operation in [
        TransactionOperation::Prepare {
            attachment: spec("legacy"),
        },
        TransactionOperation::BeginAbort { key: key("legacy") },
        TransactionOperation::CompleteAbort { key: key("legacy") },
    ] {
        journal.apply(request(operation)).unwrap();
        let document: JournalDocument = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            document.schema_version,
            REQUIRED_RETIREMENT_JOURNAL_SCHEMA_VERSION
        );
    }
    assert!(journal.is_empty());
    drop(journal);
    let reopened = AttachmentJournal::open(&path, provider()).unwrap();
    assert!(reopened.retirement_required() && reopened.cut().is_none());
}

#[test]
fn failed_required_upgrade_exposes_no_registration_or_current_cut() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    ready(&mut journal, "bound");
    let before = fs::read(&path).unwrap();
    let records = journal.records();
    let cut = journal.cut().unwrap();
    fs::create_dir(temporary_path(&path)).unwrap();
    let (hook, _, _) = observer(&path);
    assert!(journal.install_required_retirement(Box::new(hook)).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(journal.records(), records);
    assert!(journal.retirement_required());
    assert!(journal.cut().is_none() && !journal.is_current(&cut));
    let (hook, _, _) = observer(&path);
    assert!(journal.install_required_retirement(Box::new(hook)).is_err());
}

fn bound_spec(name: &str) -> AttachmentSpec {
    let mut attachment = spec(name);
    attachment.workload_uid = Some(name.into());
    attachment
}

fn ready(journal: &mut AttachmentJournal, name: &str) -> [u8; 32] {
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: bound_spec(name),
        }))
        .unwrap();
    journal
        .apply(request(TransactionOperation::Commit { key: key(name) }))
        .unwrap();
    journal.get(&key(name)).unwrap().creation_token.unwrap()
}

#[test]
fn exact_incarnation_retires_before_persistence_without_revoking_other_records() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let first = ready(&mut journal, "first");
    let second = ready(&mut journal, "second");
    let before_install = journal.cut().unwrap();
    let durable = fs::read(&path).unwrap();
    let (hook, calls, _) = observer(&path);
    journal.install_retirement(Box::new(hook)).unwrap();
    assert!(!journal.is_current(&before_install));
    assert_eq!(fs::read(&path).unwrap(), durable);
    assert!(calls.lock().unwrap().is_empty());
    let after_install = journal.cut().unwrap();
    let (replacement, _, _) = observer(&path);
    assert!(journal.install_retirement(Box::new(replacement)).is_err());
    assert!(journal.is_current(&after_install));

    for _ in 0..2 {
        journal
            .apply(request(TransactionOperation::BeginDelete {
                key: key("first"),
            }))
            .unwrap();
        assert_eq!(*calls.lock().unwrap(), [first]);
    }
    journal
        .apply(request(TransactionOperation::CompleteDelete {
            key: key("first"),
        }))
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), [first]);
    assert_eq!(
        journal.get(&key("second")).unwrap().creation_token,
        Some(second)
    );
    assert_eq!(
        journal.get(&key("second")).unwrap().phase,
        AttachmentPhase::Ready
    );
    let replacement = ready(&mut journal, "first");
    assert_ne!(replacement, first);
    assert_eq!(*calls.lock().unwrap(), [first]);
    journal
        .apply(request(TransactionOperation::BeginDelete {
            key: key("first"),
        }))
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), [first, replacement]);
}

#[test]
fn read_replay_invalid_and_nonready_operations_do_not_retire() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    ready(&mut journal, "first");
    let (hook, calls, _) = observer(&path);
    journal.install_retirement(Box::new(hook)).unwrap();
    let cut = journal.cut().unwrap();
    for operation in [
        TransactionOperation::Status,
        TransactionOperation::Inspect { key: key("first") },
        TransactionOperation::List {
            network: "unf-test".into(),
            after: None,
            limit: 8,
        },
        TransactionOperation::Check {
            attachment: bound_spec("first"),
        },
        TransactionOperation::Commit { key: key("first") },
        TransactionOperation::BeginDelete { key: key("absent") },
    ] {
        journal.apply(request(operation)).unwrap();
        assert!(journal.is_current(&cut));
    }
    for operation in [
        TransactionOperation::Prepare {
            attachment: bound_spec("first"),
        },
        TransactionOperation::BeginAbort { key: key("first") },
        TransactionOperation::CompleteAbort { key: key("first") },
        TransactionOperation::CompleteDelete { key: key("first") },
    ] {
        assert!(journal.apply(request(operation)).is_err());
        assert!(journal.is_current(&cut));
    }
    for version in [0, 2, 3, 5] {
        assert!(
            journal
                .apply(TransactionRequest::new(
                    version,
                    TransactionOperation::BeginDelete { key: key("first") }
                ))
                .is_err()
        );
        assert!(journal.is_current(&cut));
    }
    for abort in [false, true] {
        journal
            .apply(request(TransactionOperation::Prepare {
                attachment: bound_spec("preparing"),
            }))
            .unwrap();
        let key = key("preparing");
        let operations = if abort {
            [
                TransactionOperation::BeginAbort { key: key.clone() },
                TransactionOperation::CompleteAbort { key },
            ]
        } else {
            [
                TransactionOperation::BeginDelete { key: key.clone() },
                TransactionOperation::CompleteDelete { key },
            ]
        };
        for operation in operations {
            journal.apply(request(operation)).unwrap();
        }
    }
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: spec("legacy"),
        }))
        .unwrap();
    journal
        .apply(request(TransactionOperation::Commit { key: key("legacy") }))
        .unwrap();
    journal
        .apply(request(TransactionOperation::BeginDelete {
            key: key("legacy"),
        }))
        .unwrap();
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn retirement_failure_blocks_durable_delete_and_invalidates_publication_cut() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let nonce = ready(&mut journal, "first");
    ready(&mut journal, "second");
    let (hook, calls, fail) = observer(&path);
    journal.install_retirement(Box::new(hook)).unwrap();
    let cut = journal.cut().unwrap();
    let records = journal.records();
    let durable = fs::read(&path).unwrap();
    fail.store(true, Ordering::Release);
    assert!(matches!(
        journal.apply(request(TransactionOperation::BeginDelete {
            key: key("first"),
        })),
        Err(JournalError::Retirement(_))
    ));
    assert_eq!(journal.records(), records);
    assert_eq!(fs::read(&path).unwrap(), durable);
    assert!(!journal.is_current(&cut));
    assert!(journal.cut().is_none());
    journal
        .apply(request(TransactionOperation::Commit { key: key("first") }))
        .unwrap();
    journal
        .apply(request(TransactionOperation::Check {
            attachment: bound_spec("first"),
        }))
        .unwrap();
    assert!(journal.cut().is_none());
    let (replacement, _, _) = observer(&path);
    assert!(journal.install_retirement(Box::new(replacement)).is_err());
    fail.store(false, Ordering::Release);
    journal
        .apply(request(TransactionOperation::BeginDelete {
            key: key("first"),
        }))
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), [nonce, nonce]);
    assert!(journal.cut().is_some());
    assert!(!journal.is_current(&cut));
    assert_eq!(
        journal.get(&key("second")),
        records.iter().find(|r| r.spec.key == key("second"))
    );
}

#[test]
fn persistence_failure_never_rearms_retired_incarnation_and_retry_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    let nonce = ready(&mut journal, "first");
    ready(&mut journal, "second");
    let (hook, calls, _) = observer(&path);
    journal.install_retirement(Box::new(hook)).unwrap();
    let records = journal.records();
    let durable = fs::read(&path).unwrap();
    let temporary = temporary_path(&path);
    fs::create_dir(&temporary).unwrap();
    assert!(matches!(
        journal.apply(request(TransactionOperation::BeginDelete {
            key: key("first"),
        })),
        Err(JournalError::Io(_))
    ));
    assert_eq!(*calls.lock().unwrap(), [nonce]);
    assert_eq!(journal.records(), records);
    assert_eq!(fs::read(&path).unwrap(), durable);
    assert!(journal.cut().is_none());
    fs::remove_dir(&temporary).unwrap();
    journal
        .apply(request(TransactionOperation::BeginDelete {
            key: key("first"),
        }))
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), [nonce, nonce]);
    journal
        .apply(request(TransactionOperation::BeginDelete {
            key: key("first"),
        }))
        .unwrap();
    assert_eq!(*calls.lock().unwrap(), [nonce, nonce]);
}

#[test]
fn revision_exhaustion_does_not_retire_or_mutate_and_reopen_restores_no_hook() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    ready(&mut journal, "first");
    let (hook, calls, _) = observer(&path);
    journal.install_retirement(Box::new(hook)).unwrap();
    journal.revision = u64::MAX;
    let cut = journal.cut().unwrap();
    let records = journal.records();
    let durable = fs::read(&path).unwrap();
    assert!(
        journal
            .apply(request(TransactionOperation::BeginDelete {
                key: key("first")
            }))
            .is_err()
    );
    assert!(journal.is_current(&cut));
    assert_eq!(journal.records(), records);
    assert_eq!(fs::read(&path).unwrap(), durable);
    assert!(calls.lock().unwrap().is_empty());
    drop(journal);
    let reopened = AttachmentJournal::open(&path, provider()).unwrap();
    assert!(reopened.retirement.is_none());
    assert!(!reopened.is_current(&cut));
}

#[test]
fn single_record_rollback_restores_failed_creation_commit_abort_and_removal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attachments.json");
    let mut journal = AttachmentJournal::open(&path, provider()).unwrap();
    ready(&mut journal, "untouched");
    for operation in [
        TransactionOperation::Prepare {
            attachment: bound_spec("subject"),
        },
        TransactionOperation::Commit {
            key: key("subject"),
        },
        TransactionOperation::BeginDelete {
            key: key("subject"),
        },
        TransactionOperation::CompleteDelete {
            key: key("subject"),
        },
        TransactionOperation::Prepare {
            attachment: bound_spec("subject"),
        },
        TransactionOperation::BeginAbort {
            key: key("subject"),
        },
        TransactionOperation::CompleteAbort {
            key: key("subject"),
        },
    ] {
        let records = journal.records();
        let durable = fs::read(&path).unwrap();
        let temporary = temporary_path(&path);
        fs::create_dir(&temporary).unwrap();
        assert!(matches!(
            journal.apply(request(operation.clone())),
            Err(JournalError::Io(_))
        ));
        assert_eq!(journal.records(), records);
        assert_eq!(fs::read(&path).unwrap(), durable);
        assert!(journal.cut().is_none());
        fs::remove_dir(&temporary).unwrap();
        journal.apply(request(operation)).unwrap();
        assert!(journal.cut().is_some());
        assert_eq!(
            journal.get(&key("untouched")),
            records.iter().find(|r| r.spec.key == key("untouched"))
        );
    }
}

#[test]
fn registration_is_bound_to_one_hook_and_open_journal_not_to_a_changing_cut() {
    let directory = tempfile::tempdir().unwrap();
    let first_path = directory.path().join("first.json");
    let second_path = directory.path().join("second.json");
    let mut first = AttachmentJournal::open(&first_path, provider()).unwrap();
    let mut second = AttachmentJournal::open(&second_path, provider()).unwrap();
    let (hook, _, _) = observer(&first_path);
    let registration = first.install_retirement(Box::new(hook)).unwrap();
    let (hook, _, _) = observer(&second_path);
    let foreign = second.install_retirement(Box::new(hook)).unwrap();
    assert!(first.retirement_matches(&registration));
    assert!(!first.retirement_matches(&foreign));
    assert!(!second.retirement_matches(&registration));
    let cut = first.cut().unwrap();
    ready(&mut first, "first");
    assert!(!first.is_current(&cut));
    assert!(first.retirement_matches(&registration));
    drop(first);
    let reopened = AttachmentJournal::open(&first_path, provider()).unwrap();
    assert!(!reopened.retirement_matches(&registration));
}
