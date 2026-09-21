//! Disposable kernel-map qualification, not a packet-delivery test. Uses only
//! fresh anonymous BPF maps and a private temporary journal; no host pins/links.

use std::{fs, path::Path};

use unf_cni_state::{
    AttachmentJournal, AttachmentKey, AttachmentPhase, AttachmentSpec,
    CNI_TRANSACTION_SCHEMA_VERSION, TransactionOperation, TransactionRequest,
};
use unf_ipam::NodeBlockProvider;
use unf_locality::{IncarnationGate, IncarnationLease};

fn request(operation: TransactionOperation) -> TransactionRequest {
    TransactionRequest::new(CNI_TRANSACTION_SCHEMA_VERSION, operation)
}

fn spec(name: &str) -> AttachmentSpec {
    AttachmentSpec {
        key: AttachmentKey {
            network: "locality-test".into(),
            container_id: name.into(),
            ifname: "eth0".into(),
        },
        netns: format!("/run/unf-locality-disposable/{name}"),
        mtu: 1400,
        workload_uid: Some(name.into()),
    }
}

fn ready(journal: &mut AttachmentJournal, name: &str) {
    journal
        .apply(request(TransactionOperation::Prepare {
            attachment: spec(name),
        }))
        .unwrap();
    journal
        .apply(request(TransactionOperation::Commit {
            key: spec(name).key,
        }))
        .unwrap();
}

fn map_reader(gate: &IncarnationGate) -> aya::maps::HashMap<aya::maps::MapData, [u8; 32], u64> {
    let data = aya::maps::MapData::from_fd(gate.duplicate_map_fd().unwrap()).unwrap();
    let info = data.info().unwrap();
    assert_eq!(info.key_size(), 32);
    assert_eq!(info.value_size(), 8);
    assert_eq!(info.max_entries(), 8);
    assert_eq!(info.map_flags(), 1 << 7);
    aya::maps::HashMap::try_from(aya::maps::Map::HashMap(data)).unwrap()
}

fn verify_reopen(
    path: &Path,
    provider: NodeBlockProvider,
    gate: &IncarnationGate,
    old: &IncarnationLease,
) {
    let mut reopened = AttachmentJournal::open(path, provider).unwrap();
    assert!(
        gate.issue(
            &reopened,
            &reopened.cut().unwrap(),
            reopened.get(&spec("second").key).unwrap()
        )
        .is_err()
    );
    let new_gate = IncarnationGate::install(&mut reopened, 8).unwrap();
    assert!(!new_gate.is_current(old).unwrap());
    let new = new_gate
        .issue(
            &reopened,
            &reopened.cut().unwrap(),
            reopened.get(&spec("second").key).unwrap(),
        )
        .unwrap();
    assert!(!gate.is_current(&new).unwrap());
    assert!(new_gate.is_current(&new).unwrap());
}

fn verify_capacity(path: &Path, provider: NodeBlockProvider) {
    let mut journal = AttachmentJournal::open(path, provider).unwrap();
    ready(&mut journal, "first");
    ready(&mut journal, "second");
    let gate = IncarnationGate::install(&mut journal, 1).unwrap();
    let first = journal.get(&spec("first").key).unwrap();
    let second = journal.get(&spec("second").key).unwrap();
    let cut = journal.cut().unwrap();
    let lease = gate.issue(&journal, &cut, first).unwrap();
    assert!(gate.issue(&journal, &cut, second).is_err());
    assert!(gate.issue(&journal, &cut, first).is_err());
    assert!(gate.is_current(&lease).unwrap());
    journal
        .apply(request(TransactionOperation::BeginDelete {
            key: spec("first").key,
        }))
        .unwrap();
    assert!(!gate.is_current(&lease).unwrap());
}

fn main() {
    assert_eq!(
        std::env::var("UNF_LOCALITY_GATE_ISOLATED_CONTAINER").as_deref(),
        Ok("yes"),
        "run only in the disposable platform qualification container"
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal.json");
    let provider = NodeBlockProvider::new(
        "192.0.2.0/24".parse().unwrap(),
        "2001:db8::/120".parse().unwrap(),
    );
    let mut journal = AttachmentJournal::open(&path, provider).unwrap();
    ready(&mut journal, "first");
    ready(&mut journal, "second");
    let before_install = journal.cut().unwrap();
    let gate = IncarnationGate::install(&mut journal, 8).unwrap();
    assert!(!journal.is_current(&before_install));
    let first = journal.get(&spec("first").key).unwrap().clone();
    let second = journal.get(&spec("second").key).unwrap().clone();
    let cut = journal.cut().unwrap();
    assert!(gate.issue(&journal, &before_install, &first).is_err());
    let a = gate.issue(&journal, &cut, &first).unwrap();
    let b = gate.issue(&journal, &cut, &second).unwrap();
    assert_ne!(a.serial(), b.serial());
    assert!(gate.is_current(&a).unwrap());
    assert!(gate.is_current(&b).unwrap());
    assert_eq!(
        gate.issue(&journal, &cut, &first).unwrap().serial(),
        a.serial()
    );
    let reader = map_reader(&gate);
    assert_eq!(reader.get(a.nonce(), 0).unwrap(), a.serial());

    // Persist failure AFTER the callback must leave the kernel lease revoked
    // despite restoring a Ready record in memory. Reissue requires a fresh cut
    // and a new serial; a stale immutable bank's old serial never matches.
    let temporary = path.with_extension("json.tmp");
    fs::create_dir(&temporary).unwrap();
    assert!(
        journal
            .apply(request(TransactionOperation::BeginDelete {
                key: first.spec.key.clone()
            }))
            .is_err()
    );
    assert_eq!(
        journal.get(&first.spec.key).unwrap().phase,
        AttachmentPhase::Ready
    );
    assert!(!gate.is_current(&a).unwrap());
    assert!(gate.is_current(&b).unwrap());
    assert!(matches!(
        reader.get(a.nonce(), 0),
        Err(aya::maps::MapError::KeyNotFound)
    ));
    assert!(gate.issue(&journal, &cut, &first).is_err());
    fs::remove_dir(&temporary).unwrap();
    ready(&mut journal, "third");
    let fresh = journal.cut().unwrap();
    let a_new = gate.issue(&journal, &fresh, &first).unwrap();
    assert_ne!(a_new.serial(), a.serial());
    assert!(!gate.is_current(&a).unwrap());
    assert!(gate.is_current(&a_new).unwrap());
    assert!(gate.is_current(&b).unwrap());
    for _ in 0..2 {
        journal
            .apply(request(TransactionOperation::BeginDelete {
                key: first.spec.key.clone(),
            }))
            .unwrap();
        assert!(!gate.is_current(&a_new).unwrap());
        assert!(gate.is_current(&b).unwrap());
    }
    assert!(
        gate.issue(&journal, &journal.cut().unwrap(), &first)
            .is_err()
    );
    journal
        .apply(request(TransactionOperation::CompleteDelete {
            key: first.spec.key.clone(),
        }))
        .unwrap();
    ready(&mut journal, "first");
    let replaced = journal.get(&first.spec.key).unwrap();
    assert_ne!(replaced.creation_token, first.creation_token);
    assert!(
        gate.issue(&journal, &journal.cut().unwrap(), &first)
            .is_err()
    );
    let replacement = gate
        .issue(&journal, &journal.cut().unwrap(), replaced)
        .unwrap();
    assert!(gate.is_current(&replacement).unwrap());
    assert!(!gate.is_current(&a).unwrap());
    assert!(!gate.is_current(&a_new).unwrap());

    verify_reopen(&path, provider, &gate, &b);
    verify_capacity(&directory.path().join("capacity.json"), provider);

    // All descriptors/journals are local to this process; no shared pin was
    // created. Dropping them cannot remove any preexisting cluster resource.
    drop((reader, gate, journal, a, a_new, b, replacement));
    directory.close().unwrap();
    println!(
        "kernel-incarnation-gate: PASS schema=1 exact-revocation=true unrelated-preserved=true stale-serial-denied=true foreign-journal-denied=true cleanup=true packet-delivery-tested=false"
    );
}
