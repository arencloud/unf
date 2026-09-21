use std::collections::BTreeMap;

use super::*;

#[derive(Default)]
struct Model {
    entries: BTreeMap<[u8; 32], u64>,
    fail_write: bool,
    fail_read: bool,
    wrong_readback: bool,
}

impl MapBackend for Model {
    fn lookup(&self, nonce: &[u8; 32]) -> io::Result<Option<u64>> {
        if self.fail_read {
            return Err(io::Error::other("injected lookup failure"));
        }
        Ok(self.entries.get(nonce).copied())
    }

    fn write(&mut self, nonce: &[u8; 32], serial: u64) -> io::Result<()> {
        // Model the conservative ambiguous-success boundary, not just a
        // failure that happened before any kernel change.
        self.entries
            .insert(*nonce, serial + u64::from(self.wrong_readback));
        if self.fail_write {
            return Err(io::Error::other("injected post-write failure"));
        }
        Ok(())
    }

    fn revoke(&mut self, nonce: &[u8; 32]) -> io::Result<()> {
        self.entries.remove(nonce);
        Ok(())
    }
}

fn state() -> GateState<Model> {
    GateState {
        map: Model::default(),
        last_serial: 0,
        issuance_retired: false,
    }
}

#[test]
fn exact_nonce_reuse_preserves_serial_but_retire_reissue_never_rearms_old_bank() {
    let mut state = state();
    let nonce = [1; 32];
    let mut other = nonce;
    other[31] = 2;
    let old = state.issue(&nonce).unwrap();
    assert_eq!(state.issue(&nonce).unwrap(), old);
    let unrelated = state.issue(&other).unwrap();
    assert_ne!(old, unrelated);
    state.map.revoke(&nonce).unwrap();
    state.map.revoke(&nonce).unwrap();
    assert_eq!(state.map.lookup(&nonce).unwrap(), None);
    assert_eq!(state.map.lookup(&other).unwrap(), Some(unrelated));
    let new = state.issue(&nonce).unwrap();
    assert_ne!(new, old);
    assert_eq!(state.map.lookup(&nonce).unwrap(), Some(new));
    assert_eq!(state.map.entries.len(), 2);
    for _ in 0..4096 {
        state.map.revoke(&nonce).unwrap();
        let serial = state.issue(&nonce).unwrap();
        assert!(serial > new);
        assert_eq!(state.map.entries.len(), 2, "no retained tombstone growth");
    }
}

#[test]
fn ambiguous_write_or_wrong_readback_permanently_fences_issuance_but_not_revocation() {
    for wrong_readback in [false, true] {
        let mut state = state();
        state.map.fail_write = !wrong_readback;
        state.map.wrong_readback = wrong_readback;
        assert!(state.issue(&[1; 32]).is_err());
        assert_eq!(state.last_serial, 1);
        assert!(state.issuance_retired);
        state.map.fail_write = false;
        state.map.wrong_readback = false;
        state.map.revoke(&[1; 32]).unwrap();
        assert_eq!(state.map.lookup(&[1; 32]).unwrap(), None);
        assert!(state.issue(&[1; 32]).is_err());
        assert!(state.issue(&[2; 32]).is_err());
        assert!(state.map.entries.is_empty());
    }
}

#[test]
fn read_failures_do_not_mint_leases_and_unknown_serials_retire_issuance() {
    let mut failed_read = state();
    failed_read.map.fail_read = true;
    assert!(failed_read.issue(&[1; 32]).is_err());
    assert!(failed_read.map.entries.is_empty());
    assert_eq!(failed_read.last_serial, 0);
    for serial in [0, 1, u64::MAX] {
        let mut state = state();
        state.map.entries.insert([1; 32], serial);
        assert!(state.issue(&[1; 32]).is_err());
        assert!(state.issuance_retired);
    }
}

#[test]
fn serial_exhaustion_never_wraps_or_writes_a_zero_lease() {
    let mut state = state();
    state.last_serial = u64::MAX - 1;
    assert_eq!(state.issue(&[1; 32]).unwrap(), u64::MAX);
    assert_eq!(state.issue(&[1; 32]).unwrap(), u64::MAX);
    assert!(state.issue(&[2; 32]).is_err());
    assert!(state.issuance_retired);
    assert_eq!(state.map.entries.len(), 1);
    assert_eq!(state.last_serial, u64::MAX);
    state.map.revoke(&[1; 32]).unwrap();
    assert!(state.map.entries.is_empty());
}

#[test]
fn invalid_capacity_is_rejected_before_a_privileged_operation() {
    let directory = tempfile::tempdir().unwrap();
    let mut journal = AttachmentJournal::open(
        directory.path().join("journal.json"),
        unf_ipam::NodeBlockProvider::new(
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/120".parse().unwrap(),
        ),
    )
    .unwrap();
    for capacity in [0, MAX_INCARNATIONS + 1, u32::MAX] {
        assert!(matches!(
            IncarnationGate::install(&mut journal, capacity),
            Err(LocalityGateError::Invalid)
        ));
    }
}
