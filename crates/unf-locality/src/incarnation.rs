use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard};

use aya::maps::{HashMap, MapData, MapError};
use thiserror::Error;
use unf_cni_state::{
    AttachmentJournal, AttachmentJournalCut, AttachmentPhase, AttachmentRecord,
    AttachmentRetirement, AttachmentRetirementRegistration, JournalError,
};

// Linux UAPI BPF_F_RDONLY_PROG: the packet program cannot mint/rearm leases.
const READ_ONLY_PROGRAM: u32 = 1 << 7;
const MAX_INCARNATIONS: u32 = 65_536;
type LeaseMap = HashMap<MapData, [u8; 32], u64>;

#[derive(Debug, Error)]
pub enum LocalityGateError {
    #[error("locality gate rejects invalid capacity, record, journal registration or cut")]
    Invalid,
    #[error("locality gate cannot issue leases after an ambiguous write or serial exhaustion")]
    Retired,
    #[error("locality gate journal: {0}")]
    Journal(#[from] JournalError),
    #[error("locality gate map: {0}")]
    Map(#[from] MapError),
    #[error("locality gate I/O: {0}")]
    Io(#[from] io::Error),
}

/// One fresh kernel gate, installed as the invalidator of exactly one journal.
/// Nothing is restored from disk or from a previous runtime map. The caller
/// must fence previous program dispatch before publishing a new runtime gate.
///
/// Full nonce keys and nonzero serials are only one conjunct of a bank's proof.
/// A consumer must also establish authenticated placement, packet-policy/egress
/// precedence, exact device ownership/lifetime and packet-time route agreement.
pub struct IncarnationGate {
    state: Arc<Mutex<GateState<LeaseMap>>>,
    registration: AttachmentRetirementRegistration,
}

/// Non-serializable lease from one gate. A bank must compare both full nonce
/// and serial against that exact map on every packet. Checking presence alone
/// permits ABA rearm and is prohibited. A lease is not packet permission.
pub struct IncarnationLease {
    nonce: [u8; 32],
    serial: u64,
    gate: Arc<Mutex<GateState<LeaseMap>>>,
}

impl IncarnationLease {
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }
}

struct GateState<M> {
    map: M,
    last_serial: u64,
    issuance_retired: bool,
}

struct Retirer(Arc<Mutex<GateState<LeaseMap>>>);

impl AttachmentRetirement for Retirer {
    fn retire(&self, nonce: &[u8; 32]) -> io::Result<()> {
        let mut state = lock(&self.0)?;
        state.map.revoke(nonce)
    }
}

impl IncarnationGate {
    /// Creates an empty, bounded, program-read-only map and installs its callback
    /// under the caller's journal lock. No nonce becomes live during install.
    /// There is intentionally no constructor from a pinned or serialized map.
    ///
    /// # Errors
    /// Rejects invalid capacity, kernel map errors, uncertain journals or a
    /// journal with another installed hook. Failed installation drops the map.
    pub fn install(
        journal: &mut AttachmentJournal,
        capacity: u32,
    ) -> Result<Self, LocalityGateError> {
        if !(1..=MAX_INCARNATIONS).contains(&capacity) {
            return Err(LocalityGateError::Invalid);
        }
        let map = LeaseMap::create(capacity, READ_ONLY_PROGRAM)?;
        let state = Arc::new(Mutex::new(GateState {
            map,
            last_serial: 0,
            issuance_retired: false,
        }));
        let registration = journal.install_retirement(Box::new(Retirer(Arc::clone(&state))))?;
        Ok(Self {
            state,
            registration,
        })
    }

    /// Issues/reuses a lease for the exact current Ready UID/nonce-bound record.
    /// Caller holds the journal transaction lock through this method and bank
    /// publication, after independently checking placement and kernel evidence.
    /// No async work, journal mutation or link repair occurs here.
    ///
    /// A removed nonce gets a NEW serial. No tombstone inventory is retained.
    /// A failed/ambiguous write permanently stops issuance from this gate but
    /// never stops subsequent revocation attempts during CNI deletion.
    ///
    /// # Errors
    /// Rejects stale/foreign cuts or registrations, legacy/non-Ready/different
    /// records, exhausted serials, poisoned synchronization or kernel failures.
    pub fn issue(
        &self,
        journal: &AttachmentJournal,
        cut: &AttachmentJournalCut,
        record: &AttachmentRecord,
    ) -> Result<IncarnationLease, LocalityGateError> {
        if !journal.retirement_matches(&self.registration)
            || !journal.is_current(cut)
            || journal.get(&record.spec.key) != Some(record)
            || record.phase != AttachmentPhase::Ready
            || record.spec.workload_uid.is_none()
        {
            return Err(LocalityGateError::Invalid);
        }
        let nonce = record
            .creation_token
            .filter(|nonce| *nonce != [0; 32])
            .ok_or(LocalityGateError::Invalid)?;
        let serial = lock(&self.state)?.issue(&nonce)?;
        Ok(IncarnationLease {
            nonce,
            serial,
            gate: Arc::clone(&self.state),
        })
    }

    /// Bounded readback of this gate's exact lease; not an application-delivery
    /// claim and not a substitute for the packet-time lookup.
    ///
    /// # Errors
    /// Reports synchronization and kernel observation failures.
    pub fn is_current(&self, lease: &IncarnationLease) -> Result<bool, LocalityGateError> {
        if !Arc::ptr_eq(&self.state, &lease.gate) {
            return Ok(false);
        }
        Ok(lock(&self.state)?.map.lookup(&lease.nonce)? == Some(lease.serial))
    }

    /// Duplicates the owned kernel map descriptor for an authenticated bank
    /// loader. Never exports entries or kernel pointers. The loader must bind
    /// THIS map, not reopen a map selected only by its name/shape.
    ///
    /// # Errors
    /// Reports poisoned synchronization or descriptor exhaustion.
    pub fn duplicate_map_fd(&self) -> Result<OwnedFd, LocalityGateError> {
        use aya::maps::IterableMap as _;
        Ok(lock(&self.state)?
            .map
            .map()
            .fd()
            .as_fd()
            .try_clone_to_owned()?)
    }
}

fn lock<M>(state: &Mutex<GateState<M>>) -> io::Result<MutexGuard<'_, GateState<M>>> {
    state
        .lock()
        .map_err(|_| io::Error::other("locality gate lock is poisoned"))
}

trait MapBackend {
    fn lookup(&self, nonce: &[u8; 32]) -> io::Result<Option<u64>>;
    fn write(&mut self, nonce: &[u8; 32], serial: u64) -> io::Result<()>;
    fn revoke(&mut self, nonce: &[u8; 32]) -> io::Result<()>;
}

impl MapBackend for LeaseMap {
    fn lookup(&self, nonce: &[u8; 32]) -> io::Result<Option<u64>> {
        match self.get(nonce, 0) {
            Ok(serial) => Ok(Some(serial)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(io::Error::other(error)),
        }
    }

    fn write(&mut self, nonce: &[u8; 32], serial: u64) -> io::Result<()> {
        // BPF_NOEXIST. There is one serialized userspace owner and the program
        // is read-only. Unexpected replacement is an error, not a rearm.
        self.insert(nonce, serial, 1).map_err(io::Error::other)
    }

    fn revoke(&mut self, nonce: &[u8; 32]) -> io::Result<()> {
        match self.remove(nonce) {
            Ok(()) => {}
            Err(MapError::SyscallError(error))
                if error.io_error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io::Error::other(error)),
        }
        if self.lookup(nonce)?.is_some() {
            return Err(io::Error::other(
                "retired locality incarnation remains present",
            ));
        }
        Ok(())
    }
}

impl<M: MapBackend> GateState<M> {
    fn issue(&mut self, nonce: &[u8; 32]) -> Result<u64, LocalityGateError> {
        if self.issuance_retired {
            return Err(LocalityGateError::Retired);
        }
        if let Some(serial) = self.map.lookup(nonce)? {
            if serial == 0 || serial > self.last_serial {
                self.issuance_retired = true;
                return Err(LocalityGateError::Retired);
            }
            return Ok(serial);
        }
        let Some(serial) = self.last_serial.checked_add(1) else {
            self.issuance_retired = true;
            return Err(LocalityGateError::Retired);
        };
        // Consume the serial before any write, including a failed one.
        self.last_serial = serial;
        if let Err(error) = self.map.write(nonce, serial).and_then(|()| {
            if self.map.lookup(nonce)? != Some(serial) {
                return Err(io::Error::other("locality lease readback differs"));
            }
            Ok(())
        }) {
            self.issuance_retired = true;
            return Err(LocalityGateError::Io(error));
        }
        Ok(serial)
    }
}

#[cfg(test)]
mod tests;
