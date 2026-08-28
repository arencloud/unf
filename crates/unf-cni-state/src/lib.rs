use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CNI_TRANSACTION_SCHEMA_VERSION: u16 = 1;
pub const MAX_TRANSACTION_MESSAGE_BYTES: usize = 65_536;

const MIN_DUAL_STACK_MTU: u32 = 1_280;
const MAX_MTU: u32 = 65_535;
const MAX_IDENTIFIER_BYTES: usize = 253;
const MAX_NETNS_BYTES: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttachmentKey {
    pub network: String,
    pub container_id: String,
    pub ifname: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttachmentSpec {
    pub key: AttachmentKey,
    pub netns: String,
    pub mtu: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentPhase {
    Preparing,
    Ready,
    Aborting,
    Deleting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttachmentRecord {
    pub spec: AttachmentSpec,
    pub host_interface: String,
    pub phase: AttachmentPhase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "operation", rename_all = "snake_case")]
pub enum TransactionOperation {
    Status,
    Prepare { attachment: AttachmentSpec },
    Commit { key: AttachmentKey },
    BeginAbort { key: AttachmentKey },
    CompleteAbort { key: AttachmentKey },
    Check { attachment: AttachmentSpec },
    BeginDelete { key: AttachmentKey },
    CompleteDelete { key: AttachmentKey },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    tag = "operation"
)]
pub enum TransactionRequest {
    Status {
        schema_version: u16,
    },
    Prepare {
        schema_version: u16,
        attachment: AttachmentSpec,
    },
    Commit {
        schema_version: u16,
        key: AttachmentKey,
    },
    BeginAbort {
        schema_version: u16,
        key: AttachmentKey,
    },
    CompleteAbort {
        schema_version: u16,
        key: AttachmentKey,
    },
    Check {
        schema_version: u16,
        attachment: AttachmentSpec,
    },
    BeginDelete {
        schema_version: u16,
        key: AttachmentKey,
    },
    CompleteDelete {
        schema_version: u16,
        key: AttachmentKey,
    },
}

impl TransactionRequest {
    #[must_use]
    pub fn new(schema_version: u16, operation: TransactionOperation) -> Self {
        match operation {
            TransactionOperation::Status => Self::Status { schema_version },
            TransactionOperation::Prepare { attachment } => Self::Prepare {
                schema_version,
                attachment,
            },
            TransactionOperation::Commit { key } => Self::Commit {
                schema_version,
                key,
            },
            TransactionOperation::BeginAbort { key } => Self::BeginAbort {
                schema_version,
                key,
            },
            TransactionOperation::CompleteAbort { key } => Self::CompleteAbort {
                schema_version,
                key,
            },
            TransactionOperation::Check { attachment } => Self::Check {
                schema_version,
                attachment,
            },
            TransactionOperation::BeginDelete { key } => Self::BeginDelete {
                schema_version,
                key,
            },
            TransactionOperation::CompleteDelete { key } => Self::CompleteDelete {
                schema_version,
                key,
            },
        }
    }

    const fn schema_version(&self) -> u16 {
        match self {
            Self::Status { schema_version }
            | Self::Prepare { schema_version, .. }
            | Self::Commit { schema_version, .. }
            | Self::BeginAbort { schema_version, .. }
            | Self::CompleteAbort { schema_version, .. }
            | Self::Check { schema_version, .. }
            | Self::BeginDelete { schema_version, .. }
            | Self::CompleteDelete { schema_version, .. } => *schema_version,
        }
    }

    fn into_operation(self) -> TransactionOperation {
        match self {
            Self::Status { .. } => TransactionOperation::Status,
            Self::Prepare { attachment, .. } => TransactionOperation::Prepare { attachment },
            Self::Commit { key, .. } => TransactionOperation::Commit { key },
            Self::BeginAbort { key, .. } => TransactionOperation::BeginAbort { key },
            Self::CompleteAbort { key, .. } => TransactionOperation::CompleteAbort { key },
            Self::Check { attachment, .. } => TransactionOperation::Check { attachment },
            Self::BeginDelete { key, .. } => TransactionOperation::BeginDelete { key },
            Self::CompleteDelete { key, .. } => TransactionOperation::CompleteDelete { key },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionErrorCode {
    InvalidRequest,
    IncompatibleSchema,
    NotFound,
    Conflict,
    InvalidTransition,
    PersistenceFailure,
    Unauthorized,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
pub enum TransactionOutcome {
    #[serde(rename = "ok")]
    Ok {
        attachment: Option<AttachmentRecord>,
        attachment_count: usize,
    },
    #[serde(rename = "error")]
    Error {
        code: TransactionErrorCode,
        message: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    pub schema_version: u16,
    #[serde(flatten)]
    pub outcome: TransactionOutcome,
}

impl TransactionResponse {
    #[must_use]
    pub fn error(code: TransactionErrorCode, message: impl Into<String>) -> Self {
        Self {
            schema_version: CNI_TRANSACTION_SCHEMA_VERSION,
            outcome: TransactionOutcome::Error {
                code,
                message: message.into(),
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("attachment request is invalid: {0}")]
    Invalid(String),
    #[error("attachment does not exist")]
    NotFound,
    #[error("attachment conflicts with existing durable state: {0}")]
    Conflict(String),
    #[error("attachment state transition is invalid: {0}")]
    InvalidTransition(String),
    #[error("attachment journal schema {actual} is incompatible with schema {expected}")]
    IncompatibleSchema { actual: u16, expected: u16 },
    #[error("attachment journal I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("attachment journal JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct JournalDocument {
    schema_version: u16,
    attachments: Vec<AttachmentRecord>,
}

pub struct AttachmentJournal {
    path: PathBuf,
    attachments: BTreeMap<AttachmentKey, AttachmentRecord>,
}

impl AttachmentJournal {
    /// Opens and validates a journal, creating its parent directory when needed.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths, malformed or incompatible state, and
    /// filesystem failures.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(JournalError::Invalid(
                "journal path must be absolute".to_owned(),
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            JournalError::Invalid("journal path must have a parent directory".to_owned())
        })?;
        reject_symlink_components(&path)?;
        fs::create_dir_all(parent)?;
        reject_symlink_components(&path)?;
        remove_stale_temporary(&path)?;

        let attachments = if path.exists() {
            let metadata = fs::metadata(&path)?;
            if !metadata.file_type().is_file() {
                return Err(JournalError::Invalid(
                    "journal path must be a regular file".to_owned(),
                ));
            }
            let document: JournalDocument = serde_json::from_reader(File::open(&path)?)?;
            let attachments = validate_document(document)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            attachments
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, attachments })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.attachments.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attachments.is_empty()
    }

    #[must_use]
    pub fn get(&self, key: &AttachmentKey) -> Option<&AttachmentRecord> {
        self.attachments.get(key)
    }

    #[must_use]
    pub fn records(&self) -> Vec<AttachmentRecord> {
        self.attachments.values().cloned().collect()
    }

    /// Applies one validated, durable transaction operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the schema, request, transition, or persistence is
    /// invalid. Failed writes restore the prior in-memory state.
    pub fn apply(
        &mut self,
        request: TransactionRequest,
    ) -> Result<TransactionResponse, JournalError> {
        if request.schema_version() != CNI_TRANSACTION_SCHEMA_VERSION {
            return Err(JournalError::IncompatibleSchema {
                actual: request.schema_version(),
                expected: CNI_TRANSACTION_SCHEMA_VERSION,
            });
        }

        let previous = self.attachments.clone();
        let attachment = match request.into_operation() {
            TransactionOperation::Status => None,
            TransactionOperation::Prepare { attachment } => {
                validate_spec(&attachment)?;
                Some(self.prepare(attachment)?)
            }
            TransactionOperation::Commit { key } => {
                validate_key(&key)?;
                Some(self.commit(&key)?)
            }
            TransactionOperation::BeginAbort { key } => {
                validate_key(&key)?;
                self.begin_abort(&key)?
            }
            TransactionOperation::CompleteAbort { key } => {
                validate_key(&key)?;
                self.complete_abort(&key)?
            }
            TransactionOperation::Check { attachment } => {
                validate_spec(&attachment)?;
                Some(self.check(&attachment)?)
            }
            TransactionOperation::BeginDelete { key } => {
                validate_key(&key)?;
                self.begin_delete(&key)?
            }
            TransactionOperation::CompleteDelete { key } => {
                validate_key(&key)?;
                self.complete_delete(&key)?
            }
        };

        if self.attachments != previous
            && let Err(error) = self.persist()
        {
            self.attachments = previous;
            return Err(error);
        }
        Ok(TransactionResponse {
            schema_version: CNI_TRANSACTION_SCHEMA_VERSION,
            outcome: TransactionOutcome::Ok {
                attachment,
                attachment_count: self.attachments.len(),
            },
        })
    }

    fn prepare(&mut self, spec: AttachmentSpec) -> Result<AttachmentRecord, JournalError> {
        if let Some(existing) = self.attachments.get(&spec.key) {
            if existing.spec != spec {
                return Err(JournalError::Conflict(
                    "the same key has a different namespace or MTU".to_owned(),
                ));
            }
            if existing.phase == AttachmentPhase::Preparing {
                return Ok(existing.clone());
            }
            return Err(JournalError::InvalidTransition(format!(
                "prepare cannot replay from {:?}",
                existing.phase
            )));
        }

        let host_interface = deterministic_host_interface(&spec.key);
        if self
            .attachments
            .values()
            .any(|record| record.host_interface == host_interface)
        {
            return Err(JournalError::Conflict(format!(
                "derived host interface {host_interface} is already owned"
            )));
        }
        let record = AttachmentRecord {
            spec: spec.clone(),
            host_interface,
            phase: AttachmentPhase::Preparing,
        };
        self.attachments.insert(spec.key, record.clone());
        Ok(record)
    }

    fn commit(&mut self, key: &AttachmentKey) -> Result<AttachmentRecord, JournalError> {
        let record = self
            .attachments
            .get_mut(key)
            .ok_or(JournalError::NotFound)?;
        match record.phase {
            AttachmentPhase::Preparing => record.phase = AttachmentPhase::Ready,
            AttachmentPhase::Ready => {}
            phase => {
                return Err(JournalError::InvalidTransition(format!(
                    "commit cannot run from {phase:?}"
                )));
            }
        }
        Ok(record.clone())
    }

    fn begin_abort(
        &mut self,
        key: &AttachmentKey,
    ) -> Result<Option<AttachmentRecord>, JournalError> {
        let Some(record) = self.attachments.get_mut(key) else {
            return Ok(None);
        };
        match record.phase {
            AttachmentPhase::Preparing | AttachmentPhase::Aborting => {
                record.phase = AttachmentPhase::Aborting;
                Ok(Some(record.clone()))
            }
            phase => Err(JournalError::InvalidTransition(format!(
                "abort cannot run from {phase:?}"
            ))),
        }
    }

    fn complete_abort(
        &mut self,
        key: &AttachmentKey,
    ) -> Result<Option<AttachmentRecord>, JournalError> {
        let Some(record) = self.attachments.get(key) else {
            return Ok(None);
        };
        if record.phase != AttachmentPhase::Aborting {
            return Err(JournalError::InvalidTransition(format!(
                "abort cannot complete from {:?}",
                record.phase
            )));
        }
        self.attachments.remove(key);
        Ok(None)
    }

    fn check(&self, spec: &AttachmentSpec) -> Result<AttachmentRecord, JournalError> {
        let record = self
            .attachments
            .get(&spec.key)
            .ok_or(JournalError::NotFound)?;
        if record.spec != *spec {
            return Err(JournalError::Conflict(
                "CHECK does not match the durable attachment specification".to_owned(),
            ));
        }
        if record.phase != AttachmentPhase::Ready {
            return Err(JournalError::InvalidTransition(format!(
                "CHECK requires ready state, found {:?}",
                record.phase
            )));
        }
        Ok(record.clone())
    }

    fn begin_delete(
        &mut self,
        key: &AttachmentKey,
    ) -> Result<Option<AttachmentRecord>, JournalError> {
        let Some(record) = self.attachments.get_mut(key) else {
            return Ok(None);
        };
        match record.phase {
            AttachmentPhase::Preparing | AttachmentPhase::Ready => {
                record.phase = AttachmentPhase::Deleting;
            }
            AttachmentPhase::Deleting => {}
            AttachmentPhase::Aborting => {
                return Err(JournalError::InvalidTransition(
                    "delete cannot begin while aborting".to_owned(),
                ));
            }
        }
        Ok(Some(record.clone()))
    }

    fn complete_delete(
        &mut self,
        key: &AttachmentKey,
    ) -> Result<Option<AttachmentRecord>, JournalError> {
        let Some(record) = self.attachments.get(key) else {
            return Ok(None);
        };
        if record.phase != AttachmentPhase::Deleting {
            return Err(JournalError::InvalidTransition(format!(
                "delete cannot complete from {:?}",
                record.phase
            )));
        }
        self.attachments.remove(key);
        Ok(None)
    }

    fn persist(&self) -> Result<(), JournalError> {
        let parent = self.path.parent().expect("validated journal parent");
        reject_symlink_components(&self.path)?;
        let temporary = temporary_path(&self.path);
        if temporary.exists() {
            return Err(JournalError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("temporary journal {} already exists", temporary.display()),
            )));
        }
        let document = JournalDocument {
            schema_version: CNI_TRANSACTION_SCHEMA_VERSION,
            attachments: self.attachments.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&document)?;
        let write_result = (|| -> Result<(), JournalError> {
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.write_all(b"\n")?;
            output.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            File::open(parent)?.sync_all()?;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }
}

fn validate_document(
    document: JournalDocument,
) -> Result<BTreeMap<AttachmentKey, AttachmentRecord>, JournalError> {
    if document.schema_version != CNI_TRANSACTION_SCHEMA_VERSION {
        return Err(JournalError::IncompatibleSchema {
            actual: document.schema_version,
            expected: CNI_TRANSACTION_SCHEMA_VERSION,
        });
    }
    let mut attachments = BTreeMap::new();
    let mut interfaces = BTreeSet::new();
    let mut previous_key: Option<AttachmentKey> = None;
    for record in document.attachments {
        validate_spec(&record.spec)?;
        if record.host_interface != deterministic_host_interface(&record.spec.key) {
            return Err(JournalError::Invalid(
                "journal contains a non-deterministic host interface".to_owned(),
            ));
        }
        if previous_key
            .as_ref()
            .is_some_and(|key| key >= &record.spec.key)
        {
            return Err(JournalError::Invalid(
                "journal attachments must be uniquely sorted by key".to_owned(),
            ));
        }
        if !interfaces.insert(record.host_interface.clone()) {
            return Err(JournalError::Conflict(
                "journal contains duplicate host-interface ownership".to_owned(),
            ));
        }
        previous_key = Some(record.spec.key.clone());
        attachments.insert(record.spec.key.clone(), record);
    }
    Ok(attachments)
}

fn validate_spec(spec: &AttachmentSpec) -> Result<(), JournalError> {
    validate_key(&spec.key)?;
    if !spec.netns.starts_with('/')
        || spec.netns.as_bytes().contains(&0)
        || spec.netns.len() > MAX_NETNS_BYTES
    {
        return Err(JournalError::Invalid(
            "network namespace must be a bounded absolute path without NUL bytes".to_owned(),
        ));
    }
    if !(MIN_DUAL_STACK_MTU..=MAX_MTU).contains(&spec.mtu) {
        return Err(JournalError::Invalid(format!(
            "MTU must be between {MIN_DUAL_STACK_MTU} and {MAX_MTU}"
        )));
    }
    Ok(())
}

fn validate_key(key: &AttachmentKey) -> Result<(), JournalError> {
    if !valid_identifier(&key.network, MAX_IDENTIFIER_BYTES)
        || !valid_identifier(&key.container_id, MAX_IDENTIFIER_BYTES)
        || !valid_interface_name(&key.ifname)
    {
        return Err(JournalError::Invalid(
            "network, container ID, or interface name is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str, max: usize) -> bool {
    let mut bytes = value.bytes();
    value.len() <= max
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_interface_name(value: &str) -> bool {
    valid_identifier(value, 15)
}

fn deterministic_host_interface(key: &AttachmentKey) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for value in [&key.network, &key.container_id, &key.ifname] {
        for byte in value.bytes().chain(std::iter::once(0)) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("unf{:011x}", hash & 0x0000_07ff_ffff_ffff)
}

fn reject_symlink_components(path: &Path) -> Result<(), JournalError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(JournalError::Invalid(format!(
                    "journal path contains symlink {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension("json.tmp")
}

fn remove_stale_temporary(path: &Path) -> Result<(), JournalError> {
    let temporary = temporary_path(path);
    let metadata = match fs::symlink_metadata(&temporary) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        return Err(JournalError::Invalid(format!(
            "temporary journal path is not a regular file: {}",
            temporary.display()
        )));
    }
    fs::remove_file(temporary)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn key(container_id: &str) -> AttachmentKey {
        AttachmentKey {
            network: "unf-test".to_owned(),
            container_id: container_id.to_owned(),
            ifname: "eth0".to_owned(),
        }
    }

    fn spec(container_id: &str) -> AttachmentSpec {
        AttachmentSpec {
            key: key(container_id),
            netns: format!("/run/netns/{container_id}"),
            mtu: 1_500,
        }
    }

    fn request(operation: TransactionOperation) -> TransactionRequest {
        TransactionRequest::new(CNI_TRANSACTION_SCHEMA_VERSION, operation)
    }

    #[test]
    fn prepare_commit_check_and_restart_are_durable_and_idempotent() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("attachments.json");
        let mut journal = AttachmentJournal::open(&path).expect("open journal");
        let prepare = request(TransactionOperation::Prepare {
            attachment: spec("container-1"),
        });
        let first = journal.apply(prepare.clone()).expect("prepare");
        let replay = journal.apply(prepare).expect("replay prepare");
        assert_eq!(first, replay);
        assert_eq!(journal.len(), 1);

        let commit = request(TransactionOperation::Commit {
            key: key("container-1"),
        });
        journal.apply(commit.clone()).expect("commit");
        journal.apply(commit).expect("replay commit");
        let reopened = AttachmentJournal::open(&path).expect("restart journal");
        assert_eq!(reopened.len(), 1);
        assert_eq!(
            reopened.get(&key("container-1")).expect("record").phase,
            AttachmentPhase::Ready
        );

        let mode = fs::metadata(path)
            .expect("journal metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn abort_and_delete_are_repeatable_and_do_not_release_early() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("attachments.json");
        let mut journal = AttachmentJournal::open(&path).expect("open journal");
        journal
            .apply(request(TransactionOperation::Prepare {
                attachment: spec("abort-me"),
            }))
            .expect("prepare abort");
        let begin_abort = request(TransactionOperation::BeginAbort {
            key: key("abort-me"),
        });
        journal.apply(begin_abort.clone()).expect("begin abort");
        journal.apply(begin_abort).expect("repeat begin abort");
        assert_eq!(
            journal.get(&key("abort-me")).expect("aborting").phase,
            AttachmentPhase::Aborting
        );
        assert_eq!(
            AttachmentJournal::open(&path)
                .expect("restart while aborting")
                .get(&key("abort-me"))
                .expect("durable aborting record")
                .phase,
            AttachmentPhase::Aborting
        );
        let complete_abort = request(TransactionOperation::CompleteAbort {
            key: key("abort-me"),
        });
        journal
            .apply(complete_abort.clone())
            .expect("complete abort");
        journal
            .apply(complete_abort)
            .expect("repeat complete abort");

        journal
            .apply(request(TransactionOperation::Prepare {
                attachment: spec("delete-me"),
            }))
            .expect("prepare delete");
        journal
            .apply(request(TransactionOperation::Commit {
                key: key("delete-me"),
            }))
            .expect("commit delete");
        let begin = request(TransactionOperation::BeginDelete {
            key: key("delete-me"),
        });
        journal.apply(begin.clone()).expect("begin delete");
        journal.apply(begin).expect("repeat begin delete");
        assert_eq!(
            journal.get(&key("delete-me")).expect("deleting").phase,
            AttachmentPhase::Deleting
        );
        assert_eq!(
            AttachmentJournal::open(&path)
                .expect("restart while deleting")
                .get(&key("delete-me"))
                .expect("durable deleting record")
                .phase,
            AttachmentPhase::Deleting
        );
        let complete = request(TransactionOperation::CompleteDelete {
            key: key("delete-me"),
        });
        journal.apply(complete.clone()).expect("complete delete");
        journal.apply(complete).expect("repeat complete delete");
        assert!(journal.is_empty());
    }

    #[test]
    fn conflicts_and_invalid_transitions_do_not_change_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut journal =
            AttachmentJournal::open(directory.path().join("state.json")).expect("open journal");
        journal
            .apply(request(TransactionOperation::Prepare {
                attachment: spec("container-1"),
            }))
            .expect("prepare");
        let mut changed = spec("container-1");
        changed.mtu = 1_400;
        assert!(matches!(
            journal.apply(request(TransactionOperation::Prepare {
                attachment: changed
            })),
            Err(JournalError::Conflict(_))
        ));
        assert!(matches!(
            journal.apply(request(TransactionOperation::Check {
                attachment: spec("container-1")
            })),
            Err(JournalError::InvalidTransition(_))
        ));
        assert_eq!(journal.len(), 1);
    }

    #[test]
    fn incompatible_malformed_unsorted_and_symlinked_journals_are_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let incompatible = directory.path().join("incompatible.json");
        fs::write(&incompatible, r#"{"schemaVersion":2,"attachments":[]}"#)
            .expect("write incompatible state");
        assert!(matches!(
            AttachmentJournal::open(incompatible),
            Err(JournalError::IncompatibleSchema { .. })
        ));

        let malformed = directory.path().join("malformed.json");
        fs::write(&malformed, b"not-json").expect("write malformed state");
        assert!(matches!(
            AttachmentJournal::open(malformed),
            Err(JournalError::Json(_))
        ));

        let sorted = directory.path().join("sorted.json");
        let records = [spec("container-b"), spec("container-a")]
            .into_iter()
            .map(|spec| AttachmentRecord {
                host_interface: deterministic_host_interface(&spec.key),
                spec,
                phase: AttachmentPhase::Preparing,
            })
            .collect();
        let document = JournalDocument {
            schema_version: CNI_TRANSACTION_SCHEMA_VERSION,
            attachments: records,
        };
        fs::write(
            &sorted,
            serde_json::to_vec(&document).expect("encode document"),
        )
        .expect("write unsorted state");
        assert!(matches!(
            AttachmentJournal::open(sorted),
            Err(JournalError::Invalid(_))
        ));

        let real = directory.path().join("real.json");
        fs::write(&real, b"{}").expect("write real target");
        let link = directory.path().join("link.json");
        symlink(real, &link).expect("create journal symlink");
        assert!(matches!(
            AttachmentJournal::open(link),
            Err(JournalError::Invalid(_))
        ));

        let recoverable = directory.path().join("recoverable.json");
        fs::write(temporary_path(&recoverable), b"interrupted write")
            .expect("write stale temporary journal");
        assert!(
            AttachmentJournal::open(&recoverable)
                .expect("stale temporary state is recovered")
                .is_empty()
        );
        assert!(!temporary_path(&recoverable).exists());
    }

    #[test]
    fn requests_and_results_have_a_stable_versioned_wire_shape() {
        let encoded =
            serde_json::to_value(request(TransactionOperation::Status)).expect("encode request");
        assert_eq!(encoded["schemaVersion"], 1);
        assert_eq!(encoded["operation"], "status");
        let response = TransactionResponse::error(
            TransactionErrorCode::Unauthorized,
            "root credentials required",
        );
        let encoded = serde_json::to_value(response).expect("encode response");
        assert_eq!(encoded["schemaVersion"], 1);
        assert_eq!(encoded["status"], "error");
        assert_eq!(encoded["code"], "unauthorized");

        let unknown = br#"{"schemaVersion":1,"operation":"status","unexpected":true}"#;
        assert!(serde_json::from_slice::<TransactionRequest>(unknown).is_err());
    }
}
