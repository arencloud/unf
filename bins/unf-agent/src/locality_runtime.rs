//! Early runtime ownership. No serialized checkpoint is packet permission.
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use unf_cni_state::AttachmentJournal;
use unf_locality::{IncarnationGate, LocalityAdmission, LocalityRuntimeMaps};

use super::{AgentState, Args, load_secure_json, persist_secure_json};

pub(super) struct LocalityRuntime {
    pub(super) admission: LocalityAdmission,
    gate: OnceLock<IncarnationGate>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartupCheckpoint {
    schema_version: u16,
    boot_id: String,
    node_name: String,
    journal_path: PathBuf,
    pin_directory: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
enum StartupDecision {
    Create,
    Reopen,
}

fn boot_id_valid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
        && value
            .bytes()
            .any(|byte| matches!(byte, b'1'..=b'9' | b'a'..=b'f'))
}

fn decide(
    previous: Option<&StartupCheckpoint>,
    current: &StartupCheckpoint,
    guarded_journal: bool,
    pins_exist: bool,
) -> Result<StartupDecision> {
    ensure!(boot_id_valid(&current.boot_id), "invalid kernel boot ID");
    if let Some(previous) = previous {
        ensure!(
            previous.schema_version == 1
                && boot_id_valid(&previous.boot_id)
                && previous.node_name == current.node_name
                && previous.journal_path == current.journal_path
                && previous.pin_directory == current.pin_directory,
            "foreign or incompatible locality startup checkpoint"
        );
        if pins_exist {
            return Ok(StartupDecision::Reopen);
        }
        ensure!(
            previous.boot_id != current.boot_id,
            "locality pins missing during the same kernel boot; refusing replacement"
        );
        return Ok(StartupDecision::Create);
    }
    ensure!(
        !guarded_journal,
        "retirement-required journal has no locality startup checkpoint"
    );
    // An interrupted first startup can leave its empty complete pin set before
    // the durable checkpoint. Reopen still validates and withdraws every map.
    Ok(if pins_exist {
        StartupDecision::Reopen
    } else {
        StartupDecision::Create
    })
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Only root-owned non-symlink ancestors may be traversed/created. Existing
/// contents and permissions are never repaired to make startup pass.
fn managed_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "locality startup path must be plain and absolute"
    );
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        if !exists(&current)? {
            DirBuilder::new().mode(0o700).create(&current)?;
        }
        let metadata = fs::symlink_metadata(&current)?;
        let mode = metadata.permissions().mode();
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && (mode & 0o022 == 0 || (current != path && mode & 0o1000 != 0)),
            "unsafe locality startup directory {}",
            current.display()
        );
    }
    Ok(())
}

fn guarded_journal(path: &Path) -> Result<bool> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Header {
        schema_version: u16,
    }
    if !exists(path)? {
        return Ok(false);
    }
    private_root_file(path)?;
    let header: Header = load_secure_json(path, "locality journal header")?;
    ensure!(
        (1..=5).contains(&header.schema_version),
        "unknown CNI journal schema"
    );
    Ok(header.schema_version == 5)
}

#[allow(clippy::verbose_bit_mask)] // Octal POSIX permissions remain readable.
fn private_root_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o077 == 0,
        "unsafe locality startup file {}",
        path.display()
    );
    Ok(())
}

/// Call before provider resolution (which may migrate a journal), remote-route
/// repair, CNI binding or any dataplane task. A new boot permits fresh maps, not
/// restored placement, leases, coordinates or a previously selected bank.
pub(super) fn initialize(args: &Args, state: &AgentState, dataplane: bool) -> Result<()> {
    if !dataplane {
        return Ok(());
    }
    super::ensure_bpf_pin_path_abi(&args.bpf_pin_path)?;
    let pin_parent = args
        .bpf_pin_path
        .parent()
        .context("BPF ABI parent")?
        .join("locality");
    let journal_parent = args.cni_state_path.parent().context("CNI journal parent")?;
    managed_directory(&pin_parent)?;
    managed_directory(journal_parent)?;
    let pin_directory = pin_parent.join("v1");
    let checkpoint_path = journal_parent.join("locality-runtime.json");
    let owner_path = journal_parent.join("locality-runtime.lock");
    let current = StartupCheckpoint {
        schema_version: 1,
        boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned(),
        node_name: args.node_name.clone(),
        journal_path: args.cni_state_path.clone(),
        pin_directory: pin_directory.clone(),
    };
    let previous = if exists(&checkpoint_path)? {
        private_root_file(&checkpoint_path)?;
        Some(load_secure_json::<StartupCheckpoint>(
            &checkpoint_path,
            "locality startup",
        )?)
    } else {
        None
    };
    let decision = decide(
        previous.as_ref(),
        &current,
        guarded_journal(&args.cni_state_path)?,
        exists(&pin_directory)?,
    )?;
    let runtime = match decision {
        StartupDecision::Create => LocalityRuntimeMaps::create_owned(&pin_directory, &owner_path)?,
        StartupDecision::Reopen => LocalityRuntimeMaps::open_owned(&pin_directory, &owner_path)?,
    };
    // The exclusive owner is held before this write. Persist before schema-5
    // enablement; failed persistence stops startup with all maps withdrawn.
    persist_secure_json(&checkpoint_path, &current, "locality startup")?;
    state
        .locality_runtime
        .set(LocalityRuntime {
            admission: LocalityAdmission::new(runtime)?,
            gate: OnceLock::new(),
        })
        .map_err(|_| anyhow::anyhow!("locality startup initialized twice"))?;
    tracing::info!(
        ?decision,
        "locality runtime owned and withdrawn before route/CNI startup"
    );
    Ok(())
}

impl LocalityRuntime {
    pub(super) fn install_journal(&self, journal: &mut AttachmentJournal) -> Result<()> {
        ensure!(
            self.gate.get().is_none(),
            "locality journal gate already installed"
        );
        let gate = IncarnationGate::install(journal, 65_536)?;
        self.gate
            .set(gate)
            .map_err(|_| anyhow::anyhow!("locality journal gate replaced"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(boot: &str) -> StartupCheckpoint {
        StartupCheckpoint {
            schema_version: 1,
            boot_id: boot.into(),
            node_name: "node-a".into(),
            journal_path: "/var/lib/unf/cni/v1/attachments.json".into(),
            pin_directory: "/sys/fs/bpf/unf/locality/v1".into(),
        }
    }
    const FIRST: &str = "11111111-1111-4111-8111-111111111111";
    const SECOND: &str = "22222222-2222-4222-8222-222222222222";

    #[test]
    fn initial_creation_and_interrupted_first_start_are_explicit() {
        let now = checkpoint(FIRST);
        assert_eq!(
            decide(None, &now, false, false).unwrap(),
            StartupDecision::Create
        );
        assert_eq!(
            decide(None, &now, false, true).unwrap(),
            StartupDecision::Reopen
        );
        assert!(decide(None, &now, true, false).is_err());
        assert!(decide(None, &now, true, true).is_err());
    }

    #[test]
    fn same_boot_missing_pins_never_authorize_fresh_maps() {
        let previous = checkpoint(FIRST);
        for guarded in [false, true] {
            assert!(decide(Some(&previous), &checkpoint(FIRST), guarded, false).is_err());
            assert_eq!(
                decide(Some(&previous), &checkpoint(FIRST), guarded, true).unwrap(),
                StartupDecision::Reopen
            );
            assert_eq!(
                decide(Some(&previous), &checkpoint(SECOND), guarded, false).unwrap(),
                StartupDecision::Create
            );
        }
    }

    #[test]
    fn foreign_and_unknown_checkpoints_cannot_authorize_reboot_creation() {
        let now = checkpoint(SECOND);
        for field in 0..5 {
            let mut previous = checkpoint(FIRST);
            match field {
                0 => previous.schema_version = 2,
                1 => previous.boot_id = "not-a-boot-id".into(),
                2 => previous.node_name = "other".into(),
                3 => previous.journal_path = "/foreign/journal".into(),
                _ => previous.pin_directory = "/foreign/pins".into(),
            }
            for pins in [false, true] {
                assert!(decide(Some(&previous), &now, true, pins).is_err());
            }
        }
        assert!(
            decide(
                None,
                &checkpoint("00000000-0000-0000-0000-000000000000"),
                false,
                false
            )
            .is_err()
        );
    }
}
