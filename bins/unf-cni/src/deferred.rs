use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use unf_cni_state::AttachmentKey;

const DEFERRED_DELETE_SCHEMA_VERSION: u16 = 1;
const MAX_PENDING_DELETES: usize = 65_536;

#[derive(Debug)]
pub(crate) struct PendingDelete {
    pub(crate) key: AttachmentKey,
    path: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeferredDeleteDocument {
    schema_version: u16,
    key: AttachmentKey,
}

pub(crate) fn enqueue(root: &Path, key: &AttachmentKey) -> Result<(), String> {
    validate_root(root)?;
    let _lock = queue_lock(root, &key.network, FlockOperation::LockExclusive)?;
    let path = root
        .join(&key.network)
        .join(&key.container_id)
        .join(format!("{}.json", key.ifname));
    if path.exists() {
        let document = load(&path)?;
        if document.key != *key {
            return Err(format!(
                "deferred delete path {} contains a different attachment key",
                path.display()
            ));
        }
        return Ok(());
    }
    if list_unlocked(root, &key.network)?.len() >= MAX_PENDING_DELETES {
        return Err(format!(
            "deferred delete queue reached its {MAX_PENDING_DELETES}-record limit"
        ));
    }

    let parent = root.join(&key.network).join(&key.container_id);
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&parent)
        .map_err(|error| {
            format!(
                "create deferred delete directory {}: {error}",
                parent.display()
            )
        })?;
    reject_symlink_components(&parent)?;
    validate_queue_directory(root)?;
    validate_queue_directory(&root.join(&key.network))?;
    validate_queue_directory(&parent)?;

    let document = DeferredDeleteDocument {
        schema_version: DEFERRED_DELETE_SCHEMA_VERSION,
        key: key.clone(),
    };
    let bytes = serde_json::to_vec(&document)
        .map_err(|error| format!("encode deferred delete {}: {error}", path.display()))?;
    let temporary = parent.join(format!("{}.{}.tmp", key.ifname, std::process::id()));
    let write_result = (|| -> Result<(), String> {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| {
                format!(
                    "create deferred delete temporary file {}: {error}",
                    temporary.display()
                )
            })?;
        output.write_all(&bytes).map_err(|error| {
            format!(
                "write deferred delete temporary file {}: {error}",
                temporary.display()
            )
        })?;
        output.sync_all().map_err(|error| {
            format!(
                "sync deferred delete temporary file {}: {error}",
                temporary.display()
            )
        })?;
        fs::rename(&temporary, &path).map_err(|error| {
            format!(
                "publish deferred delete {} from {}: {error}",
                path.display(),
                temporary.display()
            )
        })?;
        File::open(&parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                format!(
                    "sync deferred delete directory {}: {error}",
                    parent.display()
                )
            })?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

pub(crate) fn list(root: &Path, network: &str) -> Result<Vec<PendingDelete>, String> {
    validate_root(root)?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let _lock = queue_lock(root, network, FlockOperation::LockShared)?;
    list_unlocked(root, network)
}

fn list_unlocked(root: &Path, network: &str) -> Result<Vec<PendingDelete>, String> {
    let network_path = root.join(network);
    if !network_path.exists() {
        return Ok(Vec::new());
    }
    reject_symlink_components(&network_path)?;
    validate_queue_directory(&network_path)?;
    let mut pending = Vec::new();
    for container in read_sorted(&network_path)? {
        validate_queue_directory(&container)?;
        for path in read_sorted(&container)? {
            let document = load(&path)?;
            let expected_file = format!("{}.json", document.key.ifname);
            if document.key.network != network
                || container.file_name().and_then(|name| name.to_str())
                    != Some(document.key.container_id.as_str())
                || path.file_name().and_then(|name| name.to_str()) != Some(expected_file.as_str())
            {
                return Err(format!(
                    "deferred delete path does not match its attachment key: {}",
                    path.display()
                ));
            }
            pending.push(PendingDelete {
                key: document.key,
                path,
            });
            if pending.len() > MAX_PENDING_DELETES {
                return Err(format!(
                    "deferred delete queue exceeds {MAX_PENDING_DELETES} records"
                ));
            }
        }
    }
    pending.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(pending)
}

fn queue_lock(root: &Path, network: &str, operation: FlockOperation) -> Result<File, String> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .map_err(|error| format!("create deferred delete root {}: {error}", root.display()))?;
    reject_symlink_components(root)?;
    validate_queue_directory(root)?;
    let path = root.join(format!(".{network}.lock"));
    reject_symlink_components(&path)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("open deferred delete lock {}: {error}", path.display()))?;
    let metadata = lock
        .metadata()
        .map_err(|error| format!("inspect deferred delete lock {}: {error}", path.display()))?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(format!(
            "deferred delete lock must be a mode-0600 single-link regular file: {}",
            path.display()
        ));
    }
    flock(&lock, operation)
        .map_err(|error| format!("lock deferred delete queue {}: {error}", path.display()))?;
    Ok(lock)
}

fn validate_queue_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "inspect deferred delete directory {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() != geteuid().as_raw()
    {
        return Err(format!(
            "deferred delete directory must be owner-owned with mode 0700: {}",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn complete(pending: &PendingDelete) -> Result<(), String> {
    let document = load(&pending.path)?;
    if document.key != pending.key {
        return Err(format!(
            "deferred delete changed before completion: {}",
            pending.path.display()
        ));
    }
    let container = pending
        .path
        .parent()
        .ok_or_else(|| "deferred delete file has no parent".to_owned())?;
    fs::remove_file(&pending.path).map_err(|error| {
        format!(
            "remove completed deferred delete {}: {error}",
            pending.path.display()
        )
    })?;
    File::open(container)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "sync completed deferred delete directory {}: {error}",
                container.display()
            )
        })?;
    remove_empty_directory(container)?;
    if let Some(network) = container.parent() {
        remove_empty_directory(network)?;
    }
    Ok(())
}

fn load(path: &Path) -> Result<DeferredDeleteDocument, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect deferred delete {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "deferred delete is not a regular file: {}",
            path.display()
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o600 || metadata.uid() != geteuid().as_raw() {
        return Err(format!(
            "deferred delete must be owner-owned with mode 0600: {}",
            path.display()
        ));
    }
    if metadata.nlink() != 1 {
        return Err(format!(
            "deferred delete must have exactly one hard link: {}",
            path.display()
        ));
    }
    let document: DeferredDeleteDocument = serde_json::from_slice(
        &fs::read(path)
            .map_err(|error| format!("read deferred delete {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("decode deferred delete {}: {error}", path.display()))?;
    if document.schema_version != DEFERRED_DELETE_SCHEMA_VERSION {
        return Err(format!(
            "deferred delete {} has schema {}, expected {}",
            path.display(),
            document.schema_version,
            DEFERRED_DELETE_SCHEMA_VERSION
        ));
    }
    Ok(document)
}

fn read_sorted(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut entries = fs::read_dir(path)
        .map_err(|error| format!("read deferred delete directory {}: {error}", path.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| format!("read deferred delete entry: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    Ok(entries)
}

fn validate_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err("deferred delete directory must be absolute".to_owned());
    }
    reject_symlink_components(root)
}

fn reject_symlink_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "deferred delete path contains a symlink: {}",
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "inspect deferred delete path {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

fn remove_empty_directory(path: &Path) -> Result<(), String> {
    match fs::remove_dir(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| {
                        format!(
                            "sync deferred delete parent directory {}: {error}",
                            parent.display()
                        )
                    })?;
            }
            Ok(())
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(format!(
            "remove empty deferred delete directory {}: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn key(container: &str) -> AttachmentKey {
        AttachmentKey {
            network: "unf-test".to_owned(),
            container_id: container.to_owned(),
            ifname: "eth0".to_owned(),
        }
    }

    #[test]
    fn queue_is_durable_ordered_idempotent_and_exactly_completed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root = directory.path().join("pending");
        enqueue(&root, &key("container-b")).expect("enqueue b");
        enqueue(&root, &key("container-a")).expect("enqueue a");
        enqueue(&root, &key("container-a")).expect("replay a");

        let pending = list(&root, "unf-test").expect("list queue");
        assert_eq!(
            pending
                .iter()
                .map(|entry| entry.key.container_id.as_str())
                .collect::<Vec<_>>(),
            ["container-a", "container-b"]
        );
        complete(&pending[0]).expect("complete a");
        let remaining = list(&root, "unf-test").expect("list remaining queue");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].key, key("container-b"));
        complete(&remaining[0]).expect("complete b");
        assert!(list(&root, "unf-test").expect("empty queue").is_empty());
    }

    #[test]
    fn queue_rejects_symlinks_and_weak_permissions() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let weak_root = directory.path().join("weak-root");
        fs::create_dir(&weak_root).expect("weak root directory");
        fs::set_permissions(&weak_root, fs::Permissions::from_mode(0o755))
            .expect("weaken root permissions");
        assert!(enqueue(&weak_root, &key("container-a")).is_err());
        assert_eq!(
            fs::metadata(&weak_root)
                .expect("weak root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "the plugin must not chmod a misconfigured arbitrary path"
        );

        let foreign = directory.path().join("foreign");
        fs::create_dir(&foreign).expect("foreign directory");
        let linked = directory.path().join("linked");
        symlink(&foreign, &linked).expect("root symlink");
        assert!(enqueue(&linked, &key("container-a")).is_err());

        let root = directory.path().join("pending");
        enqueue(&root, &key("container-a")).expect("enqueue attachment");
        let path = root.join("unf-test/container-a/eth0.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("weaken fixture permissions");
        assert!(list(&root, "unf-test").is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restore fixture permissions");
        fs::hard_link(&path, directory.path().join("foreign-record"))
            .expect("create unexpected hard link");
        assert!(list(&root, "unf-test").is_err());
    }
}
