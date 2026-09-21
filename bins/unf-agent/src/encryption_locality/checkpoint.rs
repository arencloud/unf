//! Bounded, root-owned compiler input. Never restore a kernel capability.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;
use unf_encryption::{
    CapturedEncryptionLocality, EncryptionLocalityContext, MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES,
};

pub(super) fn path(plan: &Path) -> PathBuf {
    plan.with_file_name("locality-placement-source.json")
}

fn parent(path: &Path) -> Result<&Path> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "locality checkpoint path must be plain and absolute"
    );
    let parent = path.parent().context("locality checkpoint parent")?;
    let mut current = PathBuf::new();
    for part in parent.components() {
        current.push(part);
        let metadata = fs::symlink_metadata(&current)?;
        let mode = metadata.permissions().mode();
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && (mode & 0o022 == 0 || (current != parent && mode & 0o1000 != 0)),
            "unsafe locality checkpoint ancestor {}",
            current.display()
        );
    }
    Ok(parent)
}

#[allow(clippy::verbose_bit_mask)]
fn private_file(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.len() <= MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES as u64,
        "unsafe or oversized locality checkpoint file"
    );
    Ok(())
}

pub(super) fn load(path: &Path) -> Result<Option<Vec<u8>>> {
    parent(path)?;
    let fd = match rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let file = File::from(fd);
    private_file(&file.metadata()?)?;
    let mut bytes = Vec::new();
    file.take(MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES,
        "locality checkpoint grew beyond budget"
    );
    Ok(Some(bytes))
}

struct BoundedWriter<'a> {
    file: &'a mut File,
    remaining: usize,
}

impl io::Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("locality checkpoint byte budget"));
        }
        let written = self.file.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

pub(super) fn save(
    path: &Path,
    source: &CapturedEncryptionLocality,
    current: &EncryptionLocalityContext,
) -> Result<()> {
    ensure!(
        source.context() == current,
        "checkpoint source differs from save cut"
    );
    let directory = parent(path)?;
    if let Some(previous) = load(path)? {
        // Refuse schema downgrade or replacement of a foreign cluster/Node's
        // source file. No malformed/foreign checkpoint is deleted to pass.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Header {
            schema_version: u16,
            request: unf_encryption::EncryptionLocalityRequest,
        }
        let header: Header = serde_json::from_slice(&previous)?;
        ensure!(
            header.schema_version == 1
                && header.request.context.cluster_id == current.cluster_id
                && header.request.context.recipient == current.recipient,
            "foreign or incompatible existing locality checkpoint"
        );
    }
    let temporary = path.with_file_name(".locality-placement-source.tmp");
    match fs::symlink_metadata(&temporary) {
        Ok(metadata) => {
            private_file(&metadata)?;
            fs::remove_file(&temporary)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let owned = file.metadata()?;
    let result = (|| -> Result<()> {
        serde_json::to_writer(
            BoundedWriter {
                file: &mut file,
                remaining: MAX_ENCRYPTION_LOCALITY_CHECKPOINT_BYTES - 1,
            },
            source,
        )?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        // Only our exact exclusive-created temporary; successful rename leaves
        // no such path. Never unlink the destination on uncertain persistence.
        if fs::symlink_metadata(&temporary)
            .is_ok_and(|metadata| metadata.dev() == owned.dev() && metadata.ino() == owned.ino())
        {
            let _ = fs::remove_file(&temporary);
        }
    }
    result
}
