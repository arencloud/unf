//! Startup ownership and fail-closed reopen. Pin names confer no packet grant;
//! the actual loaded runtime must subsequently prove exact map-ID equality.
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path};
use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use aya::{
    Ebpf, EbpfLoader,
    maps::{Map, MapData, MapType},
};
use rustix::fs::{CWD, FlockOperation, OFlags, RenameFlags, flock, renameat_with};

use super::LocalityRuntimeMaps;

// map type, key/value widths, capacity, create flags. No old map is resized.
const SPECS: [(&str, MapType, u32, u32, u32, u32); 4] = [
    ("UL_INPUT_V1", MapType::PerCpuArray, 4, 80, 1, 0),
    ("UL_FENCE_V1", MapType::Array, 4, 32, 1, 128),
    ("UL_RESUME_V1", MapType::ProgramArray, 4, 4, 4, 0),
    ("UL_DISPATCH_V1", MapType::ProgramArray, 4, 4, 1, 0),
];

impl LocalityRuntimeMaps {
    /// Acquire exclusive startup ownership, reopen the exact existing set, and immediately
    /// withdraw. Caller supplies a managed root-owned parent and a private
    /// regular-file lock path outside bpffs. Retain this runtime through CNI
    /// serving; its banks retain the owner lock too. Call BEFORE route mutation
    /// or CNI serving, not lazily from a later dataplane task.
    ///
    /// This never restores a bank, lease or applied coordinates. A partial or
    /// foreign inventory is an error, not permission to remove/replace it.
    ///
    /// # Errors
    /// Rejects unsafe paths/ownership, a competing process, incompatible or
    /// aliased maps, uncertain atomic creation or inability to withdraw.
    pub fn open_owned(pin_directory: &Path, owner_path: &Path) -> Result<Self> {
        Self::start_owned(pin_directory, owner_path, false)
    }

    /// Explicitly create a fresh empty four-map runtime and atomically pin it.
    /// Caller must establish that no previous locality program can survive:
    /// a first deployment or independently verified kernel-boot transition,
    /// NOT just absent pins. Existing directories are never replaced.
    ///
    /// # Errors
    /// Rejects existing/unsafe paths, owner contention, allocation/pinning or
    /// atomic directory publication failure. No packet authority is installed.
    pub fn create_owned(pin_directory: &Path, owner_path: &Path) -> Result<Self> {
        Self::start_owned(pin_directory, owner_path, true)
    }

    fn start_owned(pin_directory: &Path, owner_path: &Path, create: bool) -> Result<Self> {
        plain_absolute(pin_directory)?;
        plain_absolute(owner_path)?;
        let parent = pin_directory.parent().context("locality pin parent")?;
        secure_directory(parent)?;
        secure_directory(owner_path.parent().context("locality owner parent")?)?;
        let owner = owner_lock(owner_path)?;
        let maps = match fs::symlink_metadata(pin_directory) {
            Ok(_) if !create => open_existing(pin_directory)?,
            Ok(_) => anyhow::bail!("refusing to replace existing locality pins"),
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                create_new(pin_directory)?
            }
            Err(error) => return Err(error.into()),
        };
        let [input, fence, resume, dispatch] = maps;
        let mut runtime = Self::bind(
            input.fd().as_fd().try_clone_to_owned()?,
            fence.fd().as_fd().try_clone_to_owned()?,
            resume.fd().as_fd().try_clone_to_owned()?,
            dispatch.fd().as_fd().try_clone_to_owned()?,
        )?;
        clear_continuations(&runtime.maps.resume)?;
        let held = Arc::get_mut(&mut runtime.maps).context("unexpected shared startup runtime")?;
        held.owner = Some(owner);
        held.pin_directory = Some(pin_directory.to_path_buf());
        Ok(runtime)
    }

    /// Bind the actual production loader to this owner's pins. Always call
    /// `verify_loaded` immediately after loading, before attaching/publishing:
    /// Aya may create a missing pin instead of failing.
    ///
    /// # Errors
    /// Rejects a runtime without explicit startup ownership.
    pub fn configure_loader(&self, loader: &mut EbpfLoader<'_>) -> Result<()> {
        let directory = self
            .maps
            .pin_directory
            .as_ref()
            .context("runtime has no owned pins")?;
        ensure!(self.maps.owner.is_some(), "runtime owner absent");
        for (name, ..) in SPECS {
            loader.map_pin_path(name, directory.join(name));
        }
        Ok(())
    }

    /// Verify every loaded shared map is the held exact object, not merely the
    /// same name/shape. Does not authenticate policy, placement or program code.
    ///
    /// # Errors
    /// Rejects missing/substituted maps before any program publication.
    pub fn verify_loaded(&self, object: &Ebpf) -> Result<()> {
        for ((name, ..), expected) in SPECS.into_iter().zip([
            &self.maps.input,
            &self.maps.fence,
            &self.maps.resume,
            &self.maps.dispatch,
        ]) {
            let (Map::Array(actual) | Map::PerCpuArray(actual) | Map::ProgramArray(actual)) =
                object.map(name).context("missing locality runtime map")?
            else {
                anyhow::bail!("wrong locality runtime map type");
            };
            ensure!(
                actual.info()?.id() == expected.info()?.id(),
                "substituted locality runtime map {name}"
            );
        }
        Ok(())
    }
}

fn clear_continuations(map: &MapData) -> Result<()> {
    let mut array = aya::maps::ProgramArray::try_from(Map::ProgramArray(MapData::from_fd(
        map.fd().as_fd().try_clone_to_owned()?,
    )?))?;
    let mut failures = Vec::new();
    for index in 0..4 {
        match array.clear_index(&index) {
            Ok(()) | Err(aya::maps::MapError::KeyNotFound) => {}
            Err(aya::maps::MapError::SyscallError(error))
                if error.io_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => failures.push(error.to_string()),
        }
    }
    ensure!(
        failures.is_empty(),
        "failed to withdraw old locality continuations: {failures:?}"
    );
    Ok(())
}

fn plain_absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.file_name().is_some()
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "locality path must be absolute without traversal"
    );
    Ok(())
}

fn secure_directory(path: &Path) -> Result<()> {
    for parent in path.ancestors() {
        let metadata = fs::symlink_metadata(parent)?;
        let mode = metadata.permissions().mode();
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && (mode & 0o022 == 0 || mode & 0o1000 != 0),
            "unsafe locality directory {}",
            parent.display()
        );
    }
    // The exact directory must not be writable by any other user/group, even
    // if a root-owned sticky ancestor (e.g. /tmp) is acceptable.
    ensure!(
        fs::metadata(path)?.permissions().mode() & 0o022 == 0,
        "shared locality directory"
    );
    Ok(())
}

fn owner_lock(path: &Path) -> Result<File> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.nlink() == 1,
            "unsafe existing locality owner file"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(i32::try_from(OFlags::NOFOLLOW.bits())?)
        .open(path)?;
    let metadata = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
            && !named.file_type().is_symlink()
            && named.dev() == metadata.dev()
            && named.ino() == metadata.ino(),
        "unsafe locality owner file"
    );
    flock(&file, FlockOperation::NonBlockingLockExclusive)
        .context("locality runtime already owned")?;
    Ok(file)
}

#[allow(clippy::verbose_bit_mask)] // Octal POSIX permission masks are intentional.
fn open_existing(directory: &Path) -> Result<[MapData; 4]> {
    secure_directory(directory)?;
    let mut names = fs::read_dir(directory)?
        .take(5)
        .map(|entry| Ok(entry?.file_name()))
        .collect::<Result<Vec<_>>>()?;
    names.sort();
    let mut expected = SPECS.map(|(name, ..)| std::ffi::OsString::from(name));
    expected.sort();
    ensure!(
        names == expected,
        "partial or foreign locality pin inventory"
    );
    let mut maps = Vec::with_capacity(4);
    for (name, kind, key, value, entries, flags) in SPECS {
        let path = directory.join(name);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.permissions().mode() & 0o077 == 0,
            "unsafe locality pin {name}"
        );
        let map = MapData::from_pin(&path)?;
        super::runtime::check_shape(&map, kind, key, value, entries, flags)?;
        ensure!(
            map.info()?.name_as_str() == Some(name),
            "foreign locality kernel map name"
        );
        maps.push(map);
    }
    maps.try_into()
        .map_err(|_| anyhow::anyhow!("locality map count"))
}

fn create_new(directory: &Path) -> Result<[MapData; 4]> {
    let staging = tempfile::Builder::new()
        .prefix("unf-locality-startup-")
        .tempdir_in(directory.parent().context("pin parent")?)?;
    let mut maps = Vec::with_capacity(4);
    for (name, kind, key, value, entries, flags) in SPECS {
        let map = MapData::create(
            aya_obj::Map::new_from_params(kind as u32, key, value, entries, flags),
            name,
            None,
        )?;
        let path = staging.path().join(name);
        map.pin(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        maps.push(map);
    }
    // Validate the persisted set before it becomes the startup inventory.
    drop(open_existing(staging.path())?);
    // No program can reference these maps yet; both authority maps are empty.
    // NOREPLACE prevents clobbering a concurrently created/foreign directory.
    renameat_with(CWD, staging.path(), CWD, directory, RenameFlags::NOREPLACE)?;
    let _former_name = staging.keep();
    maps.try_into()
        .map_err(|_| anyhow::anyhow!("created locality map count"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_absolute_owned_leaf_paths_are_accepted() {
        for path in ["/sys/fs/bpf/unf/locality/v1", "/tmp/private/bpffs/runtime"] {
            plain_absolute(Path::new(path)).unwrap();
        }
        for path in ["", "v1", "/", "/tmp/../foreign"] {
            assert!(plain_absolute(Path::new(path)).is_err());
        }
    }

    #[test]
    fn binding_spec_has_unique_names_and_exact_fixed_widths() {
        let names: std::collections::BTreeSet<_> = SPECS.iter().map(|spec| spec.0).collect();
        assert_eq!(names.len(), 4);
        assert!(
            SPECS
                .iter()
                .all(|spec| spec.0.len() <= 15 && spec.2 == 4 && spec.4 > 0)
        );
        assert_eq!(
            SPECS[0].3,
            u32::try_from(std::mem::size_of::<unf_ebpf_common::locality::PacketInput>()).unwrap()
        );
        assert_eq!(
            SPECS[1].3,
            u32::try_from(std::mem::size_of::<unf_ebpf_common::locality::PlacementFence>())
                .unwrap()
        );
    }
}
