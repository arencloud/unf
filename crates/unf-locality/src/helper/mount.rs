use super::PrivateMount;
use anyhow::{Context as _, Result};
use rustix::fs::{Mode, OFlags, mkdirat, openat};
use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, fsconfig_create, fsconfig_set_string, fsmount,
    fsopen,
};
use std::os::fd::{AsFd, OwnedFd};

pub(super) fn allocate() -> Result<PrivateMount> {
    // Create a detached filesystem using Linux's FD-based mount API. Never
    // attach it to ANY namespace: there is no mount target, propagation change,
    // temporary directory, pathname race or persistent cleanup operation.
    let context = fsopen("bpf", FsOpenFlags::FSOPEN_CLOEXEC).context("helper fsopen bpffs")?;
    fsconfig_set_string(&context, "mode", "0700").context("helper private bpffs mode")?;
    fsconfig_create(&context).context("helper create bpffs")?;
    let directory = fsmount(
        &context,
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )
    .context("helper detached fsmount")?;
    // Newer kernels may populate progs.debug/maps.debug in a new filesystem.
    // Preserve those entries: create one exclusive private adapter directory,
    // never accept EEXIST, and return only that held directory reference.
    PrivateMount::validate(adapter_directory(&directory)?)
}

pub(super) fn adapter_directory(root: &impl AsFd) -> Result<OwnedFd> {
    mkdirat(root, "unf-locality", Mode::RWXU).context("helper exclusive adapter directory")?;
    Ok(openat(
        root,
        "unf-locality",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}
