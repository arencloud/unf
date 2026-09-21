use super::PrivateMount;
use anyhow::{Context as _, Result};
use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, fsconfig_create, fsconfig_set_string, fsmount,
    fsopen,
};

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
    // Only this root FD leaves the helper. It is not a mount namespace FD or
    // filesystem configuration FD. No fallback to shared/attached pins exists.
    PrivateMount::validate(directory)
}
