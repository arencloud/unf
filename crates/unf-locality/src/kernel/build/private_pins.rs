//! Shared-map adapter pins cannot survive the dedicated thread's mount namespace.
use std::path::Path;

use anyhow::{Result, anyhow, ensure};
use rustix::mount::{MountFlags, MountPropagationFlags, mount, mount_change};
use rustix::thread::{UnshareFlags, unshare_unsafe};

pub(super) fn with_private_mount<T: Send>(
    root: &Path,
    action: impl FnOnce(&Path) -> Result<T> + Send,
) -> Result<T> {
    ensure!(
        std::fs::read_dir(root)?.next().is_none(),
        "persistent locality preparation residue; preserving it"
    );
    // Never change the mount/FS context of a Tokio worker. This joined, leaf OS
    // thread creates no child threads and exports no mount-namespace handles.
    // A returned BPF object retains map/program FDs, not temporary bpffs pins.
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                // SAFETY: Only FS and mount namespace are unshared, NEVER FILES.
                // The process FD table stays shared, so returned FDs remain valid.
                // FS context changes are confined to this non-reused leaf thread.
                #[allow(unsafe_code)]
                unsafe {
                    unshare_unsafe(UnshareFlags::FS | UnshareFlags::NEWNS)?;
                }
                // Stop propagation before mounting anything. The original process
                // and host mount trees must never see this temporary filesystem.
                mount_change(
                    "/",
                    MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
                )?;
                mount(
                    "unf-locality-private",
                    root,
                    "bpf",
                    MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
                    None,
                )?;
                // No restoration or persistent cleanup is needed: on success,
                // error, panic or SIGKILL, the last namespace reference disappears
                // with this thread/process. The pre-existing underlying directory
                // is untouched. Do not spawn work or return namespace FDs here.
                action(root)
            })
            .join()
            .map_err(|_| anyhow!("private locality loader thread panicked"))?
    })
}

#[cfg(test)]
mod tests;
