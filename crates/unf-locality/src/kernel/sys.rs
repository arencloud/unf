//! Small audited ABI boundary; no map values or kernel pointers are exported.

use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, BorrowedFd};

use unf_ebpf_common::locality::{
    AddressKey, AddressOwner, BankConfig, Endpoint, PacketInput, PlacementFence,
};

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(super) struct Value<T>(pub T);

macro_rules! plain_value {
    ($($ty:ty),+ $(,)?) => {$ (
        // SAFETY: these repr(C) layouts contain integers/byte arrays only, with
        // no padding or invalid bit patterns. Shared ABI offset/size tests
        // assert the complete layouts. The wrapper is repr(transparent).
        #[allow(unsafe_code)]
        unsafe impl aya::Pod for Value<$ty> {}
    )+};
}
plain_value!(
    AddressKey,
    AddressOwner,
    BankConfig,
    Endpoint,
    PacketInput,
    PlacementFence
);

/// Linux `BPF_MAP_FREEZE` operates on the borrowed actual descriptor. No guessed
/// map name/ID lookup and no general-purpose syscall interface is exposed.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub(super) fn freeze(fd: BorrowedFd<'_>) -> io::Result<()> {
    unsafe extern "C" {
        fn syscall(number: isize, ...) -> isize;
    }
    // x86-64 Linux __NR_bpf=321, BPF_MAP_FREEZE=22. The command consumes only
    // bpf_attr.map_fd (first u32). A four-byte attribute has no tail/padding.
    let attribute = u32::try_from(fd.as_raw_fd()).map_err(io::Error::other)?;
    // SAFETY: this owned borrow and initialized four-byte input live throughout
    // the synchronous call. Kernel receives exact length, no writable pointer.
    let result = unsafe { syscall(321_isize, 22_u32, &raw const attribute, 4_u32) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    require_frozen(fd)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(super) fn freeze(_fd: BorrowedFd<'_>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "locality kernel ABI requires qualified x86-64 Linux",
    ))
}

pub(super) fn require_frozen(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut text = String::new();
    File::open(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?
        .take(4097)
        .read_to_string(&mut text)?;
    if text.len() > 4096 || !frozen_fdinfo(&text) {
        return Err(io::Error::other("locality bank map is not sealed"));
    }
    Ok(())
}

fn frozen_fdinfo(text: &str) -> bool {
    let mut rows = text.lines().filter_map(|line| line.strip_prefix("frozen:"));
    rows.next().is_some_and(|row| row.trim() == "1") && rows.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    #[test]
    fn freeze_requires_one_positive_kernel_field() {
        assert!(frozen_fdinfo("map_id:\t7\nfrozen:\t1\n"));
        for invalid in [
            "",
            "frozen: 0",
            "not_frozen: 1",
            "frozen: 1\nfrozen: 0",
            "frozen: 1\nfrozen: 1",
            "frozen: 11",
        ] {
            assert!(!frozen_fdinfo(invalid));
        }
    }

    #[test]
    fn ordinary_file_cannot_pass_frozen_map_observation() {
        let file = File::open("/dev/null").unwrap();
        assert!(require_frozen(file.as_fd()).is_err());
        // Do not exercise a privileged BPF syscall here: real kernel feature
        // validation runs on cl02 before matching Kind, never this workstation.
    }
}
