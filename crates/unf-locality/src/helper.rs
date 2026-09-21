//! First helper boundary: one authenticated, bounded private-bpffs FD transfer.
//!
//! This is not a generic privileged RPC. No pathname, command, ELF, map FD,
//! network-namespace FD or policy authority is accepted from a client. A trusted
//! supervisor must provide the connected socket and expected peer credentials;
//! this module intentionally exposes no public listening endpoint. Namespace
//! observations and device seeding still require separate helper integration.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use rustix::fs::{FileType, fstat, fstatfs};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketType, UCred, recvmsg, sendmsg,
    sockopt::{self, Timeout},
};

mod mount;
#[cfg(test)]
mod tests;

// Fixed version/operation, 32-byte unpredictable request identity. No parser,
// variable-size allocation, retries or caller-selected mount options.
const REQUEST: &[u8; 8] = b"ULH1MNT?";
const RESPONSE: &[u8; 8] = b"ULH1MNT!";
const FRAME_SIZE: usize = 40;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

/// A single-use, credential-bound channel. Ownership consumes both success and
/// failure paths, so a failed/replayed request cannot reuse a privileged session.
pub struct PrivateMountChannel {
    socket: OwnedFd,
    peer: UCred,
}

/// Owns a private bpffs mount reference, not a mount-namespace descriptor.
/// The mount is reclaimed after the final directory reference closes, including
/// process death. BPF object FDs may survive independently; no persistent shared
/// preparation pins are created. Do not duplicate or export the directory FD.
pub struct PrivateMount {
    directory: OwnedFd,
}

impl PrivateMountChannel {
    /// Bind an already connected Unix SEQPACKET socket to independently trusted
    /// supervisor credentials (not values supplied by a request).
    ///
    /// # Errors
    /// Rejects other socket types, missing/wrong peer credentials or failed
    /// credential/deadline setup. The supervisor must enable `SO_PASSCRED` before
    /// allowing the peer to send; early queued uncredentialed frames fail closed.
    pub fn authenticate(socket: OwnedFd, expected: UCred) -> Result<Self> {
        ensure!(
            sockopt::socket_domain(&socket)? == AddressFamily::UNIX,
            "helper socket domain"
        );
        ensure!(
            sockopt::socket_type(&socket)? == SocketType::SEQPACKET,
            "helper socket type"
        );
        ensure!(
            sockopt::socket_peercred(&socket)? == expected,
            "helper peer credentials"
        );
        sockopt::set_socket_passcred(&socket, true)?;
        sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(IO_TIMEOUT))?;
        sockopt::set_socket_timeout(&socket, Timeout::Send, Some(IO_TIMEOUT))?;
        Ok(Self {
            socket,
            peer: expected,
        })
    }

    /// Request exactly one fresh private mount from the authenticated helper.
    ///
    /// # Errors
    /// Rejects stale/malformed responses, wrong credentials, missing/excess FDs,
    /// truncation, non-bpffs/non-directory descriptors and I/O failure/deadline.
    pub fn request(self) -> Result<PrivateMount> {
        let mut frame = [0_u8; FRAME_SIZE];
        frame[..8].copy_from_slice(REQUEST);
        getrandom::fill(&mut frame[8..])
            .map_err(|error| anyhow::anyhow!("helper nonce: {error}"))?;
        self.send(&frame, &[])?;
        let (reply, mut descriptors) = self.receive()?;
        ensure!(
            reply[..8] == RESPONSE[..] && reply[8..] == frame[8..],
            "helper response binding"
        );
        ensure!(descriptors.len() == 1, "helper response descriptor count");
        PrivateMount::validate(descriptors.pop().context("missing helper directory FD")?)
    }

    /// Serve one detached mount operation. No filesystem pathname or namespace
    /// is accepted or modified. This cannot touch runtime maps or publish a bank.
    ///
    /// # Errors
    /// Rejects malformed/credential-mismatched requests and ALL inbound FDs;
    /// fails closed on mount/allocation/transport errors. No automatic retry.
    pub fn serve(self) -> Result<()> {
        let (request, descriptors) = self.receive()?;
        ensure!(
            request[..8] == REQUEST[..] && request[8..].iter().any(|byte| *byte != 0),
            "helper request version or nonce"
        );
        ensure!(
            descriptors.is_empty(),
            "helper accepts no client descriptors"
        );
        let mount = mount::allocate()?;
        let mut response = request;
        response[..8].copy_from_slice(RESPONSE);
        self.send(&response, &[mount.directory.as_fd()])
    }

    fn send(&self, frame: &[u8], descriptors: &[BorrowedFd<'_>]) -> Result<()> {
        ensure!(descriptors.len() <= 1, "helper outgoing descriptor bound");
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        if !descriptors.is_empty() {
            ensure!(
                ancillary.push(SendAncillaryMessage::ScmRights(descriptors)),
                "helper ancillary capacity"
            );
        }
        ensure!(
            sendmsg(
                &self.socket,
                &[IoSlice::new(frame)],
                &mut ancillary,
                SendFlags::NOSIGNAL
            )? == frame.len(),
            "helper short send"
        );
        Ok(())
    }

    fn receive(&self) -> Result<([u8; FRAME_SIZE], Vec<OwnedFd>)> {
        let mut bytes = [0_u8; FRAME_SIZE];
        // Two slots detect excess descriptors. Truncated and unconsumed rights
        // are closed by rustix's RAII buffer; extracted rights remain owned too.
        let mut space =
            [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2), ScmCredentials(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let result = recvmsg(
            &self.socket,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        ensure!(
            result.bytes == FRAME_SIZE
                && !result
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC),
            "helper truncated or wrong-sized frame"
        );
        let mut credentials = None;
        let mut descriptors = Vec::with_capacity(2);
        for message in ancillary.drain() {
            match message {
                RecvAncillaryMessage::ScmRights(rights) => descriptors.extend(rights),
                RecvAncillaryMessage::ScmCredentials(peer) => {
                    ensure!(
                        credentials.replace(peer).is_none(),
                        "helper duplicate credentials"
                    );
                }
                _ => anyhow::bail!("helper unknown ancillary message"),
            }
        }
        ensure!(
            credentials == Some(self.peer),
            "helper sender credentials changed"
        );
        ensure!(descriptors.len() <= 1, "helper excess received descriptors");
        Ok((bytes, descriptors))
    }
}

impl PrivateMount {
    #[allow(clippy::unnecessary_debug_formatting)] // Escape unexpected filenames in diagnostics.
    fn validate(directory: OwnedFd) -> Result<Self> {
        let stat = fstat(&directory)?;
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::Directory,
            "helper FD is not a directory"
        );
        ensure!(
            stat.st_uid == 0 && stat.st_mode.trailing_zeros() >= 6,
            "helper mount ownership or mode"
        );
        ensure!(
            fstatfs(&directory)?.f_type == BPF_FS_MAGIC,
            "helper FD is not bpffs"
        );
        let mount = Self { directory };
        if let Some(entry) = std::fs::read_dir(mount.path())?.next() {
            anyhow::bail!("helper mount is not empty: {:?}", entry?.file_name());
        }
        Ok(mount)
    }

    // This path is valid only while self owns the FD; callers receive it solely
    // under a borrow. This does not enter a namespace or change the mount tree.
    fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    /// Load through a held mount reference without `SYS_ADMIN` in the client.
    /// A returned BPF object may retain its own FDs, never this directory FD.
    ///
    /// # Errors
    /// Propagates the caller's loading error; mount ownership still drops.
    pub fn with_path<T>(self, load: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
        load(&self.path())
    }
}
