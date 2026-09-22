//! Privileged-bootstrap supervision, not privilege escalation from an agent.
//! Blocking calls belong on the existing bounded preparation worker, never an
//! async executor thread. No public daemon or caller-selected command protocol.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use rustix::fs::{
    CWD, FileType, MemfdFlags, Mode, OFlags, ResolveFlags, SealFlags, fcntl_add_seals,
    fcntl_get_seals, fstat, memfd_create, openat2,
};
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, UCred, accept_with, bind, listen,
    socket_with, sockopt,
};
use rustix::process::{
    Pid, PidfdFlags, Signal, getegid, geteuid, getpid, pidfd_open, pidfd_send_signal,
};
use sha2::{Digest as _, Sha256};

use super::{PrivateMount, PrivateMountChannel};

mod worker;
pub use worker::run_mount_worker;
#[cfg(test)]
mod tests;

const MAX_EXECUTABLE: u64 = 32 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(5);

/// Packaged native ELF copied into immutable sealed memory after digest and
/// root-owned file checks. Expected digest comes from trusted packaging, NOT RPC.
pub struct TrustedHelper(File);

impl TrustedHelper {
    /// # Errors
    /// Refuses symlinks, writable/unowned/non-ELF/oversized files and bad digests.
    pub fn open(path: &Path, expected: [u8; 32]) -> Result<Self> {
        let source = openat2(
            CWD,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )?;
        let stat = fstat(&source)?;
        ensure!(
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && stat.st_uid == 0
                && stat.st_nlink == 1
                && stat.st_mode & 0o022 == 0
                && stat.st_mode & 0o111 != 0,
            "helper executable ownership/type/mode"
        );
        let length = u64::try_from(stat.st_size)?;
        ensure!(
            (4..=MAX_EXECUTABLE).contains(&length),
            "helper executable size"
        );
        Self::seal(File::from(source), expected, length)
    }

    fn seal(mut source: File, expected: [u8; 32], length: u64) -> Result<Self> {
        let mut header = [0_u8; 4];
        source.read_exact(&mut header)?;
        ensure!(header == *b"\x7fELF", "helper must be native ELF");
        source.seek(SeekFrom::Start(0))?;
        let mut sealed = File::from(memfd_create(
            "unf-locality-helper",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?);
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut copied = 0_u64;
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied += u64::try_from(count)?;
            ensure!(
                copied <= length && copied <= MAX_EXECUTABLE,
                "helper executable grew during read"
            );
            hash.update(&buffer[..count]);
            sealed.write_all(&buffer[..count])?;
        }
        ensure!(
            copied == length && <[u8; 32]>::from(hash.finalize()) == expected,
            "helper executable digest/length mismatch"
        );
        let seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
        fcntl_add_seals(&sealed, seals)?;
        ensure!(
            fcntl_get_seals(&sealed)? == seals,
            "helper executable seals"
        );
        Ok(Self(sealed))
    }
}

/// Keep ONE supervisor for the bootstrap lifetime. Dropping a session kills and
/// reaps its child before releasing this non-queuing slot. It cannot give an
/// unprivileged spawning process capabilities it does not already have.
pub struct HelperSupervisor {
    executable: TrustedHelper,
    busy: Arc<AtomicBool>,
}

#[derive(Clone, Default)]
pub struct HelperCancellation {
    cancelled: Arc<AtomicBool>,
    claimed: Arc<AtomicBool>,
    process: Arc<Mutex<Option<OwnedFd>>>,
}

impl HelperCancellation {
    /// Signal the exact process descriptor, never a reusable numeric PID.
    /// # Errors
    /// Reports a poisoned owner lock or failed kernel signal other than ESRCH.
    pub fn cancel(&self) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        let process = self
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("helper process lock poisoned"))?;
        if let Some(process) = process.as_ref() {
            match pidfd_send_signal(process, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn check(&self) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::Acquire),
            "helper session cancelled"
        );
        Ok(())
    }
}

struct Slot {
    busy: Arc<AtomicBool>,
    release: bool,
}
impl Drop for Slot {
    fn drop(&mut self) {
        if self.release {
            self.busy.store(false, Ordering::Release);
        }
    }
}

struct OwnedChild {
    child: Option<Child>,
    cancellation: HelperCancellation,
    slot: Slot,
}

impl OwnedChild {
    fn poll(&mut self) -> Result<Option<ExitStatus>> {
        let result = self
            .child
            .as_mut()
            .context("helper already reaped")?
            .try_wait()?;
        if result.is_some() {
            self.child.take();
            self.cancellation
                .process
                .lock()
                .map_err(|_| anyhow::anyhow!("helper process lock poisoned"))?
                .take();
        }
        Ok(result)
    }

    fn finish(&mut self, deadline: Instant) -> Result<()> {
        loop {
            self.cancellation.check()?;
            if let Some(status) = self.poll()? {
                ensure!(status.success(), "helper unsuccessful exit: {status}");
                ensure!(Instant::now() < deadline, "helper completed after deadline");
                return Ok(());
            }
            ensure!(Instant::now() < deadline, "helper exit deadline");
            std::thread::sleep(TICK);
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = self.cancellation.cancel();
            // Covers failure to acquire pidfd during startup. This Child is
            // still owned and unreaped; no request-supplied numeric PID is used.
            let _ = child.kill();
            // Never free the slot while an actual child is still alive. A task
            // in uninterruptible kernel sleep may delay reap beyond the deadline.
            // Such a stuck worker stays fenced; do not spawn its replacement.
            if let Err(error) = child.wait() {
                self.slot.release = false;
                eprintln!(
                    "locality-helper: reap uncertain; worker slot permanently fenced: {error}"
                );
            }
        }
        if let Ok(mut process) = self.cancellation.process.lock() {
            process.take();
        }
    }
}

/// One connected authenticated child. This owns its lifetime and its slot.
pub struct HelperSession {
    channel: PrivateMountChannel,
    child: OwnedChild,
    deadline: Instant,
}

impl HelperSupervisor {
    #[must_use]
    pub fn new(executable: TrustedHelper) -> Self {
        Self {
            executable,
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Launch only the sealed fixed-purpose worker and authenticate its actual
    /// connection against the unreaped owned child PID plus root UID/GID. The
    /// random abstract address is a rendezvous name, NOT an authorization token.
    /// Caller and worker must share a PID and network namespace for this slice.
    ///
    /// # Errors
    /// Rejects missing bootstrap privilege, cancellation, connection substitution,
    /// child failure or timeout. Returns None while a previous session is owned.
    pub fn try_start(&self, cancellation: HelperCancellation) -> Result<Option<HelperSession>> {
        cancellation.check()?;
        ensure!(
            geteuid().is_root() && getegid().is_root(),
            "helper bootstrap requires root credentials"
        );
        let bootstrap = rustix::thread::capabilities(None)?;
        ensure!(
            bootstrap
                .effective
                .contains(rustix::thread::CapabilitySet::SYS_ADMIN)
                && bootstrap
                    .permitted
                    .contains(rustix::thread::CapabilitySet::SYS_ADMIN),
            "helper bootstrap lacks existing SYS_ADMIN authority"
        );
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(None);
        }
        let slot = Slot {
            busy: Arc::clone(&self.busy),
            release: true,
        };
        ensure!(
            !cancellation.claimed.swap(true, Ordering::AcqRel),
            "helper cancellation token already used"
        );
        let deadline = Instant::now() + DEADLINE;
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce)
            .map_err(|error| anyhow::anyhow!("helper rendezvous entropy: {error}"))?;
        let mut name = String::with_capacity(64);
        for byte in nonce {
            use std::fmt::Write as _;
            write!(&mut name, "{byte:02x}")?;
        }
        let address = address(&name)?;
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        sockopt::set_socket_passcred(&listener, true)?;
        bind(&listener, &address)?;
        listen(&listener, 1)?;
        // No shell, inherited environment, stdin or caller-provided operation.
        // FD lookup occurs before exec closes the CLOEXEC executable descriptor.
        let child = Command::new(format!("/proc/self/fd/{}", self.executable.0.as_raw_fd()))
            .args(["--mount-worker", &name, &getpid().as_raw_pid().to_string()])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let pid = Pid::from_raw(i32::try_from(child.id())?).context("helper invalid child PID")?;
        let mut owner = OwnedChild {
            child: Some(child),
            cancellation,
            slot,
        };
        let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
        *owner
            .cancellation
            .process
            .lock()
            .map_err(|_| anyhow::anyhow!("helper process lock poisoned"))? = Some(pidfd);
        loop {
            owner.cancellation.check()?;
            ensure!(
                owner.poll()?.is_none(),
                "helper exited before authentication"
            );
            ensure!(Instant::now() < deadline, "helper rendezvous deadline");
            match accept_with(&listener, SocketFlags::CLOEXEC) {
                Ok(socket) => {
                    let expected = UCred {
                        pid,
                        uid: geteuid(),
                        gid: getegid(),
                    };
                    let channel = PrivateMountChannel::authenticate(socket, expected)?;
                    return Ok(Some(HelperSession {
                        channel,
                        child: owner,
                        deadline,
                    }));
                }
                Err(rustix::io::Errno::AGAIN) => std::thread::sleep(TICK),
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl HelperSession {
    /// # Errors
    /// No mount escapes a failed/cancelled session or unsuccessful child exit.
    pub fn request(mut self) -> Result<PrivateMount> {
        self.child.cancellation.check()?;
        ensure!(Instant::now() < self.deadline, "helper request deadline");
        let result = self.channel.request();
        // Preserve the actual process exit even when a transport EOF occurs.
        self.child.finish(self.deadline)?;
        self.child.cancellation.check()?;
        result
    }
}

fn address(name: &str) -> Result<SocketAddrUnix> {
    ensure!(
        name.len() == 64
            && name
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "helper rendezvous name"
    );
    Ok(SocketAddrUnix::new_abstract_name(
        format!("unf-locality-{name}").as_bytes(),
    )?)
}
