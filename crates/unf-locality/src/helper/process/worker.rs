use anyhow::{Result, ensure};
use rustix::net::{AddressFamily, SocketFlags, SocketType, UCred, connect, socket_with, sockopt};
use rustix::process::{DumpableBehavior, Pid, getegid, geteuid, getppid, set_dumpable_behavior};
use rustix::thread::{
    CapabilitySet, CapabilitySets, capabilities, capability_is_in_bounding_set,
    clear_ambient_capability_set, remove_capability_from_bounding_set, set_capabilities,
    set_no_new_privs,
};

use super::{PrivateMountChannel, address};

/// Fixed-purpose worker entry point. It never grants itself missing privileges.
/// Bootstrap arguments are local process configuration, not request fields.
///
/// # Errors
/// Refuses wrong parent/root identity or capability hardening/readback failures,
/// substituted peers, malformed requests and mount/transport errors.
pub fn run_mount_worker(name: &str, parent: Pid) -> Result<()> {
    ensure!(
        geteuid().is_root() && getegid().is_root() && getppid() == Some(parent),
        "helper parent or root identity"
    );
    arm_parent_death()?;
    ensure!(
        getppid() == Some(parent),
        "helper parent exited during startup"
    );
    harden()?;
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )?;
    // Set before connect: requests queued immediately after accept still receive
    // kernel credentials, never synthetic/default credentials for old data.
    sockopt::set_socket_passcred(&socket, true)?;
    connect(&socket, &address(name)?)?;
    let expected = UCred {
        pid: parent,
        uid: geteuid(),
        gid: getegid(),
    };
    PrivateMountChannel::authenticate(socket, expected)?.serve()
}

fn harden() -> Result<()> {
    set_no_new_privs(true)?;
    clear_ambient_capability_set()?;
    // Exact bounding set too. A production profile already restricted to
    // SYS_ADMIN needs no SETPCAP; a broader diagnostic bootstrap drops its extras.
    for bit in 0..64 {
        let capability = CapabilitySet::from_bits_retain(1_u64 << bit);
        match capability_is_in_bounding_set(capability) {
            Ok(true) if capability != CapabilitySet::SYS_ADMIN => {
                remove_capability_from_bounding_set(capability)?;
            }
            Ok(_) | Err(rustix::io::Errno::INVAL) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let desired = CapabilitySets {
        effective: CapabilitySet::SYS_ADMIN,
        permitted: CapabilitySet::SYS_ADMIN,
        inheritable: CapabilitySet::empty(),
    };
    set_capabilities(None, desired)?;
    // A root three-capability agent must not ptrace this more-privileged worker
    // merely because they share a UID. No helper core dumps or proc-FD access.
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    ensure!(
        capabilities(None)? == desired
            && rustix::thread::no_new_privs()?
            && rustix::process::dumpable_behavior()? == DumpableBehavior::NotDumpable,
        "helper hardening readback"
    );
    for bit in 0..64 {
        let capability = CapabilitySet::from_bits_retain(1_u64 << bit);
        match capability_is_in_bounding_set(capability) {
            Ok(present) => ensure!(
                present == (capability == CapabilitySet::SYS_ADMIN),
                "helper bounding set drift"
            ),
            Err(rustix::io::Errno::INVAL) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn arm_parent_death() -> Result<()> {
    unsafe extern "C" {
        fn prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> i32;
    }
    // SAFETY: Linux PR_SET_PDEATHSIG=1, SIGKILL=9, scalar args, no pointers.
    // The worker verifies its original parent again after setting this flag.
    let result = unsafe { prctl(1, 9, 0, 0, 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
