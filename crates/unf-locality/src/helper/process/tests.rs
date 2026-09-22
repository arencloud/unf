use super::*;

fn fixture(bytes: &[u8]) -> File {
    let mut source = tempfile::tempfile().unwrap();
    source.write_all(bytes).unwrap();
    source.seek(SeekFrom::Start(0)).unwrap();
    source
}

#[test]
fn executable_seals_bind_exact_bytes_and_refuse_scripts_mismatch_and_growth() {
    let bytes = b"\x7fELFfixed-test-bytes";
    let digest = Sha256::digest(bytes).into();
    let sealed = TrustedHelper::seal(fixture(bytes), digest, bytes.len() as u64).unwrap();
    assert!(rustix::fs::ftruncate(&sealed.0, 0).is_err());
    assert!(rustix::io::write(&sealed.0, b"mutated").is_err());
    assert!(TrustedHelper::seal(fixture(bytes), [0; 32], bytes.len() as u64).is_err());
    assert!(TrustedHelper::seal(fixture(bytes), digest, 4).is_err());
    assert!(TrustedHelper::seal(fixture(bytes), digest, bytes.len() as u64 + 1).is_err());
    assert!(TrustedHelper::seal(fixture(b"#!/bin/sh"), [0; 32], 9).is_err());
}

#[test]
fn executable_paths_and_rendezvous_names_are_not_untrusted_authority() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("link");
    std::os::unix::fs::symlink("/proc/self/exe", &path).unwrap();
    assert!(TrustedHelper::open(&path, [0; 32]).is_err());
    assert!(TrustedHelper::open(Path::new("/dev/null"), [0; 32]).is_err());
    assert!(TrustedHelper::open(root.path(), [0; 32]).is_err());
    for name in [
        "",
        "../socket",
        &"A".repeat(64),
        &"g".repeat(64),
        &"a".repeat(63),
        &"a".repeat(65),
    ] {
        assert!(address(name).is_err());
    }
    assert!(address(&"a".repeat(64)).is_ok());
}

#[test]
fn cancelled_or_busy_work_cannot_launch_a_process() {
    let bytes = b"\x7fELFnot-executed";
    let supervisor = HelperSupervisor::new(
        TrustedHelper::seal(
            fixture(bytes),
            Sha256::digest(bytes).into(),
            bytes.len() as u64,
        )
        .unwrap(),
    );
    let cancellation = HelperCancellation::default();
    cancellation.cancel().unwrap();
    assert!(supervisor.try_start(cancellation).is_err());
    assert!(!supervisor.busy.load(Ordering::Acquire));
    // Slot lifetime itself must not depend on a caller-held cancellation clone.
    supervisor.busy.store(true, Ordering::Release);
    let slot = Slot {
        busy: Arc::clone(&supervisor.busy),
        release: true,
    };
    drop(slot);
    assert!(!supervisor.busy.load(Ordering::Acquire));
    supervisor.busy.store(true, Ordering::Release);
    drop(Slot {
        busy: Arc::clone(&supervisor.busy),
        release: false,
    });
    assert!(
        supervisor.busy.load(Ordering::Acquire),
        "uncertain reap reopened slot"
    );
}

fn child_pid(session: &HelperSession) -> u32 {
    session.child.child.as_ref().unwrap().id()
}

fn assert_reaped(pid: u32) {
    // No subsequent process is spawned between reaping and this observation.
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "helper child was not reaped"
    );
}

#[test]
#[ignore = "isolated cl02-first packaged helper process and kernel gate"]
#[allow(clippy::too_many_lines)] // Keep process lifetime/slot assertions in one audited sequence.
fn privileged_supervisor_authenticates_reaps_and_retains_its_slot() {
    assert_eq!(
        std::env::var("UNF_LOCALITY_HELPER_ISOLATED").as_deref(),
        Ok("yes")
    );
    let revision = std::env::var("UNF_EXPECT_BUILD_REVISION").unwrap();
    assert_eq!(option_env!("UNF_BUILD_REVISION"), Some(revision.as_str()));
    let executable = Path::new("/usr/local/bin/unf-locality-helper");
    assert_eq!(
        Command::new(executable)
            .arg("--version")
            .output()
            .unwrap()
            .stdout,
        format!("{revision}\n").as_bytes()
    );
    let digest = Sha256::digest(std::fs::read(executable).unwrap()).into();
    // The immutable image fixes this packaged file; the test additionally binds
    // the actual measured file to the immutable sealed executable copy.
    let supervisor = HelperSupervisor::new(TrustedHelper::open(executable, digest).unwrap());
    let cancel = HelperCancellation::default();
    let session = supervisor.try_start(cancel.clone()).unwrap().unwrap();
    let pid = child_pid(&session);
    assert_ne!(pid, std::process::id());
    assert!(
        supervisor
            .try_start(HelperCancellation::default())
            .unwrap()
            .is_none()
    );
    // Real worker hardening is visible through the kernel, not a response flag.
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    for field in ["CapPrm", "CapEff", "CapBnd"] {
        assert!(
            status
                .lines()
                .any(|line| line == format!("{field}:\t0000000000200000"))
        );
    }
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    // The client requests/uses the FD without SYS_ADMIN in a dedicated thread.
    let map = std::thread::spawn(move || {
        use rustix::thread::{CapabilitySet, CapabilitySets, set_capabilities, set_no_new_privs};
        let caps = CapabilitySet::BPF | CapabilitySet::NET_ADMIN | CapabilitySet::PERFMON;
        set_no_new_privs(true).unwrap();
        set_capabilities(
            None,
            CapabilitySets {
                effective: caps,
                permitted: caps,
                inheritable: CapabilitySet::empty(),
            },
        )
        .unwrap();
        let memory = File::open(format!("/proc/{pid}/mem")).unwrap_err();
        assert_eq!(
            memory.kind(),
            std::io::ErrorKind::PermissionDenied,
            "helper memory must not be readable by same-UID three-capability client"
        );
        let mount = session.request().unwrap();
        mount
            .with_path(|root| {
                use aya::maps::{MapData, MapType};
                let map = MapData::create(
                    aya_obj::Map::new_from_params(MapType::Array as u32, 4, 8, 1, 0),
                    "UL_PROCESS_TEST",
                    None,
                )?;
                map.pin(root.join("UL_PROCESS_TEST"))?;
                Ok(map)
            })
            .unwrap()
    })
    .join()
    .unwrap();
    assert_reaped(pid);
    assert!(!supervisor.busy.load(Ordering::Acquire));
    assert!(
        supervisor.try_start(cancel).is_err(),
        "consumed cancellation token replayed"
    );
    let id = map.info().unwrap().id();
    drop(map);
    let deadline = Instant::now() + DEADLINE;
    loop {
        match aya::maps::MapInfo::from_id(id) {
            Err(aya::maps::MapError::SyscallError(error))
                if error.io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                break;
            }
            Ok(_) => assert!(Instant::now() < deadline, "helper pin leaked"),
            other => panic!("unexpected map observer error: {other:?}"),
        }
        std::thread::sleep(TICK);
    }
    for explicit_cancel in [true, false] {
        let cancel = HelperCancellation::default();
        let session = supervisor.try_start(cancel.clone()).unwrap().unwrap();
        let pid = child_pid(&session);
        if explicit_cancel {
            cancel.cancel().unwrap();
            assert!(
                supervisor
                    .try_start(HelperCancellation::default())
                    .unwrap()
                    .is_none(),
                "slot released before reap"
            );
            assert!(session.request().is_err());
        } else {
            drop(session);
        }
        assert_reaped(pid);
        assert!(!supervisor.busy.load(Ordering::Acquire));
    }
    let mut expired = supervisor
        .try_start(HelperCancellation::default())
        .unwrap()
        .unwrap();
    let pid = child_pid(&expired);
    expired.deadline = Instant::now();
    assert!(
        expired.request().is_err(),
        "expired session admitted a mount"
    );
    assert_reaped(pid);
    assert!(!supervisor.busy.load(Ordering::Acquire));
    println!(
        "locality-helper-process: PASS separate-process=true sealed-executable=true exact-peer=true helper-bounding-sys-admin=true client-three-caps=true single-slot=true cancel-drop-reaped=true token-replay-denied=true pin-reclaimed=true production-integration=false"
    );
}
