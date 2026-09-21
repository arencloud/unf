use super::*;
use aya::maps::{MapData, MapInfo, MapType};
use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

fn pinned(root: &Path) -> MapData {
    let map = MapData::create(
        aya_obj::Map::new_from_params(MapType::Array as u32, 4, 8, 1, 0),
        "UL_PRIVATE_TEST",
        None,
    )
    .unwrap();
    map.pin(root.join("UL_PRIVATE_TEST")).unwrap();
    map
}

fn reclaimed(id: u32) {
    assert_ne!(id, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match MapInfo::from_id(id) {
            Ok(_) => assert!(Instant::now() < deadline, "orphaned BPF map {id}"),
            Err(aya::maps::MapError::SyscallError(error))
                if error.io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                return;
            }
            other => panic!("unexpected map-lifetime observation: {other:?}"),
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn persistent_residue_is_preserved_before_any_namespace_action() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("foreign"), b"preserve").unwrap();
    let result = with_private_mount(root.path(), |_| -> Result<()> {
        panic!("must refuse before invoking the loader")
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("persistent locality preparation residue")
    );
    assert_eq!(fs::read(root.path().join("foreign")).unwrap(), b"preserve");
    assert!(with_private_mount(&root.path().join("absent"), |_| Ok(())).is_err());
}

#[test]
#[ignore = "private child of the explicit isolated mount-lifetime gate"]
fn privileged_private_pin_kill_child() {
    assert_eq!(
        std::env::var("UNF_MAIN_COMPOSITION_ISOLATED").as_deref(),
        Ok("yes")
    );
    let root = std::path::PathBuf::from(std::env::var("UNF_PRIVATE_PIN_ROOT").unwrap());
    let ready = std::path::PathBuf::from(std::env::var("UNF_PRIVATE_PIN_READY").unwrap());
    assert!(root.starts_with("/tmp"));
    assert!(
        root.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("unf-private-pin-")
    );
    assert_eq!(ready.parent(), root.parent());
    with_private_mount::<()>(&root, |root| {
        let map = pinned(root);
        fs::write(&ready, map.info().unwrap().id().to_string()).unwrap();
        loop {
            std::thread::park();
        }
    })
    .unwrap();
}

#[test]
#[ignore = "requires root/CAP_SYS_ADMIN in isolated private-network diagnostic"]
fn privileged_mount_lifetime_reclaims_pins_on_success_error_and_kill() {
    assert_eq!(
        std::env::var("UNF_MAIN_COMPOSITION_ISOLATED").as_deref(),
        Ok("yes")
    );
    let directory = tempfile::Builder::new()
        .prefix("unf-private-pin-")
        .tempdir()
        .unwrap();
    let root = directory.path().join("pins");
    fs::create_dir(&root).unwrap();
    let namespace = fs::read_link("/proc/thread-self/ns/mnt").unwrap();
    let id = AtomicU32::new(0);
    let held = with_private_mount(&root, |root| Ok(pinned(root))).unwrap();
    let held_id = held.info().unwrap().id();
    assert!(
        MapInfo::from_id(held_id).is_ok(),
        "returned FD lost across mount-thread exit"
    );
    assert!(fs::read_dir(&root).unwrap().next().is_none());
    drop(held);
    reclaimed(held_id);
    assert!(
        with_private_mount::<()>(&root, |root| {
            let map = pinned(root);
            id.store(map.info().unwrap().id(), Ordering::Release);
            anyhow::bail!("injected loader failure")
        })
        .is_err_and(|error| error.to_string().contains("injected loader failure"))
    );
    reclaimed(id.load(Ordering::Acquire));
    assert!(
        with_private_mount::<()>(&root, |root| {
            let map = pinned(root);
            id.store(map.info().unwrap().id(), Ordering::Release);
            panic!("injected private loader panic");
        })
        .is_err()
    );
    reclaimed(id.load(Ordering::Acquire));
    let ready = directory.path().join("ready");
    let log = fs::File::create(directory.path().join("child.log")).unwrap();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "kernel::build::private_pins::tests::privileged_private_pin_kill_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("UNF_PRIVATE_PIN_ROOT", &root)
            .env("UNF_PRIVATE_PIN_READY", &ready)
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let killed_id = loop {
        if let Ok(bytes) = fs::read_to_string(&ready)
            && let Ok(id) = bytes.parse::<u32>()
        {
            break id;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "private pin child exited before readiness: {}",
            fs::read_to_string(directory.path().join("child.log")).unwrap_or_default()
        );
        assert!(
            Instant::now() < deadline,
            "private pin child readiness timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(MapInfo::from_id(killed_id).is_ok());
    assert!(
        fs::read_dir(&root).unwrap().next().is_none(),
        "child mount propagated to parent"
    );
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(9));
    reclaimed(killed_id);
    assert_eq!(
        fs::read_link("/proc/thread-self/ns/mnt").unwrap(),
        namespace
    );
    assert!(fs::read_dir(&root).unwrap().next().is_none());
    fs::write(root.join("foreign"), b"preserve").unwrap();
    assert!(with_private_mount(&root, |_| Ok(())).is_err());
    assert_eq!(fs::read(root.join("foreign")).unwrap(), b"preserve");
    println!(
        "locality-private-pins: PASS fd-survives=true success-error-panic-kill-reclaimed=true parent-namespace-unchanged=true residue-preserved=true"
    );
}
