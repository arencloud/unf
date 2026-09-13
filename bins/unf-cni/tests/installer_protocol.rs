//! Real candidate executable against bounded, disposable Unix transaction peers.
//! Rewrites only fixed packaging paths into a private test fixture, never /host.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use unf_cni_state::{
    CNI_TRANSACTION_SCHEMA_VERSION, TransactionOutcome, TransactionRequest, TransactionResponse,
};

struct Fixture {
    directory: tempfile::TempDir,
    target: PathBuf,
    marker: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        for path in [
            "opt/unf/cni",
            "opt/unf/install",
            "host/var/lib/cni/bin",
            "host/etc/kubernetes/cni/net.d",
            "host/run/unf",
        ] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::copy(
            std::env::var("UNF_CNI_INSTALLER_TEST_BINARY")
                .unwrap_or_else(|_| env!("CARGO_BIN_EXE_unf-cni").to_owned()),
            root.join("opt/unf/cni/unf-cni"),
        )
        .unwrap();
        fs::write(
            root.join("opt/unf/install/10-unf.conflist"),
            include_str!("../../../deploy/openshift-primary-cni/runtime/10-unf.conflist"),
        )
        .unwrap();
        let script = include_str!("../../../deploy/openshift-primary-cni/runtime/install.sh")
            .replace("/opt/unf/", &format!("{}/opt/unf/", root.display()))
            .replace("/host/", &format!("{}/host/", root.display()));
        fs::write(root.join("install.sh"), script).unwrap();
        Self {
            target: root.join("host/var/lib/cni/bin/unf"),
            marker: root.join("host/var/lib/unf/cni/v1/install.env"),
            socket: root.join("host/run/unf/cni.sock"),
            directory,
        }
    }

    fn run(&self) -> Output {
        self.run_with_wait("1")
    }

    fn run_with_wait(&self, wait: &str) -> Output {
        Command::new("sh")
            .arg(self.directory.path().join("install.sh"))
            .env("UNF_INSTALL_ONESHOT", "true")
            .env("UNF_INSTALL_AGENT_WAIT_SECONDS", wait)
            .output()
            .unwrap()
    }

    fn peer(&self, response: Vec<u8>) -> thread::JoinHandle<()> {
        if self.socket.exists() {
            fs::remove_file(&self.socket).unwrap();
        }
        let listener = UnixListener::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut request = Vec::new();
                        stream.read_to_end(&mut request).unwrap();
                        assert!(matches!(
                            serde_json::from_slice::<TransactionRequest>(&request).unwrap(),
                            TransactionRequest::Status {
                                schema_version: CNI_TRANSACTION_SCHEMA_VERSION
                            }
                        ));
                        stream.write_all(&response).unwrap();
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "installer did not probe the peer"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept fixture peer: {error}"),
                }
            }
        })
    }
}

#[test]
fn installer_rejects_unbounded_or_ambiguous_wait_settings() {
    let fixture = Fixture::new();
    for wait in ["0", "181", "01", "-1", "x", "999999999999999999999999999"] {
        assert!(!fixture.run_with_wait(wait).status.success());
        assert!(!fixture.target.exists() && !fixture.marker.exists());
    }
}

fn success(schema: u16) -> Vec<u8> {
    serde_json::to_vec(&TransactionResponse {
        schema_version: schema,
        outcome: TransactionOutcome::Ok {
            attachment: None,
            attachments: Vec::new(),
            attachment_count: 0,
        },
    })
    .unwrap()
}

#[test]
fn installer_requires_candidate_protocol_before_first_install_or_upgrade() {
    let fixture = Fixture::new();
    // Even a syntactically successful old response cannot authorize installation.
    let peer = fixture.peer(success(2));
    let rejected = fixture.run();
    peer.join().unwrap();
    assert!(!rejected.status.success());
    assert!(!fixture.target.exists() && !fixture.marker.exists());

    let peer = fixture.peer(success(CNI_TRANSACTION_SCHEMA_VERSION));
    let installed = fixture.run();
    peer.join().unwrap();
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let binary_before = fs::read(&fixture.target).unwrap();
    let marker_before = fs::read(&fixture.marker).unwrap();
    // Appending a trailer changes the candidate digest without changing its ELF
    // execution. A failed upgrade must retain the prior executable and marker.
    fs::OpenOptions::new()
        .append(true)
        .open(fixture.directory.path().join("opt/unf/cni/unf-cni"))
        .unwrap()
        .write_all(b"installer-upgrade-fixture")
        .unwrap();
    for response in [success(3), b"malformed-response".to_vec()] {
        let peer = fixture.peer(response);
        assert!(!fixture.run().status.success());
        peer.join().unwrap();
        assert_eq!(fs::read(&fixture.target).unwrap(), binary_before);
        assert_eq!(fs::read(&fixture.marker).unwrap(), marker_before);
    }
    let peer = fixture.peer(success(CNI_TRANSACTION_SCHEMA_VERSION));
    assert!(fixture.run().status.success());
    peer.join().unwrap();
    assert_ne!(fs::read(&fixture.target).unwrap(), binary_before);
    assert_ne!(fs::read(&fixture.marker).unwrap(), marker_before);
}

#[test]
fn installer_never_uses_a_fresh_lease_to_admit_a_stale_socket() {
    let fixture = Fixture::new();
    let lease = fixture
        .directory
        .path()
        .join("host/run/unf/cni-status.lease");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    fs::write(&lease, format!("{timestamp}\n")).unwrap();
    fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).unwrap();
    drop(UnixListener::bind(&fixture.socket).unwrap());
    let rejected = fixture.run();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8(rejected.stderr)
            .unwrap()
            .contains("protocol-compatible")
    );
    assert!(!fixture.target.exists() && !fixture.marker.exists());
    assert_eq!(
        fs::read_to_string(&lease).unwrap(),
        format!("{timestamp}\n")
    );
}
