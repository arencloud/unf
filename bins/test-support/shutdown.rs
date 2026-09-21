// Real-process regression shared by the two long-running service binaries.
// Signals never target the test runner or an existing UNF process.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct OwnedProcess(Child);

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn version_ready(address: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    if stream
        .write_all(b"GET /v1/version HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut header = [0; 13];
    stream.read_exact(&mut header).is_ok() && &header == b"HTTP/1.0 200 "
}

fn service_signal_exits_successfully(signal: &str) {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let mut command = Command::new(SERVICE_BINARY);
    command
        .env_clear()
        .env("RUST_LOG", "warn")
        .args(SERVICE_ARGS)
        .arg("--listen")
        .arg(address.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    drop(reservation);
    let mut process = OwnedProcess(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(15);
    while !version_ready(address) {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "service exited before API readiness"
        );
        assert!(
            Instant::now() < deadline,
            "service API did not become ready"
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        Command::new("kill")
            .arg(signal)
            .arg(process.0.id().to_string())
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(
                status.success(),
                "{signal} bypassed graceful shutdown: {status}"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{signal} did not stop the service within five seconds"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn sigterm_uses_service_shutdown() {
    service_signal_exits_successfully("-TERM");
}

#[test]
fn sigint_uses_service_shutdown() {
    service_signal_exits_successfully("-INT");
}
