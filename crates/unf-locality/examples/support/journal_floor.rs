//! Independent old-agent rejection on the exact private upgraded journal.
use std::{fs, path::Path, process::Command};

use anyhow::{Result, ensure};
use unf_cni_state::{
    AttachmentJournal, CNI_TRANSACTION_SCHEMA_VERSION, TransactionOperation, TransactionRequest,
};
use unf_ipam::NodeBlockProvider;

pub fn verify(path: &Path, provider: NodeBlockProvider) -> Result<()> {
    let before = fs::read(path)?;
    let mut reopened = AttachmentJournal::open(path, provider)?;
    ensure!(
        reopened.retirement_required() && reopened.cut().is_none(),
        "reopen restored a permission without a hook"
    );
    ensure!(
        reopened
            .apply(TransactionRequest::new(
                CNI_TRANSACTION_SCHEMA_VERSION,
                TransactionOperation::Status
            ))
            .is_err(),
        "unhooked journal served CNI"
    );
    drop(reopened);
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("old.sock");
    let readiness = directory.path().join("old.ready");
    // Frozen production 45d85d5 executable, not a reimplementation of its
    // parser. No controller, BPF object, uplink, host mount or inherited secret.
    let output = Command::new("/usr/bin/timeout")
        .args([
            "10s",
            "/usr/local/bin/unf-legacy-agent",
            "--listen",
            "127.0.0.1:0",
            "--cni-socket",
        ])
        .arg(&socket)
        .arg("--cni-state-path")
        .arg(path)
        .arg("--cni-status-lease-path")
        .arg(&readiness)
        .arg("--cni-ipv4-block")
        .arg(provider.ipv4_block.to_string())
        .arg("--cni-ipv6-block")
        .arg(provider.ipv6_block.to_string())
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("RUST_LOG", "error")
        .env("TOKIO_WORKER_THREADS", "2")
        .output()?;
    ensure!(
        output.stdout.len() + output.stderr.len() <= 16_384,
        "legacy rejection output exceeds bound"
    );
    let stdout = std::str::from_utf8(&output.stdout)?;
    let stderr = std::str::from_utf8(&output.stderr)?;
    println!("legacy-journal-rejection-stdout: {stdout}");
    println!("legacy-journal-rejection-stderr: {stderr}");
    ensure!(
        output.status.code() == Some(1)
            && stderr.contains("attachment journal schema 5 is incompatible with schema 4"),
        "old agent did not reject the reader floor: {}",
        output.status
    );
    ensure!(
        !socket.exists() && !readiness.exists(),
        "old agent bound or advertised CNI before rejection"
    );
    ensure!(
        fs::read(path)? == before,
        "reader changed private journal bytes"
    );
    directory.close()?;
    println!(
        "kernel-locality-journal-floor: PASS schema=5 reopen-fenced=true legacy-agent-rejected=true socket-absent=true readiness-absent=true bytes-preserved=true"
    );
    Ok(())
}
