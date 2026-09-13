//! Loader for the separate drop-only diagnostic, never the live UNF object.
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use aya::{EbpfLoader, VerifierLogLevel, programs::SchedClassifier};

fn main() -> Result<()> {
    ensure!(
        std::env::var("UNF_DEVICE_OBSERVATION_ISOLATED_CONTAINER").as_deref() == Ok("yes"),
        "isolated diagnostic opt-in required"
    );
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        arguments.len() == 2,
        "expected object and private bpffs directory"
    );
    let object = PathBuf::from(&arguments[0]);
    let directory = PathBuf::from(&arguments[1]);
    ensure!(
        directory.file_name().is_some_and(|name| name == "bpffs")
            && directory
                .parent()
                .and_then(|parent| parent.file_name())
                .is_some_and(|name| name
                    .to_string_lossy()
                    .starts_with("unf-device-observation.")),
        "unexpected diagnostic pin directory"
    );
    ensure!(
        std::fs::metadata(&object)?.len() <= 4 * 1024 * 1024,
        "diagnostic object too large"
    );
    let bytes = std::fs::read(object)?;
    let mut bpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .load(&bytes)
        .context("load diagnostic object")?;
    let program: &mut SchedClassifier = bpf
        .program_mut("device_observation")
        .context("missing diagnostic classifier")?
        .try_into()?;
    program
        .load()
        .context("kernel rejected diagnostic classifier")?;
    program.pin(directory.join("program"))?;
    for name in ["P9DEVCFG", "P9DEVOBS"] {
        bpf.map(name)
            .context("missing diagnostic map")?
            .pin(directory.join("maps").join(name))?;
    }
    println!(
        "Drop-only diagnostic program and maps loaded into private bpffs; no TC attachment performed by loader"
    );
    Ok(())
}
