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
        arguments.len() == 2 || (arguments.len() == 3 && arguments[2] == "lease"),
        "expected object, private bpffs directory and optional lease mode"
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
    let lease = arguments.len() == 3;
    let programs: &[(&str, &str)] = if lease {
        &[
            ("device_lease_seed", "seed"),
            ("device_lease_redirect", "program"),
            ("device_lease_concurrent", "concurrent"),
        ]
    } else {
        &[("device_observation", "program")]
    };
    for (name, pin) in programs {
        let program: &mut SchedClassifier = bpf
            .program_mut(name)
            .context("missing diagnostic classifier")?
            .try_into()?;
        program
            .load()
            .context("kernel rejected diagnostic classifier")?;
        program.pin(directory.join(pin))?;
    }
    let maps: &[&str] = if lease {
        &[
            "P9LEASECFG",
            "P9LEASEPTR",
            "P9LEASEDEV",
            "P9LEASEOWN",
            "P9LEASERES",
            "P9LEASECON",
        ]
    } else {
        &["P9DEVCFG", "P9DEVOBS"]
    };
    for name in maps {
        bpf.map(name)
            .context("missing diagnostic map")?
            .pin(directory.join("maps").join(name))?;
    }
    println!(
        "Isolated diagnostic programs and maps loaded into private bpffs; no TC attachment performed by loader"
    );
    Ok(())
}
