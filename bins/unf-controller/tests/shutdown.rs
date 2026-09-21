#![cfg(unix)]

const SERVICE_BINARY: &str = env!("CARGO_BIN_EXE_unf-controller");
const SERVICE_ARGS: &[&str] = &["--offline"];

include!("../../test-support/shutdown.rs");
