#![cfg(unix)]

const SERVICE_BINARY: &str = env!("CARGO_BIN_EXE_unf-agent");
const SERVICE_ARGS: &[&str] = &[];

include!("../../test-support/shutdown.rs");
