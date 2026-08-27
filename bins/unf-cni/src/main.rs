use std::io::{self, Read, Write};
use std::process::ExitCode;

use serde::Serialize;
use unf_cni::{CniError, InvocationEnvironment, MAX_CONFIG_BYTES, Success, execute};

fn main() -> ExitCode {
    let input = match read_bounded_stdin() {
        Ok(input) => input,
        Err(error) => return emit_error(&error),
    };
    match execute(&InvocationEnvironment::from_process(), &input) {
        Ok(Success::Empty) => ExitCode::SUCCESS,
        Ok(Success::Version(response)) => emit_success(&response),
        Err(error) => emit_error(&error),
    }
}

fn read_bounded_stdin() -> Result<Vec<u8>, CniError> {
    let limit = u64::try_from(MAX_CONFIG_BYTES).expect("configuration limit fits u64") + 1;
    let mut input = Vec::new();
    io::stdin()
        .take(limit)
        .read_to_end(&mut input)
        .map_err(|error| CniError::io(format!("failed to read stdin: {error}")))?;
    if input.len() > MAX_CONFIG_BYTES {
        return Err(CniError::oversized_config(input.len()));
    }
    Ok(input)
}

fn emit_success(value: &impl Serialize) -> ExitCode {
    if emit_json(value).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn emit_error(error: &CniError) -> ExitCode {
    let _ = emit_json(error);
    ExitCode::FAILURE
}

fn emit_json(value: &impl Serialize) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    output.flush()
}
