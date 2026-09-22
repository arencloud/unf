//! No daemon listener, arbitrary exec, namespace pathname or file-capability setup.
use anyhow::{Result, ensure};
use rustix::process::Pid;

fn main() {
    if let Err(error) = run() {
        eprintln!("locality-helper: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["--version"] {
        println!("{}", option_env!("UNF_BUILD_REVISION").unwrap_or("unknown"));
        return Ok(());
    }
    ensure!(
        arguments.len() == 3 && arguments[0] == "--mount-worker",
        "expected fixed mount-worker invocation"
    );
    let parent = Pid::from_raw(arguments[2].parse()?)
        .ok_or_else(|| anyhow::anyhow!("invalid parent PID"))?;
    unf_locality::helper::process::run_mount_worker(&arguments[1], parent)
}
