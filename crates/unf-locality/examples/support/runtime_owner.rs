//! Owned disposable startup pins. No production path, map or attachment.
use std::os::fd::AsFd as _;
use std::process::Command;
use std::{fs, path::Path};

use anyhow::{Context as _, Result, ensure};
use aya::{
    Ebpf, EbpfLoader,
    maps::{Array, Map, ProgramArray},
    programs::SchedClassifier,
};
use unf_encryption::EncryptionLocalityContext;
use unf_locality::LocalityRuntimeMaps;

const NAMES: [&str; 4] = [
    "UL_INPUT_V1",
    "UL_FENCE_V1",
    "UL_RESUME_V1",
    "UL_DISPATCH_V1",
];

fn program(object: &Ebpf) -> Result<&SchedClassifier> {
    object
        .program("unf_locality_fixture")
        .context("fixture program")?
        .try_into()
        .map_err(Into::into)
}

fn load(runtime: &LocalityRuntimeMaps) -> Result<Ebpf> {
    let mut loader = EbpfLoader::new();
    runtime.configure_loader(&mut loader)?;
    let mut object = loader.load_file("/usr/local/lib/unf/locality-fixture")?;
    runtime.verify_loaded(&object)?;
    let classifier: &mut SchedClassifier = object
        .program_mut("unf_locality_fixture")
        .context("fixture program")?
        .try_into()?;
    classifier.load()?;
    Ok(object)
}

fn data<'a>(object: &'a Ebpf, name: &str) -> Result<&'a aya::maps::MapData> {
    match object.map(name).context("fixture map")? {
        Map::Array(data) | Map::PerCpuArray(data) | Map::ProgramArray(data) => Ok(data),
        _ => anyhow::bail!("unexpected map type"),
    }
}

fn assert_withdrawn(object: &Ebpf) -> Result<()> {
    let fence: Array<_, [u64; 4]> = Array::try_from(object.map("UL_FENCE_V1").context("fence")?)?;
    ensure!(fence.get(&0, 0)? == [0; 4], "reopen left an armed fence");
    // Program-array UAPI lookup returns a fixed-width program ID, or ENOENT.
    let dispatch: Array<_, u32> = Array::try_from(Map::Array(aya::maps::MapData::from_fd(
        data(object, "UL_DISPATCH_V1")?
            .fd()
            .as_fd()
            .try_clone_to_owned()?,
    )?))?;
    ensure!(
        matches!(dispatch.get(&0, 0), Err(aya::maps::MapError::KeyNotFound)),
        "reopen left a selected program"
    );
    let resume: Array<_, u32> = Array::try_from(Map::Array(aya::maps::MapData::from_fd(
        data(object, "UL_RESUME_V1")?
            .fd()
            .as_fd()
            .try_clone_to_owned()?,
    )?))?;
    for index in 0..4 {
        ensure!(
            matches!(resume.get(&index, 0), Err(aya::maps::MapError::KeyNotFound)),
            "reopen retained an old continuation"
        );
    }
    Ok(())
}

pub fn verify(bpffs: &Path, context: &EncryptionLocalityContext) -> Result<()> {
    ensure!(
        bpffs.starts_with("/tmp") && bpffs.file_name().is_some_and(|name| name == "bpffs"),
        "fixture bpffs scope"
    );
    let parent = tempfile::Builder::new()
        .prefix("unf-locality-owned-")
        .tempdir_in(bpffs)?;
    let regular = tempfile::tempdir()?;
    let owner = regular.path().join("owner.lock");
    let pins = parent.path().join("v1");
    ensure!(
        LocalityRuntimeMaps::open_owned(&pins, &owner).is_err() && !pins.exists(),
        "missing pins silently became fresh authority"
    );
    let mut runtime = LocalityRuntimeMaps::create_owned(&pins, &owner)?;
    let object = load(&runtime)?;
    assert_withdrawn(&object)?;
    ensure!(
        LocalityRuntimeMaps::open_owned(&pins, &owner).is_err(),
        "competing runtime owner accepted"
    );
    runtime.set_applied(context)?;
    // A deliberately armed private table, not a production consumer. No TC
    // attachment and no packet invocation; reopen must clear this real table.
    let mut dispatch =
        ProgramArray::try_from(aya::maps::Map::ProgramArray(aya::maps::MapData::from_fd(
            data(&object, "UL_DISPATCH_V1")?
                .fd()
                .as_fd()
                .try_clone_to_owned()?,
        )?))?;
    dispatch.set(0, program(&object)?.fd()?, 0)?;
    drop(dispatch);
    let mut resume = ProgramArray::try_from(Map::ProgramArray(aya::maps::MapData::from_fd(
        data(&object, "UL_RESUME_V1")?
            .fd()
            .as_fd()
            .try_clone_to_owned()?,
    )?))?;
    for index in 0..4 {
        resume.set(index, program(&object)?.fd()?, 0)?;
    }
    drop(resume);
    drop(runtime);
    let reopened = LocalityRuntimeMaps::open_owned(&pins, &owner)?;
    reopened.verify_loaded(&object)?;
    assert_withdrawn(&object)?;
    let foreign = Ebpf::load_file("/usr/local/lib/unf/locality-fixture")?;
    ensure!(
        reopened.verify_loaded(&foreign).is_err(),
        "foreign runtime accepted by shape"
    );
    drop(foreign);
    drop(reopened);

    let missing = pins.join("UL_FENCE_V1");
    // This exact fixture-created pin is recoverable from the retained FD.
    fs::remove_file(&missing)?;
    ensure!(
        LocalityRuntimeMaps::open_owned(&pins, &owner).is_err(),
        "partial inventory accepted"
    );
    ensure!(
        !missing.exists(),
        "partial inventory silently recreated a map"
    );
    data(&object, "UL_FENCE_V1")?.pin(&missing)?;
    let extra = pins.join("unexpected");
    data(&object, "UL_INPUT_V1")?.pin(&extra)?;
    ensure!(
        LocalityRuntimeMaps::open_owned(&pins, &owner).is_err(),
        "foreign inventory accepted"
    );
    ensure!(extra.exists(), "foreign inventory silently removed");
    fs::remove_file(&extra)?;
    let final_owner = LocalityRuntimeMaps::open_owned(&pins, &owner)?;
    final_owner.verify_loaded(&object)?;
    assert_withdrawn(&object)?;
    drop(final_owner);
    for name in NAMES {
        let path = pins.join(name);
        let pinned = aya::maps::MapData::from_pin(&path)?;
        ensure!(
            pinned.info()?.id() == data(&object, name)?.info()?.id(),
            "cleanup pin was substituted"
        );
        fs::remove_file(path)?;
    }
    fs::remove_dir(&pins)?;
    drop(object);
    parent.close()?;
    regular.close()?;
    println!(
        "kernel-locality-runtime-owner: PASS atomic-create=true exclusive-owner=true reopen-withdrawn=true exact-bindings=true partial-rejected=true foreign-preserved=true cleanup=true"
    );
    Ok(())
}

/// Execute the current real agent with only private pins/journal and a missing
/// ELF. It must establish early ownership/CNI retirement, then fail before any
/// attachment. No controller, credentials, uplink or production path is passed.
fn startup_agent(bpffs: &Path, state: &Path, expected: &str) -> Result<String> {
    let output = Command::new("/usr/bin/timeout")
        .args(["15s", "/usr/local/bin/unf-startup-agent"])
        .args(["--listen", "127.0.0.1:0", "--node-name", "fixture-startup"])
        .arg("--ebpf-object")
        .arg(state.join("missing-elf"))
        .args(["--interface", "unf-no-device"])
        .arg("--bpf-pin-path")
        .arg(bpffs.join("v15"))
        .arg("--cni-socket")
        .arg(state.join("cni.sock"))
        .arg("--cni-state-path")
        .arg(state.join("attachments.json"))
        .arg("--cni-status-lease-path")
        .arg(state.join("readiness"))
        .args([
            "--cni-ipv4-block",
            "10.250.0.0/24",
            "--cni-ipv6-block",
            "fd00:250::/120",
        ])
        .arg("--encryption-generation-state-path")
        .arg(state.join("generations.json"))
        .arg("--encryption-plan-state-path")
        .arg(state.join("plans.json"))
        .arg("--encryption-key-state-path")
        .arg(state.join("keys.json"))
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("RUST_LOG", "info")
        .env("TOKIO_WORKER_THREADS", "2")
        .output()?;
    ensure!(
        output.stdout.len() + output.stderr.len() <= 128 * 1024,
        "startup output budget"
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?
    );
    ensure!(
        output.status.code() == Some(1) && combined.contains(expected),
        "unexpected isolated agent startup: {combined}"
    );
    // Retain full real-process output, including the deliberate terminal error.
    println!("kernel-locality-agent-startup-process: expected={expected}\n{combined}");
    Ok(combined)
}

pub fn verify_agent_startup(bpffs: &Path, context: &EncryptionLocalityContext) -> Result<()> {
    ensure!(
        bpffs.starts_with("/tmp") && bpffs.file_name().is_some_and(|name| name == "bpffs"),
        "fixture bpffs scope"
    );
    let root = tempfile::Builder::new()
        .prefix("unf-agent-startup-")
        .tempdir_in(bpffs)?;
    let state = tempfile::tempdir()?;
    let pins = root.path().join("locality/v1");
    let owner = state.path().join("locality-runtime.lock");
    let checkpoint = state.path().join("locality-runtime.json");
    let journal = state.path().join("attachments.json");
    let first = startup_agent(root.path(), state.path(), "load eBPF object")?;
    let owner_message = first
        .find("locality runtime owned and withdrawn before route/CNI startup")
        .context("early owner log")?;
    let serving = first
        .find("root-authenticated CNI transaction API enabled")
        .context("CNI startup log")?;
    ensure!(owner_message < serving, "CNI preceded startup fence");
    ensure!(first.contains("Create"), "first startup did not create");
    let before_checkpoint = fs::read(&checkpoint)?;
    let before_journal = fs::read(&journal)?;
    let reopened_journal = unf_cni_state::AttachmentJournal::open(
        &journal,
        unf_ipam::NodeBlockProvider::new("10.250.0.0/24".parse()?, "fd00:250::/120".parse()?),
    )?;
    ensure!(
        reopened_journal.retirement_required()
            && reopened_journal.is_empty()
            && reopened_journal.cut().is_none(),
        "real CNI gate did not persist empty reader floor"
    );
    drop(reopened_journal);
    let mut runtime = LocalityRuntimeMaps::open_owned(&pins, &owner)?;
    let object = load(&runtime)?;
    assert_withdrawn(&object)?;
    runtime.set_applied(context)?;
    let mut dispatch = ProgramArray::try_from(Map::ProgramArray(aya::maps::MapData::from_fd(
        data(&object, "UL_DISPATCH_V1")?
            .fd()
            .as_fd()
            .try_clone_to_owned()?,
    )?))?;
    dispatch.set(0, program(&object)?.fd()?, 0)?;
    drop(dispatch);
    drop(runtime);
    let reopened = startup_agent(root.path(), state.path(), "load eBPF object")?;
    ensure!(reopened.contains("Reopen"), "same boot did not reopen");
    assert_withdrawn(&object)?;
    ensure!(
        fs::read(&checkpoint)? == before_checkpoint && fs::read(&journal)? == before_journal,
        "reopen changed journal/checkpoint bytes"
    );

    let fence = pins.join("UL_FENCE_V1");
    fs::remove_file(&fence)?;
    let partial = startup_agent(
        root.path(),
        state.path(),
        "partial or foreign locality pin inventory",
    )?;
    ensure!(
        !partial.contains("root-authenticated CNI") && !fence.exists(),
        "partial startup served or repaired"
    );
    data(&object, "UL_FENCE_V1")?.pin(&fence)?;
    for name in NAMES {
        let path = pins.join(name);
        ensure!(
            aya::maps::MapData::from_pin(&path)?.info()?.id() == data(&object, name)?.info()?.id(),
            "cleanup pin substituted"
        );
        fs::remove_file(path)?;
    }
    fs::remove_dir(&pins)?;
    // Old maps/program remain held by object: missing pins do NOT mean dead BPF.
    let missing = startup_agent(
        root.path(),
        state.path(),
        "locality pins missing during the same kernel boot",
    )?;
    ensure!(
        !missing.contains("root-authenticated CNI") && !pins.exists(),
        "same-boot missing inventory served or recreated"
    );
    ensure!(
        fs::read(&checkpoint)? == before_checkpoint && fs::read(&journal)? == before_journal,
        "rejection changed durable state"
    );
    drop(object);
    root.close()?;
    state.close()?;
    println!(
        "kernel-locality-agent-startup: PASS actual-agent=true early-owner=true real-journal-floor=5 armed-reopen-withdrawn=true partial-rejected=true missing-same-boot-rejected=true bytes-preserved=true packet-attachment=false cleanup=true"
    );
    Ok(())
}
