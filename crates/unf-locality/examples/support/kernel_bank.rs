//! Disposable kernel consumer checks; the fixture supplies artificial trusted
//! policy input and therefore cannot qualify production policy integration.
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use aya::{
    Ebpf,
    maps::{Array, Map},
    programs::{SchedClassifier, TestRun as _, TestRunOptions},
};
use unf_cni_state::{
    AttachmentJournal, CNI_TRANSACTION_SCHEMA_VERSION, TransactionOperation, TransactionRequest,
};
use unf_ebpf_common::locality::{ABI_VERSION, PACKET_DSR_PENDING, PacketInput};
use unf_encryption::EncryptionLocalityContext;
use unf_locality::{
    IncarnationGate, KernelLocalityBank, LeasedLocalityBank, LocalityAdmission,
    LocalityApplyComponent, LocalityObservationWorker, LocalityRuntimeMaps,
};
use unf_route::NativeRoutePlan;

#[path = "packet_delivery.rs"]
mod packet_delivery;
use packet_delivery::{Delivery, pair};

#[derive(Clone, Copy)]
#[repr(transparent)]
struct Input(PacketInput);
// SAFETY: fixed-width repr(C), padding-free integer ABI; assertions live in the
// shared ABI tests. No pointers, invalid bit patterns or private Rust layout.
#[allow(unsafe_code)]
unsafe impl aya::Pod for Input {}

fn fd(object: &Ebpf, name: &str) -> Result<OwnedFd> {
    let (Map::Array(data) | Map::PerCpuArray(data) | Map::ProgramArray(data)) =
        object.map(name).context("fixture map")?
    else {
        anyhow::bail!("unexpected fixture map type");
    };
    Ok(data.fd().as_fd().try_clone_to_owned()?)
}

fn runtime(object: &Ebpf) -> Result<LocalityRuntimeMaps> {
    LocalityRuntimeMaps::bind(
        fd(object, "UL_INPUT_V1")?,
        fd(object, "UL_FENCE_V1")?,
        fd(object, "UL_RESUME_V1")?,
        fd(object, "UL_DISPATCH_V1")?,
    )
}

fn fixture() -> Result<Ebpf> {
    let mut object = Ebpf::load_file("/usr/local/lib/unf/locality-fixture")?;
    let program: &mut SchedClassifier = object
        .program_mut("unf_locality_fixture")
        .context("fixture program")?
        .try_into()?;
    program.load()?;
    Ok(object)
}

fn input(leased: &LeasedLocalityBank, family: u8) -> Result<PacketInput> {
    let endpoints = leased.observed().endpoints().context("endpoints")?;
    ensure!(
        endpoints.len() == 2,
        "fixture requires exactly two endpoints"
    );
    let (source, destination) = (&endpoints[0], &endpoints[1]);
    let mut source_address = [0; 16];
    let mut destination_address = [0; 16];
    if family == 4 {
        source_address[..4].copy_from_slice(&source.attachment().lease.ipv4.address.octets());
        destination_address[..4]
            .copy_from_slice(&destination.attachment().lease.ipv4.address.octets());
    } else {
        source_address = source.attachment().lease.ipv6.address.octets();
        destination_address = destination.attachment().lease.ipv6.address.octets();
    }
    let context = leased.observed().context();
    Ok(PacketInput {
        identity_epoch: context.identity_epoch,
        identity_revision: context.identity_revision.get(),
        routing_revision: context.routing_revision.get(),
        source_address,
        destination_address,
        source_identity: 17,
        destination_identity: 17,
        ingress_index: source.readback().context("links")?.0.host_index,
        schema_version: ABI_VERSION,
        family,
        protocol: 17,
        source_port: 17778_u16.to_be_bytes(),
        destination_port: 17779_u16.to_be_bytes(),
        flags: 0,
    })
}

fn packet(input: PacketInput) -> Vec<u8> {
    let offset = if input.family == 4 { 34 } else { 54 };
    let mut packet = vec![0; offset + 8];
    packet[..6].copy_from_slice(&[2, 0, 0, 0, 1, 1]);
    packet[6..12].copy_from_slice(&[2, 0, 0, 0, 1, 2]);
    if input.family == 4 {
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&28_u16.to_be_bytes());
        packet[22] = 64;
        packet[23] = input.protocol;
        packet[26..30].copy_from_slice(&input.source_address[..4]);
        packet[30..34].copy_from_slice(&input.destination_address[..4]);
        let sum: u32 = packet[14..34]
            .chunks_exact(2)
            .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
            .sum();
        let folded = (sum & 0xffff) + (sum >> 16);
        let folded = (folded & 0xffff) + (folded >> 16);
        packet[24..26].copy_from_slice(&(!u16::try_from(folded).unwrap()).to_be_bytes());
    } else {
        packet[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        packet[14] = 0x60;
        packet[18..20].copy_from_slice(&8_u16.to_be_bytes());
        packet[20] = input.protocol;
        packet[21] = 64;
        packet[22..38].copy_from_slice(&input.source_address);
        packet[38..54].copy_from_slice(&input.destination_address);
    }
    packet[offset..offset + 2].copy_from_slice(&input.source_port);
    packet[offset + 2..offset + 4].copy_from_slice(&input.destination_port);
    packet[offset + 4..offset + 6].copy_from_slice(&8_u16.to_be_bytes());
    packet
}

fn probe(
    object: &mut Ebpf,
    name: &str,
    input: PacketInput,
    wire: &[u8],
    expected: u32,
) -> Result<Vec<u8>> {
    let mut map: Array<_, Input> =
        Array::try_from(object.map_mut("UL_FIXTURE_V1").context("fixture input")?)?;
    map.set(0, Input(input), 0)?;
    let program: &SchedClassifier = object
        .program("unf_locality_fixture")
        .context("fixture classifier")?
        .try_into()?;
    let mut context = [0_u8; 44];
    context[40..44].copy_from_slice(&input.ingress_index.to_ne_bytes());
    let mut output = vec![0; wire.len()];
    let mut output_context = [0_u8; 256];
    let result = program.test_run(TestRunOptions {
        data_in: Some(wire),
        data_out: Some(&mut output),
        ctx_in: Some(&context),
        ctx_out: Some(&mut output_context),
        ..TestRunOptions::default()
    })?;
    ensure!(
        result.return_value == expected && result.data_size_out == u32::try_from(wire.len())?,
        "{name}: action={} expected={expected}",
        result.return_value
    );
    println!("kernel-locality-check: name={name} action={expected} transmitted=false");
    Ok(output)
}

#[allow(clippy::too_many_lines)] // Ordered disposable lifecycle with explicit failure cases.
pub async fn verify(
    leased: LeasedLocalityBank,
    journal: &mut AttachmentJournal,
    gate: &IncarnationGate,
    current: &EncryptionLocalityContext,
    target_route: &NativeRoutePlan,
) -> Result<()> {
    let v4 = input(&leased, 4)?;
    let v6 = input(&leased, 6)?;
    let endpoints = leased.observed().endpoints().context("endpoints")?;
    let source_key = endpoints[0].attachment().spec.key.clone();
    let target_mac = endpoints[1]
        .readback()
        .context("target links")?
        .0
        .peer_address;
    let host_mac = endpoints[1]
        .readback()
        .context("target links")?
        .0
        .host_address;
    let mut object = fixture()?;
    let mut runtime = runtime(&object)?;
    let mut delivery = if std::env::var("UNF_KERNEL_BANK_PACKET_DELIVERY").as_deref() == Ok("yes") {
        Some(Delivery::attach(&leased, &mut object)?)
    } else {
        None
    };
    let wire4 = packet(v4);
    let wire6 = packet(v6);
    probe(&mut object, "unpublished-bank", v4, &wire4, 2)?;
    pair(
        &mut delivery,
        &mut object,
        "unpublished",
        [v4, v6],
        &[17],
        false,
    )?;
    let worker = LocalityObservationWorker::default();
    let pin_root = std::env::var("UNF_KERNEL_BANK_BPFFS")?;
    ensure!(
        pin_root.starts_with("/tmp/unf-observed-bank.")
            && Path::new(&pin_root)
                .file_name()
                .is_some_and(|name| name == "bpffs"),
        "unexpected disposable bpffs root"
    );
    let bank = worker
        .try_prepare(
            leased,
            &runtime,
            std::fs::read("/usr/local/lib/unf/locality-bank")?,
            Path::new(&pin_root).into(),
        )?
        .context("worker busy")?
        .finish()
        .await?;
    ensure!(
        bank.endpoint_count() == 2 && bank.program_id()? != 0,
        "bank metadata"
    );
    let id = bank.publish(&mut runtime, journal, gate, current)?;
    ensure!(id == bank.program_id()?, "publication identity");
    probe(&mut object, "unarmed-fence", v4, &wire4, 2)?;
    pair(
        &mut delivery,
        &mut object,
        "unarmed",
        [v4, v6],
        &[17],
        false,
    )?;
    runtime.set_applied(current)?;
    pair(
        &mut delivery,
        &mut object,
        "current",
        [v4, v6],
        &[6, 17],
        true,
    )?;
    pair(
        &mut delivery,
        &mut object,
        "wrong-source-identity",
        [
            PacketInput {
                source_identity: 18,
                ..v4
            },
            PacketInput {
                source_identity: 18,
                ..v6
            },
        ],
        &[17],
        false,
    )?;
    for (name, input, wire, hop) in [
        ("ipv4-current", v4, &wire4, 22),
        ("ipv6-current", v6, &wire6, 21),
    ] {
        let output = probe(&mut object, name, input, wire, 7)?;
        ensure!(
            output[hop] == 63 && output[..6] == target_mac && output[6..12] == host_mac,
            "forwarding rewrite mismatch"
        );
    }
    for (name, changed) in [
        (
            "wrong-source-identity",
            PacketInput {
                source_identity: 18,
                ..v4
            },
        ),
        (
            "wrong-target-identity",
            PacketInput {
                destination_identity: 18,
                ..v4
            },
        ),
        (
            "stale-identity-epoch",
            PacketInput {
                identity_epoch: v4.identity_epoch + 1,
                ..v4
            },
        ),
        (
            "stale-routing",
            PacketInput {
                routing_revision: v4.routing_revision + 1,
                ..v4
            },
        ),
        (
            "wrong-port",
            PacketInput {
                destination_port: 17780_u16.to_be_bytes(),
                ..v4
            },
        ),
        (
            "unknown-schema",
            PacketInput {
                schema_version: 0,
                ..v4
            },
        ),
        (
            "missing-dsr-continuation",
            PacketInput {
                flags: PACKET_DSR_PENDING,
                ..v4
            },
        ),
    ] {
        probe(&mut object, name, changed, &wire4, 2)?;
    }
    let foreign = fixture()?;
    let mut foreign_runtime = runtime_from(&foreign)?;
    ensure!(
        bank.publish(&mut foreign_runtime, journal, gate, current)
            .is_err(),
        "foreign runtime accepted"
    );
    let mut changed = current.clone();
    changed.identity_epoch += 1;
    ensure!(
        bank.publish(&mut runtime, journal, gate, &changed).is_err(),
        "stale bank publication accepted"
    );
    runtime.withdraw()?;
    probe(&mut object, "withdrawn-dispatch", v4, &wire4, 2)?;
    pair(
        &mut delivery,
        &mut object,
        "withdrawn",
        [v4, v6],
        &[17],
        false,
    )?;
    bank.publish(&mut runtime, journal, gate, current)?;
    probe(&mut object, "publish-does-not-rearm-fence", v4, &wire4, 2)?;
    pair(
        &mut delivery,
        &mut object,
        "not-rearmed",
        [v4, v6],
        &[17],
        false,
    )?;
    runtime.set_applied(current)?;
    target_route.delete().await?;
    probe(&mut object, "target-route-absent-v4", v4, &wire4, 2)?;
    probe(&mut object, "target-route-absent-v6", v6, &wire6, 2)?;
    pair(
        &mut delivery,
        &mut object,
        "route-absent",
        [v4, v6],
        &[17],
        false,
    )?;
    target_route.apply().await?;
    // Restoring the identical route is safe while the exact device and nonce
    // remain live. Revoking the nonce below cannot be repaired by route state.
    probe(&mut object, "target-route-restored-v4", v4, &wire4, 7)?;
    probe(&mut object, "target-route-restored-v6", v6, &wire6, 7)?;
    let admission = verify_admission(
        runtime,
        &mut object,
        &bank,
        journal,
        gate,
        current,
        target_route,
        [v4, v6],
    )
    .await?;
    pair(
        &mut delivery,
        &mut object,
        "route-restored",
        [v4, v6],
        &[6, 17],
        true,
    )?;
    journal.apply(TransactionRequest::new(
        CNI_TRANSACTION_SCHEMA_VERSION,
        TransactionOperation::BeginDelete { key: source_key },
    ))?;
    probe(&mut object, "revoked-source-nonce-v4", v4, &wire4, 2)?;
    probe(&mut object, "revoked-source-nonce-v6", v6, &wire6, 2)?;
    pair(
        &mut delivery,
        &mut object,
        "nonce-revoked",
        [v4, v6],
        &[6, 17],
        false,
    )?;
    ensure!(
        admission.publish(&bank, journal, gate, current).is_err(),
        "stale original journal cut accepted"
    );
    admission.withdraw()?;
    if let Some(delivery) = &delivery {
        delivery.finish()?;
    }
    println!(
        "kernel-locality-bank: PASS endpoints=2 addresses=4 exact-runtime=true sealed=true seed-destroyed=true nonce-revoked=true packet-delivery-tested=false production-integration=false"
    );
    Ok(())
}

fn runtime_from(object: &Ebpf) -> Result<LocalityRuntimeMaps> {
    runtime(object)
}

#[allow(clippy::too_many_arguments)] // Exact live fixture authorities, never reopened pins.
async fn verify_admission(
    runtime: LocalityRuntimeMaps,
    object: &mut Ebpf,
    bank: &KernelLocalityBank,
    journal: &AttachmentJournal,
    gate: &IncarnationGate,
    context: &EncryptionLocalityContext,
    route: &NativeRoutePlan,
    inputs: [PacketInput; 2],
) -> Result<LocalityAdmission> {
    use LocalityApplyComponent::{Identity, Routing};
    let admission = LocalityAdmission::new(runtime)?;
    let [v4, v6] = inputs;
    let wire4 = packet(v4);
    let wire6 = packet(v6);
    probe(object, "coordinator-startup-withdrawn", v4, &wire4, 2)?;
    let identity = admission.begin(Identity)?;
    let routing = admission.begin(Routing)?;
    identity.complete(context.identity_epoch, context.identity_revision)?;
    ensure!(
        admission.publish(bank, journal, gate, context).is_err(),
        "pending route writer admitted"
    );
    probe(object, "coordinator-route-pending", v4, &wire4, 2)?;
    // Simulate a real route update interrupted before commit, not merely a
    // fabricated status flag. Drop leaves it failed even after route rollback.
    route.delete().await?;
    drop(routing);
    route.apply().await?;
    ensure!(
        admission.publish(bank, journal, gate, context).is_err(),
        "cancelled route writer admitted"
    );
    probe(object, "coordinator-route-cancelled", v4, &wire4, 2)?;
    let routing = admission.begin(Routing)?;
    route.readback().await?;
    routing.complete(context.identity_epoch, context.routing_revision)?;
    admission.publish(bank, journal, gate, context)?;
    probe(object, "coordinator-recovered-v4", v4, &wire4, 7)?;
    probe(object, "coordinator-recovered-v6", v6, &wire6, 7)?;
    let identity = admission.begin(Identity)?;
    let routing = admission.begin(Routing)?;
    drop(identity);
    routing.complete(context.identity_epoch, context.routing_revision)?;
    ensure!(
        admission.publish(bank, journal, gate, context).is_err(),
        "route completion masked failed identity writer"
    );
    probe(object, "coordinator-identity-cancelled", v4, &wire4, 2)?;
    admission
        .begin(Identity)?
        .complete(context.identity_epoch, context.identity_revision)?;
    admission.publish(bank, journal, gate, context)?;
    probe(object, "coordinator-settled-v4", v4, &wire4, 7)?;
    probe(object, "coordinator-settled-v6", v6, &wire6, 7)?;
    println!(
        "kernel-locality-admission: PASS decisions=8 pending-writer-denied=true cancelled-writer-denied=true rollback-not-rearmed=true production-integration=false"
    );
    Ok(admission)
}
