use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use aya::Ebpf;
use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use clap::{Parser, ValueEnum};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use serde::Serialize;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use unf_common::{IdentityId, PolicyId, RuleId, Verdict};
use unf_ebpf_common::{FlowEvent, FlowKey, IdentityMapValue, Ipv4IdentityKey};
use unf_state::{IDENTITY_SNAPSHOT_SCHEMA_VERSION, IdentityStateSnapshot, Ipv4IdentityMapping};

#[derive(Debug, Parser)]
#[command(about = "UNF per-node eBPF agent")]
struct Args {
    #[arg(long, env = "UNF_AGENT_LISTEN", default_value = "0.0.0.0:9963")]
    listen: SocketAddr,
    #[arg(long, env = "UNF_EBPF_OBJECT")]
    ebpf_object: Option<PathBuf>,
    #[arg(long, env = "UNF_INTERFACE")]
    interface: Option<String>,
    #[arg(long, env = "UNF_ALL_INTERFACES", conflicts_with = "interface")]
    all_interfaces: bool,
    #[arg(long, value_enum, default_value = "ingress")]
    direction: Direction,
    #[arg(long, env = "UNF_CONTROLLER_URL")]
    controller_url: Option<String>,
    #[arg(long, env = "UNF_IDENTITY_SYNC_SECONDS", default_value_t = 2)]
    identity_sync_seconds: u64,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Direction {
    Ingress,
    Egress,
}

struct AgentMetrics {
    flow_events: Counter,
    invalid_events: Counter,
    bpf_loaded: Gauge,
    identity_sync_errors: Counter,
    desired_identity_revision: Gauge,
    applied_identity_revision: Gauge,
    identity_map_entries: Gauge,
}

struct AgentState {
    ready: AtomicBool,
    bpf_loaded: AtomicBool,
    observed_flows: AtomicU64,
    desired_identity_revision: AtomicU64,
    applied_identity_revision: AtomicU64,
    desired_identity_epoch: AtomicU64,
    applied_identity_epoch: AtomicU64,
    identity_map_entries: AtomicU64,
    capabilities: KernelCapabilities,
    registry: Mutex<Registry>,
    metrics: AgentMetrics,
}

struct IdentitySynchronizer {
    map: AyaHashMap<MapData, [u8; 4], [u8; 16]>,
    applied: BTreeMap<[u8; 4], [u8; 16]>,
    applied_epoch: u64,
    controller_url: Option<String>,
    client: reqwest::Client,
    interval: Duration,
}

struct DataplaneConfig {
    object: PathBuf,
    interface: Option<String>,
    all_interfaces: bool,
    direction: Direction,
    controller_url: Option<String>,
    identity_sync_interval: Duration,
}

struct InterfaceAttachments<'program> {
    program: &'program mut SchedClassifier,
    all_interfaces: bool,
    attach_type: TcAttachType,
    direction: Direction,
    attached: HashSet<String>,
}

impl InterfaceAttachments<'_> {
    fn refresh(&mut self) -> Result<()> {
        refresh_interfaces(
            self.program,
            self.attach_type,
            self.direction,
            &mut self.attached,
        )
    }
}

#[derive(Debug, Clone, Serialize)]
struct KernelCapabilities {
    kernel_release: String,
    btf: bool,
    bpffs: bool,
    cgroup_v2: bool,
}

#[derive(Debug, Serialize)]
struct AgentStatus {
    component: &'static str,
    healthy: bool,
    ready: bool,
    bpf_loaded: bool,
    observed_flows: u64,
    desired_identity_revision: u64,
    applied_identity_revision: u64,
    desired_identity_epoch: u64,
    applied_identity_epoch: u64,
    identity_map_entries: u64,
    capabilities: KernelCapabilities,
    limitation: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider()?;
    init_tracing();
    let args = Args::parse();
    let state = Arc::new(new_state(detect_capabilities()));
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();

    match (&args.ebpf_object, &args.interface, args.all_interfaces) {
        (Some(object), interface, all_interfaces) if interface.is_some() || all_interfaces => {
            let state = Arc::clone(&state);
            let cancellation = cancellation.clone();
            let object = object.clone();
            let interface = interface.clone();
            let direction = args.direction;
            let controller_url = args.controller_url.clone();
            let identity_sync_interval = Duration::from_secs(args.identity_sync_seconds.max(1));
            tasks.spawn(async move {
                let config = DataplaneConfig {
                    object,
                    interface,
                    all_interfaces,
                    direction,
                    controller_url,
                    identity_sync_interval,
                };
                if let Err(error) = run_dataplane(config, &state, cancellation).await {
                    error!(?error, "eBPF dataplane stopped");
                    state.ready.store(false, Ordering::Release);
                }
            });
        }
        (None, None, false) => {
            warn!("no eBPF object/interface configured; capability-only mode");
            state.ready.store(true, Ordering::Release);
        }
        _ => bail!("--ebpf-object must be paired with either --interface or --all-interfaces"),
    }

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind agent API to {}", args.listen))?;
    info!(address = %args.listen, "agent API listening");
    let shutdown = cancellation.clone();
    tasks.spawn(async move {
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
        {
            error!(%error, "agent API server failed");
        }
    });

    tokio::signal::ctrl_c()
        .await
        .context("listen for shutdown signal")?;
    cancellation.cancel();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            error!(%error, "agent task failed");
        }
    }
    Ok(())
}

fn install_crypto_provider() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("install process-wide Rustls crypto provider"))
}

fn new_state(capabilities: KernelCapabilities) -> AgentState {
    let metrics = AgentMetrics {
        flow_events: Counter::default(),
        invalid_events: Counter::default(),
        bpf_loaded: Gauge::default(),
        identity_sync_errors: Counter::default(),
        desired_identity_revision: Gauge::default(),
        applied_identity_revision: Gauge::default(),
        identity_map_entries: Gauge::default(),
    };
    let mut registry = Registry::default();
    registry.register(
        "unf_flow",
        "Flow events consumed from the eBPF ring buffer",
        metrics.flow_events.clone(),
    );
    registry.register(
        "unf_telemetry_invalid_events",
        "Ring-buffer records rejected due to an ABI mismatch",
        metrics.invalid_events.clone(),
    );
    registry.register(
        "unf_bpf_program_loaded",
        "Whether the observation program is loaded and attached",
        metrics.bpf_loaded.clone(),
    );
    registry.register(
        "unf_identity_sync_errors",
        "Controller identity snapshots rejected or not applied",
        metrics.identity_sync_errors.clone(),
    );
    registry.register(
        "unf_identity_revision_desired",
        "Latest identity revision observed from the controller",
        metrics.desired_identity_revision.clone(),
    );
    registry.register(
        "unf_identity_revision_applied",
        "Identity revision successfully applied to the BPF map",
        metrics.applied_identity_revision.clone(),
    );
    registry.register(
        "unf_identity_map_entries",
        "IPv4 identity entries currently applied to the BPF map",
        metrics.identity_map_entries.clone(),
    );
    AgentState {
        ready: AtomicBool::new(false),
        bpf_loaded: AtomicBool::new(false),
        observed_flows: AtomicU64::new(0),
        desired_identity_revision: AtomicU64::new(0),
        applied_identity_revision: AtomicU64::new(0),
        desired_identity_epoch: AtomicU64::new(0),
        applied_identity_epoch: AtomicU64::new(0),
        identity_map_entries: AtomicU64::new(0),
        capabilities,
        registry: Mutex::new(registry),
        metrics,
    }
}

async fn run_dataplane(
    config: DataplaneConfig,
    state: &AgentState,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut ebpf = Ebpf::load_file(&config.object)
        .with_context(|| format!("load eBPF object {}", config.object.display()))?;
    let ring = RingBuf::try_from(
        ebpf.take_map("FLOW_EVENTS")
            .context("eBPF object does not contain FLOW_EVENTS ring buffer")?,
    )
    .context("open FLOW_EVENTS ring buffer")?;
    let identity_map = AyaHashMap::<_, [u8; 4], [u8; 16]>::try_from(
        ebpf.take_map("IDENTITY_V4")
            .context("eBPF object does not contain IDENTITY_V4 map")?,
    )
    .context("open IDENTITY_V4 map")?;
    let program_name = match config.direction {
        Direction::Ingress => "unf_observe_ingress",
        Direction::Egress => "unf_observe_egress",
    };
    let program: &mut SchedClassifier = ebpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF object does not contain program {program_name}"))?
        .try_into()
        .context("unf_observe is not a TC classifier")?;
    program.load().context("load TC classifier into kernel")?;
    let attach_type = match config.direction {
        Direction::Ingress => TcAttachType::Ingress,
        Direction::Egress => TcAttachType::Egress,
    };
    let mut attachments = InterfaceAttachments {
        program,
        all_interfaces: config.all_interfaces,
        attach_type,
        direction: config.direction,
        attached: HashSet::new(),
    };
    if config.all_interfaces {
        attachments.refresh()?;
        if attachments.attached.is_empty() {
            bail!("no non-loopback network interfaces are available");
        }
    } else if let Some(interface) = config.interface.as_deref() {
        attach_interface(
            attachments.program,
            interface,
            attachments.attach_type,
            attachments.direction,
        )?;
        attachments.attached.insert(interface.to_owned());
    }
    state.bpf_loaded.store(true, Ordering::Release);
    state.metrics.bpf_loaded.set(1);
    state.ready.store(true, Ordering::Release);
    let mut identities = IdentitySynchronizer {
        map: identity_map,
        applied: BTreeMap::new(),
        applied_epoch: 0,
        controller_url: config
            .controller_url
            .map(|url| url.trim_end_matches('/').to_owned()),
        client: reqwest::Client::new(),
        interval: config.identity_sync_interval,
    };
    consume_events(ring, &mut attachments, &mut identities, state, cancellation).await;
    state.ready.store(false, Ordering::Release);
    state.bpf_loaded.store(false, Ordering::Release);
    state.metrics.bpf_loaded.set(0);
    Ok(())
}

async fn consume_events(
    mut ring: RingBuf<aya::maps::MapData>,
    attachments: &mut InterfaceAttachments<'_>,
    identities: &mut IdentitySynchronizer,
    state: &AgentState,
    cancellation: CancellationToken,
) {
    let mut event_interval = tokio::time::interval(Duration::from_millis(25));
    let mut interface_interval = tokio::time::interval(Duration::from_secs(1));
    let mut identity_interval = tokio::time::interval(identities.interval);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = interface_interval.tick(), if attachments.all_interfaces => {
                if let Err(error) = attachments.refresh() {
                    warn!(?error, "could not refresh TC interface attachments");
                }
            }
            _ = identity_interval.tick(), if identities.controller_url.is_some() => {
                if let Err(error) = synchronize_identities(identities, state).await {
                    state.metrics.identity_sync_errors.inc();
                    warn!(?error, "identity synchronization failed");
                }
            }
            _ = event_interval.tick() => {
                while let Some(item) = ring.next() {
                    if item.len() != size_of::<FlowEvent>() {
                        state.metrics.invalid_events.inc();
                        continue;
                    }
                    let Some(event) = decode_event(&item) else {
                        state.metrics.invalid_events.inc();
                        continue;
                    };
                    state.metrics.flow_events.inc();
                    state.observed_flows.fetch_add(1, Ordering::Relaxed);
                    info!(
                        source_identity = event.flow.source_identity.get(),
                        destination_identity = event.flow.destination_identity.get(),
                        source = ?event.flow.source_address,
                        destination = ?event.flow.destination_address,
                        source_port = u16::from_be_bytes(event.flow.source_port),
                        destination_port = u16::from_be_bytes(event.flow.destination_port),
                        protocol = event.flow.protocol,
                        interface_index = event.interface_index,
                        "flow observed"
                    );
                }
            }
        }
    }
}

async fn synchronize_identities(
    synchronizer: &mut IdentitySynchronizer,
    state: &AgentState,
) -> Result<()> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("identity synchronization requires a controller URL")?;
    let snapshot: IdentityStateSnapshot = synchronizer
        .client
        .get(format!("{controller_url}/v1/state/identities"))
        .send()
        .await
        .context("request controller identity snapshot")?
        .error_for_status()
        .context("controller rejected identity snapshot request")?
        .json()
        .await
        .context("decode controller identity snapshot")?;
    if snapshot.schema_version != IDENTITY_SNAPSHOT_SCHEMA_VERSION {
        bail!(
            "unsupported identity snapshot schema {}; expected {}",
            snapshot.schema_version,
            IDENTITY_SNAPSHOT_SCHEMA_VERSION
        );
    }

    let desired_revision = snapshot.revision.get();
    state
        .desired_identity_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .desired_identity_revision
        .store(desired_revision, Ordering::Release);
    state
        .metrics
        .desired_identity_revision
        .set(metric_value(desired_revision));

    let applied_revision = state.applied_identity_revision.load(Ordering::Acquire);
    if snapshot.source_epoch == synchronizer.applied_epoch {
        if desired_revision == applied_revision {
            return Ok(());
        }
        if desired_revision < applied_revision {
            bail!(
                "stale identity revision {desired_revision} from epoch {}; applied revision is {applied_revision}",
                snapshot.source_epoch
            );
        }
    }

    let desired = desired_identity_entries(&snapshot.entries, desired_revision)?;
    apply_identity_entries(synchronizer, desired)?;
    synchronizer.applied_epoch = snapshot.source_epoch;
    state
        .applied_identity_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .applied_identity_revision
        .store(desired_revision, Ordering::Release);
    state
        .identity_map_entries
        .store(synchronizer.applied.len() as u64, Ordering::Release);
    state
        .metrics
        .applied_identity_revision
        .set(metric_value(desired_revision));
    state
        .metrics
        .identity_map_entries
        .set(metric_value(synchronizer.applied.len() as u64));
    info!(
        identity_epoch = snapshot.source_epoch,
        identity_revision = desired_revision,
        entries = synchronizer.applied.len(),
        "identity snapshot applied"
    );
    Ok(())
}

fn desired_identity_entries(
    mappings: &[Ipv4IdentityMapping],
    revision: u64,
) -> Result<BTreeMap<[u8; 4], [u8; 16]>> {
    let mut desired = BTreeMap::new();
    for mapping in mappings {
        if mapping.identity_id.get() == 0 {
            bail!("controller snapshot contains reserved identity ID zero");
        }
        let key = Ipv4IdentityKey::new(mapping.address.octets());
        let value = IdentityMapValue::new(mapping.identity_id, revision);
        let encoded = encode_identity_value(value);
        if let Some(existing) = desired.insert(key.address, encoded)
            && existing != encoded
        {
            bail!("controller snapshot contains a conflicting duplicate IPv4 address");
        }
    }
    Ok(desired)
}

fn encode_identity_value(value: IdentityMapValue) -> [u8; 16] {
    let mut encoded = [0_u8; 16];
    encoded[0..4].copy_from_slice(&value.identity_id.get().to_ne_bytes());
    encoded[4..6].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[6..8].copy_from_slice(&value.flags.to_ne_bytes());
    encoded[8..16].copy_from_slice(&value.revision.to_ne_bytes());
    encoded
}

fn apply_identity_entries(
    synchronizer: &mut IdentitySynchronizer,
    desired: BTreeMap<[u8; 4], [u8; 16]>,
) -> Result<()> {
    let previous = synchronizer.applied.clone();
    if let Err(error) = replace_identity_entries(&mut synchronizer.map, &previous, &desired) {
        if let Err(rollback_error) = restore_identity_entries(&mut synchronizer.map, &previous) {
            return Err(anyhow!(
                "identity map update failed: {error:#}; rollback also failed: {rollback_error:#}"
            ));
        }
        return Err(error).context("identity map update rolled back");
    }
    synchronizer.applied = desired;
    Ok(())
}

fn replace_identity_entries(
    map: &mut AyaHashMap<MapData, [u8; 4], [u8; 16]>,
    current: &BTreeMap<[u8; 4], [u8; 16]>,
    desired: &BTreeMap<[u8; 4], [u8; 16]>,
) -> Result<()> {
    for (key, value) in desired {
        map.insert(key, value, 0)
            .with_context(|| format!("insert IPv4 identity map key {key:?}"))?;
    }
    for key in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(key)
            .with_context(|| format!("remove stale IPv4 identity map key {key:?}"))?;
    }
    Ok(())
}

fn restore_identity_entries(
    map: &mut AyaHashMap<MapData, [u8; 4], [u8; 16]>,
    previous: &BTreeMap<[u8; 4], [u8; 16]>,
) -> Result<()> {
    let keys: Vec<_> = map.keys().collect::<Result<_, _>>()?;
    for key in keys {
        map.remove(&key)?;
    }
    for (key, value) in previous {
        map.insert(key, value, 0)?;
    }
    Ok(())
}

fn metric_value(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn refresh_interfaces(
    program: &mut SchedClassifier,
    attach_type: TcAttachType,
    direction: Direction,
    attached: &mut HashSet<String>,
) -> Result<()> {
    let discovered = discover_interfaces()?;
    attached.retain(|interface| discovered.contains(interface));
    let unattached: Vec<_> = discovered.difference(attached).cloned().collect();
    for interface in unattached {
        match attach_interface(program, &interface, attach_type, direction) {
            Ok(()) => {
                attached.insert(interface);
            }
            Err(error) => warn!(?error, %interface, "could not attach TC observation program"),
        }
    }
    Ok(())
}

fn discover_interfaces() -> Result<HashSet<String>> {
    let interfaces = fs::read_dir("/sys/class/net")
        .context("enumerate network interfaces")?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|interface| interface != "lo")
        .collect();
    Ok(interfaces)
}

fn attach_interface(
    program: &mut SchedClassifier,
    interface: &str,
    attach_type: TcAttachType,
    direction: Direction,
) -> Result<()> {
    if let Err(error) = tc::qdisc_add_clsact(interface) {
        // EEXIST is expected when another TC program already created clsact.
        warn!(%error, %interface, "could not create clsact qdisc; attach will still be attempted");
    }
    program
        .attach(interface, attach_type)
        .with_context(|| format!("attach TC classifier to {interface}"))?;
    info!(%interface, ?direction, "TC observation program attached");
    Ok(())
}

fn decode_event(bytes: &[u8]) -> Option<FlowEvent> {
    if bytes.len() != size_of::<FlowEvent>() {
        return None;
    }
    let verdict = match bytes[72] {
        0 => Verdict::Unknown,
        1 => Verdict::Allow,
        2 => Verdict::Deny,
        3 => Verdict::Audit,
        _ => return None,
    };
    Some(FlowEvent {
        timestamp_ns: u64::from_ne_bytes(copy_bytes(bytes, 0)?),
        flow: FlowKey {
            source_identity: IdentityId::new(u32::from_ne_bytes(copy_bytes(bytes, 8)?)),
            destination_identity: IdentityId::new(u32::from_ne_bytes(copy_bytes(bytes, 12)?)),
            source_address: copy_bytes(bytes, 16)?,
            destination_address: copy_bytes(bytes, 32)?,
            source_port: copy_bytes(bytes, 48)?,
            destination_port: copy_bytes(bytes, 50)?,
            protocol: bytes[52],
            address_family: bytes[53],
            reserved: copy_bytes(bytes, 54)?,
        },
        policy_id: PolicyId::new(u32::from_ne_bytes(copy_bytes(bytes, 56)?)),
        rule_id: RuleId::new(u32::from_ne_bytes(copy_bytes(bytes, 60)?)),
        interface_index: u32::from_ne_bytes(copy_bytes(bytes, 64)?),
        version: u16::from_ne_bytes(copy_bytes(bytes, 68)?),
        size: u16::from_ne_bytes(copy_bytes(bytes, 70)?),
        verdict,
        direction: bytes[73],
        reason: bytes[74],
        reserved: bytes[75],
    })
}

fn copy_bytes<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset + N)?.try_into().ok()
}

fn detect_capabilities() -> KernelCapabilities {
    KernelCapabilities {
        kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_or_else(|_| "unknown".to_owned(), |value| value.trim().to_owned()),
        btf: Path::new("/sys/kernel/btf/vmlinux").is_file(),
        bpffs: fs::read_to_string("/proc/mounts").is_ok_and(|mounts| {
            mounts.lines().any(|line| {
                let mut fields = line.split_whitespace();
                matches!(
                    (fields.next(), fields.next(), fields.next()),
                    (Some(_), Some("/sys/fs/bpf"), Some("bpf"))
                )
            })
        }),
        cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
    }
}

async fn health() -> &'static str {
    "ok\n"
}

async fn ready(State(state): State<Arc<AgentState>>) -> Response {
    if state.ready.load(Ordering::Acquire) {
        (StatusCode::OK, "ready\n").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
    }
}

async fn metrics(State(state): State<Arc<AgentState>>) -> Response {
    let mut body = String::new();
    match encode(&mut body, &mutex_lock(&state.registry)) {
        Ok(()) => (StatusCode::OK, body).into_response(),
        Err(error) => {
            error!(%error, "encode agent metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn status(State(state): State<Arc<AgentState>>) -> Json<AgentStatus> {
    Json(AgentStatus {
        component: "unf-agent",
        healthy: true,
        ready: state.ready.load(Ordering::Acquire),
        bpf_loaded: state.bpf_loaded.load(Ordering::Acquire),
        observed_flows: state.observed_flows.load(Ordering::Relaxed),
        desired_identity_revision: state.desired_identity_revision.load(Ordering::Acquire),
        applied_identity_revision: state.applied_identity_revision.load(Ordering::Acquire),
        desired_identity_epoch: state.desired_identity_epoch.load(Ordering::Acquire),
        applied_identity_epoch: state.applied_identity_epoch.load(Ordering::Acquire),
        identity_map_entries: state.identity_map_entries.load(Ordering::Acquire),
        capabilities: state.capabilities.clone(),
        limitation: "identity lookup is connected; policy maps and enforcement are not enabled",
    })
}

fn mutex_lock<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "unf_agent=info".into()),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_decoder_preserves_fixed_layout_bytes() {
        let bytes = [0_u8; size_of::<FlowEvent>()];
        let event = decode_event(&bytes).expect("zero event is valid");
        assert_eq!(event.timestamp_ns, 0);
        assert_eq!(event.flow.source_port, [0, 0]);
    }

    #[test]
    fn capability_detection_is_total() {
        let capabilities = detect_capabilities();
        assert!(!capabilities.kernel_release.is_empty());
    }

    #[test]
    fn identity_value_encoding_matches_shared_abi_layout() {
        let value = IdentityMapValue::new(IdentityId::new(42), 17);
        let encoded = encode_identity_value(value);
        assert_eq!(u32::from_ne_bytes(encoded[0..4].try_into().unwrap()), 42);
        assert_eq!(
            u16::from_ne_bytes(encoded[4..6].try_into().unwrap()),
            unf_ebpf_common::IDENTITY_MAP_ABI_VERSION
        );
        assert_eq!(u64::from_ne_bytes(encoded[8..16].try_into().unwrap()), 17);
    }

    #[test]
    fn identity_snapshot_compilation_is_deterministic() {
        let mappings = vec![
            Ipv4IdentityMapping {
                address: "10.244.1.4".parse().unwrap(),
                identity_id: IdentityId::new(84),
            },
            Ipv4IdentityMapping {
                address: "10.244.1.3".parse().unwrap(),
                identity_id: IdentityId::new(42),
            },
        ];
        let desired = desired_identity_entries(&mappings, 7).expect("snapshot is valid");
        assert_eq!(desired.len(), 2);
        assert_eq!(desired.keys().next(), Some(&[10, 244, 1, 3]));
    }

    #[test]
    fn identity_snapshot_rejects_reserved_identity() {
        let mappings = [Ipv4IdentityMapping {
            address: "10.244.1.3".parse().unwrap(),
            identity_id: IdentityId::new(0),
        }];
        assert!(desired_identity_entries(&mappings, 7).is_err());
    }
}
