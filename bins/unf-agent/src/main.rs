use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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
use aya::maps::lpm_trie::{Key as LpmKey, LpmTrie as AyaLpmTrie};
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::{SchedClassifier, TcAttachType, tc};
use clap::{Parser, ValueEnum};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use unf_common::{IdentityId, PolicyId, PolicyReason, Revision, RuleId, Verdict};
use unf_ebpf_common::{
    FLOW_ABI_VERSION, FlowEvent, FlowKey, IdentityMapValue, Ipv4IdentityKey, Ipv6IdentityKey,
    POLICY_BANK_COUNT, POLICY_FLAG_HAS_POLICY, POLICY_FLAG_HAS_RULE, POLICY_FLAG_HAS_SHADOW,
    POLICY_FLAG_SHADOW_HAS_POLICY, POLICY_FLAG_SHADOW_HAS_RULE, POLICY_MAP_ABI_VERSION,
};
use unf_state::{
    AGENT_STATUS_SCHEMA_VERSION, AgentStateReport, FLOW_EXPORT_BATCH_LIMIT,
    FLOW_EXPORT_SCHEMA_VERSION, FlowExportBatch, FlowExportDecision, FlowExportRecord,
    FlowHistoryKey, IDENTITY_SNAPSHOT_SCHEMA_VERSION, IdentityStateSnapshot, Ipv4IdentityMapping,
    Ipv4PolicyMapEntry, Ipv6IdentityMapping, Ipv6PolicyMapEntry, POLICY_MAP_BANK_ENTRY_LIMIT,
    POLICY_SNAPSHOT_SCHEMA_VERSION, PolicyDecisionRecord, PolicyMapEntry, PolicyStateSnapshot,
};

const FLOW_EXPORT_CHANNEL_CAPACITY: usize = 4_096;
const FLOW_EXPORT_PENDING_CAPACITY: usize = 2_048;

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
    #[arg(long, env = "UNF_NODE_NAME", default_value = "unknown")]
    node_name: String,
    #[arg(long, env = "UNF_FLOW_EXPORT_SECONDS", default_value_t = 1)]
    flow_export_seconds: u64,
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
    ipv4_identity_map_entries: Gauge,
    ipv6_identity_map_entries: Gauge,
    policy_sync_errors: Counter,
    desired_policy_revision: Gauge,
    applied_policy_revision: Gauge,
    policy_map_entries: Gauge,
    telemetry_dropped_events: Counter,
    telemetry_export_errors: Counter,
    telemetry_exported_events: Counter,
}

struct AgentState {
    node_name: String,
    ready: AtomicBool,
    bpf_loaded: AtomicBool,
    observed_flows: AtomicU64,
    desired_identity_revision: AtomicU64,
    applied_identity_revision: AtomicU64,
    desired_identity_epoch: AtomicU64,
    applied_identity_epoch: AtomicU64,
    identity_map_entries: AtomicU64,
    ipv4_identity_map_entries: AtomicU64,
    ipv6_identity_map_entries: AtomicU64,
    desired_policy_revision: AtomicU64,
    applied_policy_revision: AtomicU64,
    desired_policy_epoch: AtomicU64,
    applied_policy_epoch: AtomicU64,
    policy_map_entries: AtomicU64,
    active_policy_bank: AtomicU64,
    queued_flow_exports: AtomicU64,
    dropped_flow_exports: AtomicU64,
    exported_flow_events: AtomicU64,
    capabilities: KernelCapabilities,
    registry: Mutex<Registry>,
    metrics: AgentMetrics,
}

struct IdentitySynchronizer {
    ipv4_map: AyaHashMap<MapData, [u8; 4], [u8; 16]>,
    ipv6_map: AyaHashMap<MapData, [u8; 16], [u8; 16]>,
    ipv4_applied: BTreeMap<[u8; 4], [u8; 16]>,
    ipv6_applied: BTreeMap<[u8; 16], [u8; 16]>,
    applied_epoch: u64,
    controller_url: Option<String>,
    client: reqwest::Client,
    interval: Duration,
}

struct PolicySynchronizer {
    identity_map: AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    ipv4_map: AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    ipv6_map: AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    config: AyaArray<MapData, [u8; 24]>,
    identity_banks: [BTreeMap<[u8; 12], [u8; 32]>; POLICY_BANK_COUNT as usize],
    ipv4_banks: [BTreeMap<[u8; 12], [u8; 32]>; POLICY_BANK_COUNT as usize],
    ipv6_banks: [EncodedIpv6PolicyBank; POLICY_BANK_COUNT as usize],
    active_bank: u8,
    applied_epoch: u64,
    controller_url: Option<String>,
    client: reqwest::Client,
    interval: Duration,
}

type EncodedPolicyMap = AyaHashMap<MapData, [u8; 12], [u8; 32]>;
type EncodedIpv6PolicyKey = (u32, [u8; 24]);
type EncodedIpv6PolicyBank = BTreeMap<EncodedIpv6PolicyKey, [u8; 32]>;
type PolicyMaps = (
    EncodedPolicyMap,
    EncodedPolicyMap,
    AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    AyaArray<MapData, [u8; 24]>,
);
type IdentityMaps = (
    AyaHashMap<MapData, [u8; 4], [u8; 16]>,
    AyaHashMap<MapData, [u8; 16], [u8; 16]>,
);

struct DataplaneConfig {
    object: PathBuf,
    interface: Option<String>,
    all_interfaces: bool,
    direction: Direction,
    controller_url: Option<String>,
    identity_sync_interval: Duration,
    node_name: String,
    flow_export_interval: Duration,
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
    observed_flows: u64,
    #[serde(flatten)]
    state: AgentStateReport,
    queued_flow_exports: u64,
    dropped_flow_exports: u64,
    exported_flow_events: u64,
    capabilities: KernelCapabilities,
    limitation: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider()?;
    init_tracing();
    let args = Args::parse();
    let state = Arc::new(new_state(detect_capabilities(), args.node_name.clone()));
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
            let node_name = args.node_name.clone();
            let flow_export_interval = Duration::from_secs(args.flow_export_seconds.max(1));
            tasks.spawn(async move {
                let config = DataplaneConfig {
                    object,
                    interface,
                    all_interfaces,
                    direction,
                    controller_url,
                    identity_sync_interval,
                    node_name,
                    flow_export_interval,
                };
                if let Err(error) = run_dataplane(config, Arc::clone(&state), cancellation).await {
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

fn new_state(capabilities: KernelCapabilities, node_name: String) -> AgentState {
    let metrics = AgentMetrics {
        flow_events: Counter::default(),
        invalid_events: Counter::default(),
        bpf_loaded: Gauge::default(),
        identity_sync_errors: Counter::default(),
        desired_identity_revision: Gauge::default(),
        applied_identity_revision: Gauge::default(),
        identity_map_entries: Gauge::default(),
        ipv4_identity_map_entries: Gauge::default(),
        ipv6_identity_map_entries: Gauge::default(),
        policy_sync_errors: Counter::default(),
        desired_policy_revision: Gauge::default(),
        applied_policy_revision: Gauge::default(),
        policy_map_entries: Gauge::default(),
        telemetry_dropped_events: Counter::default(),
        telemetry_export_errors: Counter::default(),
        telemetry_exported_events: Counter::default(),
    };
    let mut registry = Registry::default();
    register_agent_metrics(&mut registry, &metrics);
    AgentState {
        node_name,
        ready: AtomicBool::new(false),
        bpf_loaded: AtomicBool::new(false),
        observed_flows: AtomicU64::new(0),
        desired_identity_revision: AtomicU64::new(0),
        applied_identity_revision: AtomicU64::new(0),
        desired_identity_epoch: AtomicU64::new(0),
        applied_identity_epoch: AtomicU64::new(0),
        identity_map_entries: AtomicU64::new(0),
        ipv4_identity_map_entries: AtomicU64::new(0),
        ipv6_identity_map_entries: AtomicU64::new(0),
        desired_policy_revision: AtomicU64::new(0),
        applied_policy_revision: AtomicU64::new(0),
        desired_policy_epoch: AtomicU64::new(0),
        applied_policy_epoch: AtomicU64::new(0),
        policy_map_entries: AtomicU64::new(0),
        active_policy_bank: AtomicU64::new(0),
        queued_flow_exports: AtomicU64::new(0),
        dropped_flow_exports: AtomicU64::new(0),
        exported_flow_events: AtomicU64::new(0),
        capabilities,
        registry: Mutex::new(registry),
        metrics,
    }
}

fn register_agent_metrics(registry: &mut Registry, metrics: &AgentMetrics) {
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
        "IPv4 and IPv6 identity entries currently applied to BPF maps",
        metrics.identity_map_entries.clone(),
    );
    registry.register(
        "unf_ipv4_identity_map_entries",
        "IPv4 identity entries currently applied to the BPF map",
        metrics.ipv4_identity_map_entries.clone(),
    );
    registry.register(
        "unf_ipv6_identity_map_entries",
        "IPv6 identity entries currently applied to the BPF map",
        metrics.ipv6_identity_map_entries.clone(),
    );
    registry.register(
        "unf_policy_sync_errors",
        "Controller policy snapshots rejected or not applied",
        metrics.policy_sync_errors.clone(),
    );
    registry.register(
        "unf_policy_revision_desired",
        "Latest effective policy revision observed from the controller",
        metrics.desired_policy_revision.clone(),
    );
    registry.register(
        "unf_policy_revision_applied",
        "Policy revision atomically activated in the BPF map set",
        metrics.applied_policy_revision.clone(),
    );
    registry.register(
        "unf_policy_map_entries",
        "Policy entries in the active BPF map bank",
        metrics.policy_map_entries.clone(),
    );
    registry.register(
        "unf_telemetry_dropped_events",
        "Flow events dropped by bounded userspace export buffering",
        metrics.telemetry_dropped_events.clone(),
    );
    registry.register(
        "unf_telemetry_export_errors",
        "Flow export batches that could not reach the controller",
        metrics.telemetry_export_errors.clone(),
    );
    registry.register(
        "unf_telemetry_exported_events",
        "Aggregated flow-event observations accepted by the controller",
        metrics.telemetry_exported_events.clone(),
    );
}

async fn run_dataplane(
    config: DataplaneConfig,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut ebpf = Ebpf::load_file(&config.object)
        .with_context(|| format!("load eBPF object {}", config.object.display()))?;
    let ring = RingBuf::try_from(
        ebpf.take_map("FLOW_EVENTS")
            .context("eBPF object does not contain FLOW_EVENTS ring buffer")?,
    )
    .context("open FLOW_EVENTS ring buffer")?;
    let (ipv4_identity_map, ipv6_identity_map) = take_identity_maps(&mut ebpf)?;
    let (policy_map, ipv4_policy_map, ipv6_policy_map, policy_config) =
        take_policy_maps(&mut ebpf)?;
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
    let controller_url = config
        .controller_url
        .as_deref()
        .map(|url| url.trim_end_matches('/').to_owned());
    let mut identities = IdentitySynchronizer {
        ipv4_map: ipv4_identity_map,
        ipv6_map: ipv6_identity_map,
        ipv4_applied: BTreeMap::new(),
        ipv6_applied: BTreeMap::new(),
        applied_epoch: 0,
        controller_url: controller_url.clone(),
        client: reqwest::Client::new(),
        interval: config.identity_sync_interval,
    };
    let mut policies = PolicySynchronizer {
        identity_map: policy_map,
        ipv4_map: ipv4_policy_map,
        ipv6_map: ipv6_policy_map,
        config: policy_config,
        identity_banks: [BTreeMap::new(), BTreeMap::new()],
        ipv4_banks: [BTreeMap::new(), BTreeMap::new()],
        ipv6_banks: [BTreeMap::new(), BTreeMap::new()],
        active_bank: 0,
        applied_epoch: 0,
        controller_url: controller_url.clone(),
        client: reqwest::Client::new(),
        interval: config.identity_sync_interval,
    };
    let (flow_export_sender, flow_export_task) =
        spawn_flow_exporter(controller_url.clone(), &config, &state, &cancellation);
    let status_report_task =
        spawn_agent_status_reporter(controller_url, &config, &state, &cancellation);
    consume_events(
        ring,
        &mut attachments,
        &mut identities,
        &mut policies,
        &state,
        flow_export_sender.as_ref(),
        cancellation,
    )
    .await;
    drop(flow_export_sender);
    await_background_task(flow_export_task, "flow exporter").await;
    await_background_task(status_report_task, "agent status reporter").await;
    state.ready.store(false, Ordering::Release);
    state.bpf_loaded.store(false, Ordering::Release);
    state.metrics.bpf_loaded.set(0);
    Ok(())
}

async fn await_background_task(task: Option<tokio::task::JoinHandle<()>>, name: &'static str) {
    if let Some(task) = task
        && let Err(error) = task.await
    {
        warn!(%error, task = name, "background task failed");
    }
}

fn take_identity_maps(ebpf: &mut Ebpf) -> Result<IdentityMaps> {
    let ipv4 = AyaHashMap::<_, [u8; 4], [u8; 16]>::try_from(
        ebpf.take_map("IDENTITY_V4")
            .context("eBPF object does not contain IDENTITY_V4 map")?,
    )
    .context("open IDENTITY_V4 map")?;
    let ipv6 = AyaHashMap::<_, [u8; 16], [u8; 16]>::try_from(
        ebpf.take_map("IDENTITY_V6")
            .context("eBPF object does not contain IDENTITY_V6 map")?,
    )
    .context("open IDENTITY_V6 map")?;
    Ok((ipv4, ipv6))
}

fn spawn_flow_exporter(
    controller_url: Option<String>,
    config: &DataplaneConfig,
    state: &Arc<AgentState>,
    cancellation: &CancellationToken,
) -> (
    Option<mpsc::Sender<FlowExportRecord>>,
    Option<tokio::task::JoinHandle<()>>,
) {
    let Some(controller_url) = controller_url else {
        return (None, None);
    };
    let (sender, receiver) = mpsc::channel(FLOW_EXPORT_CHANNEL_CAPACITY);
    let exporter_state = Arc::clone(state);
    let exporter_cancel = cancellation.clone();
    let node_name = config.node_name.clone();
    let interval = config.flow_export_interval;
    let task = tokio::spawn(async move {
        export_flow_batches(
            controller_url,
            node_name,
            receiver,
            exporter_state,
            exporter_cancel,
            interval,
        )
        .await;
    });
    (Some(sender), Some(task))
}

fn spawn_agent_status_reporter(
    controller_url: Option<String>,
    config: &DataplaneConfig,
    state: &Arc<AgentState>,
    cancellation: &CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let controller_url = controller_url?;
    let reporter_state = Arc::clone(state);
    let reporter_cancel = cancellation.clone();
    let interval = config.identity_sync_interval;
    Some(tokio::spawn(async move {
        report_agent_status(controller_url, reporter_state, reporter_cancel, interval).await;
    }))
}

fn take_policy_maps(ebpf: &mut Ebpf) -> Result<PolicyMaps> {
    let policy_map = AyaHashMap::<_, [u8; 12], [u8; 32]>::try_from(
        ebpf.take_map("POLICY_RULES")
            .context("eBPF object does not contain POLICY_RULES map")?,
    )
    .context("open POLICY_RULES map")?;
    let ipv4_policy_map = AyaHashMap::<_, [u8; 12], [u8; 32]>::try_from(
        ebpf.take_map("POLICY_IPV4")
            .context("eBPF object does not contain POLICY_IPV4 map")?,
    )
    .context("open POLICY_IPV4 map")?;
    let ipv6_policy_map = AyaLpmTrie::<_, [u8; 24], [u8; 32]>::try_from(
        ebpf.take_map("POLICY_IPV6")
            .context("eBPF object does not contain POLICY_IPV6 map")?,
    )
    .context("open POLICY_IPV6 map")?;
    let policy_config = AyaArray::<_, [u8; 24]>::try_from(
        ebpf.take_map("POLICY_CONFIG")
            .context("eBPF object does not contain POLICY_CONFIG map")?,
    )
    .context("open POLICY_CONFIG map")?;
    Ok((policy_map, ipv4_policy_map, ipv6_policy_map, policy_config))
}

async fn consume_events(
    mut ring: RingBuf<aya::maps::MapData>,
    attachments: &mut InterfaceAttachments<'_>,
    identities: &mut IdentitySynchronizer,
    policies: &mut PolicySynchronizer,
    state: &AgentState,
    flow_export_sender: Option<&mpsc::Sender<FlowExportRecord>>,
    cancellation: CancellationToken,
) {
    let mut event_interval = tokio::time::interval(Duration::from_millis(25));
    let mut interface_interval = tokio::time::interval(Duration::from_secs(1));
    let mut identity_interval = tokio::time::interval(identities.interval);
    let mut policy_interval = tokio::time::interval(policies.interval);
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
            _ = policy_interval.tick(), if policies.controller_url.is_some() => {
                if let Err(error) = synchronize_policies(policies, state).await {
                    state.metrics.policy_sync_errors.inc();
                    warn!(?error, "policy synchronization failed");
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
                    if let Some(sender) = flow_export_sender
                        && event.flow.destination_identity.get() != 0
                    {
                        enqueue_flow_export(sender, state, flow_export_record(&event));
                    }
                    info!(
                        source_identity = event.flow.source_identity.get(),
                        destination_identity = event.flow.destination_identity.get(),
                        source = ?event.flow.source_address,
                        destination = ?event.flow.destination_address,
                        source_port = u16::from_be_bytes(event.flow.source_port),
                        destination_port = u16::from_be_bytes(event.flow.destination_port),
                        protocol = event.flow.protocol,
                        address_family = event.flow.address_family,
                        policy_revision = event.policy_revision,
                        policy_id = event.policy_id.get(),
                        rule_id = event.rule_id.get(),
                        verdict = ?event.verdict,
                        reason = event.reason,
                        shadow_policy_id = event.shadow_policy_id.get(),
                        shadow_rule_id = event.shadow_rule_id.get(),
                        shadow_verdict = event.shadow_verdict,
                        shadow_reason = event.shadow_reason,
                        direction = event.direction,
                        interface_index = event.interface_index,
                        "flow observed"
                    );
                }
            }
        }
    }
}

fn enqueue_flow_export(
    sender: &mpsc::Sender<FlowExportRecord>,
    state: &AgentState,
    record: FlowExportRecord,
) {
    state.queued_flow_exports.fetch_add(1, Ordering::Relaxed);
    match sender.try_send(record) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {
            state.queued_flow_exports.fetch_sub(1, Ordering::Relaxed);
            record_telemetry_drop(state, 1);
        }
    }
}

fn record_telemetry_drop(state: &AgentState, count: u64) {
    state
        .dropped_flow_exports
        .fetch_add(count, Ordering::Relaxed);
    state.metrics.telemetry_dropped_events.inc_by(count);
}

fn flow_export_record(event: &FlowEvent) -> FlowExportRecord {
    FlowExportRecord {
        key: FlowHistoryKey {
            source_identity: event.flow.source_identity,
            destination_identity: event.flow.destination_identity,
            source_ipv4: event_ipv4(event.flow.address_family, event.flow.source_address),
            destination_ipv4: event_ipv4(event.flow.address_family, event.flow.destination_address),
            source_ipv6: event_ipv6(event.flow.address_family, event.flow.source_address),
            destination_ipv6: event_ipv6(event.flow.address_family, event.flow.destination_address),
            protocol: event.flow.protocol,
            destination_port: u16::from_be_bytes(event.flow.destination_port),
        },
        policy_revision: Revision::new(event.policy_revision),
        decision: FlowExportDecision {
            verdict: event.verdict,
            reason: event.reason,
            policy_id: nonzero_policy_id(event.policy_id),
            rule_id: rule_id_for_reason(event.rule_id, event.reason),
        },
        shadow: verdict_from_u8(event.shadow_verdict).map(|verdict| FlowExportDecision {
            verdict,
            reason: event.shadow_reason,
            policy_id: nonzero_policy_id(event.shadow_policy_id),
            rule_id: rule_id_for_reason(event.shadow_rule_id, event.shadow_reason),
        }),
        observed_events: 1,
    }
}

fn event_ipv4(address_family: u8, address: [u8; 16]) -> Option<Ipv4Addr> {
    (address_family == 4).then(|| Ipv4Addr::new(address[0], address[1], address[2], address[3]))
}

fn event_ipv6(address_family: u8, address: [u8; 16]) -> Option<Ipv6Addr> {
    (address_family == 6).then(|| Ipv6Addr::from(address))
}

fn nonzero_policy_id(id: PolicyId) -> Option<PolicyId> {
    (id.get() != 0).then_some(id)
}

fn rule_id_for_reason(id: RuleId, reason: u8) -> Option<RuleId> {
    matches!(reason, 1 | 2).then_some(id)
}

const fn verdict_from_u8(verdict: u8) -> Option<Verdict> {
    match verdict {
        1 => Some(Verdict::Allow),
        2 => Some(Verdict::Deny),
        3 => Some(Verdict::Audit),
        _ => None,
    }
}

async fn export_flow_batches(
    controller_url: String,
    node_name: String,
    mut receiver: mpsc::Receiver<FlowExportRecord>,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
    export_interval: Duration,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            state.metrics.telemetry_export_errors.inc();
            error!(%error, "could not construct flow telemetry HTTP client");
            return;
        }
    };
    let mut interval = tokio::time::interval(export_interval);
    let mut pending = BTreeMap::new();
    let mut last_reported_drops = 0_u64;
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            record = receiver.recv() => match record {
                Some(record) => {
                    state.queued_flow_exports.fetch_sub(1, Ordering::Relaxed);
                    let dropped = aggregate_pending_flow(
                        &mut pending,
                        record,
                        FLOW_EXPORT_PENDING_CAPACITY,
                    );
                    if dropped != 0 {
                        record_telemetry_drop(&state, dropped);
                    }
                }
                None => break,
            },
            _ = interval.tick() => {
                let dropped_events = state.dropped_flow_exports.load(Ordering::Relaxed);
                if pending.is_empty() && dropped_events == last_reported_drops {
                    continue;
                }
                let entries: Vec<_> = pending
                    .values()
                    .take(FLOW_EXPORT_BATCH_LIMIT)
                    .cloned()
                    .collect();
                let batch = FlowExportBatch {
                    schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                    node_name: node_name.clone(),
                    dropped_events,
                    entries: entries.clone(),
                };
                let result = client
                    .post(format!("{controller_url}/v1/telemetry/flows"))
                    .json(&batch)
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status);
                match result {
                    Ok(_) => {
                        let exported = entries
                            .iter()
                            .map(|record| record.observed_events)
                            .fold(0_u64, u64::saturating_add);
                        for entry in entries {
                            pending.remove(&entry.key);
                        }
                        state.exported_flow_events.fetch_add(exported, Ordering::Relaxed);
                        state.metrics.telemetry_exported_events.inc_by(exported);
                        last_reported_drops = dropped_events;
                    }
                    Err(error) => {
                        state.metrics.telemetry_export_errors.inc();
                        warn!(%error, pending = pending.len(), "flow telemetry export failed");
                    }
                }
            }
        }
    }
}

async fn report_agent_status(
    controller_url: String,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
    report_interval: Duration,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            error!(%error, "could not construct agent status HTTP client");
            return;
        }
    };
    let mut interval = tokio::time::interval(report_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = interval.tick() => {
                let result = client
                    .post(format!("{controller_url}/v1/state/agents"))
                    .json(&agent_state_report(&state))
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status);
                if let Err(error) = result {
                    warn!(%error, "agent status acknowledgement failed");
                }
            }
        }
    }
}

fn agent_state_report(state: &AgentState) -> AgentStateReport {
    AgentStateReport {
        schema_version: AGENT_STATUS_SCHEMA_VERSION,
        node_name: state.node_name.clone(),
        ready: state.ready.load(Ordering::Acquire),
        bpf_loaded: state.bpf_loaded.load(Ordering::Acquire),
        desired_identity_revision: state.desired_identity_revision.load(Ordering::Acquire),
        applied_identity_revision: state.applied_identity_revision.load(Ordering::Acquire),
        desired_identity_epoch: state.desired_identity_epoch.load(Ordering::Acquire),
        applied_identity_epoch: state.applied_identity_epoch.load(Ordering::Acquire),
        identity_map_entries: state.identity_map_entries.load(Ordering::Acquire),
        ipv4_identity_map_entries: state.ipv4_identity_map_entries.load(Ordering::Acquire),
        ipv6_identity_map_entries: state.ipv6_identity_map_entries.load(Ordering::Acquire),
        desired_policy_revision: state.desired_policy_revision.load(Ordering::Acquire),
        applied_policy_revision: state.applied_policy_revision.load(Ordering::Acquire),
        desired_policy_epoch: state.desired_policy_epoch.load(Ordering::Acquire),
        applied_policy_epoch: state.applied_policy_epoch.load(Ordering::Acquire),
        policy_map_entries: state.policy_map_entries.load(Ordering::Acquire),
        active_policy_bank: state.active_policy_bank.load(Ordering::Acquire),
    }
}

fn aggregate_pending_flow(
    pending: &mut BTreeMap<FlowHistoryKey, FlowExportRecord>,
    record: FlowExportRecord,
    capacity: usize,
) -> u64 {
    if let Some(existing) = pending.get_mut(&record.key) {
        existing.policy_revision = record.policy_revision;
        existing.decision = record.decision;
        existing.shadow = record.shadow;
        existing.observed_events = existing
            .observed_events
            .saturating_add(record.observed_events);
        return 0;
    }
    if pending.len() == capacity {
        return record.observed_events;
    }
    pending.insert(record.key.clone(), record);
    0
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

    let desired_ipv4 = desired_ipv4_identity_entries(&snapshot.ipv4_entries, desired_revision)?;
    let desired_ipv6 = desired_ipv6_identity_entries(&snapshot.ipv6_entries, desired_revision)?;
    apply_identity_entries(synchronizer, desired_ipv4, desired_ipv6)?;
    synchronizer.applied_epoch = snapshot.source_epoch;
    state
        .applied_identity_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .applied_identity_revision
        .store(desired_revision, Ordering::Release);
    state
        .identity_map_entries
        .store(identity_entry_count(synchronizer), Ordering::Release);
    state
        .ipv4_identity_map_entries
        .store(synchronizer.ipv4_applied.len() as u64, Ordering::Release);
    state
        .ipv6_identity_map_entries
        .store(synchronizer.ipv6_applied.len() as u64, Ordering::Release);
    state
        .metrics
        .applied_identity_revision
        .set(metric_value(desired_revision));
    state
        .metrics
        .identity_map_entries
        .set(metric_value(identity_entry_count(synchronizer)));
    state
        .metrics
        .ipv4_identity_map_entries
        .set(metric_value(synchronizer.ipv4_applied.len() as u64));
    state
        .metrics
        .ipv6_identity_map_entries
        .set(metric_value(synchronizer.ipv6_applied.len() as u64));
    info!(
        identity_epoch = snapshot.source_epoch,
        identity_revision = desired_revision,
        ipv4_entries = synchronizer.ipv4_applied.len(),
        ipv6_entries = synchronizer.ipv6_applied.len(),
        "identity snapshot applied"
    );
    Ok(())
}

fn identity_entry_count(synchronizer: &IdentitySynchronizer) -> u64 {
    (synchronizer.ipv4_applied.len() + synchronizer.ipv6_applied.len()) as u64
}

fn desired_ipv4_identity_entries(
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

fn desired_ipv6_identity_entries(
    mappings: &[Ipv6IdentityMapping],
    revision: u64,
) -> Result<BTreeMap<[u8; 16], [u8; 16]>> {
    let mut desired = BTreeMap::new();
    for mapping in mappings {
        if mapping.identity_id.get() == 0 {
            bail!("controller snapshot contains reserved identity ID zero");
        }
        let key = Ipv6IdentityKey::new(mapping.address.octets());
        let value = IdentityMapValue::new(mapping.identity_id, revision);
        let encoded = encode_identity_value(value);
        if let Some(existing) = desired.insert(key.address, encoded)
            && existing != encoded
        {
            bail!("controller snapshot contains a conflicting duplicate IPv6 address");
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
    desired_ipv4: BTreeMap<[u8; 4], [u8; 16]>,
    desired_ipv6: BTreeMap<[u8; 16], [u8; 16]>,
) -> Result<()> {
    let previous_ipv4 = synchronizer.ipv4_applied.clone();
    let previous_ipv6 = synchronizer.ipv6_applied.clone();
    let result =
        replace_ipv4_identity_entries(&mut synchronizer.ipv4_map, &previous_ipv4, &desired_ipv4)
            .and_then(|()| {
                replace_ipv6_identity_entries(
                    &mut synchronizer.ipv6_map,
                    &previous_ipv6,
                    &desired_ipv6,
                )
            });
    if let Err(error) = result {
        let ipv4_rollback =
            restore_ipv4_identity_entries(&mut synchronizer.ipv4_map, &previous_ipv4);
        let ipv6_rollback =
            restore_ipv6_identity_entries(&mut synchronizer.ipv6_map, &previous_ipv6);
        if ipv4_rollback.is_err() || ipv6_rollback.is_err() {
            return Err(anyhow!(
                "identity map update failed: {error:#}; IPv4 rollback: {ipv4_rollback:?}; IPv6 rollback: {ipv6_rollback:?}"
            ));
        }
        return Err(error).context("identity map update rolled back");
    }
    synchronizer.ipv4_applied = desired_ipv4;
    synchronizer.ipv6_applied = desired_ipv6;
    Ok(())
}

fn replace_ipv4_identity_entries(
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

fn restore_ipv4_identity_entries(
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

fn replace_ipv6_identity_entries(
    map: &mut AyaHashMap<MapData, [u8; 16], [u8; 16]>,
    current: &BTreeMap<[u8; 16], [u8; 16]>,
    desired: &BTreeMap<[u8; 16], [u8; 16]>,
) -> Result<()> {
    for (key, value) in desired {
        map.insert(key, value, 0)
            .with_context(|| format!("insert IPv6 identity map key {key:?}"))?;
    }
    for key in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(key)
            .with_context(|| format!("remove stale IPv6 identity map key {key:?}"))?;
    }
    Ok(())
}

fn restore_ipv6_identity_entries(
    map: &mut AyaHashMap<MapData, [u8; 16], [u8; 16]>,
    previous: &BTreeMap<[u8; 16], [u8; 16]>,
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

async fn synchronize_policies(
    synchronizer: &mut PolicySynchronizer,
    state: &AgentState,
) -> Result<()> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("policy synchronization requires a controller URL")?;
    let snapshot: PolicyStateSnapshot = synchronizer
        .client
        .get(format!("{controller_url}/v1/state/policies"))
        .send()
        .await
        .context("request controller policy snapshot")?
        .error_for_status()
        .context("controller rejected policy snapshot request")?
        .json()
        .await
        .context("decode controller policy snapshot")?;
    if snapshot.schema_version != POLICY_SNAPSHOT_SCHEMA_VERSION {
        bail!(
            "unsupported policy snapshot schema {}; expected {}",
            snapshot.schema_version,
            POLICY_SNAPSHOT_SCHEMA_VERSION
        );
    }

    let desired_revision = snapshot.revision.get();
    state
        .desired_policy_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .desired_policy_revision
        .store(desired_revision, Ordering::Release);
    state
        .metrics
        .desired_policy_revision
        .set(metric_value(desired_revision));

    let applied_revision = state.applied_policy_revision.load(Ordering::Acquire);
    if snapshot.source_epoch == synchronizer.applied_epoch {
        if desired_revision == applied_revision {
            return Ok(());
        }
        if desired_revision < applied_revision {
            bail!(
                "stale policy revision {desired_revision} from epoch {}; applied revision is {applied_revision}",
                snapshot.source_epoch
            );
        }
    }

    let staging_bank = (synchronizer.active_bank + 1) % POLICY_BANK_COUNT;
    let desired = desired_policy_entries(&snapshot.entries, desired_revision, staging_bank)?;
    let desired_ipv4 =
        desired_ipv4_policy_entries(&snapshot.ipv4_entries, desired_revision, staging_bank)?;
    let desired_ipv6 =
        desired_ipv6_policy_entries(&snapshot.ipv6_entries, desired_revision, staging_bank)?;
    apply_policy_entries(
        synchronizer,
        desired,
        desired_ipv4,
        desired_ipv6,
        snapshot.source_epoch,
        desired_revision,
        staging_bank,
    )?;
    synchronizer.applied_epoch = snapshot.source_epoch;
    state
        .applied_policy_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .applied_policy_revision
        .store(desired_revision, Ordering::Release);
    state
        .policy_map_entries
        .store(active_policy_entry_count(synchronizer), Ordering::Release);
    state
        .active_policy_bank
        .store(u64::from(synchronizer.active_bank), Ordering::Release);
    state
        .metrics
        .applied_policy_revision
        .set(metric_value(desired_revision));
    state
        .metrics
        .policy_map_entries
        .set(metric_value(active_policy_entry_count(synchronizer)));
    info!(
        policy_epoch = snapshot.source_epoch,
        policy_revision = desired_revision,
        entries = active_policy_entry_count(synchronizer),
        active_bank = synchronizer.active_bank,
        "policy snapshot activated"
    );
    Ok(())
}

fn active_policy_entry_count(synchronizer: &PolicySynchronizer) -> u64 {
    let active = usize::from(synchronizer.active_bank);
    (synchronizer.identity_banks[active].len()
        + synchronizer.ipv4_banks[active].len()
        + synchronizer.ipv6_banks[active].len()) as u64
}

fn desired_policy_entries(
    entries: &[PolicyMapEntry],
    revision: u64,
    bank: u8,
) -> Result<BTreeMap<[u8; 12], [u8; 32]>> {
    if bank >= POLICY_BANK_COUNT {
        bail!("invalid policy bank {bank}");
    }
    validate_policy_bank_capacity(entries.len())?;
    let mut desired = BTreeMap::new();
    for entry in entries {
        validate_policy_entry(entry)?;
        let key = encode_policy_key(entry, bank);
        let value = encode_policy_value(entry, revision);
        if desired.insert(key, value).is_some() {
            bail!("controller snapshot contains a duplicate policy key");
        }
    }
    Ok(desired)
}

fn desired_ipv4_policy_entries(
    entries: &[Ipv4PolicyMapEntry],
    revision: u64,
    bank: u8,
) -> Result<BTreeMap<[u8; 12], [u8; 32]>> {
    if bank >= POLICY_BANK_COUNT {
        bail!("invalid policy bank {bank}");
    }
    validate_policy_bank_capacity(entries.len())?;
    let mut desired = BTreeMap::new();
    for entry in entries {
        validate_ipv4_policy_entry(entry)?;
        let key = encode_ipv4_policy_key(entry, bank);
        let value = encode_policy_decisions(&entry.decision, entry.shadow.as_ref(), revision);
        if desired.insert(key, value).is_some() {
            bail!("controller snapshot contains a duplicate IPv4 policy key");
        }
    }
    Ok(desired)
}

fn desired_ipv6_policy_entries(
    entries: &[Ipv6PolicyMapEntry],
    revision: u64,
    bank: u8,
) -> Result<EncodedIpv6PolicyBank> {
    if bank >= POLICY_BANK_COUNT {
        bail!("invalid policy bank {bank}");
    }
    validate_policy_bank_capacity(entries.len())?;
    let mut desired = BTreeMap::new();
    for entry in entries {
        validate_ipv6_policy_entry(entry)?;
        let key = encode_ipv6_policy_key(entry, bank);
        let value = encode_policy_decisions(&entry.decision, entry.shadow.as_ref(), revision);
        if desired.insert(key, value).is_some() {
            bail!("controller snapshot contains a duplicate IPv6 policy key");
        }
    }
    Ok(desired)
}

fn validate_policy_bank_capacity(entry_count: usize) -> Result<()> {
    if entry_count > POLICY_MAP_BANK_ENTRY_LIMIT {
        bail!(
            "controller snapshot contains {entry_count} entries; policy bank limit is {POLICY_MAP_BANK_ENTRY_LIMIT}"
        );
    }
    Ok(())
}

fn validate_policy_entry(entry: &PolicyMapEntry) -> Result<()> {
    if entry.key.source_identity.get() == 0 || entry.key.destination_identity.get() == 0 {
        bail!("policy entry contains reserved identity ID zero");
    }
    match (entry.key.protocol, entry.key.destination_port) {
        (0, 0) | (6 | 17 | 132, 0..=u16::MAX) => {}
        _ => bail!("policy entry contains an invalid protocol/port wildcard combination"),
    }
    validate_policy_decision(&entry.decision)?;
    if let Some(shadow) = &entry.shadow {
        validate_policy_decision(shadow)?;
    }
    Ok(())
}

fn validate_ipv4_policy_entry(entry: &Ipv4PolicyMapEntry) -> Result<()> {
    if entry.key.destination_identity.get() == 0 {
        bail!("IPv4 policy entry contains reserved destination identity ID zero");
    }
    match (entry.key.protocol, entry.key.destination_port) {
        (0, 0) | (6 | 17 | 132, 0..=u16::MAX) => {}
        _ => bail!("IPv4 policy entry contains an invalid protocol/port wildcard combination"),
    }
    validate_policy_decision(&entry.decision)?;
    if let Some(shadow) = &entry.shadow {
        validate_policy_decision(shadow)?;
    }
    Ok(())
}

fn validate_ipv6_policy_entry(entry: &Ipv6PolicyMapEntry) -> Result<()> {
    if entry.key.destination_identity.get() == 0 {
        bail!("IPv6 policy entry contains reserved destination identity ID zero");
    }
    if entry.key.source_prefix_len > 128 {
        bail!("IPv6 policy entry contains an invalid source prefix length");
    }
    let prefix = entry.key.source_prefix_len;
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    if u128::from(entry.key.source_network) & mask != u128::from(entry.key.source_network) {
        bail!("IPv6 policy entry source network is not canonical");
    }
    match (entry.key.protocol, entry.key.destination_port) {
        (0, 0) | (6 | 17 | 132, 0..=u16::MAX) => {}
        _ => bail!("IPv6 policy entry contains an invalid protocol/port wildcard combination"),
    }
    validate_policy_decision(&entry.decision)?;
    if let Some(shadow) = &entry.shadow {
        validate_policy_decision(shadow)?;
    }
    Ok(())
}

fn validate_policy_decision(decision: &PolicyDecisionRecord) -> Result<()> {
    if !matches!(decision.verdict, Verdict::Allow | Verdict::Deny) {
        bail!("policy map decision must be allow or deny");
    }
    if decision.policy_id.is_some_and(|id| id.get() == 0) {
        bail!("policy entry contains reserved policy ID zero");
    }
    match decision.reason {
        PolicyReason::NoApplicablePolicy => {
            if decision.policy_id.is_some() || decision.rule_id.is_some() {
                bail!("no-applicable-policy decision cannot contain policy provenance");
            }
        }
        PolicyReason::ExplicitRule => {
            if decision.policy_id.is_none() || decision.rule_id.is_none() {
                bail!("explicit policy decision requires policy and rule provenance");
            }
        }
        PolicyReason::DefaultAction => {
            if decision.policy_id.is_none() || decision.rule_id.is_some() {
                bail!("default policy decision requires a policy and no rule");
            }
        }
    }
    Ok(())
}

fn encode_policy_key(entry: &PolicyMapEntry, bank: u8) -> [u8; 12] {
    let mut encoded = [0_u8; 12];
    encoded[0..4].copy_from_slice(&entry.key.source_identity.get().to_ne_bytes());
    encoded[4..8].copy_from_slice(&entry.key.destination_identity.get().to_ne_bytes());
    encoded[8..10].copy_from_slice(&entry.key.destination_port.to_be_bytes());
    encoded[10] = entry.key.protocol;
    encoded[11] = bank;
    encoded
}

fn encode_ipv4_policy_key(entry: &Ipv4PolicyMapEntry, bank: u8) -> [u8; 12] {
    let mut encoded = [0_u8; 12];
    encoded[0..4].copy_from_slice(&entry.key.source_address.octets());
    encoded[4..8].copy_from_slice(&entry.key.destination_identity.get().to_ne_bytes());
    encoded[8..10].copy_from_slice(&entry.key.destination_port.to_be_bytes());
    encoded[10] = entry.key.protocol;
    encoded[11] = bank;
    encoded
}

fn encode_ipv6_policy_key(entry: &Ipv6PolicyMapEntry, bank: u8) -> (u32, [u8; 24]) {
    let mut encoded = [0_u8; 24];
    encoded[0..4].copy_from_slice(&entry.key.destination_identity.get().to_ne_bytes());
    encoded[4..6].copy_from_slice(&entry.key.destination_port.to_be_bytes());
    encoded[6] = entry.key.protocol;
    encoded[7] = bank;
    encoded[8..24].copy_from_slice(&entry.key.source_network.octets());
    (64 + u32::from(entry.key.source_prefix_len), encoded)
}

fn encode_policy_value(entry: &PolicyMapEntry, revision: u64) -> [u8; 32] {
    encode_policy_decisions(&entry.decision, entry.shadow.as_ref(), revision)
}

fn encode_policy_decisions(
    decision: &PolicyDecisionRecord,
    shadow: Option<&PolicyDecisionRecord>,
    revision: u64,
) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    let mut flags = 0_u16;
    if let Some(policy_id) = decision.policy_id {
        flags |= POLICY_FLAG_HAS_POLICY;
        encoded[0..4].copy_from_slice(&policy_id.get().to_ne_bytes());
    }
    if let Some(rule_id) = decision.rule_id {
        flags |= POLICY_FLAG_HAS_RULE;
        encoded[4..8].copy_from_slice(&rule_id.get().to_ne_bytes());
    }
    if let Some(shadow) = shadow {
        flags |= POLICY_FLAG_HAS_SHADOW;
        if let Some(policy_id) = shadow.policy_id {
            flags |= POLICY_FLAG_SHADOW_HAS_POLICY;
            encoded[8..12].copy_from_slice(&policy_id.get().to_ne_bytes());
        }
        if let Some(rule_id) = shadow.rule_id {
            flags |= POLICY_FLAG_SHADOW_HAS_RULE;
            encoded[12..16].copy_from_slice(&rule_id.get().to_ne_bytes());
        }
        encoded[30] = shadow.verdict as u8;
        encoded[31] = shadow.reason as u8;
    }
    encoded[16..24].copy_from_slice(&revision.to_ne_bytes());
    encoded[24..26].copy_from_slice(&POLICY_MAP_ABI_VERSION.to_ne_bytes());
    encoded[26..28].copy_from_slice(&flags.to_ne_bytes());
    encoded[28] = decision.verdict as u8;
    encoded[29] = decision.reason as u8;
    encoded
}

fn encode_policy_config(
    source_epoch: u64,
    revision: u64,
    entry_count: usize,
    active_bank: u8,
) -> Result<[u8; 24]> {
    let entry_count = u32::try_from(entry_count).context("policy entry count exceeds u32")?;
    let mut encoded = [0_u8; 24];
    encoded[0..8].copy_from_slice(&source_epoch.to_ne_bytes());
    encoded[8..16].copy_from_slice(&revision.to_ne_bytes());
    encoded[16..20].copy_from_slice(&entry_count.to_ne_bytes());
    encoded[20..22].copy_from_slice(&POLICY_MAP_ABI_VERSION.to_ne_bytes());
    encoded[22] = active_bank;
    Ok(encoded)
}

#[allow(clippy::too_many_lines)]
fn apply_policy_entries(
    synchronizer: &mut PolicySynchronizer,
    desired: BTreeMap<[u8; 12], [u8; 32]>,
    desired_ipv4: BTreeMap<[u8; 12], [u8; 32]>,
    desired_ipv6: EncodedIpv6PolicyBank,
    source_epoch: u64,
    revision: u64,
    staging_bank: u8,
) -> Result<()> {
    let staging_index = usize::from(staging_bank);
    let previous_identity = synchronizer.identity_banks[staging_index].clone();
    let previous_ipv4 = synchronizer.ipv4_banks[staging_index].clone();
    let previous_ipv6 = synchronizer.ipv6_banks[staging_index].clone();
    if let Err(error) =
        replace_policy_entries(&mut synchronizer.identity_map, &previous_identity, &desired)
    {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &error.context("stage identity policy map bank"),
        ));
    }
    if let Err(error) =
        replace_policy_entries(&mut synchronizer.ipv4_map, &previous_ipv4, &desired_ipv4)
    {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &error.context("stage IPv4 policy map bank"),
        ));
    }
    if let Err(error) =
        replace_ipv6_policy_entries(&mut synchronizer.ipv6_map, &previous_ipv6, &desired_ipv6)
    {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &error.context("stage IPv6 policy map bank"),
        ));
    }
    let validation = validate_staged_policy_entries(&synchronizer.identity_map, &desired)
        .and_then(|()| validate_staged_policy_entries(&synchronizer.ipv4_map, &desired_ipv4))
        .and_then(|()| validate_staged_ipv6_policy_entries(&synchronizer.ipv6_map, &desired_ipv6));
    if let Err(error) = validation {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &error,
        ));
    }
    let entry_count = desired.len() + desired_ipv4.len() + desired_ipv6.len();
    let config = match encode_policy_config(source_epoch, revision, entry_count, staging_bank) {
        Ok(config) => config,
        Err(error) => {
            return Err(rollback_policy_stages(
                synchronizer,
                &previous_identity,
                &previous_ipv4,
                &previous_ipv6,
                staging_bank,
                &error,
            ));
        }
    };
    if let Err(error) = synchronizer.config.set(0, config, 0) {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &anyhow!(error).context("atomically activate staged policy bank"),
        ));
    }

    let previous_active = synchronizer.active_bank;
    synchronizer.identity_banks[staging_index] = desired;
    synchronizer.ipv4_banks[staging_index] = desired_ipv4;
    synchronizer.ipv6_banks[staging_index] = desired_ipv6;
    synchronizer.active_bank = staging_bank;
    let previous_index = usize::from(previous_active);
    if previous_active != staging_bank {
        if let Err(error) = clear_policy_bank(
            &mut synchronizer.identity_map,
            &synchronizer.identity_banks[previous_index],
        ) {
            warn!(
                ?error,
                bank = previous_active,
                "could not garbage-collect old identity policy bank"
            );
        } else {
            synchronizer.identity_banks[previous_index].clear();
        }
        if let Err(error) = clear_policy_bank(
            &mut synchronizer.ipv4_map,
            &synchronizer.ipv4_banks[previous_index],
        ) {
            warn!(
                ?error,
                bank = previous_active,
                "could not garbage-collect old IPv4 policy bank"
            );
        } else {
            synchronizer.ipv4_banks[previous_index].clear();
        }
        if let Err(error) = clear_ipv6_policy_bank(
            &mut synchronizer.ipv6_map,
            &synchronizer.ipv6_banks[previous_index],
        ) {
            warn!(
                ?error,
                bank = previous_active,
                "could not garbage-collect old IPv6 policy bank"
            );
        } else {
            synchronizer.ipv6_banks[previous_index].clear();
        }
    }
    Ok(())
}

fn validate_staged_policy_entries(
    map: &AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    desired: &BTreeMap<[u8; 12], [u8; 32]>,
) -> Result<()> {
    for (key, expected) in desired {
        let actual = map
            .get(key, 0)
            .with_context(|| format!("read staged policy map key {key:?}"))?;
        if &actual != expected {
            bail!("staged policy map validation mismatch for key {key:?}");
        }
    }
    Ok(())
}

fn validate_staged_ipv6_policy_entries(
    map: &AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    desired: &EncodedIpv6PolicyBank,
) -> Result<()> {
    for ((prefix_len, data), expected) in desired {
        let key = LpmKey::new(*prefix_len, *data);
        let actual = map
            .get(&key, 0)
            .with_context(|| format!("read staged IPv6 policy map prefix {prefix_len}"))?;
        if &actual != expected {
            bail!("staged IPv6 policy map validation mismatch");
        }
    }
    Ok(())
}

fn rollback_policy_stages(
    synchronizer: &mut PolicySynchronizer,
    previous_identity: &BTreeMap<[u8; 12], [u8; 32]>,
    previous_ipv4: &BTreeMap<[u8; 12], [u8; 32]>,
    previous_ipv6: &EncodedIpv6PolicyBank,
    bank: u8,
    cause: &anyhow::Error,
) -> anyhow::Error {
    let identity_rollback =
        restore_policy_entries(&mut synchronizer.identity_map, previous_identity, bank);
    let ipv4_rollback = restore_policy_entries(&mut synchronizer.ipv4_map, previous_ipv4, bank);
    let ipv6_rollback =
        restore_ipv6_policy_entries(&mut synchronizer.ipv6_map, previous_ipv6, bank);
    match (identity_rollback, ipv4_rollback, ipv6_rollback) {
        (Ok(()), Ok(()), Ok(())) => {
            anyhow!("policy update failed and staging banks were rolled back: {cause:#}")
        }
        (identity, ipv4, ipv6) => anyhow!(
            "policy update failed: {cause:#}; identity rollback: {identity:?}; IPv4 rollback: {ipv4:?}; IPv6 rollback: {ipv6:?}"
        ),
    }
}

fn replace_policy_entries(
    map: &mut AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    current: &BTreeMap<[u8; 12], [u8; 32]>,
    desired: &BTreeMap<[u8; 12], [u8; 32]>,
) -> Result<()> {
    for key in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(key)
            .with_context(|| format!("remove stale policy map key {key:?}"))?;
    }
    for (key, value) in desired {
        map.insert(key, value, 0)
            .with_context(|| format!("insert policy map key {key:?}"))?;
    }
    Ok(())
}

fn replace_ipv6_policy_entries(
    map: &mut AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    current: &EncodedIpv6PolicyBank,
    desired: &EncodedIpv6PolicyBank,
) -> Result<()> {
    for (prefix_len, data) in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(&LpmKey::new(*prefix_len, *data))?;
    }
    for ((prefix_len, data), value) in desired {
        map.insert(&LpmKey::new(*prefix_len, *data), value, 0)?;
    }
    Ok(())
}

fn restore_policy_entries(
    map: &mut AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    previous: &BTreeMap<[u8; 12], [u8; 32]>,
    bank: u8,
) -> Result<()> {
    let bank_keys: Vec<_> = map
        .keys()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|key| key[11] == bank)
        .collect();
    for key in bank_keys {
        map.remove(&key)?;
    }
    for (key, value) in previous {
        map.insert(key, value, 0)?;
    }
    Ok(())
}

fn restore_ipv6_policy_entries(
    map: &mut AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    previous: &EncodedIpv6PolicyBank,
    bank: u8,
) -> Result<()> {
    let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
    for key in keys.into_iter().filter(|key| key.data()[7] == bank) {
        map.remove(&key)?;
    }
    for ((prefix_len, data), value) in previous {
        map.insert(&LpmKey::new(*prefix_len, *data), value, 0)?;
    }
    Ok(())
}

fn clear_policy_bank(
    map: &mut AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    entries: &BTreeMap<[u8; 12], [u8; 32]>,
) -> Result<()> {
    for key in entries.keys() {
        map.remove(key)?;
    }
    Ok(())
}

fn clear_ipv6_policy_bank(
    map: &mut AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    entries: &EncodedIpv6PolicyBank,
) -> Result<()> {
    for (prefix_len, data) in entries.keys() {
        map.remove(&LpmKey::new(*prefix_len, *data))?;
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
    let version = u16::from_ne_bytes(copy_bytes(bytes, 84)?);
    let size = u16::from_ne_bytes(copy_bytes(bytes, 86)?);
    if version != FLOW_ABI_VERSION || usize::from(size) != size_of::<FlowEvent>() {
        return None;
    }
    let verdict = match bytes[88] {
        0 => Verdict::Unknown,
        1 => Verdict::Allow,
        2 => Verdict::Deny,
        3 => Verdict::Audit,
        _ => return None,
    };
    if bytes[91] > Verdict::Audit as u8 {
        return None;
    }
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
        policy_revision: u64::from_ne_bytes(copy_bytes(bytes, 56)?),
        policy_id: PolicyId::new(u32::from_ne_bytes(copy_bytes(bytes, 64)?)),
        rule_id: RuleId::new(u32::from_ne_bytes(copy_bytes(bytes, 68)?)),
        shadow_policy_id: PolicyId::new(u32::from_ne_bytes(copy_bytes(bytes, 72)?)),
        shadow_rule_id: RuleId::new(u32::from_ne_bytes(copy_bytes(bytes, 76)?)),
        interface_index: u32::from_ne_bytes(copy_bytes(bytes, 80)?),
        version,
        size,
        verdict,
        direction: bytes[89],
        reason: bytes[90],
        shadow_verdict: bytes[91],
        shadow_reason: bytes[92],
        reserved: copy_bytes(bytes, 93)?,
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
        observed_flows: state.observed_flows.load(Ordering::Relaxed),
        state: agent_state_report(&state),
        queued_flow_exports: state.queued_flow_exports.load(Ordering::Relaxed),
        dropped_flow_exports: state.dropped_flow_exports.load(Ordering::Relaxed),
        exported_flow_events: state.exported_flow_events.load(Ordering::Relaxed),
        capabilities: state.capabilities.clone(),
        limitation: "TC policy enforcement is active; maps are unpinned and acknowledgements use unauthenticated prototype transport",
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
        let mut bytes = [0_u8; size_of::<FlowEvent>()];
        bytes[84..86].copy_from_slice(&FLOW_ABI_VERSION.to_ne_bytes());
        let event_size = u16::try_from(size_of::<FlowEvent>()).expect("event ABI fits in u16");
        bytes[86..88].copy_from_slice(&event_size.to_ne_bytes());
        let event = decode_event(&bytes).expect("versioned event is valid");
        assert_eq!(event.timestamp_ns, 0);
        assert_eq!(event.flow.source_port, [0, 0]);
    }

    #[test]
    fn event_decoder_rejects_an_unknown_abi() {
        let bytes = [0_u8; size_of::<FlowEvent>()];
        assert!(decode_event(&bytes).is_none());
    }

    #[test]
    fn capability_detection_is_total() {
        let capabilities = detect_capabilities();
        assert!(!capabilities.kernel_release.is_empty());
    }

    fn test_agent_state() -> AgentState {
        new_state(
            KernelCapabilities {
                kernel_release: "test".to_owned(),
                btf: true,
                bpffs: true,
                cgroup_v2: true,
            },
            "worker-a".to_owned(),
        )
    }

    #[test]
    fn agent_state_report_preserves_node_and_revision_acknowledgements() {
        let state = test_agent_state();
        state.ready.store(true, Ordering::Release);
        state.bpf_loaded.store(true, Ordering::Release);
        state.desired_identity_epoch.store(7, Ordering::Release);
        state.applied_identity_epoch.store(7, Ordering::Release);
        state.desired_identity_revision.store(11, Ordering::Release);
        state.applied_identity_revision.store(11, Ordering::Release);
        state.desired_policy_epoch.store(7, Ordering::Release);
        state.applied_policy_epoch.store(7, Ordering::Release);
        state.desired_policy_revision.store(13, Ordering::Release);
        state.applied_policy_revision.store(13, Ordering::Release);

        let report = agent_state_report(&state);
        assert_eq!(report.schema_version, AGENT_STATUS_SCHEMA_VERSION);
        assert_eq!(report.node_name, "worker-a");
        assert!(report.ready);
        assert!(report.bpf_loaded);
        assert_eq!(report.applied_identity_epoch, 7);
        assert_eq!(report.applied_identity_revision, 11);
        assert_eq!(report.applied_policy_epoch, 7);
        assert_eq!(report.applied_policy_revision, 13);
    }

    fn test_flow_record(port: u16) -> FlowExportRecord {
        FlowExportRecord {
            key: FlowHistoryKey {
                source_identity: IdentityId::new(1),
                destination_identity: IdentityId::new(2),
                source_ipv4: Some(Ipv4Addr::new(10, 42, 0, 1)),
                destination_ipv4: Some(Ipv4Addr::new(10, 42, 1, 2)),
                source_ipv6: None,
                destination_ipv6: None,
                protocol: 6,
                destination_port: port,
            },
            policy_revision: Revision::new(7),
            decision: FlowExportDecision {
                verdict: Verdict::Allow,
                reason: 1,
                policy_id: Some(PolicyId::new(9)),
                rule_id: Some(RuleId::new(0)),
            },
            shadow: None,
            observed_events: 1,
        }
    }

    #[test]
    fn bounded_export_queue_drops_telemetry_without_blocking() {
        let state = test_agent_state();
        let (sender, _receiver) = mpsc::channel(1);
        enqueue_flow_export(&sender, &state, test_flow_record(8080));
        enqueue_flow_export(&sender, &state, test_flow_record(8081));
        assert_eq!(state.queued_flow_exports.load(Ordering::Relaxed), 1);
        assert_eq!(state.dropped_flow_exports.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pending_flow_aggregation_is_bounded_and_saturating() {
        let mut pending = BTreeMap::new();
        let mut first = test_flow_record(8080);
        first.observed_events = u64::MAX;
        assert_eq!(aggregate_pending_flow(&mut pending, first, 1), 0);
        assert_eq!(
            aggregate_pending_flow(&mut pending, test_flow_record(8080), 1),
            0
        );
        assert_eq!(
            pending[&test_flow_record(8080).key].observed_events,
            u64::MAX
        );
        assert_eq!(
            aggregate_pending_flow(&mut pending, test_flow_record(8081), 1),
            1
        );
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn flow_export_conversion_preserves_identity_and_provenance() {
        let mut event = FlowEvent {
            timestamp_ns: 17,
            flow: FlowKey {
                source_identity: IdentityId::new(1),
                destination_identity: IdentityId::new(2),
                source_address: [10, 42, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                destination_address: [10, 42, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                source_port: 32_000_u16.to_be_bytes(),
                destination_port: 8080_u16.to_be_bytes(),
                protocol: 6,
                address_family: 4,
                reserved: [0; 2],
            },
            policy_revision: 7,
            policy_id: PolicyId::new(9),
            rule_id: RuleId::new(0),
            shadow_policy_id: PolicyId::new(10),
            shadow_rule_id: RuleId::new(0),
            interface_index: 3,
            version: FLOW_ABI_VERSION,
            size: u16::try_from(size_of::<FlowEvent>()).expect("event size fits"),
            verdict: Verdict::Allow,
            direction: 1,
            reason: 1,
            shadow_verdict: 2,
            shadow_reason: 2,
            reserved: [0; 3],
        };
        let record = flow_export_record(&event);
        assert_eq!(record.key.source_ipv4, Some(Ipv4Addr::new(10, 42, 0, 1)));
        assert_eq!(record.key.destination_port, 8080);
        assert_eq!(record.decision.rule_id, Some(RuleId::new(0)));
        assert_eq!(
            record.shadow.expect("shadow decision exists").verdict,
            Verdict::Deny
        );

        let source_ipv6: Ipv6Addr = "fd00:10:42::1".parse().unwrap();
        let destination_ipv6: Ipv6Addr = "fd00:10:42:1::2".parse().unwrap();
        event.flow.source_address = source_ipv6.octets();
        event.flow.destination_address = destination_ipv6.octets();
        event.flow.address_family = 6;
        let ipv6_record = flow_export_record(&event);
        assert_eq!(ipv6_record.key.source_ipv4, None);
        assert_eq!(ipv6_record.key.source_ipv6, Some(source_ipv6));
        assert_eq!(ipv6_record.key.destination_ipv6, Some(destination_ipv6));
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
        let desired = desired_ipv4_identity_entries(&mappings, 7).expect("snapshot is valid");
        assert_eq!(desired.len(), 2);
        assert_eq!(desired.keys().next(), Some(&[10, 244, 1, 3]));

        let ipv6_mappings = vec![
            Ipv6IdentityMapping {
                address: "fd00:10:244:1::4".parse().unwrap(),
                identity_id: IdentityId::new(84),
            },
            Ipv6IdentityMapping {
                address: "fd00:10:244:1::3".parse().unwrap(),
                identity_id: IdentityId::new(42),
            },
        ];
        let desired_ipv6 =
            desired_ipv6_identity_entries(&ipv6_mappings, 7).expect("snapshot is valid");
        assert_eq!(desired_ipv6.len(), 2);
        assert_eq!(
            desired_ipv6.keys().next().copied(),
            Some("fd00:10:244:1::3".parse::<Ipv6Addr>().unwrap().octets())
        );
    }

    #[test]
    fn identity_snapshot_rejects_reserved_identity() {
        let mappings = [Ipv4IdentityMapping {
            address: "10.244.1.3".parse().unwrap(),
            identity_id: IdentityId::new(0),
        }];
        assert!(desired_ipv4_identity_entries(&mappings, 7).is_err());
        let ipv6_mappings = [Ipv6IdentityMapping {
            address: "fd00:10:244:1::3".parse().unwrap(),
            identity_id: IdentityId::new(0),
        }];
        assert!(desired_ipv6_identity_entries(&ipv6_mappings, 7).is_err());
    }

    fn policy_entry() -> PolicyMapEntry {
        PolicyMapEntry {
            key: unf_state::PolicyMapKey {
                source_identity: IdentityId::new(11),
                destination_identity: IdentityId::new(22),
                protocol: 6,
                destination_port: 8080,
            },
            decision: PolicyDecisionRecord {
                verdict: Verdict::Allow,
                reason: PolicyReason::ExplicitRule,
                policy_id: Some(PolicyId::new(7)),
                rule_id: Some(RuleId::new(0)),
            },
            shadow: Some(PolicyDecisionRecord {
                verdict: Verdict::Deny,
                reason: PolicyReason::DefaultAction,
                policy_id: Some(PolicyId::new(8)),
                rule_id: None,
            }),
        }
    }

    #[test]
    fn policy_snapshot_encoding_matches_shared_abi_layout() {
        let desired = desired_policy_entries(&[policy_entry()], 17, 1).expect("policy is valid");
        let (key, value) = desired.first_key_value().expect("one encoded entry");
        assert_eq!(u32::from_ne_bytes(key[0..4].try_into().unwrap()), 11);
        assert_eq!(u32::from_ne_bytes(key[4..8].try_into().unwrap()), 22);
        assert_eq!(u16::from_be_bytes(key[8..10].try_into().unwrap()), 8080);
        assert_eq!(key[10], 6);
        assert_eq!(key[11], 1);
        assert_eq!(u32::from_ne_bytes(value[0..4].try_into().unwrap()), 7);
        assert_eq!(u32::from_ne_bytes(value[8..12].try_into().unwrap()), 8);
        assert_eq!(u64::from_ne_bytes(value[16..24].try_into().unwrap()), 17);
        assert_eq!(
            u16::from_ne_bytes(value[24..26].try_into().unwrap()),
            POLICY_MAP_ABI_VERSION
        );
        let flags = u16::from_ne_bytes(value[26..28].try_into().unwrap());
        assert_eq!(
            flags,
            POLICY_FLAG_HAS_POLICY
                | POLICY_FLAG_HAS_RULE
                | POLICY_FLAG_HAS_SHADOW
                | POLICY_FLAG_SHADOW_HAS_POLICY
        );
    }

    #[test]
    fn ipv4_policy_snapshot_encoding_matches_shared_abi_layout() {
        let policy = policy_entry();
        let entry = Ipv4PolicyMapEntry {
            key: unf_state::Ipv4PolicyMapKey {
                source_address: "10.244.1.3".parse().unwrap(),
                destination_identity: policy.key.destination_identity,
                protocol: policy.key.protocol,
                destination_port: policy.key.destination_port,
            },
            decision: policy.decision,
            shadow: policy.shadow,
        };
        let desired = desired_ipv4_policy_entries(&[entry], 17, 1).expect("IPv4 policy is valid");
        let (key, value) = desired.first_key_value().expect("one encoded entry");
        assert_eq!(&key[0..4], &[10, 244, 1, 3]);
        assert_eq!(u32::from_ne_bytes(key[4..8].try_into().unwrap()), 22);
        assert_eq!(u16::from_be_bytes(key[8..10].try_into().unwrap()), 8080);
        assert_eq!(key[10], 6);
        assert_eq!(key[11], 1);
        assert_eq!(u32::from_ne_bytes(value[0..4].try_into().unwrap()), 7);
        assert_eq!(u64::from_ne_bytes(value[16..24].try_into().unwrap()), 17);
    }

    #[test]
    fn ipv6_policy_snapshot_encoding_matches_lpm_abi_layout() {
        let policy = policy_entry();
        let source_network: Ipv6Addr = "2001:db8:1::".parse().unwrap();
        let entry = Ipv6PolicyMapEntry {
            key: unf_state::Ipv6PolicyMapKey {
                source_network,
                source_prefix_len: 64,
                destination_identity: policy.key.destination_identity,
                protocol: policy.key.protocol,
                destination_port: policy.key.destination_port,
            },
            decision: policy.decision,
            shadow: policy.shadow,
        };
        let desired = desired_ipv6_policy_entries(&[entry], 17, 1).expect("IPv6 policy is valid");
        let ((prefix_len, key), value) = desired.first_key_value().expect("one encoded entry");
        assert_eq!(*prefix_len, 128);
        assert_eq!(u32::from_ne_bytes(key[0..4].try_into().unwrap()), 22);
        assert_eq!(u16::from_be_bytes(key[4..6].try_into().unwrap()), 8080);
        assert_eq!(key[6], 6);
        assert_eq!(key[7], 1);
        assert_eq!(&key[8..24], &source_network.octets());
        assert_eq!(u32::from_ne_bytes(value[0..4].try_into().unwrap()), 7);
        assert_eq!(u64::from_ne_bytes(value[16..24].try_into().unwrap()), 17);
    }

    #[test]
    fn policy_snapshot_rejects_invalid_wildcard() {
        let mut entry = policy_entry();
        entry.key.protocol = 0;
        assert!(desired_policy_entries(&[entry], 17, 1).is_err());
    }

    #[test]
    fn policy_snapshot_accepts_protocol_specific_wildcard() {
        let mut identity_entry = policy_entry();
        identity_entry.key.destination_port = 0;
        assert!(desired_policy_entries(&[identity_entry], 17, 1).is_ok());

        let mut ipv4_entry = Ipv4PolicyMapEntry {
            key: unf_state::Ipv4PolicyMapKey {
                source_address: "10.244.1.3".parse().unwrap(),
                destination_identity: identity_entry.key.destination_identity,
                protocol: identity_entry.key.protocol,
                destination_port: 0,
            },
            decision: identity_entry.decision,
            shadow: identity_entry.shadow,
        };
        assert!(desired_ipv4_policy_entries(&[ipv4_entry], 17, 1).is_ok());
        identity_entry.key.protocol = unf_common::Protocol::Sctp as u8;
        assert!(desired_policy_entries(&[identity_entry], 17, 1).is_ok());
        ipv4_entry.key.protocol = 0;
        ipv4_entry.key.destination_port = 8080;
        assert!(desired_ipv4_policy_entries(&[ipv4_entry], 17, 1).is_err());
    }

    #[test]
    fn policy_snapshot_rejects_entries_beyond_one_bank() {
        assert!(validate_policy_bank_capacity(POLICY_MAP_BANK_ENTRY_LIMIT).is_ok());
        assert!(validate_policy_bank_capacity(POLICY_MAP_BANK_ENTRY_LIMIT + 1).is_err());
    }

    #[test]
    fn policy_config_encoding_contains_atomic_revision_pointer() {
        let config = encode_policy_config(9, 17, 3, 1).expect("config is valid");
        assert_eq!(u64::from_ne_bytes(config[0..8].try_into().unwrap()), 9);
        assert_eq!(u64::from_ne_bytes(config[8..16].try_into().unwrap()), 17);
        assert_eq!(u32::from_ne_bytes(config[16..20].try_into().unwrap()), 3);
        assert_eq!(config[22], 1);
    }
}
