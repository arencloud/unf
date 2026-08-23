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
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, RingBuf};
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
use unf_common::{IdentityId, PolicyId, PolicyReason, RuleId, Verdict};
use unf_ebpf_common::{
    FLOW_ABI_VERSION, FlowEvent, FlowKey, IdentityMapValue, Ipv4IdentityKey, POLICY_BANK_COUNT,
    POLICY_FLAG_HAS_POLICY, POLICY_FLAG_HAS_RULE, POLICY_FLAG_HAS_SHADOW,
    POLICY_FLAG_SHADOW_HAS_POLICY, POLICY_FLAG_SHADOW_HAS_RULE, POLICY_MAP_ABI_VERSION,
};
use unf_state::{
    IDENTITY_SNAPSHOT_SCHEMA_VERSION, IdentityStateSnapshot, Ipv4IdentityMapping,
    POLICY_SNAPSHOT_SCHEMA_VERSION, PolicyDecisionRecord, PolicyMapEntry, PolicyStateSnapshot,
};

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
    policy_sync_errors: Counter,
    desired_policy_revision: Gauge,
    applied_policy_revision: Gauge,
    policy_map_entries: Gauge,
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
    desired_policy_revision: AtomicU64,
    applied_policy_revision: AtomicU64,
    desired_policy_epoch: AtomicU64,
    applied_policy_epoch: AtomicU64,
    policy_map_entries: AtomicU64,
    active_policy_bank: AtomicU64,
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

struct PolicySynchronizer {
    map: AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    config: AyaArray<MapData, [u8; 24]>,
    banks: [BTreeMap<[u8; 12], [u8; 32]>; POLICY_BANK_COUNT as usize],
    active_bank: u8,
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
    desired_policy_revision: u64,
    applied_policy_revision: u64,
    desired_policy_epoch: u64,
    applied_policy_epoch: u64,
    policy_map_entries: u64,
    active_policy_bank: u64,
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
        policy_sync_errors: Counter::default(),
        desired_policy_revision: Gauge::default(),
        applied_policy_revision: Gauge::default(),
        policy_map_entries: Gauge::default(),
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
    AgentState {
        ready: AtomicBool::new(false),
        bpf_loaded: AtomicBool::new(false),
        observed_flows: AtomicU64::new(0),
        desired_identity_revision: AtomicU64::new(0),
        applied_identity_revision: AtomicU64::new(0),
        desired_identity_epoch: AtomicU64::new(0),
        applied_identity_epoch: AtomicU64::new(0),
        identity_map_entries: AtomicU64::new(0),
        desired_policy_revision: AtomicU64::new(0),
        applied_policy_revision: AtomicU64::new(0),
        desired_policy_epoch: AtomicU64::new(0),
        applied_policy_epoch: AtomicU64::new(0),
        policy_map_entries: AtomicU64::new(0),
        active_policy_bank: AtomicU64::new(0),
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
    let policy_map = AyaHashMap::<_, [u8; 12], [u8; 32]>::try_from(
        ebpf.take_map("POLICY_RULES")
            .context("eBPF object does not contain POLICY_RULES map")?,
    )
    .context("open POLICY_RULES map")?;
    let policy_config = AyaArray::<_, [u8; 24]>::try_from(
        ebpf.take_map("POLICY_CONFIG")
            .context("eBPF object does not contain POLICY_CONFIG map")?,
    )
    .context("open POLICY_CONFIG map")?;
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
            .clone()
            .map(|url| url.trim_end_matches('/').to_owned()),
        client: reqwest::Client::new(),
        interval: config.identity_sync_interval,
    };
    let mut policies = PolicySynchronizer {
        map: policy_map,
        config: policy_config,
        banks: [BTreeMap::new(), BTreeMap::new()],
        active_bank: 0,
        applied_epoch: 0,
        controller_url: config
            .controller_url
            .map(|url| url.trim_end_matches('/').to_owned()),
        client: reqwest::Client::new(),
        interval: config.identity_sync_interval,
    };
    consume_events(
        ring,
        &mut attachments,
        &mut identities,
        &mut policies,
        state,
        cancellation,
    )
    .await;
    state.ready.store(false, Ordering::Release);
    state.bpf_loaded.store(false, Ordering::Release);
    state.metrics.bpf_loaded.set(0);
    Ok(())
}

async fn consume_events(
    mut ring: RingBuf<aya::maps::MapData>,
    attachments: &mut InterfaceAttachments<'_>,
    identities: &mut IdentitySynchronizer,
    policies: &mut PolicySynchronizer,
    state: &AgentState,
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
                    info!(
                        source_identity = event.flow.source_identity.get(),
                        destination_identity = event.flow.destination_identity.get(),
                        source = ?event.flow.source_address,
                        destination = ?event.flow.destination_address,
                        source_port = u16::from_be_bytes(event.flow.source_port),
                        destination_port = u16::from_be_bytes(event.flow.destination_port),
                        protocol = event.flow.protocol,
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
    apply_policy_entries(
        synchronizer,
        desired,
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
    state.policy_map_entries.store(
        synchronizer.banks[usize::from(synchronizer.active_bank)].len() as u64,
        Ordering::Release,
    );
    state
        .active_policy_bank
        .store(u64::from(synchronizer.active_bank), Ordering::Release);
    state
        .metrics
        .applied_policy_revision
        .set(metric_value(desired_revision));
    state.metrics.policy_map_entries.set(metric_value(
        synchronizer.banks[usize::from(synchronizer.active_bank)].len() as u64,
    ));
    info!(
        policy_epoch = snapshot.source_epoch,
        policy_revision = desired_revision,
        entries = synchronizer.banks[usize::from(synchronizer.active_bank)].len(),
        active_bank = synchronizer.active_bank,
        "policy snapshot activated"
    );
    Ok(())
}

fn desired_policy_entries(
    entries: &[PolicyMapEntry],
    revision: u64,
    bank: u8,
) -> Result<BTreeMap<[u8; 12], [u8; 32]>> {
    if bank >= POLICY_BANK_COUNT {
        bail!("invalid policy bank {bank}");
    }
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

fn validate_policy_entry(entry: &PolicyMapEntry) -> Result<()> {
    if entry.key.source_identity.get() == 0 || entry.key.destination_identity.get() == 0 {
        bail!("policy entry contains reserved identity ID zero");
    }
    match (entry.key.protocol, entry.key.destination_port) {
        (0, 0) | (6 | 17, 1..=u16::MAX) => {}
        _ => bail!("policy entry contains an invalid protocol/port wildcard combination"),
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

fn encode_policy_value(entry: &PolicyMapEntry, revision: u64) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    let mut flags = 0_u16;
    if let Some(policy_id) = entry.decision.policy_id {
        flags |= POLICY_FLAG_HAS_POLICY;
        encoded[0..4].copy_from_slice(&policy_id.get().to_ne_bytes());
    }
    if let Some(rule_id) = entry.decision.rule_id {
        flags |= POLICY_FLAG_HAS_RULE;
        encoded[4..8].copy_from_slice(&rule_id.get().to_ne_bytes());
    }
    if let Some(shadow) = entry.shadow {
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
    encoded[28] = entry.decision.verdict as u8;
    encoded[29] = entry.decision.reason as u8;
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

fn apply_policy_entries(
    synchronizer: &mut PolicySynchronizer,
    desired: BTreeMap<[u8; 12], [u8; 32]>,
    source_epoch: u64,
    revision: u64,
    staging_bank: u8,
) -> Result<()> {
    let staging_index = usize::from(staging_bank);
    let previous_staging = synchronizer.banks[staging_index].clone();
    if let Err(error) = replace_policy_entries(&mut synchronizer.map, &previous_staging, &desired) {
        return Err(rollback_policy_stage(
            &mut synchronizer.map,
            &previous_staging,
            staging_bank,
            &error.context("stage policy map bank"),
        ));
    }
    if let Err(error) = validate_staged_policy_entries(&synchronizer.map, &desired) {
        return Err(rollback_policy_stage(
            &mut synchronizer.map,
            &previous_staging,
            staging_bank,
            &error,
        ));
    }
    let config = match encode_policy_config(source_epoch, revision, desired.len(), staging_bank) {
        Ok(config) => config,
        Err(error) => {
            return Err(rollback_policy_stage(
                &mut synchronizer.map,
                &previous_staging,
                staging_bank,
                &error,
            ));
        }
    };
    if let Err(error) = synchronizer.config.set(0, config, 0) {
        return Err(rollback_policy_stage(
            &mut synchronizer.map,
            &previous_staging,
            staging_bank,
            &anyhow!(error).context("atomically activate staged policy bank"),
        ));
    }

    let previous_active = synchronizer.active_bank;
    synchronizer.banks[staging_index] = desired;
    synchronizer.active_bank = staging_bank;
    let previous_index = usize::from(previous_active);
    if previous_active != staging_bank {
        if let Err(error) =
            clear_policy_bank(&mut synchronizer.map, &synchronizer.banks[previous_index])
        {
            warn!(
                ?error,
                bank = previous_active,
                "could not garbage-collect old policy bank"
            );
        } else {
            synchronizer.banks[previous_index].clear();
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

fn rollback_policy_stage(
    map: &mut AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    previous: &BTreeMap<[u8; 12], [u8; 32]>,
    bank: u8,
    cause: &anyhow::Error,
) -> anyhow::Error {
    restore_policy_entries(map, previous, bank).map_or_else(
        |rollback| anyhow!("policy update failed: {cause:#}; rollback also failed: {rollback:#}"),
        |()| anyhow!("policy update failed and staging bank was rolled back: {cause:#}"),
    )
}

fn replace_policy_entries(
    map: &mut AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    current: &BTreeMap<[u8; 12], [u8; 32]>,
    desired: &BTreeMap<[u8; 12], [u8; 32]>,
) -> Result<()> {
    for (key, value) in desired {
        map.insert(key, value, 0)
            .with_context(|| format!("insert policy map key {key:?}"))?;
    }
    for key in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(key)
            .with_context(|| format!("remove stale policy map key {key:?}"))?;
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

fn clear_policy_bank(
    map: &mut AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    entries: &BTreeMap<[u8; 12], [u8; 32]>,
) -> Result<()> {
    for key in entries.keys() {
        map.remove(key)?;
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
        ready: state.ready.load(Ordering::Acquire),
        bpf_loaded: state.bpf_loaded.load(Ordering::Acquire),
        observed_flows: state.observed_flows.load(Ordering::Relaxed),
        desired_identity_revision: state.desired_identity_revision.load(Ordering::Acquire),
        applied_identity_revision: state.applied_identity_revision.load(Ordering::Acquire),
        desired_identity_epoch: state.desired_identity_epoch.load(Ordering::Acquire),
        applied_identity_epoch: state.applied_identity_epoch.load(Ordering::Acquire),
        identity_map_entries: state.identity_map_entries.load(Ordering::Acquire),
        desired_policy_revision: state.desired_policy_revision.load(Ordering::Acquire),
        applied_policy_revision: state.applied_policy_revision.load(Ordering::Acquire),
        desired_policy_epoch: state.desired_policy_epoch.load(Ordering::Acquire),
        applied_policy_epoch: state.applied_policy_epoch.load(Ordering::Acquire),
        policy_map_entries: state.policy_map_entries.load(Ordering::Acquire),
        active_policy_bank: state.active_policy_bank.load(Ordering::Acquire),
        capabilities: state.capabilities.clone(),
        limitation: "TC policy enforcement is active; maps are unpinned and status is node-local",
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
    fn policy_snapshot_rejects_invalid_wildcard() {
        let mut entry = policy_entry();
        entry.key.protocol = 0;
        assert!(desired_policy_entries(&[entry], 17, 1).is_err());
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
