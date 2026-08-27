use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Bound::{Excluded, Unbounded};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use aya::maps::lpm_trie::{Key as LpmKey, LpmTrie as AyaLpmTrie};
use aya::maps::{Array as AyaArray, HashMap as AyaHashMap, IterableMap, MapData, RingBuf};
use aya::programs::links::{FdLink, LinkError, PinnedLink};
use aya::programs::tc::{NlOptions, SchedClassifierLink, TcAttachOptions, TcError, TcHandle};
use aya::programs::{LinkOrder, SchedClassifier, TcAttachType, tc};
use aya::sys::SyscallError;
use aya::{Ebpf, EbpfLoader};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use unf_common::{IdentityId, PolicyDirection, PolicyId, PolicyReason, Revision, RuleId, Verdict};
use unf_ebpf_common::{
    FLOW_ABI_VERSION, FlowEvent, FlowKey, IDENTITY_BANK_COUNT, IdentityMapValue, Ipv4IdentityKey,
    Ipv6IdentityKey, POLICY_BANK_COUNT, POLICY_FLAG_HAS_POLICY, POLICY_FLAG_HAS_RULE,
    POLICY_FLAG_HAS_SHADOW, POLICY_FLAG_SHADOW_HAS_POLICY, POLICY_FLAG_SHADOW_HAS_RULE,
    POLICY_MAP_ABI_VERSION,
};
use unf_state::{
    AGENT_STATUS_SCHEMA_VERSION, AgentStateReport, ComponentCompatibility,
    EgressIpv4PolicyMapEntry, EgressIpv6PolicyMapEntry, FLOW_EXPORT_BATCH_LIMIT,
    FLOW_EXPORT_SCHEMA_VERSION, FlowExportBatch, FlowExportDecision, FlowExportRecord,
    FlowHistoryKey, IDENTITY_SNAPSHOT_SCHEMA_VERSION, IdentityStateSnapshot, Ipv4IdentityMapping,
    Ipv4PolicyMapEntry, Ipv6IdentityMapping, Ipv6PolicyMapEntry, PERSISTENT_BPF_STATE_ABI_VERSION,
    POLICY_MAP_BANK_ENTRY_LIMIT, POLICY_SNAPSHOT_SCHEMA_VERSION, PolicyDecisionRecord,
    PolicyMapEntry, PolicyStateSnapshot,
};

const FLOW_EXPORT_CHANNEL_CAPACITY: usize = 4_096;
const FLOW_EXPORT_PENDING_CAPACITY: usize = 2_048;
const DEFAULT_BPF_PIN_PATH: &str = "/sys/fs/bpf/unf/v3";
const DEFAULT_AGENT_TOKEN_PATH: &str = "/var/run/secrets/unf-agent/token";
const DEFAULT_CONTROLLER_CA_PATH: &str = "/var/run/secrets/unf-internal-ca/ca.crt";
const CURRENT_BPF_ABI_VERSION: u16 = PERSISTENT_BPF_STATE_ABI_VERSION;
const BUILD_REVISION: &str = match option_env!("UNF_BUILD_REVISION") {
    Some(revision) => revision,
    None => "unknown",
};
const ABI_V1_MAP_NAMES: [&str; 6] = [
    "IDENTITY_V4",
    "IDENTITY_V6",
    "POLICY_RULES",
    "POLICY_IPV4",
    "POLICY_IPV6",
    "POLICY_CONFIG",
];
const ABI_V2_MAP_NAMES: [&str; 9] = [
    "IDENTITY_V4",
    "IDENTITY_V4_B",
    "IDENTITY_V6",
    "IDENTITY_V6_B",
    "IDENTITY_CONFIG",
    "POLICY_RULES",
    "POLICY_IPV4",
    "POLICY_IPV6",
    "POLICY_CONFIG",
];
const PERSISTENT_MAP_NAMES: [&str; 11] = [
    "IDENTITY_V4",
    "IDENTITY_V4_B",
    "IDENTITY_V6",
    "IDENTITY_V6_B",
    "IDENTITY_CONFIG",
    "POLICY_RULES",
    "POLICY_IPV4",
    "POLICY_IPV6",
    "EGRESS_IPV4",
    "EGRESS_IPV6",
    "POLICY_CONFIG",
];
const IDENTITY_MAP_CAPACITY: u32 = 65_536;
const POLICY_MAP_CAPACITY: u32 = 262_144;
const CONTROLLER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const LEGACY_TC_PRIORITY: u16 = 0x554e;
const LEGACY_TC_HANDLE_MAJOR: u16 = 0x554e;

#[derive(Debug, Parser)]
#[command(about = "UNF per-node eBPF agent")]
struct Args {
    #[command(subcommand)]
    command: Option<AgentCommand>,
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
    #[arg(
        long,
        env = "UNF_CONTROLLER_CA_PATH",
        default_value = DEFAULT_CONTROLLER_CA_PATH
    )]
    controller_ca_path: PathBuf,
    #[arg(long, env = "UNF_IDENTITY_SYNC_SECONDS", default_value_t = 2)]
    identity_sync_seconds: u64,
    #[arg(long, env = "UNF_NODE_NAME", default_value = "unknown")]
    node_name: String,
    #[arg(long, env = "UNF_POD_NAME", default_value = "unknown")]
    pod_name: String,
    #[arg(long, env = "UNF_POD_UID", default_value = "unknown")]
    pod_uid: String,
    #[arg(
        long,
        env = "UNF_AGENT_TOKEN_PATH",
        default_value = DEFAULT_AGENT_TOKEN_PATH
    )]
    agent_token_path: PathBuf,
    #[arg(long, env = "UNF_FLOW_EXPORT_SECONDS", default_value_t = 1)]
    flow_export_seconds: u64,
    #[arg(long, env = "UNF_BPF_PIN_PATH", default_value = DEFAULT_BPF_PIN_PATH)]
    bpf_pin_path: PathBuf,
    #[arg(
        long,
        env = "UNF_TC_ATTACHMENT_MODE",
        value_enum,
        default_value = "auto"
    )]
    tc_attachment_mode: TcAttachmentPreference,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Plan or execute narrowly scoped cleanup of UNF-owned host state.
    Cleanup(CleanupArgs),
}

#[derive(Debug, ClapArgs)]
#[allow(clippy::struct_excessive_bools)] // Independent opt-in CLI switches are clearer as flags.
struct CleanupArgs {
    /// Parent directory containing versioned UNF bpffs state.
    #[arg(long, default_value = "/sys/fs/bpf/unf")]
    bpf_root: PathBuf,
    /// Remove one known ABI directory (supported: 1 or 2).
    #[arg(long)]
    abi_version: Option<u16>,
    /// Permit removal of the currently deployed ABI v2 directory.
    #[arg(long, requires = "abi_version")]
    allow_current_abi: bool,
    /// Remove UNF-named persistent netlink filters.
    #[arg(long)]
    legacy_attachments: bool,
    /// Target every current non-loopback interface for legacy cleanup.
    #[arg(long, requires = "legacy_attachments", conflicts_with = "interfaces")]
    all_interfaces: bool,
    /// Target one interface for legacy cleanup; may be repeated.
    #[arg(
        long = "interface",
        requires = "legacy_attachments",
        conflicts_with = "all_interfaces"
    )]
    interfaces: Vec<String>,
    /// Direction of legacy filters to remove.
    #[arg(
        long,
        value_enum,
        default_value = "ingress",
        requires = "legacy_attachments"
    )]
    legacy_direction: CleanupDirection,
    /// Apply the plan. Without this flag cleanup is a non-mutating dry run.
    #[arg(long)]
    execute: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Direction {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CleanupDirection {
    Ingress,
    Egress,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TcAttachmentPreference {
    Auto,
    TcxPinned,
    LegacyNetlink,
}

struct AgentMetrics {
    flow_events: Counter,
    management_flow_events_filtered: Counter,
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
    controller_trust_reloads: Counter,
    controller_trust_reload_errors: Counter,
}

struct AgentState {
    node_name: String,
    pod_name: String,
    pod_uid: String,
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
    tc_attachment_mode: AtomicU64,
    capabilities: KernelCapabilities,
    registry: Mutex<Registry>,
    metrics: AgentMetrics,
}

struct IdentitySynchronizer {
    ipv4_maps: [EncodedIpv4IdentityMap; IDENTITY_BANK_COUNT as usize],
    ipv6_maps: [EncodedIpv6IdentityMap; IDENTITY_BANK_COUNT as usize],
    config: AyaArray<MapData, [u8; 24]>,
    ipv4_banks: [EncodedIpv4IdentityBank; IDENTITY_BANK_COUNT as usize],
    ipv6_banks: [EncodedIpv6IdentityBank; IDENTITY_BANK_COUNT as usize],
    active_bank: u8,
    applied_epoch: u64,
    controller_url: Option<String>,
    controller_management_port: Option<u16>,
    client: ReloadingControllerClient,
    agent_token_path: PathBuf,
    interval: Duration,
}

struct PolicySynchronizer {
    identity_map: AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    ipv4_map: AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    ipv6_map: AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    egress_ipv4_map: AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    egress_ipv6_map: AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    config: AyaArray<MapData, [u8; 24]>,
    identity_banks: [BTreeMap<[u8; 12], [u8; 32]>; POLICY_BANK_COUNT as usize],
    ipv4_banks: [BTreeMap<[u8; 12], [u8; 32]>; POLICY_BANK_COUNT as usize],
    ipv6_banks: [EncodedIpv6PolicyBank; POLICY_BANK_COUNT as usize],
    egress_ipv4_banks: [BTreeMap<[u8; 12], [u8; 32]>; POLICY_BANK_COUNT as usize],
    egress_ipv6_banks: [EncodedIpv6PolicyBank; POLICY_BANK_COUNT as usize],
    active_bank: u8,
    applied_epoch: u64,
    controller_url: Option<String>,
    client: ReloadingControllerClient,
    agent_token_path: PathBuf,
    interval: Duration,
}

type EncodedPolicyMap = AyaHashMap<MapData, [u8; 12], [u8; 32]>;
type EncodedIpv4IdentityMap = AyaHashMap<MapData, [u8; 4], [u8; 16]>;
type EncodedIpv6IdentityMap = AyaHashMap<MapData, [u8; 16], [u8; 16]>;
type EncodedIpv4IdentityBank = BTreeMap<[u8; 4], [u8; 16]>;
type EncodedIpv6IdentityBank = BTreeMap<[u8; 16], [u8; 16]>;
type EncodedIpv6PolicyKey = (u32, [u8; 24]);
type EncodedIpv6PolicyBank = BTreeMap<EncodedIpv6PolicyKey, [u8; 32]>;
type PolicyMaps = (
    EncodedPolicyMap,
    EncodedPolicyMap,
    AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    EncodedPolicyMap,
    AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    AyaArray<MapData, [u8; 24]>,
);
type IdentityMaps = (
    [EncodedIpv4IdentityMap; IDENTITY_BANK_COUNT as usize],
    [EncodedIpv6IdentityMap; IDENTITY_BANK_COUNT as usize],
    AyaArray<MapData, [u8; 24]>,
);

struct DataplaneConfig {
    object: PathBuf,
    interface: Option<String>,
    all_interfaces: bool,
    direction: Direction,
    controller_url: Option<String>,
    controller_ca_path: PathBuf,
    identity_sync_interval: Duration,
    node_name: String,
    agent_token_path: PathBuf,
    flow_export_interval: Duration,
    bpf_pin_path: PathBuf,
    tc_attachment_preference: TcAttachmentPreference,
}

struct FlowExporterConfig {
    controller_url: String,
    client: ReloadingControllerClient,
    node_name: String,
    token_path: PathBuf,
    interval: Duration,
}

#[derive(Clone)]
struct ReloadingControllerClient {
    ca_path: PathBuf,
    controller_resolution: Option<(String, SocketAddr)>,
    state: Arc<Mutex<ControllerClientState>>,
    reloads: Counter,
    reload_errors: Counter,
}

struct ControllerClientState {
    observed_ca_pem: Vec<u8>,
    client: reqwest::Client,
}

struct RecoveredDataplane {
    identity_epoch: Option<u64>,
    identity_revision: Option<u64>,
    policy_epoch: Option<u64>,
    policy_revision: Option<u64>,
}

#[derive(Debug)]
struct AbiCleanupPlan {
    abi_directory: PathBuf,
    map_pins: Vec<PathBuf>,
    link_pins: Vec<PathBuf>,
    links_directory: Option<PathBuf>,
    directory_exists: bool,
}

#[derive(Debug)]
struct LegacyCleanupTarget {
    interface: String,
    attach_type: TcAttachType,
    program_name: &'static str,
    direction: &'static str,
}

struct InterfaceAttachments<'program> {
    program: &'program mut SchedClassifier,
    all_interfaces: bool,
    attach_type: TcAttachType,
    direction: Direction,
    mode: TcAttachmentMode,
    pin_root: PathBuf,
    attached: HashMap<String, u32>,
}

impl InterfaceAttachments<'_> {
    fn refresh(&mut self) -> Result<()> {
        refresh_interfaces(
            self.program,
            self.attach_type,
            self.direction,
            self.mode,
            &self.pin_root,
            &mut self.attached,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
enum TcAttachmentMode {
    None = 0,
    TcxPinned = 1,
    LegacyNetlink = 2,
}

impl TcAttachmentMode {
    const fn status_label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TcxPinned => "tcx_pinned",
            Self::LegacyNetlink => "legacy_netlink",
        }
    }

    const fn from_state(value: u64) -> Self {
        match value {
            1 => Self::TcxPinned,
            2 => Self::LegacyNetlink,
            _ => Self::None,
        }
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
    tc_attachment_mode: &'static str,
    capabilities: KernelCapabilities,
    limitation: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider()?;
    init_tracing();
    let args = Args::parse();
    if let Some(AgentCommand::Cleanup(cleanup)) = &args.command {
        return run_cleanup(cleanup);
    }
    let state = Arc::new(new_state(
        detect_capabilities(),
        args.node_name.clone(),
        args.pod_name.clone(),
        args.pod_uid.clone(),
    ));
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let (dataplane_failure_tx, mut dataplane_failure_rx) = mpsc::channel(1);
    let mut dataplane_configured = false;

    match (&args.ebpf_object, &args.interface, args.all_interfaces) {
        (Some(object), interface, all_interfaces) if interface.is_some() || all_interfaces => {
            dataplane_configured = true;
            let state = Arc::clone(&state);
            let cancellation = cancellation.clone();
            let dataplane_failure_tx = dataplane_failure_tx.clone();
            let object = object.clone();
            let interface = interface.clone();
            let direction = args.direction;
            let controller_url = args.controller_url.clone();
            let controller_ca_path = args.controller_ca_path.clone();
            let identity_sync_interval = Duration::from_secs(args.identity_sync_seconds.max(1));
            let node_name = args.node_name.clone();
            let agent_token_path = args.agent_token_path.clone();
            let flow_export_interval = Duration::from_secs(args.flow_export_seconds.max(1));
            let bpf_pin_path = args.bpf_pin_path.clone();
            let tc_attachment_preference = args.tc_attachment_mode;
            tasks.spawn(async move {
                let config = DataplaneConfig {
                    object,
                    interface,
                    all_interfaces,
                    direction,
                    controller_url,
                    controller_ca_path,
                    identity_sync_interval,
                    node_name,
                    agent_token_path,
                    flow_export_interval,
                    bpf_pin_path,
                    tc_attachment_preference,
                };
                if let Err(error) = run_dataplane(config, Arc::clone(&state), cancellation).await {
                    error!(?error, "eBPF dataplane stopped");
                    state.ready.store(false, Ordering::Release);
                    let _ = dataplane_failure_tx.send(error).await;
                }
            });
        }
        (None, None, false) => {
            warn!("no eBPF object/interface configured; capability-only mode");
            state.ready.store(true, Ordering::Release);
        }
        _ => bail!("--ebpf-object must be paired with either --interface or --all-interfaces"),
    }
    drop(dataplane_failure_tx);

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/version", get(version))
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

    let dataplane_failure = tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.context("listen for shutdown signal")?;
            None
        }
        failure = dataplane_failure_rx.recv(), if dataplane_configured => failure,
    };
    cancellation.cancel();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            error!(%error, "agent task failed");
        }
    }
    if let Some(error) = dataplane_failure {
        return Err(error).context("eBPF dataplane failed");
    }
    Ok(())
}

fn run_cleanup(args: &CleanupArgs) -> Result<()> {
    if args.abi_version.is_none() && !args.legacy_attachments {
        bail!("cleanup requires --abi-version or --legacy-attachments");
    }
    if args.allow_current_abi && args.abi_version != Some(CURRENT_BPF_ABI_VERSION) {
        bail!("--allow-current-abi is valid only with --abi-version {CURRENT_BPF_ABI_VERSION}");
    }

    let abi_plan = args
        .abi_version
        .map(|version| plan_abi_cleanup(&args.bpf_root, version, args.allow_current_abi))
        .transpose()?;
    let legacy_targets = plan_legacy_cleanup(args)?;
    let mode = if args.execute { "execute" } else { "dry-run" };
    println!("UNF cleanup plan ({mode})");
    if let Some(plan) = &abi_plan {
        println!("ABI directory: {}", plan.abi_directory.display());
        if !plan.directory_exists {
            println!("  no matching ABI directory exists");
        }
        for path in &plan.link_pins {
            println!("  remove TCX link pin: {}", path.display());
        }
        for path in &plan.map_pins {
            println!("  remove map pin: {}", path.display());
        }
        if let Some(path) = &plan.links_directory {
            println!("  remove empty link directory: {}", path.display());
        }
        if plan.directory_exists {
            println!(
                "  remove empty ABI directory: {}",
                plan.abi_directory.display()
            );
        }
    }
    for target in &legacy_targets {
        println!(
            "legacy attachment: interface={} direction={} program={}",
            target.interface, target.direction, target.program_name
        );
    }
    if !args.execute {
        println!("dry run only; rerun with --execute to apply this exact scope");
        return Ok(());
    }

    for target in &legacy_targets {
        match tc::qdisc_detach_program(&target.interface, target.attach_type, target.program_name) {
            Ok(()) => println!(
                "removed legacy attachment: interface={} direction={} program={}",
                target.interface, target.direction, target.program_name
            ),
            Err(TcError::IoError(error)) if error.kind() == io::ErrorKind::NotFound => println!(
                "no matching legacy attachment: interface={} direction={} program={}",
                target.interface, target.direction, target.program_name
            ),
            Err(error) => {
                return Err(anyhow!(error)).with_context(|| {
                    format!(
                        "remove legacy attachment {} {}",
                        target.interface, target.direction
                    )
                });
            }
        }
    }
    if let Some(plan) = &abi_plan {
        execute_abi_cleanup(plan)?;
    }
    println!("UNF cleanup completed");
    Ok(())
}

fn plan_abi_cleanup(
    bpf_root: &Path,
    abi_version: u16,
    allow_current_abi: bool,
) -> Result<AbiCleanupPlan> {
    if !matches!(abi_version, 1 | 2 | CURRENT_BPF_ABI_VERSION) {
        bail!("unsupported ABI version {abi_version}; this binary recognizes only v1, v2, and v3");
    }
    if abi_version == CURRENT_BPF_ABI_VERSION && !allow_current_abi {
        bail!(
            "refusing to clean current ABI v{CURRENT_BPF_ABI_VERSION} without --allow-current-abi"
        );
    }
    validate_cleanup_root(bpf_root)?;
    let abi_directory = bpf_root.join(format!("v{abi_version}"));
    let mut plan = AbiCleanupPlan {
        abi_directory: abi_directory.clone(),
        map_pins: Vec::new(),
        link_pins: Vec::new(),
        links_directory: None,
        directory_exists: false,
    };
    let metadata = match fs::symlink_metadata(&abi_directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(plan),
        Err(error) => return Err(error).context("inspect ABI cleanup directory"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "ABI cleanup target must be a real directory: {}",
            abi_directory.display()
        );
    }
    plan.directory_exists = true;
    let recognized_maps: &[&str] = match abi_version {
        1 => &ABI_V1_MAP_NAMES,
        2 => &ABI_V2_MAP_NAMES,
        _ => &PERSISTENT_MAP_NAMES,
    };
    let mut unknown = Vec::new();
    for entry in fs::read_dir(&abi_directory)
        .with_context(|| format!("inspect ABI directory {}", abi_directory.display()))?
    {
        let entry = entry.context("read ABI cleanup entry")?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            unknown.push(entry.path());
            continue;
        };
        let file_type = entry
            .file_type()
            .context("inspect ABI cleanup entry type")?;
        if recognized_maps.contains(&name_text) && !file_type.is_dir() && !file_type.is_symlink() {
            plan.map_pins.push(entry.path());
        } else if name_text == "links" && file_type.is_dir() && !file_type.is_symlink() {
            plan.links_directory = Some(entry.path());
            inspect_cleanup_link_directory(&entry.path(), &mut plan.link_pins, &mut unknown)?;
        } else {
            unknown.push(entry.path());
        }
    }
    plan.map_pins.sort();
    plan.link_pins.sort();
    if !unknown.is_empty() {
        unknown.sort();
        let paths = unknown
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("unrecognized ABI state; refusing cleanup: {paths}");
    }
    Ok(plan)
}

fn validate_cleanup_root(root: &Path) -> Result<()> {
    if !root.is_absolute() || root == Path::new("/") {
        bail!("BPF cleanup root must be an absolute, non-root directory");
    }
    if root
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("BPF cleanup root must not contain '.' or '..' components");
    }
    if let Ok(metadata) = fs::symlink_metadata(root)
        && metadata.file_type().is_symlink()
    {
        bail!("BPF cleanup root must not be a symbolic link");
    }
    Ok(())
}

fn inspect_cleanup_link_directory(
    directory: &Path,
    link_pins: &mut Vec<PathBuf>,
    unknown: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("inspect TCX link directory {}", directory.display()))?
    {
        let entry = entry.context("read TCX cleanup entry")?;
        let name = entry.file_name();
        let file_type = entry
            .file_type()
            .context("inspect TCX cleanup entry type")?;
        if name.to_str().is_some_and(recognized_tcx_link_pin_name)
            && !file_type.is_dir()
            && !file_type.is_symlink()
        {
            link_pins.push(entry.path());
        } else {
            unknown.push(entry.path());
        }
    }
    Ok(())
}

fn recognized_tcx_link_pin_name(name: &str) -> bool {
    ["tcx-ingress-", "tcx-egress-"].iter().any(|prefix| {
        name.strip_prefix(prefix)
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|if_index| if_index != 0)
    })
}

fn plan_legacy_cleanup(args: &CleanupArgs) -> Result<Vec<LegacyCleanupTarget>> {
    if !args.legacy_attachments {
        return Ok(Vec::new());
    }
    if !args.all_interfaces && args.interfaces.is_empty() {
        bail!("--legacy-attachments requires --all-interfaces or at least one --interface");
    }
    let interfaces: BTreeSet<String> = if args.all_interfaces {
        discover_interfaces()?.into_keys().collect()
    } else {
        let mut interfaces = BTreeSet::new();
        for interface in &args.interfaces {
            validate_cleanup_interface_name(interface)?;
            interface_index(interface)?;
            interfaces.insert(interface.clone());
        }
        interfaces
    };
    let directions: &[(TcAttachType, &str, &str)] = match args.legacy_direction {
        CleanupDirection::Ingress => &[(TcAttachType::Ingress, "ingress", "unf_observe_ingress")],
        CleanupDirection::Egress => &[(TcAttachType::Egress, "egress", "unf_observe_egress")],
        CleanupDirection::Both => &[
            (TcAttachType::Ingress, "ingress", "unf_observe_ingress"),
            (TcAttachType::Egress, "egress", "unf_observe_egress"),
        ],
    };
    let mut targets = Vec::new();
    for interface in interfaces {
        for (attach_type, direction, program_name) in directions {
            targets.push(LegacyCleanupTarget {
                interface: interface.clone(),
                attach_type: *attach_type,
                program_name,
                direction,
            });
        }
    }
    Ok(targets)
}

fn validate_cleanup_interface_name(interface: &str) -> Result<()> {
    let mut components = Path::new(interface).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("cleanup interface must be one exact interface name");
    }
    if interface == "lo" {
        bail!("loopback is not a UNF attachment target");
    }
    Ok(())
}

fn execute_abi_cleanup(plan: &AbiCleanupPlan) -> Result<()> {
    for path in plan.link_pins.iter().chain(&plan.map_pins) {
        fs::remove_file(path)
            .with_context(|| format!("remove owned BPF pin {}", path.display()))?;
        println!("removed BPF pin: {}", path.display());
    }
    if let Some(directory) = &plan.links_directory {
        fs::remove_dir(directory)
            .with_context(|| format!("remove empty TCX link directory {}", directory.display()))?;
    }
    if plan.directory_exists {
        fs::remove_dir(&plan.abi_directory).with_context(|| {
            format!(
                "remove empty ABI directory {}",
                plan.abi_directory.display()
            )
        })?;
    }
    Ok(())
}

fn install_crypto_provider() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("install process-wide Rustls crypto provider"))
}

fn new_state(
    capabilities: KernelCapabilities,
    node_name: String,
    pod_name: String,
    pod_uid: String,
) -> AgentState {
    let metrics = AgentMetrics {
        flow_events: Counter::default(),
        management_flow_events_filtered: Counter::default(),
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
        controller_trust_reloads: Counter::default(),
        controller_trust_reload_errors: Counter::default(),
    };
    let mut registry = Registry::default();
    register_agent_metrics(&mut registry, &metrics);
    AgentState {
        node_name,
        pod_name,
        pod_uid,
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
        tc_attachment_mode: AtomicU64::new(TcAttachmentMode::None as u64),
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
        "unf_management_flow_events_filtered",
        "Controller management flow events excluded from logs and telemetry",
        metrics.management_flow_events_filtered.clone(),
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
    registry.register(
        "unf_agent_controller_trust_reloads",
        "Controller CA bundle reloads accepted without an agent restart",
        metrics.controller_trust_reloads.clone(),
    );
    registry.register(
        "unf_agent_controller_trust_reload_errors",
        "Controller CA bundle updates rejected while retaining last-known-good trust",
        metrics.controller_trust_reload_errors.clone(),
    );
}

async fn run_dataplane(
    config: DataplaneConfig,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
) -> Result<()> {
    let (mut ebpf, pins_existed) = load_persistent_ebpf(&config)?;
    let ring = RingBuf::try_from(
        ebpf.take_map("FLOW_EVENTS")
            .context("eBPF object does not contain FLOW_EVENTS ring buffer")?,
    )
    .context("open FLOW_EVENTS ring buffer")?;
    let identity_maps = take_identity_maps(&mut ebpf)?;
    let policy_maps = take_policy_maps(&mut ebpf)?;
    let controller_url = config
        .controller_url
        .as_deref()
        .map(|url| url.trim_end_matches('/').to_owned());
    let controller_client = dataplane_controller_client(
        controller_url.as_deref(),
        &config.controller_ca_path,
        &state,
    )?;
    let controller_management_port = controller_url.as_deref().map(controller_port).transpose()?;
    let (mut identities, mut policies) = new_synchronizers(
        identity_maps,
        policy_maps,
        controller_url.clone(),
        controller_management_port,
        controller_client.clone(),
        config.agent_token_path.clone(),
        config.identity_sync_interval,
    );
    let recovered = recover_persistent_dataplane(&mut identities, &mut policies, pins_existed)?;
    apply_recovered_state(&state, &identities, &policies, &recovered);
    let mut attachments = attach_dataplane_program(
        &mut ebpf,
        &config,
        select_tc_attachment_mode(
            config.tc_attachment_preference,
            kernel_supports_tcx(&state.capabilities.kernel_release),
        ),
    )?;
    state
        .tc_attachment_mode
        .store(attachments.mode as u64, Ordering::Release);
    state.bpf_loaded.store(true, Ordering::Release);
    state.metrics.bpf_loaded.set(1);
    let recovered_ready = recovered_dataplane_is_ready(&recovered);
    state.ready.store(
        controller_url.is_none() || recovered_ready,
        Ordering::Release,
    );
    if recovered_ready {
        let active_policy_bank = usize::from(policies.active_bank);
        info!(
            identity_epoch = recovered.identity_epoch,
            identity_revision = recovered.identity_revision,
            policy_epoch = recovered.policy_epoch,
            policy_revision = recovered.policy_revision,
            active_identity_bank = identities.active_bank,
            active_policy_bank = policies.active_bank,
            identity_policy_entries = policies.identity_banks[active_policy_bank].len(),
            ipv4_policy_entries = policies.ipv4_banks[active_policy_bank].len(),
            ipv6_policy_entries = policies.ipv6_banks[active_policy_bank].len(),
            egress_ipv4_entries = policies.egress_ipv4_banks[active_policy_bank].len(),
            egress_ipv6_entries = policies.egress_ipv6_banks[active_policy_bank].len(),
            "validated pinned last-known-good dataplane"
        );
    } else if controller_url.is_some() {
        info!("waiting for initial identity and policy snapshots before becoming ready");
    }
    let (flow_export_sender, flow_export_task) = spawn_flow_exporter(
        controller_url.clone(),
        controller_client.clone(),
        &config,
        &state,
        &cancellation,
    );
    let status_report_task = spawn_agent_status_reporter(
        controller_url,
        controller_client,
        &config,
        &state,
        &cancellation,
    );
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

fn attach_dataplane_program<'ebpf>(
    ebpf: &'ebpf mut Ebpf,
    config: &DataplaneConfig,
    mode: TcAttachmentMode,
) -> Result<InterfaceAttachments<'ebpf>> {
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
        mode,
        pin_root: config.bpf_pin_path.join("links"),
        attached: HashMap::new(),
    };
    if config.all_interfaces {
        attachments.refresh()?;
        if attachments.attached.is_empty() {
            bail!("no non-loopback network interfaces are available");
        }
    } else if let Some(interface) = config.interface.as_deref() {
        let if_index = interface_index(interface)?;
        attach_interface(
            attachments.program,
            interface,
            if_index,
            attachments.attach_type,
            attachments.direction,
            attachments.mode,
            &attachments.pin_root,
        )?;
        attachments.attached.insert(interface.to_owned(), if_index);
    }
    Ok(attachments)
}

fn recovered_dataplane_is_ready(recovered: &RecoveredDataplane) -> bool {
    recovered.identity_epoch.is_some()
        && recovered.identity_revision.is_some()
        && recovered.policy_epoch.is_some()
        && recovered.policy_revision.is_some()
}

fn new_synchronizers(
    identity_maps: IdentityMaps,
    policy_maps: PolicyMaps,
    controller_url: Option<String>,
    controller_management_port: Option<u16>,
    client: ReloadingControllerClient,
    agent_token_path: PathBuf,
    interval: Duration,
) -> (IdentitySynchronizer, PolicySynchronizer) {
    let (ipv4_maps, ipv6_maps, identity_config) = identity_maps;
    let (identity_map, ipv4_policy_map, ipv6_policy_map, egress_ipv4_map, egress_ipv6_map, config) =
        policy_maps;
    (
        IdentitySynchronizer {
            ipv4_maps,
            ipv6_maps,
            config: identity_config,
            ipv4_banks: [BTreeMap::new(), BTreeMap::new()],
            ipv6_banks: [BTreeMap::new(), BTreeMap::new()],
            active_bank: 0,
            applied_epoch: 0,
            controller_url: controller_url.clone(),
            controller_management_port,
            client: client.clone(),
            agent_token_path: agent_token_path.clone(),
            interval,
        },
        PolicySynchronizer {
            identity_map,
            ipv4_map: ipv4_policy_map,
            ipv6_map: ipv6_policy_map,
            egress_ipv4_map,
            egress_ipv6_map,
            config,
            identity_banks: [BTreeMap::new(), BTreeMap::new()],
            ipv4_banks: [BTreeMap::new(), BTreeMap::new()],
            ipv6_banks: [BTreeMap::new(), BTreeMap::new()],
            egress_ipv4_banks: [BTreeMap::new(), BTreeMap::new()],
            egress_ipv6_banks: [BTreeMap::new(), BTreeMap::new()],
            active_bank: 0,
            applied_epoch: 0,
            controller_url,
            client,
            agent_token_path,
            interval,
        },
    )
}

fn dataplane_controller_client(
    controller_url: Option<&str>,
    ca_path: &Path,
    state: &AgentState,
) -> Result<ReloadingControllerClient> {
    let reloads = state.metrics.controller_trust_reloads.clone();
    let reload_errors = state.metrics.controller_trust_reload_errors.clone();
    match controller_url {
        Some(url) => {
            ReloadingControllerClient::new(url, ca_path.to_path_buf(), reloads, reload_errors)
        }
        None => Ok(ReloadingControllerClient::without_custom_trust(
            reloads,
            reload_errors,
        )),
    }
}

impl ReloadingControllerClient {
    fn new(
        controller_url: &str,
        ca_path: PathBuf,
        reloads: Counter,
        reload_errors: Counter,
    ) -> Result<Self> {
        if !controller_url.starts_with("https://") {
            bail!("controller URL must use https:// when the dataplane is connected");
        }
        let ca_pem = fs::read(&ca_path)
            .with_context(|| format!("read controller CA certificate {}", ca_path.display()))?;
        let controller_resolution = controller_service_resolution(
            controller_url,
            std::env::var("UNF_CONTROLLER_SERVICE_HOST").ok().as_deref(),
        )?;
        let client = build_controller_client(&ca_pem, &ca_path, controller_resolution.as_ref())?;
        Ok(Self {
            ca_path,
            controller_resolution,
            state: Arc::new(Mutex::new(ControllerClientState {
                observed_ca_pem: ca_pem,
                client,
            })),
            reloads,
            reload_errors,
        })
    }

    fn without_custom_trust(reloads: Counter, reload_errors: Counter) -> Self {
        Self {
            ca_path: PathBuf::new(),
            controller_resolution: None,
            state: Arc::new(Mutex::new(ControllerClientState {
                observed_ca_pem: Vec::new(),
                client: reqwest::Client::new(),
            })),
            reloads,
            reload_errors,
        }
    }

    fn current(&self) -> reqwest::Client {
        if !self.ca_path.as_os_str().is_empty() {
            match self.reload_if_changed() {
                Ok(true) => {
                    self.reloads.inc();
                    info!(path = %self.ca_path.display(), "reloaded controller CA trust bundle");
                }
                Ok(false) => {}
                Err(error) => {
                    self.reload_errors.inc();
                    warn!(%error, path = %self.ca_path.display(), "rejected controller CA trust update; retaining last-known-good bundle");
                }
            }
        }
        self.lock_state().client.clone()
    }

    fn reload_if_changed(&self) -> Result<bool> {
        let ca_pem = fs::read(&self.ca_path).with_context(|| {
            format!(
                "read updated controller CA certificate {}",
                self.ca_path.display()
            )
        })?;
        let mut state = self.lock_state();
        if ca_pem == state.observed_ca_pem {
            return Ok(false);
        }
        state.observed_ca_pem.clone_from(&ca_pem);
        let client =
            build_controller_client(&ca_pem, &self.ca_path, self.controller_resolution.as_ref())?;
        state.client = client;
        Ok(true)
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ControllerClientState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn build_controller_client(
    ca_pem: &[u8],
    ca_path: &Path,
    controller_resolution: Option<&(String, SocketAddr)>,
) -> Result<reqwest::Client> {
    let certificates = reqwest::Certificate::from_pem_bundle(ca_pem)
        .with_context(|| format!("parse controller CA bundle {}", ca_path.display()))?;
    if certificates.is_empty() {
        bail!("controller CA bundle {} is empty", ca_path.display());
    }
    let mut builder = reqwest::Client::builder()
        .timeout(CONTROLLER_REQUEST_TIMEOUT)
        .https_only(true)
        .tls_certs_only(certificates);
    if let Some((hostname, address)) = controller_resolution {
        builder = builder.resolve(hostname, *address);
    }
    builder
        .build()
        .context("construct CA-pinned controller HTTPS client")
}

fn controller_service_resolution(
    controller_url: &str,
    service_host: Option<&str>,
) -> Result<Option<(String, SocketAddr)>> {
    let url = reqwest::Url::parse(controller_url).context("parse controller URL")?;
    let hostname = url.host_str().context("controller URL has no hostname")?;
    if !matches!(
        hostname,
        "unf-controller.unf-system.svc" | "unf-controller.unf-system.svc.cluster.local"
    ) {
        return Ok(None);
    }
    let Some(service_host) = service_host else {
        return Ok(None);
    };
    let address = service_host
        .parse()
        .with_context(|| format!("parse injected controller Service address {service_host:?}"))?;
    let port = url
        .port_or_known_default()
        .context("controller URL has no known port")?;
    Ok(Some((hostname.to_owned(), SocketAddr::new(address, port))))
}

fn controller_port(controller_url: &str) -> Result<u16> {
    reqwest::Url::parse(controller_url)
        .context("parse controller URL")?
        .port_or_known_default()
        .context("controller URL has no known port")
}

fn read_agent_token(path: &Path) -> Result<String> {
    let token = fs::read_to_string(path)
        .with_context(|| format!("read agent authentication token {}", path.display()))?;
    let token = token.trim();
    if token.is_empty() {
        bail!("agent authentication token is empty");
    }
    Ok(token.to_owned())
}

fn authenticated_get(
    client: &ReloadingControllerClient,
    url: String,
    token_path: &Path,
) -> Result<reqwest::RequestBuilder> {
    Ok(client
        .current()
        .get(url)
        .bearer_auth(read_agent_token(token_path)?))
}

async fn await_background_task(task: Option<tokio::task::JoinHandle<()>>, name: &'static str) {
    if let Some(task) = task
        && let Err(error) = task.await
    {
        warn!(%error, task = name, "background task failed");
    }
}

fn load_persistent_ebpf(config: &DataplaneConfig) -> Result<(Ebpf, bool)> {
    if !config.bpf_pin_path.is_absolute() {
        bail!(
            "BPF pin path must be absolute: {}",
            config.bpf_pin_path.display()
        );
    }
    fs::create_dir_all(&config.bpf_pin_path)
        .with_context(|| format!("create BPF pin directory {}", config.bpf_pin_path.display()))?;
    let existing = PERSISTENT_MAP_NAMES
        .iter()
        .filter(|name| config.bpf_pin_path.join(name).exists())
        .count();
    if existing != 0 && existing != PERSISTENT_MAP_NAMES.len() {
        bail!(
            "partial persistent BPF map set in {} ({existing}/{} pins); refusing unsafe startup",
            config.bpf_pin_path.display(),
            PERSISTENT_MAP_NAMES.len()
        );
    }

    let mut loader = EbpfLoader::new();
    for name in PERSISTENT_MAP_NAMES {
        loader.map_pin_path(name, config.bpf_pin_path.join(name));
    }
    let ebpf = loader
        .load_file(&config.object)
        .with_context(|| format!("load eBPF object {}", config.object.display()))?;
    Ok((ebpf, existing == PERSISTENT_MAP_NAMES.len()))
}

fn recover_persistent_dataplane(
    identities: &mut IdentitySynchronizer,
    policies: &mut PolicySynchronizer,
    pins_existed: bool,
) -> Result<RecoveredDataplane> {
    for (name, map) in ["IDENTITY_V4", "IDENTITY_V4_B"]
        .into_iter()
        .zip(&identities.ipv4_maps)
    {
        validate_map_capacity(name, map.map(), IDENTITY_MAP_CAPACITY)?;
    }
    for (name, map) in ["IDENTITY_V6", "IDENTITY_V6_B"]
        .into_iter()
        .zip(&identities.ipv6_maps)
    {
        validate_map_capacity(name, map.map(), IDENTITY_MAP_CAPACITY)?;
    }
    validate_map_capacity("IDENTITY_CONFIG", identities.config.map(), 1)?;
    validate_map_capacity(
        "POLICY_RULES",
        policies.identity_map.map(),
        POLICY_MAP_CAPACITY,
    )?;
    validate_map_capacity("POLICY_IPV4", policies.ipv4_map.map(), POLICY_MAP_CAPACITY)?;
    validate_map_capacity("POLICY_IPV6", policies.ipv6_map.map(), POLICY_MAP_CAPACITY)?;
    validate_map_capacity(
        "EGRESS_IPV4",
        policies.egress_ipv4_map.map(),
        POLICY_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_IPV6",
        policies.egress_ipv6_map.map(),
        POLICY_MAP_CAPACITY,
    )?;
    validate_map_capacity("POLICY_CONFIG", policies.config.map(), 1)?;

    recover_identity_entries(identities)?;
    let identity_config = identities
        .config
        .get(&0, 0)
        .context("read persistent identity config")?;
    let decoded_identity = decode_recovered_identity_config(identity_config)?;
    let (identity_epoch, identity_revision) = if let Some((epoch, revision, count, bank)) =
        decoded_identity
    {
        let active_count = identity_entry_count_for_bank(identities, bank);
        if active_count != u64::from(count) {
            bail!(
                "persistent identity config declares {count} active entries but bank {bank} contains {active_count}"
            );
        }
        validate_active_identity_revision(identities, bank, revision)?;
        identities.active_bank = bank;
        identities.applied_epoch = epoch;
        (Some(epoch), Some(revision))
    } else {
        (None, None)
    };
    recover_policy_entries(policies)?;
    let config = policies
        .config
        .get(&0, 0)
        .context("read persistent policy config")?;
    let decoded = decode_recovered_policy_config(config)?;
    let (policy_epoch, policy_revision) = if let Some((epoch, revision, count, bank)) = decoded {
        let active_count = policy_entry_count_for_bank(policies, bank);
        if active_count != u64::from(count) {
            bail!(
                "persistent policy config declares {count} active entries but bank {bank} contains {active_count}"
            );
        }
        validate_active_policy_revision(policies, bank, revision)?;
        policies.active_bank = bank;
        policies.applied_epoch = epoch;
        (Some(epoch), Some(revision))
    } else {
        (None, None)
    };

    if pins_existed {
        info!(
            identity_entries = identity_entry_count(identities),
            identity_epoch,
            identity_revision,
            policy_epoch,
            policy_revision,
            "persistent BPF maps reopened"
        );
    }
    Ok(RecoveredDataplane {
        identity_epoch,
        identity_revision,
        policy_epoch,
        policy_revision,
    })
}

fn validate_map_capacity(name: &str, map: &MapData, expected: u32) -> Result<()> {
    let info = map
        .info()
        .with_context(|| format!("inspect persistent {name} map"))?;
    if info.max_entries() != expected {
        bail!(
            "persistent {name} capacity is {}; expected {expected}",
            info.max_entries()
        );
    }
    Ok(())
}

fn recover_identity_entries(identities: &mut IdentitySynchronizer) -> Result<()> {
    for bank in 0..usize::from(IDENTITY_BANK_COUNT) {
        let ipv4_entries = identities.ipv4_maps[bank]
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .context("iterate persistent IPv4 identities")?;
        for (key, value) in ipv4_entries {
            validate_recovered_identity_value(&value)?;
            identities.ipv4_banks[bank].insert(key, value);
        }
        let ipv6_entries = identities.ipv6_maps[bank]
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .context("iterate persistent IPv6 identities")?;
        for (key, value) in ipv6_entries {
            validate_recovered_identity_value(&value)?;
            identities.ipv6_banks[bank].insert(key, value);
        }
    }
    Ok(())
}

fn validate_recovered_identity_value(value: &[u8; 16]) -> Result<u64> {
    let identity_id = u32::from_ne_bytes(value[0..4].try_into().expect("fixed identity ID"));
    let schema = u16::from_ne_bytes(value[4..6].try_into().expect("fixed identity schema"));
    let flags = u16::from_ne_bytes(value[6..8].try_into().expect("fixed identity flags"));
    let entry_revision =
        u64::from_ne_bytes(value[8..16].try_into().expect("fixed identity revision"));
    if identity_id == 0 || schema != unf_ebpf_common::IDENTITY_MAP_ABI_VERSION || flags != 0 {
        bail!("persistent identity map contains an invalid value");
    }
    if entry_revision == 0 {
        bail!("persistent identity map contains revision zero");
    }
    Ok(entry_revision)
}

fn decode_recovered_identity_config(config: [u8; 24]) -> Result<Option<(u64, u64, u32, u8)>> {
    decode_recovered_config(
        config,
        unf_ebpf_common::IDENTITY_MAP_ABI_VERSION,
        IDENTITY_BANK_COUNT,
        "identity",
    )
}

fn identity_entry_count_for_bank(identities: &IdentitySynchronizer, bank: u8) -> u64 {
    let bank = usize::from(bank);
    (identities.ipv4_banks[bank].len() + identities.ipv6_banks[bank].len()) as u64
}

fn validate_active_identity_revision(
    identities: &IdentitySynchronizer,
    bank: u8,
    revision: u64,
) -> Result<()> {
    let bank = usize::from(bank);
    for value in identities.ipv4_banks[bank]
        .values()
        .chain(identities.ipv6_banks[bank].values())
    {
        if validate_recovered_identity_value(value)? != revision {
            bail!("persistent active identity bank contains a mixed revision");
        }
    }
    Ok(())
}

fn recover_policy_entries(policies: &mut PolicySynchronizer) -> Result<()> {
    for entry in &policies.identity_map {
        let (key, value) = entry.context("iterate persistent identity policies")?;
        let bank = policy_bank(key[11])?;
        validate_recovered_policy_value(&value)?;
        policies.identity_banks[bank].insert(key, value);
    }
    for entry in &policies.ipv4_map {
        let (key, value) = entry.context("iterate persistent IPv4 policies")?;
        let bank = policy_bank(key[11])?;
        validate_recovered_policy_value(&value)?;
        policies.ipv4_banks[bank].insert(key, value);
    }
    for entry in &policies.ipv6_map {
        let (key, value) = entry.context("iterate persistent IPv6 policies")?;
        let data = key.data();
        let bank = policy_bank(data[7])?;
        validate_recovered_policy_value(&value)?;
        policies.ipv6_banks[bank].insert((key.prefix_len(), data), value);
    }
    for entry in &policies.egress_ipv4_map {
        let (key, value) = entry.context("iterate persistent IPv4 egress policies")?;
        let bank = policy_bank(key[11])?;
        validate_recovered_policy_value(&value)?;
        policies.egress_ipv4_banks[bank].insert(key, value);
    }
    for entry in &policies.egress_ipv6_map {
        let (key, value) = entry.context("iterate persistent IPv6 egress policies")?;
        let data = key.data();
        let bank = policy_bank(data[7])?;
        validate_recovered_policy_value(&value)?;
        policies.egress_ipv6_banks[bank].insert((key.prefix_len(), data), value);
    }
    Ok(())
}

fn policy_bank(bank: u8) -> Result<usize> {
    if bank >= POLICY_BANK_COUNT {
        bail!("persistent policy map contains invalid bank {bank}");
    }
    Ok(usize::from(bank))
}

fn validate_recovered_policy_value(value: &[u8; 32]) -> Result<()> {
    let revision = u64::from_ne_bytes(value[16..24].try_into().expect("fixed policy revision"));
    let schema = u16::from_ne_bytes(value[24..26].try_into().expect("fixed policy schema"));
    let flags = u16::from_ne_bytes(value[26..28].try_into().expect("fixed policy flags"));
    let known_flags = POLICY_FLAG_HAS_POLICY
        | POLICY_FLAG_HAS_RULE
        | POLICY_FLAG_HAS_SHADOW
        | POLICY_FLAG_SHADOW_HAS_POLICY
        | POLICY_FLAG_SHADOW_HAS_RULE;
    let actual_valid = recovered_verdict_reason_is_valid(value[28], value[29])
        && recovered_provenance_is_valid(flags, value[29], false);
    let shadow_valid = if flags & POLICY_FLAG_HAS_SHADOW != 0 {
        recovered_verdict_reason_is_valid(value[30], value[31])
            && recovered_provenance_is_valid(flags, value[31], true)
    } else {
        flags & (POLICY_FLAG_SHADOW_HAS_POLICY | POLICY_FLAG_SHADOW_HAS_RULE) == 0
            && value[8..16] == [0; 8]
            && value[30..32] == [0; 2]
    };
    if revision == 0
        || schema != POLICY_MAP_ABI_VERSION
        || flags & !known_flags != 0
        || !actual_valid
        || !shadow_valid
    {
        bail!("persistent policy map contains an incompatible value");
    }
    Ok(())
}

fn recovered_verdict_reason_is_valid(verdict: u8, reason: u8) -> bool {
    matches!((verdict, reason), (1, 0..=2) | (2, 1 | 2))
}

fn recovered_provenance_is_valid(flags: u16, reason: u8, shadow: bool) -> bool {
    let (policy_flag, rule_flag) = if shadow {
        (POLICY_FLAG_SHADOW_HAS_POLICY, POLICY_FLAG_SHADOW_HAS_RULE)
    } else {
        (POLICY_FLAG_HAS_POLICY, POLICY_FLAG_HAS_RULE)
    };
    let has_policy = flags & policy_flag != 0;
    let has_rule = flags & rule_flag != 0;
    match reason {
        reason if reason == PolicyReason::NoApplicablePolicy as u8 => !has_policy && !has_rule,
        reason if reason == PolicyReason::ExplicitRule as u8 => has_policy && has_rule,
        reason if reason == PolicyReason::DefaultAction as u8 => has_policy && !has_rule,
        _ => false,
    }
}

fn decode_recovered_policy_config(config: [u8; 24]) -> Result<Option<(u64, u64, u32, u8)>> {
    decode_recovered_config(config, POLICY_MAP_ABI_VERSION, POLICY_BANK_COUNT, "policy")
}

fn decode_recovered_config(
    config: [u8; 24],
    expected_schema: u16,
    bank_count: u8,
    state_name: &str,
) -> Result<Option<(u64, u64, u32, u8)>> {
    if config == [0; 24] {
        return Ok(None);
    }
    let epoch = u64::from_ne_bytes(config[0..8].try_into().expect("fixed policy epoch"));
    let revision = u64::from_ne_bytes(config[8..16].try_into().expect("fixed policy revision"));
    let count = u32::from_ne_bytes(config[16..20].try_into().expect("fixed policy count"));
    let schema = u16::from_ne_bytes(config[20..22].try_into().expect("fixed policy schema"));
    let bank = config[22];
    if epoch == 0
        || revision == 0
        || schema != expected_schema
        || bank >= bank_count
        || config[23] != 0
    {
        bail!("persistent {state_name} config is invalid or incompatible");
    }
    Ok(Some((epoch, revision, count, bank)))
}

fn policy_entry_count_for_bank(policies: &PolicySynchronizer, bank: u8) -> u64 {
    let bank = usize::from(bank);
    (policies.identity_banks[bank].len()
        + policies.ipv4_banks[bank].len()
        + policies.ipv6_banks[bank].len()
        + policies.egress_ipv4_banks[bank].len()
        + policies.egress_ipv6_banks[bank].len()) as u64
}

fn validate_active_policy_revision(
    policies: &PolicySynchronizer,
    bank: u8,
    revision: u64,
) -> Result<()> {
    let bank = usize::from(bank);
    for value in policies.identity_banks[bank]
        .values()
        .chain(policies.ipv4_banks[bank].values())
        .chain(policies.ipv6_banks[bank].values())
        .chain(policies.egress_ipv4_banks[bank].values())
        .chain(policies.egress_ipv6_banks[bank].values())
    {
        let entry_revision =
            u64::from_ne_bytes(value[16..24].try_into().expect("fixed policy revision"));
        if entry_revision != revision {
            bail!("persistent active policy bank contains a mixed revision");
        }
    }
    Ok(())
}

fn apply_recovered_state(
    state: &AgentState,
    identities: &IdentitySynchronizer,
    policies: &PolicySynchronizer,
    recovered: &RecoveredDataplane,
) {
    let identity_entries = identity_entry_count(identities);
    let identity_bank = usize::from(identities.active_bank);
    state
        .identity_map_entries
        .store(identity_entries, Ordering::Release);
    state.ipv4_identity_map_entries.store(
        identities.ipv4_banks[identity_bank].len() as u64,
        Ordering::Release,
    );
    state.ipv6_identity_map_entries.store(
        identities.ipv6_banks[identity_bank].len() as u64,
        Ordering::Release,
    );
    state
        .metrics
        .identity_map_entries
        .set(metric_value(identity_entries));
    state.metrics.ipv4_identity_map_entries.set(metric_value(
        identities.ipv4_banks[identity_bank].len() as u64,
    ));
    state.metrics.ipv6_identity_map_entries.set(metric_value(
        identities.ipv6_banks[identity_bank].len() as u64,
    ));
    if let (Some(epoch), Some(revision)) = (recovered.identity_epoch, recovered.identity_revision) {
        state.applied_identity_epoch.store(epoch, Ordering::Release);
        state
            .applied_identity_revision
            .store(revision, Ordering::Release);
        state
            .metrics
            .applied_identity_revision
            .set(metric_value(revision));
    }
    if let (Some(epoch), Some(revision)) = (recovered.policy_epoch, recovered.policy_revision) {
        state.applied_policy_epoch.store(epoch, Ordering::Release);
        state
            .applied_policy_revision
            .store(revision, Ordering::Release);
        let entries = active_policy_entry_count(policies);
        state.policy_map_entries.store(entries, Ordering::Release);
        state
            .active_policy_bank
            .store(u64::from(policies.active_bank), Ordering::Release);
        state
            .metrics
            .applied_policy_revision
            .set(metric_value(revision));
        state.metrics.policy_map_entries.set(metric_value(entries));
    }
}

fn take_identity_maps(ebpf: &mut Ebpf) -> Result<IdentityMaps> {
    let ipv4_a = AyaHashMap::<_, [u8; 4], [u8; 16]>::try_from(
        ebpf.take_map("IDENTITY_V4")
            .context("eBPF object does not contain IDENTITY_V4 map")?,
    )
    .context("open IDENTITY_V4 map")?;
    let ipv4_b = AyaHashMap::<_, [u8; 4], [u8; 16]>::try_from(
        ebpf.take_map("IDENTITY_V4_B")
            .context("eBPF object does not contain IDENTITY_V4_B map")?,
    )
    .context("open IDENTITY_V4_B map")?;
    let ipv6_a = AyaHashMap::<_, [u8; 16], [u8; 16]>::try_from(
        ebpf.take_map("IDENTITY_V6")
            .context("eBPF object does not contain IDENTITY_V6 map")?,
    )
    .context("open IDENTITY_V6 map")?;
    let ipv6_b = AyaHashMap::<_, [u8; 16], [u8; 16]>::try_from(
        ebpf.take_map("IDENTITY_V6_B")
            .context("eBPF object does not contain IDENTITY_V6_B map")?,
    )
    .context("open IDENTITY_V6_B map")?;
    let config = AyaArray::<_, [u8; 24]>::try_from(
        ebpf.take_map("IDENTITY_CONFIG")
            .context("eBPF object does not contain IDENTITY_CONFIG map")?,
    )
    .context("open IDENTITY_CONFIG map")?;
    Ok(([ipv4_a, ipv4_b], [ipv6_a, ipv6_b], config))
}

fn spawn_flow_exporter(
    controller_url: Option<String>,
    client: ReloadingControllerClient,
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
    let token_path = config.agent_token_path.clone();
    let interval = config.flow_export_interval;
    let task = tokio::spawn(async move {
        let exporter = FlowExporterConfig {
            controller_url,
            client,
            node_name,
            token_path,
            interval,
        };
        export_flow_batches(exporter, receiver, exporter_state, exporter_cancel).await;
    });
    (Some(sender), Some(task))
}

fn spawn_agent_status_reporter(
    controller_url: Option<String>,
    client: ReloadingControllerClient,
    config: &DataplaneConfig,
    state: &Arc<AgentState>,
    cancellation: &CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let controller_url = controller_url?;
    let reporter_state = Arc::clone(state);
    let reporter_cancel = cancellation.clone();
    let interval = config.identity_sync_interval;
    let token_path = config.agent_token_path.clone();
    Some(tokio::spawn(async move {
        report_agent_status(
            controller_url,
            client,
            token_path,
            reporter_state,
            reporter_cancel,
            interval,
        )
        .await;
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
    let egress_ipv4_map = AyaHashMap::<_, [u8; 12], [u8; 32]>::try_from(
        ebpf.take_map("EGRESS_IPV4")
            .context("eBPF object does not contain EGRESS_IPV4 map")?,
    )
    .context("open EGRESS_IPV4 map")?;
    let egress_ipv6_map = AyaLpmTrie::<_, [u8; 24], [u8; 32]>::try_from(
        ebpf.take_map("EGRESS_IPV6")
            .context("eBPF object does not contain EGRESS_IPV6 map")?,
    )
    .context("open EGRESS_IPV6 map")?;
    let policy_config = AyaArray::<_, [u8; 24]>::try_from(
        ebpf.take_map("POLICY_CONFIG")
            .context("eBPF object does not contain POLICY_CONFIG map")?,
    )
    .context("open POLICY_CONFIG map")?;
    Ok((
        policy_map,
        ipv4_policy_map,
        ipv6_policy_map,
        egress_ipv4_map,
        egress_ipv6_map,
        policy_config,
    ))
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
                } else {
                    refresh_controller_readiness(state);
                }
            }
            _ = policy_interval.tick(), if policies.controller_url.is_some() => {
                if let Err(error) = synchronize_policies(policies, state).await {
                    state.metrics.policy_sync_errors.inc();
                    warn!(?error, "policy synchronization failed");
                } else {
                    refresh_controller_readiness(state);
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
                    if identities.controller_management_port
                        .is_some_and(|port| is_controller_management_flow(&event, port))
                    {
                        state.metrics.management_flow_events_filtered.inc();
                        continue;
                    }
                    state.metrics.flow_events.inc();
                    state.observed_flows.fetch_add(1, Ordering::Relaxed);
                    if let Some(sender) = flow_export_sender
                        && event_has_selected_identity(&event)
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

fn is_controller_management_flow(event: &FlowEvent, port: u16) -> bool {
    event.flow.protocol == 6
        && (u16::from_be_bytes(event.flow.source_port) == port
            || u16::from_be_bytes(event.flow.destination_port) == port)
}

fn refresh_controller_readiness(state: &AgentState) {
    let synchronized = state.applied_identity_epoch.load(Ordering::Acquire) != 0
        && state.applied_policy_epoch.load(Ordering::Acquire) != 0;
    if synchronized && state.bpf_loaded.load(Ordering::Acquire) {
        state.ready.store(true, Ordering::Release);
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
            direction: policy_direction(event.direction).unwrap_or_default(),
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

const fn policy_direction(direction: u8) -> Option<PolicyDirection> {
    match direction {
        1 => Some(PolicyDirection::Ingress),
        2 => Some(PolicyDirection::Egress),
        _ => None,
    }
}

fn event_has_selected_identity(event: &FlowEvent) -> bool {
    match policy_direction(event.direction) {
        Some(PolicyDirection::Ingress) => event.flow.destination_identity.get() != 0,
        Some(PolicyDirection::Egress) => event.flow.source_identity.get() != 0,
        None => false,
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
    config: FlowExporterConfig,
    mut receiver: mpsc::Receiver<FlowExportRecord>,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
) {
    let mut interval = tokio::time::interval(config.interval);
    let mut pending = BTreeMap::new();
    let mut last_exported_key = None;
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
                let entries = pending_flow_batch(
                    &pending,
                    last_exported_key.as_ref(),
                    FLOW_EXPORT_BATCH_LIMIT,
                );
                let batch = FlowExportBatch {
                    schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                    node_name: config.node_name.clone(),
                    dropped_events,
                    entries: entries.clone(),
                };
                let token = match read_agent_token(&config.token_path) {
                    Ok(token) => token,
                    Err(error) => {
                        state.metrics.telemetry_export_errors.inc();
                        warn!(%error, "could not load flow telemetry authentication token");
                        continue;
                    }
                };
                let result = config.client.current()
                    .post(format!("{}/v1/telemetry/flows", config.controller_url))
                    .bearer_auth(token)
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
                        if let Some(entry) = entries.last() {
                            last_exported_key = Some(entry.key.clone());
                        }
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

fn pending_flow_batch(
    pending: &BTreeMap<FlowHistoryKey, FlowExportRecord>,
    after: Option<&FlowHistoryKey>,
    limit: usize,
) -> Vec<FlowExportRecord> {
    if limit == 0 || pending.is_empty() {
        return Vec::new();
    }
    let mut entries = Vec::with_capacity(limit.min(pending.len()));
    if let Some(after) = after {
        entries.extend(
            pending
                .range((Excluded(after), Unbounded))
                .take(limit)
                .map(|(_, record)| record.clone()),
        );
        if entries.len() < limit {
            entries.extend(
                pending
                    .range(..=after)
                    .take(limit - entries.len())
                    .map(|(_, record)| record.clone()),
            );
        }
    } else {
        entries.extend(pending.values().take(limit).cloned());
    }
    entries
}

async fn report_agent_status(
    controller_url: String,
    client: ReloadingControllerClient,
    token_path: PathBuf,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
    report_interval: Duration,
) {
    let mut interval = tokio::time::interval(report_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = interval.tick() => {
                let token = match read_agent_token(&token_path) {
                    Ok(token) => token,
                    Err(error) => {
                        warn!(%error, path = %token_path.display(), "could not read agent authentication token");
                        continue;
                    }
                };
                let result = client.current()
                    .post(format!("{controller_url}/v1/state/agents"))
                    .bearer_auth(token)
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
        pod_name: state.pod_name.clone(),
        pod_uid: state.pod_uid.clone(),
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
    let snapshot = request_identity_snapshot(synchronizer).await?;
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
    let staging_bank = (synchronizer.active_bank + 1) % IDENTITY_BANK_COUNT;
    apply_identity_entries(
        synchronizer,
        desired_ipv4,
        desired_ipv6,
        snapshot.source_epoch,
        desired_revision,
        staging_bank,
    )?;
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
    state.ipv4_identity_map_entries.store(
        synchronizer.ipv4_banks[usize::from(synchronizer.active_bank)].len() as u64,
        Ordering::Release,
    );
    state.ipv6_identity_map_entries.store(
        synchronizer.ipv6_banks[usize::from(synchronizer.active_bank)].len() as u64,
        Ordering::Release,
    );
    state
        .metrics
        .applied_identity_revision
        .set(metric_value(desired_revision));
    state
        .metrics
        .identity_map_entries
        .set(metric_value(identity_entry_count(synchronizer)));
    state.metrics.ipv4_identity_map_entries.set(metric_value(
        synchronizer.ipv4_banks[usize::from(synchronizer.active_bank)].len() as u64,
    ));
    state.metrics.ipv6_identity_map_entries.set(metric_value(
        synchronizer.ipv6_banks[usize::from(synchronizer.active_bank)].len() as u64,
    ));
    info!(
        identity_epoch = snapshot.source_epoch,
        identity_revision = desired_revision,
        ipv4_entries = synchronizer.ipv4_banks[usize::from(synchronizer.active_bank)].len(),
        ipv6_entries = synchronizer.ipv6_banks[usize::from(synchronizer.active_bank)].len(),
        active_identity_bank = synchronizer.active_bank,
        "identity snapshot applied"
    );
    Ok(())
}

async fn request_identity_snapshot(
    synchronizer: &IdentitySynchronizer,
) -> Result<IdentityStateSnapshot> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("identity synchronization requires a controller URL")?;
    authenticated_get(
        &synchronizer.client,
        format!("{controller_url}/v1/state/identities"),
        &synchronizer.agent_token_path,
    )?
    .send()
    .await
    .context("request controller identity snapshot")?
    .error_for_status()
    .context("controller rejected identity snapshot request")?
    .json()
    .await
    .context("decode controller identity snapshot")
}

fn identity_entry_count(synchronizer: &IdentitySynchronizer) -> u64 {
    identity_entry_count_for_bank(synchronizer, synchronizer.active_bank)
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
    desired_ipv4: EncodedIpv4IdentityBank,
    desired_ipv6: EncodedIpv6IdentityBank,
    source_epoch: u64,
    revision: u64,
    staging_bank: u8,
) -> Result<()> {
    if staging_bank >= IDENTITY_BANK_COUNT {
        bail!("invalid identity staging bank {staging_bank}");
    }
    let staging = usize::from(staging_bank);
    let previous_ipv4 = synchronizer.ipv4_banks[staging].clone();
    let previous_ipv6 = synchronizer.ipv6_banks[staging].clone();
    if let Err(error) = replace_ipv4_identity_entries(
        &mut synchronizer.ipv4_maps[staging],
        &previous_ipv4,
        &desired_ipv4,
    ) {
        return Err(rollback_identity_stage(
            synchronizer,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &error.context("stage IPv4 identity bank"),
        ));
    }
    if let Err(error) = replace_ipv6_identity_entries(
        &mut synchronizer.ipv6_maps[staging],
        &previous_ipv6,
        &desired_ipv6,
    ) {
        return Err(rollback_identity_stage(
            synchronizer,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &error.context("stage IPv6 identity bank"),
        ));
    }
    let validation =
        validate_staged_ipv4_identity_entries(&synchronizer.ipv4_maps[staging], &desired_ipv4)
            .and_then(|()| {
                validate_staged_ipv6_identity_entries(
                    &synchronizer.ipv6_maps[staging],
                    &desired_ipv6,
                )
            });
    if let Err(error) = validation {
        return Err(rollback_identity_stage(
            synchronizer,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &error,
        ));
    }
    let config = match encode_identity_config(
        source_epoch,
        revision,
        desired_ipv4.len() + desired_ipv6.len(),
        staging_bank,
    ) {
        Ok(config) => config,
        Err(error) => {
            return Err(rollback_identity_stage(
                synchronizer,
                &previous_ipv4,
                &previous_ipv6,
                staging_bank,
                &error,
            ));
        }
    };
    if let Err(error) = synchronizer.config.set(0, config, 0) {
        return Err(rollback_identity_stage(
            synchronizer,
            &previous_ipv4,
            &previous_ipv6,
            staging_bank,
            &anyhow!(error).context("atomically activate staged identity bank"),
        ));
    }

    synchronizer.ipv4_banks[staging] = desired_ipv4;
    synchronizer.ipv6_banks[staging] = desired_ipv6;
    synchronizer.active_bank = staging_bank;
    Ok(())
}

fn encode_identity_config(
    source_epoch: u64,
    revision: u64,
    entry_count: usize,
    active_bank: u8,
) -> Result<[u8; 24]> {
    encode_map_config(
        source_epoch,
        revision,
        entry_count,
        unf_ebpf_common::IDENTITY_MAP_ABI_VERSION,
        active_bank,
        IDENTITY_BANK_COUNT,
        "identity",
    )
}

fn validate_staged_ipv4_identity_entries(
    map: &EncodedIpv4IdentityMap,
    desired: &EncodedIpv4IdentityBank,
) -> Result<()> {
    for (key, expected) in desired {
        let actual = map
            .get(key, 0)
            .with_context(|| format!("read staged IPv4 identity key {key:?}"))?;
        if &actual != expected {
            bail!("staged IPv4 identity validation mismatch for key {key:?}");
        }
    }
    Ok(())
}

fn validate_staged_ipv6_identity_entries(
    map: &EncodedIpv6IdentityMap,
    desired: &EncodedIpv6IdentityBank,
) -> Result<()> {
    for (key, expected) in desired {
        let actual = map
            .get(key, 0)
            .with_context(|| format!("read staged IPv6 identity key {key:?}"))?;
        if &actual != expected {
            bail!("staged IPv6 identity validation mismatch for key {key:?}");
        }
    }
    Ok(())
}

fn rollback_identity_stage(
    synchronizer: &mut IdentitySynchronizer,
    previous_ipv4: &EncodedIpv4IdentityBank,
    previous_ipv6: &EncodedIpv6IdentityBank,
    bank: u8,
    cause: &anyhow::Error,
) -> anyhow::Error {
    let bank = usize::from(bank);
    let ipv4 = restore_ipv4_identity_entries(&mut synchronizer.ipv4_maps[bank], previous_ipv4);
    let ipv6 = restore_ipv6_identity_entries(&mut synchronizer.ipv6_maps[bank], previous_ipv6);
    match (ipv4, ipv6) {
        (Ok(()), Ok(())) => {
            anyhow!("identity update failed and staging banks were rolled back: {cause:#}")
        }
        (ipv4, ipv6) => anyhow!(
            "identity update failed: {cause:#}; IPv4 rollback: {ipv4:?}; IPv6 rollback: {ipv6:?}"
        ),
    }
}

fn replace_ipv4_identity_entries(
    map: &mut EncodedIpv4IdentityMap,
    current: &EncodedIpv4IdentityBank,
    desired: &EncodedIpv4IdentityBank,
) -> Result<()> {
    for key in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(key)
            .with_context(|| format!("remove stale IPv4 identity map key {key:?}"))?;
    }
    for (key, value) in desired {
        map.insert(key, value, 0)
            .with_context(|| format!("insert IPv4 identity map key {key:?}"))?;
    }
    Ok(())
}

fn restore_ipv4_identity_entries(
    map: &mut EncodedIpv4IdentityMap,
    previous: &EncodedIpv4IdentityBank,
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
    map: &mut EncodedIpv6IdentityMap,
    current: &EncodedIpv6IdentityBank,
    desired: &EncodedIpv6IdentityBank,
) -> Result<()> {
    for key in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(key)
            .with_context(|| format!("remove stale IPv6 identity map key {key:?}"))?;
    }
    for (key, value) in desired {
        map.insert(key, value, 0)?;
    }
    Ok(())
}

fn restore_ipv6_identity_entries(
    map: &mut EncodedIpv6IdentityMap,
    previous: &EncodedIpv6IdentityBank,
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

#[allow(clippy::too_many_lines)]
async fn synchronize_policies(
    synchronizer: &mut PolicySynchronizer,
    state: &AgentState,
) -> Result<()> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("policy synchronization requires a controller URL")?;
    let snapshot: PolicyStateSnapshot = authenticated_get(
        &synchronizer.client,
        format!("{controller_url}/v1/state/policies"),
        &synchronizer.agent_token_path,
    )?
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
    let desired_egress_ipv4 = desired_egress_ipv4_policy_entries(
        &snapshot.egress_ipv4_entries,
        desired_revision,
        staging_bank,
    )?;
    let desired_egress_ipv6 = desired_egress_ipv6_policy_entries(
        &snapshot.egress_ipv6_entries,
        desired_revision,
        staging_bank,
    )?;
    apply_policy_entries(
        synchronizer,
        desired,
        desired_ipv4,
        desired_ipv6,
        desired_egress_ipv4,
        desired_egress_ipv6,
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
        + synchronizer.ipv6_banks[active].len()
        + synchronizer.egress_ipv4_banks[active].len()
        + synchronizer.egress_ipv6_banks[active].len()) as u64
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

fn desired_egress_ipv4_policy_entries(
    entries: &[EgressIpv4PolicyMapEntry],
    revision: u64,
    bank: u8,
) -> Result<BTreeMap<[u8; 12], [u8; 32]>> {
    if bank >= POLICY_BANK_COUNT {
        bail!("invalid policy bank {bank}");
    }
    validate_policy_bank_capacity(entries.len())?;
    let mut desired = BTreeMap::new();
    for entry in entries {
        validate_egress_ipv4_policy_entry(entry)?;
        let key = encode_egress_ipv4_policy_key(entry, bank);
        let value = encode_policy_decisions(&entry.decision, entry.shadow.as_ref(), revision);
        if desired.insert(key, value).is_some() {
            bail!("controller snapshot contains a duplicate IPv4 egress policy key");
        }
    }
    Ok(desired)
}

fn desired_egress_ipv6_policy_entries(
    entries: &[EgressIpv6PolicyMapEntry],
    revision: u64,
    bank: u8,
) -> Result<EncodedIpv6PolicyBank> {
    if bank >= POLICY_BANK_COUNT {
        bail!("invalid policy bank {bank}");
    }
    validate_policy_bank_capacity(entries.len())?;
    let mut desired = BTreeMap::new();
    for entry in entries {
        validate_egress_ipv6_policy_entry(entry)?;
        let key = encode_egress_ipv6_policy_key(entry, bank);
        let value = encode_policy_decisions(&entry.decision, entry.shadow.as_ref(), revision);
        if desired.insert(key, value).is_some() {
            bail!("controller snapshot contains a duplicate IPv6 egress policy key");
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

fn validate_egress_ipv4_policy_entry(entry: &EgressIpv4PolicyMapEntry) -> Result<()> {
    if entry.key.source_identity.get() == 0 {
        bail!("IPv4 egress policy entry contains reserved source identity ID zero");
    }
    validate_policy_transport(
        entry.key.protocol,
        entry.key.destination_port,
        "IPv4 egress",
    )?;
    validate_policy_decision(&entry.decision)?;
    if let Some(shadow) = &entry.shadow {
        validate_policy_decision(shadow)?;
    }
    Ok(())
}

fn validate_egress_ipv6_policy_entry(entry: &EgressIpv6PolicyMapEntry) -> Result<()> {
    if entry.key.source_identity.get() == 0 {
        bail!("IPv6 egress policy entry contains reserved source identity ID zero");
    }
    if entry.key.destination_prefix_len > 128 {
        bail!("IPv6 egress policy entry contains an invalid destination prefix length");
    }
    let prefix = entry.key.destination_prefix_len;
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    if u128::from(entry.key.destination_network) & mask != u128::from(entry.key.destination_network)
    {
        bail!("IPv6 egress policy entry destination network is not canonical");
    }
    validate_policy_transport(
        entry.key.protocol,
        entry.key.destination_port,
        "IPv6 egress",
    )?;
    validate_policy_decision(&entry.decision)?;
    if let Some(shadow) = &entry.shadow {
        validate_policy_decision(shadow)?;
    }
    Ok(())
}

fn validate_policy_transport(protocol: u8, destination_port: u16, label: &str) -> Result<()> {
    match (protocol, destination_port) {
        (0, 0) | (6 | 17 | 132, 0..=u16::MAX) => Ok(()),
        _ => bail!("{label} policy entry contains an invalid protocol/port wildcard combination"),
    }
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

fn encode_egress_ipv4_policy_key(entry: &EgressIpv4PolicyMapEntry, bank: u8) -> [u8; 12] {
    let mut encoded = [0_u8; 12];
    encoded[0..4].copy_from_slice(&entry.key.destination_address.octets());
    encoded[4..8].copy_from_slice(&entry.key.source_identity.get().to_ne_bytes());
    encoded[8..10].copy_from_slice(&entry.key.destination_port.to_be_bytes());
    encoded[10] = entry.key.protocol;
    encoded[11] = bank;
    encoded
}

fn encode_egress_ipv6_policy_key(entry: &EgressIpv6PolicyMapEntry, bank: u8) -> (u32, [u8; 24]) {
    let mut encoded = [0_u8; 24];
    encoded[0..4].copy_from_slice(&entry.key.source_identity.get().to_ne_bytes());
    encoded[4..6].copy_from_slice(&entry.key.destination_port.to_be_bytes());
    encoded[6] = entry.key.protocol;
    encoded[7] = bank;
    encoded[8..24].copy_from_slice(&entry.key.destination_network.octets());
    (64 + u32::from(entry.key.destination_prefix_len), encoded)
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
    encode_map_config(
        source_epoch,
        revision,
        entry_count,
        POLICY_MAP_ABI_VERSION,
        active_bank,
        POLICY_BANK_COUNT,
        "policy",
    )
}

fn encode_map_config(
    source_epoch: u64,
    revision: u64,
    entry_count: usize,
    schema_version: u16,
    active_bank: u8,
    bank_count: u8,
    state_name: &str,
) -> Result<[u8; 24]> {
    if active_bank >= bank_count {
        bail!("invalid {state_name} bank {active_bank}");
    }
    let entry_count = u32::try_from(entry_count)
        .with_context(|| format!("{state_name} entry count exceeds u32"))?;
    let mut encoded = [0_u8; 24];
    encoded[0..8].copy_from_slice(&source_epoch.to_ne_bytes());
    encoded[8..16].copy_from_slice(&revision.to_ne_bytes());
    encoded[16..20].copy_from_slice(&entry_count.to_ne_bytes());
    encoded[20..22].copy_from_slice(&schema_version.to_ne_bytes());
    encoded[22] = active_bank;
    Ok(encoded)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn apply_policy_entries(
    synchronizer: &mut PolicySynchronizer,
    desired: BTreeMap<[u8; 12], [u8; 32]>,
    desired_ipv4: BTreeMap<[u8; 12], [u8; 32]>,
    desired_ipv6: EncodedIpv6PolicyBank,
    desired_egress_ipv4: BTreeMap<[u8; 12], [u8; 32]>,
    desired_egress_ipv6: EncodedIpv6PolicyBank,
    source_epoch: u64,
    revision: u64,
    staging_bank: u8,
) -> Result<()> {
    let staging_index = usize::from(staging_bank);
    let previous_identity = synchronizer.identity_banks[staging_index].clone();
    let previous_ipv4 = synchronizer.ipv4_banks[staging_index].clone();
    let previous_ipv6 = synchronizer.ipv6_banks[staging_index].clone();
    let previous_egress_ipv4 = synchronizer.egress_ipv4_banks[staging_index].clone();
    let previous_egress_ipv6 = synchronizer.egress_ipv6_banks[staging_index].clone();
    if let Err(error) =
        replace_policy_entries(&mut synchronizer.identity_map, &previous_identity, &desired)
    {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            &previous_egress_ipv4,
            &previous_egress_ipv6,
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
            &previous_egress_ipv4,
            &previous_egress_ipv6,
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
            &previous_egress_ipv4,
            &previous_egress_ipv6,
            staging_bank,
            &error.context("stage IPv6 policy map bank"),
        ));
    }
    if let Err(error) = replace_policy_entries(
        &mut synchronizer.egress_ipv4_map,
        &previous_egress_ipv4,
        &desired_egress_ipv4,
    ) {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            &previous_egress_ipv4,
            &previous_egress_ipv6,
            staging_bank,
            &error.context("stage IPv4 egress policy map bank"),
        ));
    }
    if let Err(error) = replace_ipv6_policy_entries(
        &mut synchronizer.egress_ipv6_map,
        &previous_egress_ipv6,
        &desired_egress_ipv6,
    ) {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            &previous_egress_ipv4,
            &previous_egress_ipv6,
            staging_bank,
            &error.context("stage IPv6 egress policy map bank"),
        ));
    }
    let validation = validate_staged_policy_entries(&synchronizer.identity_map, &desired)
        .and_then(|()| validate_staged_policy_entries(&synchronizer.ipv4_map, &desired_ipv4))
        .and_then(|()| validate_staged_ipv6_policy_entries(&synchronizer.ipv6_map, &desired_ipv6))
        .and_then(|()| {
            validate_staged_policy_entries(&synchronizer.egress_ipv4_map, &desired_egress_ipv4)
        })
        .and_then(|()| {
            validate_staged_ipv6_policy_entries(&synchronizer.egress_ipv6_map, &desired_egress_ipv6)
        });
    if let Err(error) = validation {
        return Err(rollback_policy_stages(
            synchronizer,
            &previous_identity,
            &previous_ipv4,
            &previous_ipv6,
            &previous_egress_ipv4,
            &previous_egress_ipv6,
            staging_bank,
            &error,
        ));
    }
    let entry_count = desired.len()
        + desired_ipv4.len()
        + desired_ipv6.len()
        + desired_egress_ipv4.len()
        + desired_egress_ipv6.len();
    let config = match encode_policy_config(source_epoch, revision, entry_count, staging_bank) {
        Ok(config) => config,
        Err(error) => {
            return Err(rollback_policy_stages(
                synchronizer,
                &previous_identity,
                &previous_ipv4,
                &previous_ipv6,
                &previous_egress_ipv4,
                &previous_egress_ipv6,
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
            &previous_egress_ipv4,
            &previous_egress_ipv6,
            staging_bank,
            &anyhow!(error).context("atomically activate staged policy bank"),
        ));
    }

    let previous_active = synchronizer.active_bank;
    synchronizer.identity_banks[staging_index] = desired;
    synchronizer.ipv4_banks[staging_index] = desired_ipv4;
    synchronizer.ipv6_banks[staging_index] = desired_ipv6;
    synchronizer.egress_ipv4_banks[staging_index] = desired_egress_ipv4;
    synchronizer.egress_ipv6_banks[staging_index] = desired_egress_ipv6;
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
        if let Err(error) = clear_policy_bank(
            &mut synchronizer.egress_ipv4_map,
            &synchronizer.egress_ipv4_banks[previous_index],
        ) {
            warn!(
                ?error,
                bank = previous_active,
                "could not garbage-collect old IPv4 egress policy bank"
            );
        } else {
            synchronizer.egress_ipv4_banks[previous_index].clear();
        }
        if let Err(error) = clear_ipv6_policy_bank(
            &mut synchronizer.egress_ipv6_map,
            &synchronizer.egress_ipv6_banks[previous_index],
        ) {
            warn!(
                ?error,
                bank = previous_active,
                "could not garbage-collect old IPv6 egress policy bank"
            );
        } else {
            synchronizer.egress_ipv6_banks[previous_index].clear();
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

#[allow(clippy::too_many_arguments)]
fn rollback_policy_stages(
    synchronizer: &mut PolicySynchronizer,
    previous_identity: &BTreeMap<[u8; 12], [u8; 32]>,
    previous_ipv4: &BTreeMap<[u8; 12], [u8; 32]>,
    previous_ipv6: &EncodedIpv6PolicyBank,
    previous_egress_ipv4: &BTreeMap<[u8; 12], [u8; 32]>,
    previous_egress_ipv6: &EncodedIpv6PolicyBank,
    bank: u8,
    cause: &anyhow::Error,
) -> anyhow::Error {
    let identity_rollback =
        restore_policy_entries(&mut synchronizer.identity_map, previous_identity, bank);
    let ipv4_rollback = restore_policy_entries(&mut synchronizer.ipv4_map, previous_ipv4, bank);
    let ipv6_rollback =
        restore_ipv6_policy_entries(&mut synchronizer.ipv6_map, previous_ipv6, bank);
    let egress_ipv4_rollback = restore_policy_entries(
        &mut synchronizer.egress_ipv4_map,
        previous_egress_ipv4,
        bank,
    );
    let egress_ipv6_rollback = restore_ipv6_policy_entries(
        &mut synchronizer.egress_ipv6_map,
        previous_egress_ipv6,
        bank,
    );
    match (
        identity_rollback,
        ipv4_rollback,
        ipv6_rollback,
        egress_ipv4_rollback,
        egress_ipv6_rollback,
    ) {
        (Ok(()), Ok(()), Ok(()), Ok(()), Ok(())) => {
            anyhow!("policy update failed and staging banks were rolled back: {cause:#}")
        }
        (identity, ipv4, ipv6, egress_ipv4, egress_ipv6) => anyhow!(
            "policy update failed: {cause:#}; identity rollback: {identity:?}; IPv4 rollback: {ipv4:?}; IPv6 rollback: {ipv6:?}; IPv4 egress rollback: {egress_ipv4:?}; IPv6 egress rollback: {egress_ipv6:?}"
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
    mode: TcAttachmentMode,
    pin_root: &Path,
    attached: &mut HashMap<String, u32>,
) -> Result<()> {
    let discovered = discover_interfaces()?;
    attached.retain(|interface, if_index| discovered.get(interface) == Some(if_index));
    let unattached: Vec<_> = discovered
        .iter()
        .filter(|(interface, if_index)| attached.get(*interface) != Some(*if_index))
        .map(|(interface, if_index)| (interface.clone(), *if_index))
        .collect();
    for (interface, if_index) in unattached {
        match attach_interface(
            program,
            &interface,
            if_index,
            attach_type,
            direction,
            mode,
            pin_root,
        ) {
            Ok(()) => {
                attached.insert(interface, if_index);
            }
            Err(error) => warn!(?error, %interface, "could not attach TC observation program"),
        }
    }
    if mode == TcAttachmentMode::TcxPinned {
        cleanup_stale_tcx_links(pin_root, direction, discovered.values().copied())?;
    }
    Ok(())
}

fn discover_interfaces() -> Result<HashMap<String, u32>> {
    let mut interfaces = HashMap::new();
    for entry in fs::read_dir("/sys/class/net").context("enumerate network interfaces")? {
        let entry = entry.context("read network interface directory entry")?;
        let Some(interface) = entry.file_name().into_string().ok() else {
            continue;
        };
        if interface == "lo" {
            continue;
        }
        let if_index = interface_index(&interface)?;
        interfaces.insert(interface, if_index);
    }
    Ok(interfaces)
}

fn interface_index(interface: &str) -> Result<u32> {
    let value = fs::read_to_string(Path::new("/sys/class/net").join(interface).join("ifindex"))
        .with_context(|| format!("read interface index for {interface}"))?;
    value
        .trim()
        .parse()
        .with_context(|| format!("parse interface index for {interface}"))
}

fn attach_interface(
    program: &mut SchedClassifier,
    interface: &str,
    if_index: u32,
    attach_type: TcAttachType,
    direction: Direction,
    mode: TcAttachmentMode,
    pin_root: &Path,
) -> Result<()> {
    match mode {
        TcAttachmentMode::TcxPinned => {
            attach_pinned_tcx(
                program,
                interface,
                if_index,
                attach_type,
                direction,
                pin_root,
            )?;
        }
        TcAttachmentMode::LegacyNetlink => {
            attach_persistent_netlink(program, interface, attach_type, direction)?;
        }
        TcAttachmentMode::None => bail!("TC attachment mode was not selected"),
    }
    Ok(())
}

fn attach_pinned_tcx(
    program: &mut SchedClassifier,
    interface: &str,
    if_index: u32,
    attach_type: TcAttachType,
    direction: Direction,
    pin_root: &Path,
) -> Result<()> {
    fs::create_dir_all(pin_root)
        .with_context(|| format!("create TCX link pin directory {}", pin_root.display()))?;
    let pin_path = tcx_link_pin_path(pin_root, direction, if_index);
    match PinnedLink::from_pin(&pin_path) {
        Ok(pinned) => {
            let link = SchedClassifierLink::try_from(FdLink::from(pinned))
                .context("pinned attachment is not a TCX link")?;
            let link_id = program
                .attach_to_link(link)
                .with_context(|| format!("atomically replace TCX program on {interface}"))?;
            let link = program.take_link(link_id)?;
            let fd_link = FdLink::try_from(link).context("updated attachment is not TCX")?;
            drop(fd_link);
            info!(
                %interface,
                if_index,
                ?direction,
                pin = %pin_path.display(),
                "TCX observation program atomically replaced"
            );
        }
        Err(error) if pinned_link_is_missing(&error) => {
            let link_id = program
                .attach_with_options(
                    interface,
                    attach_type,
                    TcAttachOptions::TcxOrder(LinkOrder::last()),
                )
                .with_context(|| format!("attach TCX classifier to {interface}"))?;
            let link = program.take_link(link_id)?;
            let fd_link = FdLink::try_from(link).context("new attachment is not TCX")?;
            let pinned = fd_link
                .pin(&pin_path)
                .with_context(|| format!("pin TCX link at {}", pin_path.display()))?;
            drop(pinned);
            info!(
                %interface,
                if_index,
                ?direction,
                pin = %pin_path.display(),
                "TCX observation program attached and pinned"
            );
        }
        Err(error) => {
            return Err(anyhow!(error))
                .with_context(|| format!("open TCX link pin {}", pin_path.display()));
        }
    }
    Ok(())
}

fn pinned_link_is_missing(error: &LinkError) -> bool {
    matches!(
        error,
        LinkError::SyscallError(SyscallError { io_error, .. })
            if io_error.kind() == io::ErrorKind::NotFound
    )
}

fn tcx_link_pin_path(pin_root: &Path, direction: Direction, if_index: u32) -> PathBuf {
    pin_root.join(format!("tcx-{}-{if_index}", direction_label(direction)))
}

const fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Ingress => "ingress",
        Direction::Egress => "egress",
    }
}

fn cleanup_stale_tcx_links(
    pin_root: &Path,
    direction: Direction,
    active_ifindices: impl Iterator<Item = u32>,
) -> Result<()> {
    if !pin_root.exists() {
        return Ok(());
    }
    let active: HashSet<_> = active_ifindices.collect();
    let prefix = format!("tcx-{}-", direction_label(direction));
    for entry in fs::read_dir(pin_root)
        .with_context(|| format!("enumerate TCX link pins in {}", pin_root.display()))?
    {
        let entry = entry.context("read TCX link pin directory entry")?;
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        let Some(if_index) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if active.contains(&if_index) {
            continue;
        }
        fs::remove_file(entry.path())
            .with_context(|| format!("remove stale TCX link pin {}", entry.path().display()))?;
        info!(if_index, ?direction, pin = %entry.path().display(), "stale TCX link pin removed");
    }
    Ok(())
}

fn attach_persistent_netlink(
    program: &mut SchedClassifier,
    interface: &str,
    attach_type: TcAttachType,
    direction: Direction,
) -> Result<()> {
    match tc::qdisc_add_clsact(interface) {
        Ok(()) | Err(TcError::AlreadyAttached) => {}
        Err(error) => {
            warn!(%error, %interface, "could not create clsact qdisc; attach will still be attempted");
        }
    }
    let handle = legacy_tc_handle(direction);
    let existing =
        SchedClassifierLink::attached(interface, attach_type, LEGACY_TC_PRIORITY, handle, None)?;
    let (link_id, replaced) = if let Ok(link_id) = program.attach_to_link(existing) {
        (link_id, true)
    } else {
        let link_id = program
            .attach_with_options(
                interface,
                attach_type,
                TcAttachOptions::Netlink(NlOptions {
                    priority: LEGACY_TC_PRIORITY,
                    handle,
                    classid: None,
                }),
            )
            .with_context(|| format!("attach persistent netlink classifier to {interface}"))?;
        (link_id, false)
    };
    let link = program.take_link(link_id)?;
    // Legacy TC filters are kernel-owned rather than fd-owned. Taking the link
    // out of Aya and intentionally forgetting its detach guard keeps the fixed
    // priority/handle installed across process exit for replacement on restart.
    std::mem::forget(link);
    info!(
        %interface,
        ?direction,
        priority = LEGACY_TC_PRIORITY,
        handle = u32::from(handle),
        replaced,
        "persistent netlink TC observation program installed"
    );
    Ok(())
}

const fn legacy_tc_handle(direction: Direction) -> TcHandle {
    let minor = match direction {
        Direction::Ingress => 1,
        Direction::Egress => 2,
    };
    TcHandle::new(LEGACY_TC_HANDLE_MAJOR, minor)
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
    if policy_direction(bytes[89]).is_none() || bytes[91] > Verdict::Audit as u8 {
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
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_or_else(|_| "unknown".to_owned(), |value| value.trim().to_owned());
    KernelCapabilities {
        kernel_release,
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

fn kernel_supports_tcx(release: &str) -> bool {
    let mut components = release.split(['.', '-']);
    let Some(major) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    let Some(minor) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    (major, minor) >= (6, 6)
}

const fn select_tc_attachment_mode(
    preference: TcAttachmentPreference,
    tcx_supported: bool,
) -> TcAttachmentMode {
    match preference {
        TcAttachmentPreference::Auto if tcx_supported => TcAttachmentMode::TcxPinned,
        TcAttachmentPreference::Auto | TcAttachmentPreference::LegacyNetlink => {
            TcAttachmentMode::LegacyNetlink
        }
        TcAttachmentPreference::TcxPinned => TcAttachmentMode::TcxPinned,
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

async fn version() -> Json<ComponentCompatibility> {
    Json(component_compatibility())
}

fn component_compatibility() -> ComponentCompatibility {
    ComponentCompatibility::current("unf-agent", env!("CARGO_PKG_VERSION"), BUILD_REVISION)
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
        tc_attachment_mode: TcAttachmentMode::from_state(
            state.tc_attachment_mode.load(Ordering::Acquire),
        )
        .status_label(),
        capabilities: state.capabilities.clone(),
        limitation: "TC policy enforcement uses transactional pinned maps and persistent atomic attachment replacement; internal controller traffic uses dedicated CA-pinned TLS and Pod-bound Kubernetes TokenReview authentication",
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
    use tempfile::tempdir;

    #[test]
    fn malformed_ca_update_retains_last_known_good_client_without_retry_storm() {
        let temporary = tempdir().expect("temporary directory is created");
        let ca_path = temporary.path().join("ca.crt");
        fs::write(&ca_path, b"not a certificate").expect("candidate CA is written");
        let reloads = Counter::default();
        let reload_errors = Counter::default();
        let client = ReloadingControllerClient {
            ca_path,
            controller_resolution: None,
            state: Arc::new(Mutex::new(ControllerClientState {
                observed_ca_pem: b"previous valid CA".to_vec(),
                client: reqwest::Client::new(),
            })),
            reloads: reloads.clone(),
            reload_errors: reload_errors.clone(),
        };

        drop(client.current());
        assert_eq!(reloads.get(), 0);
        assert_eq!(reload_errors.get(), 1);
        assert_eq!(client.lock_state().observed_ca_pem, b"not a certificate");

        drop(client.current());
        assert_eq!(reload_errors.get(), 1);
    }

    #[test]
    fn valid_ca_bundle_update_replaces_trust_without_restart() {
        let temporary = tempdir().expect("temporary directory is created");
        let ca_path = temporary.path().join("ca.crt");
        let ca_pem = include_bytes!("../testdata/ca.crt");
        fs::write(&ca_path, ca_pem).expect("initial CA is written");
        let reloads = Counter::default();
        let reload_errors = Counter::default();
        let client = ReloadingControllerClient::new(
            "https://controller.example",
            ca_path.clone(),
            reloads.clone(),
            reload_errors.clone(),
        )
        .expect("initial CA bundle is valid");
        let mut updated_ca_pem = ca_pem.to_vec();
        updated_ca_pem.push(b'\n');
        fs::write(&ca_path, &updated_ca_pem).expect("updated CA bundle is written");

        drop(client.current());

        assert_eq!(reloads.get(), 1);
        assert_eq!(reload_errors.get(), 0);
        assert_eq!(client.lock_state().observed_ca_pem, updated_ca_pem);
    }

    #[test]
    fn connected_controller_client_refuses_plaintext_before_loading_trust() {
        let error = ReloadingControllerClient::new(
            "http://controller.example",
            PathBuf::from("missing-ca.crt"),
            Counter::default(),
            Counter::default(),
        )
        .err()
        .expect("plaintext controller URL is rejected");
        assert!(error.to_string().contains("must use https://"));
    }

    #[test]
    fn cleanup_cli_is_dry_run_by_default() {
        let args = Args::try_parse_from(["unf-agent", "cleanup", "--abi-version", "1"])
            .expect("cleanup arguments parse");
        let Some(AgentCommand::Cleanup(cleanup)) = args.command else {
            panic!("cleanup subcommand is selected");
        };
        assert_eq!(cleanup.bpf_root, Path::new("/sys/fs/bpf/unf"));
        assert_eq!(cleanup.abi_version, Some(1));
        assert!(!cleanup.allow_current_abi);
        assert!(!cleanup.execute);
    }

    #[test]
    fn cleanup_recognizes_only_exact_tcx_pin_names() {
        assert!(recognized_tcx_link_pin_name("tcx-ingress-1"));
        assert!(recognized_tcx_link_pin_name("tcx-egress-4294967295"));
        assert!(!recognized_tcx_link_pin_name("tcx-ingress-0"));
        assert!(!recognized_tcx_link_pin_name("tcx-ingress-1-extra"));
        assert!(!recognized_tcx_link_pin_name("unrelated-1"));
    }

    #[test]
    fn cleanup_accepts_only_exact_non_loopback_interface_names() {
        assert!(validate_cleanup_interface_name("eth0").is_ok());
        assert!(validate_cleanup_interface_name("veth.example").is_ok());
        assert!(validate_cleanup_interface_name("lo").is_err());
        assert!(validate_cleanup_interface_name("../eth0").is_err());
        assert!(validate_cleanup_interface_name("path/eth0").is_err());
        assert!(validate_cleanup_interface_name("").is_err());
    }

    #[test]
    fn cleanup_refuses_current_or_unrecognized_abi_without_explicit_authority() {
        let temporary = tempdir().expect("temporary directory is created");
        let root = temporary.path().join("unf");
        assert!(plan_abi_cleanup(&root, CURRENT_BPF_ABI_VERSION, false).is_err());
        assert!(plan_abi_cleanup(&root, 4, true).is_err());
        assert!(plan_abi_cleanup(&root, 2, false).is_ok());
        assert!(plan_abi_cleanup(Path::new("relative"), 1, false).is_err());
        assert!(plan_abi_cleanup(Path::new("/"), 1, false).is_err());
    }

    #[test]
    fn cleanup_removes_only_planned_owned_abi_entries() {
        let temporary = tempdir().expect("temporary directory is created");
        let root = temporary.path().join("unf");
        let abi = root.join("v1");
        let links = abi.join("links");
        fs::create_dir_all(&links).expect("fixture directories are created");
        fs::write(abi.join("IDENTITY_V4"), []).expect("map fixture is created");
        fs::write(abi.join("POLICY_CONFIG"), []).expect("map fixture is created");
        fs::write(links.join("tcx-ingress-7"), []).expect("link fixture is created");
        fs::write(root.join("operator-note"), []).expect("sibling fixture is created");

        let plan = plan_abi_cleanup(&root, 1, false).expect("known fixture has a safe plan");
        assert_eq!(plan.map_pins.len(), 2);
        assert_eq!(plan.link_pins.len(), 1);
        execute_abi_cleanup(&plan).expect("known fixture is removed");

        assert!(!abi.exists());
        assert!(root.join("operator-note").exists());
    }

    #[test]
    fn cleanup_refuses_unknown_abi_content_without_mutation() {
        let temporary = tempdir().expect("temporary directory is created");
        let root = temporary.path().join("unf");
        let abi = root.join("v1");
        fs::create_dir_all(&abi).expect("fixture directory is created");
        fs::write(abi.join("IDENTITY_V4"), []).expect("known fixture is created");
        fs::write(abi.join("unknown-state"), []).expect("unknown fixture is created");

        let error = plan_abi_cleanup(&root, 1, false).expect_err("unknown state is refused");
        assert!(error.to_string().contains("unrecognized ABI state"));
        assert!(abi.join("IDENTITY_V4").exists());
        assert!(abi.join("unknown-state").exists());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_refuses_symbolic_link_roots_and_targets() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().expect("temporary directory is created");
        let real_root = temporary.path().join("real-root");
        fs::create_dir(&real_root).expect("real root is created");
        let linked_root = temporary.path().join("linked-root");
        symlink(&real_root, &linked_root).expect("root symlink is created");
        assert!(plan_abi_cleanup(&linked_root, 1, false).is_err());

        let target = real_root.join("target");
        fs::create_dir(&target).expect("target is created");
        symlink(&target, real_root.join("v1")).expect("ABI symlink is created");
        assert!(plan_abi_cleanup(&real_root, 1, false).is_err());
    }

    #[test]
    fn event_decoder_preserves_fixed_layout_bytes() {
        let mut bytes = [0_u8; size_of::<FlowEvent>()];
        bytes[84..86].copy_from_slice(&FLOW_ABI_VERSION.to_ne_bytes());
        let event_size = u16::try_from(size_of::<FlowEvent>()).expect("event ABI fits in u16");
        bytes[86..88].copy_from_slice(&event_size.to_ne_bytes());
        bytes[89] = PolicyDirection::Ingress as u8;
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
    fn tcx_capability_follows_the_kernel_introduction_boundary() {
        assert!(!kernel_supports_tcx("6.5.13-200.fc38.x86_64"));
        assert!(kernel_supports_tcx("6.6.0"));
        assert!(kernel_supports_tcx("7.1.4-204.fc44.x86_64"));
        assert!(!kernel_supports_tcx("unknown"));
    }

    #[test]
    fn attachment_preference_defaults_by_capability_and_allows_explicit_modes() {
        assert_eq!(
            select_tc_attachment_mode(TcAttachmentPreference::Auto, true),
            TcAttachmentMode::TcxPinned
        );
        assert_eq!(
            select_tc_attachment_mode(TcAttachmentPreference::Auto, false),
            TcAttachmentMode::LegacyNetlink
        );
        assert_eq!(
            select_tc_attachment_mode(TcAttachmentPreference::LegacyNetlink, true),
            TcAttachmentMode::LegacyNetlink
        );
        assert_eq!(
            select_tc_attachment_mode(TcAttachmentPreference::TcxPinned, false),
            TcAttachmentMode::TcxPinned
        );
    }

    #[test]
    fn attachment_names_and_legacy_handles_are_direction_stable() {
        assert_eq!(
            tcx_link_pin_path(
                Path::new("/sys/fs/bpf/unf/v3/links"),
                Direction::Ingress,
                17
            ),
            Path::new("/sys/fs/bpf/unf/v3/links/tcx-ingress-17")
        );
        assert_eq!(u32::from(legacy_tc_handle(Direction::Ingress)), 0x554e_0001);
        assert_eq!(u32::from(legacy_tc_handle(Direction::Egress)), 0x554e_0002);
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
            "unf-agent-test".to_owned(),
            "test-pod-uid".to_owned(),
        )
    }

    #[test]
    fn component_version_exposes_the_agent_compatibility_tuple() {
        let version = component_compatibility();
        assert_eq!(version.component, "unf-agent");
        assert_eq!(version.software_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(version.build_revision, BUILD_REVISION);
        assert_eq!(
            version.persistent_bpf_state_abi_version,
            CURRENT_BPF_ABI_VERSION
        );
        assert_eq!(
            version.agent_status_schema_version,
            AGENT_STATUS_SCHEMA_VERSION
        );
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
        assert_eq!(report.pod_name, "unf-agent-test");
        assert_eq!(report.pod_uid, "test-pod-uid");
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
                direction: PolicyDirection::Ingress,
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
    fn pending_flow_batches_advance_fairly_and_wrap() {
        let pending = [8080, 8081, 8082]
            .into_iter()
            .map(|port| {
                let record = test_flow_record(port);
                (record.key.clone(), record)
            })
            .collect::<BTreeMap<_, _>>();
        let first = pending_flow_batch(&pending, None, 2);
        assert_eq!(
            first
                .iter()
                .map(|record| record.key.destination_port)
                .collect::<Vec<_>>(),
            [8080, 8081]
        );
        let next = pending_flow_batch(&pending, Some(&first[1].key), 2);
        assert_eq!(
            next.iter()
                .map(|record| record.key.destination_port)
                .collect::<Vec<_>>(),
            [8082, 8080]
        );
        assert!(pending_flow_batch(&pending, None, 0).is_empty());
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
        assert_eq!(record.key.direction, PolicyDirection::Ingress);
        assert_eq!(record.key.source_ipv4, Some(Ipv4Addr::new(10, 42, 0, 1)));
        assert_eq!(record.key.destination_port, 8080);
        assert_eq!(record.decision.rule_id, Some(RuleId::new(0)));
        assert_eq!(
            record.shadow.expect("shadow decision exists").verdict,
            Verdict::Deny
        );
        assert!(!is_controller_management_flow(&event, 9964));
        event.flow.destination_port = 9964_u16.to_be_bytes();
        assert!(is_controller_management_flow(&event, 9964));
        event.flow.destination_port = 8080_u16.to_be_bytes();

        event.direction = PolicyDirection::Egress as u8;
        event.flow.destination_identity = IdentityId::default();
        let external_egress = flow_export_record(&event);
        assert_eq!(external_egress.key.direction, PolicyDirection::Egress);
        assert!(event_has_selected_identity(&event));
        event.flow.source_identity = IdentityId::default();
        assert!(!event_has_selected_identity(&event));
        event.flow.source_identity = IdentityId::new(1);
        event.flow.destination_identity = IdentityId::new(2);

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
    fn controller_management_port_uses_the_https_url_contract() {
        assert_eq!(
            controller_port("https://controller.example:9964").unwrap(),
            9964
        );
        assert_eq!(controller_port("https://controller.example").unwrap(), 443);
        assert!(controller_port("not a URL").is_err());
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
    fn egress_policy_snapshot_encoding_matches_source_selected_abi_layout() {
        let policy = policy_entry();
        let ipv4_tuple = unf_state::EgressIpv4PolicyMapKey {
            source_identity: policy.key.source_identity,
            destination_address: "10.244.1.3".parse().unwrap(),
            protocol: policy.key.protocol,
            destination_port: policy.key.destination_port,
        };
        let ipv4_entry = EgressIpv4PolicyMapEntry {
            key: ipv4_tuple,
            decision: policy.decision,
            shadow: policy.shadow,
        };
        let desired = desired_egress_ipv4_policy_entries(&[ipv4_entry], 17, 1)
            .expect("IPv4 egress policy is valid");
        let (key, value) = desired.first_key_value().expect("one encoded entry");
        assert_eq!(&key[0..4], &[10, 244, 1, 3]);
        assert_eq!(u32::from_ne_bytes(key[4..8].try_into().unwrap()), 11);
        assert_eq!(u16::from_be_bytes(key[8..10].try_into().unwrap()), 8080);
        assert_eq!(key[10], 6);
        assert_eq!(key[11], 1);
        assert_eq!(u64::from_ne_bytes(value[16..24].try_into().unwrap()), 17);

        let destination_network: Ipv6Addr = "2001:db8:2::".parse().unwrap();
        let ipv6_tuple = unf_state::EgressIpv6PolicyMapKey {
            source_identity: policy.key.source_identity,
            destination_network,
            destination_prefix_len: 64,
            protocol: policy.key.protocol,
            destination_port: policy.key.destination_port,
        };
        let ipv6_entry = EgressIpv6PolicyMapEntry {
            key: ipv6_tuple,
            decision: policy.decision,
            shadow: policy.shadow,
        };
        let desired = desired_egress_ipv6_policy_entries(&[ipv6_entry], 17, 1)
            .expect("IPv6 egress policy is valid");
        let ((prefix_len, key), value) = desired.first_key_value().expect("one encoded entry");
        assert_eq!(*prefix_len, 128);
        assert_eq!(u32::from_ne_bytes(key[0..4].try_into().unwrap()), 11);
        assert_eq!(u16::from_be_bytes(key[4..6].try_into().unwrap()), 8080);
        assert_eq!(key[6], 6);
        assert_eq!(key[7], 1);
        assert_eq!(&key[8..24], &destination_network.octets());
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

    #[test]
    fn recovered_policy_config_accepts_only_committed_abi_state() {
        let config = encode_policy_config(9, 17, 3, 1).expect("config is valid");
        assert_eq!(
            decode_recovered_policy_config(config).expect("config recovers"),
            Some((9, 17, 3, 1))
        );
        assert_eq!(
            decode_recovered_policy_config([0; 24]).expect("zero means no committed snapshot"),
            None
        );

        let mut invalid_bank = config;
        invalid_bank[22] = POLICY_BANK_COUNT;
        assert!(decode_recovered_policy_config(invalid_bank).is_err());
        let mut invalid_flags = config;
        invalid_flags[23] = 1;
        assert!(decode_recovered_policy_config(invalid_flags).is_err());
    }

    #[test]
    fn recovered_identity_values_are_validated_before_bank_selection() {
        let first = encode_identity_value(IdentityMapValue::new(IdentityId::new(42), 17));
        let second = encode_identity_value(IdentityMapValue::new(IdentityId::new(84), 18));
        assert_eq!(
            validate_recovered_identity_value(&first).expect("first value is valid"),
            17
        );
        assert_eq!(
            validate_recovered_identity_value(&second).expect("inactive revision is valid"),
            18
        );

        let mut invalid_schema = first;
        invalid_schema[4..6].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert!(validate_recovered_identity_value(&invalid_schema).is_err());
    }

    #[test]
    fn identity_config_encoding_is_an_atomic_bank_pointer() {
        let config = encode_identity_config(9, 17, 14, 1).expect("config is valid");
        assert_eq!(
            decode_recovered_identity_config(config).expect("config recovers"),
            Some((9, 17, 14, 1))
        );
        assert_eq!(
            u16::from_ne_bytes(config[20..22].try_into().unwrap()),
            unf_ebpf_common::IDENTITY_MAP_ABI_VERSION
        );
        assert!(encode_identity_config(9, 17, 14, IDENTITY_BANK_COUNT).is_err());
    }

    #[test]
    fn recovered_policy_values_reject_corrupt_decisions_and_flags() {
        let valid = encode_policy_value(&policy_entry(), 17);
        validate_recovered_policy_value(&valid).expect("encoded policy value recovers");

        let mut invalid_verdict = valid;
        invalid_verdict[28] = Verdict::Unknown as u8;
        assert!(validate_recovered_policy_value(&invalid_verdict).is_err());

        let mut orphaned_shadow = valid;
        let flags = u16::from_ne_bytes(orphaned_shadow[26..28].try_into().unwrap())
            & !POLICY_FLAG_HAS_SHADOW;
        orphaned_shadow[26..28].copy_from_slice(&flags.to_ne_bytes());
        assert!(validate_recovered_policy_value(&orphaned_shadow).is_err());

        let mut unknown_flag = valid;
        let flags = u16::from_ne_bytes(unknown_flag[26..28].try_into().unwrap()) | (1 << 15);
        unknown_flag[26..28].copy_from_slice(&flags.to_ne_bytes());
        assert!(validate_recovered_policy_value(&unknown_flag).is_err());
    }

    #[test]
    fn controller_readiness_waits_for_both_snapshot_epochs() {
        let state = test_agent_state();
        state.bpf_loaded.store(true, Ordering::Release);
        state.applied_identity_epoch.store(7, Ordering::Release);
        refresh_controller_readiness(&state);
        assert!(!state.ready.load(Ordering::Acquire));

        state.applied_policy_epoch.store(7, Ordering::Release);
        refresh_controller_readiness(&state);
        assert!(state.ready.load(Ordering::Acquire));
    }

    #[test]
    fn in_cluster_controller_resolution_preserves_the_tls_hostname() {
        let resolution = controller_service_resolution(
            "https://unf-controller.unf-system.svc.cluster.local:9964",
            Some("172.30.71.84"),
        )
        .expect("injected Service address is valid")
        .expect("in-cluster controller is resolved directly");
        assert_eq!(
            resolution,
            (
                "unf-controller.unf-system.svc.cluster.local".to_owned(),
                "172.30.71.84:9964".parse().expect("valid socket address")
            )
        );

        assert!(
            controller_service_resolution("https://controller.example.com:9964", Some("10.0.0.1"))
                .expect("external controller URL is valid")
                .is_none()
        );
        assert!(
            controller_service_resolution(
                "https://unf-controller.unf-system.svc.cluster.local:9964",
                None,
            )
            .expect("missing injection remains compatible")
            .is_none()
        );
    }
}
