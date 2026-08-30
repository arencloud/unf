use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Bound::{Excluded, Unbounded};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
use serde::de::DeserializeOwned;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use unf_cni_state::AttachmentJournal;
use unf_common::{IdentityId, PolicyDirection, PolicyId, PolicyReason, Revision, RuleId, Verdict};
use unf_ebpf_common::{
    FLOW_ABI_VERSION, FlowEvent, FlowKey, IDENTITY_BANK_COUNT, IdentityMapValue, Ipv4IdentityKey,
    Ipv6IdentityKey, POLICY_BANK_COUNT, POLICY_FLAG_HAS_POLICY, POLICY_FLAG_HAS_RULE,
    POLICY_FLAG_HAS_SHADOW, POLICY_FLAG_SHADOW_HAS_POLICY, POLICY_FLAG_SHADOW_HAS_RULE,
    POLICY_MAP_ABI_VERSION, SERVICE_BANK_COUNT, SERVICE_EVENT_ABI_VERSION,
    SERVICE_EVENT_ACTION_DROP, SERVICE_EVENT_ACTION_EXPIRE, SERVICE_EVENT_ACTION_TRANSLATE,
    SERVICE_MAP_ABI_VERSION, ServiceEvent, service_event_action_reason_is_valid,
};
use unf_ipam::{
    Ipv4NodeBlock, Ipv6NodeBlock, NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION, NodeBlockProvider,
    NodeBlockSnapshot,
};
use unf_route::{
    NativeIpv4NextHop, NativeIpv6NextHop, NativeRemoteNode, NativeRemoteRoutePlan,
    NativeRemoteRoutingProvider, REMOTE_ROUTE_SNAPSHOT_SCHEMA_VERSION, RemoteRouteSnapshot,
};
use unf_service::{
    MAX_BACKENDS_PER_SERVICE, SERVICE_BACKEND_BANK_CAPACITY, SERVICE_BACKEND_SLOT_BANK_CAPACITY,
    SERVICE_FRONTEND_BANK_CAPACITY, ServiceDataplaneState, ServiceSnapshot,
    compile_service_dataplane,
};
use unf_state::{
    AGENT_STATUS_SCHEMA_VERSION, AgentStateReport, ComponentCompatibility,
    EgressIpv4PolicyMapEntry, EgressIpv6PolicyMapEntry, FLOW_EXPORT_BATCH_LIMIT,
    FLOW_EXPORT_SCHEMA_VERSION, FlowExportBatch, FlowExportDecision, FlowExportRecord,
    FlowHistoryKey, IDENTITY_SNAPSHOT_SCHEMA_VERSION, IdentityStateSnapshot, Ipv4IdentityMapping,
    Ipv4PolicyMapEntry, Ipv6IdentityMapping, Ipv6PolicyMapEntry, PERSISTENT_BPF_STATE_ABI_VERSION,
    POLICY_MAP_BANK_ENTRY_LIMIT, POLICY_SNAPSHOT_SCHEMA_VERSION, PolicyDecisionRecord,
    PolicyMapEntry, PolicyStateSnapshot, ServiceFlowKey, ServiceFlowOutcome, VersionTransition,
};

mod cni_server;

use cni_server::CniTransactionServer;

const FLOW_EXPORT_CHANNEL_CAPACITY: usize = 4_096;
const FLOW_EXPORT_PENDING_CAPACITY: usize = 2_048;
const DEFAULT_BPF_PIN_PATH: &str = "/sys/fs/bpf/unf/v4";
const DEFAULT_AGENT_TOKEN_PATH: &str = "/var/run/secrets/unf-agent/token";
const DEFAULT_CONTROLLER_CA_PATH: &str = "/var/run/secrets/unf-internal-ca/ca.crt";
const DEFAULT_CNI_STATE_PATH: &str = "/var/lib/unf/cni/v1/attachments.json";
const DEFAULT_CNI_NODE_BLOCK_STATE_PATH: &str = "/var/lib/unf/cni/v1/node-block.json";
const DEFAULT_CNI_REMOTE_ROUTE_STATE_PATH: &str = "/var/lib/unf/cni/v1/remote-routes.json";
const DEFAULT_SERVICE_STATE_PATH: &str = "/var/lib/unf/cni/v1/service-snapshot.json";
const MAX_SERVICE_ERROR_BYTES: usize = 1_024;
const MAX_DURABLE_STATE_BYTES: u64 = 64 * 1024 * 1024;
const CURRENT_BPF_ABI_VERSION: u16 = PERSISTENT_BPF_STATE_ABI_VERSION;
const BLOCKED_TRANSITION_REPORTING_WINDOW: Duration = Duration::from_secs(30);
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
const ABI_V3_MAP_NAMES: [&str; 11] = [
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
const PERSISTENT_MAP_NAMES: [&str; 18] = [
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
    "SERVICE_FRONTENDS_V4",
    "SERVICE_FRONTENDS_V6",
    "SERVICE_BACKENDS_V4",
    "SERVICE_BACKENDS_V6",
    "SERVICE_BACKEND_SLOTS",
    "SERVICE_CONFIG",
    "SERVICE_CONNECTIONS",
];
const IDENTITY_MAP_CAPACITY: u32 = 65_536;
const POLICY_MAP_CAPACITY: u32 = 262_144;
const SERVICE_FRONTEND_MAP_CAPACITY: u32 = 262_144;
const SERVICE_BACKEND_MAP_CAPACITY: u32 = 524_288;
const SERVICE_BACKEND_SLOT_MAP_CAPACITY: u32 = 1_048_576;
const SERVICE_CONNECTION_MAP_CAPACITY: u32 = 262_144;
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
    /// Select one TC hook or both hooks so pre- and post-NAT tuples can share
    /// the bounded reply-state map.
    #[arg(long, env = "UNF_HOOK_COVERAGE", value_enum, default_value = "single")]
    hook_coverage: HookCoverage,
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
    /// Poll interval for validated transactional service snapshots.
    #[arg(long, env = "UNF_SERVICE_SYNC_SECONDS", default_value_t = 2)]
    service_sync_seconds: u64,
    /// Durable owner-only last-known-good service snapshot.
    #[arg(
        long,
        env = "UNF_SERVICE_STATE_PATH",
        default_value = DEFAULT_SERVICE_STATE_PATH
    )]
    service_state_path: PathBuf,
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
    /// Enable the root-only local CNI transaction API at this Unix socket.
    #[arg(long, env = "UNF_CNI_SOCKET")]
    cni_socket: Option<PathBuf>,
    /// Durable attachment journal used only when --cni-socket is enabled.
    #[arg(
        long,
        env = "UNF_CNI_STATE_PATH",
        default_value = DEFAULT_CNI_STATE_PATH
    )]
    cni_state_path: PathBuf,
    /// Durable controller-issued node-block snapshot used by the CNI service.
    #[arg(
        long,
        env = "UNF_CNI_NODE_BLOCK_STATE_PATH",
        default_value = DEFAULT_CNI_NODE_BLOCK_STATE_PATH
    )]
    cni_node_block_state_path: PathBuf,
    /// Durable last-known-good complete remote-route snapshot.
    #[arg(
        long,
        env = "UNF_CNI_REMOTE_ROUTE_STATE_PATH",
        default_value = DEFAULT_CNI_REMOTE_ROUTE_STATE_PATH
    )]
    cni_remote_route_state_path: PathBuf,
    /// Controller-assigned IPv4 node block for the opt-in CNI service.
    #[arg(
        long,
        env = "UNF_CNI_IPV4_BLOCK",
        requires = "cni_socket",
        requires = "cni_ipv6_block"
    )]
    cni_ipv4_block: Option<Ipv4NodeBlock>,
    /// Controller-assigned IPv6 node block for the opt-in CNI service.
    #[arg(
        long,
        env = "UNF_CNI_IPV6_BLOCK",
        requires = "cni_socket",
        requires = "cni_ipv4_block"
    )]
    cni_ipv6_block: Option<Ipv6NodeBlock>,
    /// Host uplink used to reach remote Node IPv4 `InternalIP` addresses.
    #[arg(
        long,
        env = "UNF_CNI_NATIVE_IPV4_UPLINK",
        requires = "cni_socket",
        requires = "cni_native_ipv6_uplink"
    )]
    cni_native_ipv4_uplink: Option<String>,
    /// Host uplink used to reach remote Node IPv6 `InternalIP` addresses.
    #[arg(
        long,
        env = "UNF_CNI_NATIVE_IPV6_UPLINK",
        requires = "cni_socket",
        requires = "cni_native_ipv4_uplink"
    )]
    cni_native_ipv6_uplink: Option<String>,
    /// Force native IPv4 remote next hops on-link.
    #[arg(
        long,
        env = "UNF_CNI_NATIVE_IPV4_ONLINK",
        requires = "cni_native_ipv4_uplink",
        default_value_t = false
    )]
    cni_native_ipv4_onlink: bool,
    /// Force native IPv6 remote next hops on-link.
    #[arg(
        long,
        env = "UNF_CNI_NATIVE_IPV6_ONLINK",
        requires = "cni_native_ipv6_uplink",
        default_value_t = false
    )]
    cni_native_ipv6_onlink: bool,
    /// Poll interval for complete remote-route snapshots.
    #[arg(long, env = "UNF_CNI_ROUTE_SYNC_SECONDS", default_value_t = 2)]
    cni_route_sync_seconds: u64,
    #[arg(
        long,
        env = "UNF_TC_ATTACHMENT_MODE",
        value_enum,
        default_value = "auto"
    )]
    tc_attachment_mode: TcAttachmentPreference,
    #[arg(
        long,
        env = "UNF_VERSION_TRANSITION",
        value_enum,
        default_value = "normal"
    )]
    version_transition: VersionTransitionIntent,
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
    /// Remove one ABI directory recognized by this binary.
    #[arg(long)]
    abi_version: Option<u16>,
    /// Permit removal of this binary's current ABI directory.
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
enum HookCoverage {
    Single,
    Both,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum VersionTransitionIntent {
    Normal,
    CompatibleRollback,
    Recovery,
}

impl From<VersionTransitionIntent> for VersionTransition {
    fn from(value: VersionTransitionIntent) -> Self {
        match value {
            VersionTransitionIntent::Normal => Self::Normal,
            VersionTransitionIntent::CompatibleRollback => Self::CompatibleRollback,
            VersionTransitionIntent::Recovery => Self::Recovery,
        }
    }
}

const fn version_transition_code(value: VersionTransition) -> u64 {
    match value {
        VersionTransition::Normal => 0,
        VersionTransition::CompatibleRollback => 1,
        VersionTransition::BlockedRollback => 2,
        VersionTransition::Recovery => 3,
    }
}

const fn version_transition_label(value: VersionTransition) -> &'static str {
    match value {
        VersionTransition::Normal => "normal",
        VersionTransition::CompatibleRollback => "compatible_rollback",
        VersionTransition::BlockedRollback => "blocked_rollback",
        VersionTransition::Recovery => "recovery",
    }
}

const fn version_transition_from_code(value: u64) -> VersionTransition {
    match value {
        1 => VersionTransition::CompatibleRollback,
        2 => VersionTransition::BlockedRollback,
        3 => VersionTransition::Recovery,
        _ => VersionTransition::Normal,
    }
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
    service_sync_errors: Counter,
    desired_service_revision: Gauge,
    applied_service_revision: Gauge,
    service_count: Gauge,
    service_frontend_count: Gauge,
    service_backend_count: Gauge,
    service_dataplane_events: Counter,
    service_translations: Counter,
    service_drops: Counter,
    service_expirations: Counter,
    invalid_service_events: Counter,
    remote_route_sync_errors: Counter,
    desired_remote_route_revision: Gauge,
    applied_remote_route_revision: Gauge,
    remote_route_entries: Gauge,
    telemetry_dropped_events: Counter,
    telemetry_export_errors: Counter,
    telemetry_exported_events: Counter,
    controller_trust_reloads: Counter,
    controller_trust_reload_errors: Counter,
    version_transition_state: Gauge,
    compatible_rollbacks: Counter,
    blocked_rollbacks: Counter,
    transition_recoveries: Counter,
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
    desired_service_epoch: AtomicU64,
    desired_service_revision: AtomicU64,
    applied_service_epoch: AtomicU64,
    applied_service_revision: AtomicU64,
    failed_service_epoch: AtomicU64,
    failed_service_revision: AtomicU64,
    service_count: AtomicU64,
    service_frontend_count: AtomicU64,
    service_backend_count: AtomicU64,
    service_reconcile_errors: AtomicU64,
    service_last_error: Mutex<Option<String>>,
    service_dataplane_events: AtomicU64,
    service_translations: AtomicU64,
    service_drops: AtomicU64,
    service_expirations: AtomicU64,
    invalid_service_events: AtomicU64,
    last_service_id: AtomicU64,
    last_backend_id: AtomicU64,
    last_service_revision: AtomicU64,
    last_service_action: AtomicU64,
    last_service_reason: AtomicU64,
    desired_node_block_revision: AtomicU64,
    applied_node_block_revision: AtomicU64,
    desired_remote_route_epoch: AtomicU64,
    applied_remote_route_epoch: AtomicU64,
    desired_remote_route_revision: AtomicU64,
    applied_remote_route_revision: AtomicU64,
    remote_route_entries: AtomicU64,
    remote_route_reconcile_errors: AtomicU64,
    queued_flow_exports: AtomicU64,
    dropped_flow_exports: AtomicU64,
    exported_flow_events: AtomicU64,
    tc_attachment_mode: AtomicU64,
    version_transition: AtomicU64,
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

struct ServiceSynchronizer {
    ipv4_frontends: AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    ipv6_frontends: AyaHashMap<MapData, [u8; 20], [u8; 32]>,
    ipv4_backends: AyaHashMap<MapData, [u8; 12], [u8; 24]>,
    ipv6_backends: AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    backend_slots: AyaHashMap<MapData, [u8; 16], [u8; 16]>,
    config: AyaArray<MapData, [u8; 32]>,
    connections: AyaHashMap<MapData, [u8; 40], [u8; 88]>,
    banks: [Option<ServiceDataplaneState>; SERVICE_BANK_COUNT as usize],
    active_bank: u8,
    applied: Option<ServiceSnapshot>,
    controller_url: Option<String>,
    client: ReloadingControllerClient,
    agent_token_path: PathBuf,
    state_path: PathBuf,
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
type ServiceMaps = (
    AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    AyaHashMap<MapData, [u8; 20], [u8; 32]>,
    AyaHashMap<MapData, [u8; 12], [u8; 24]>,
    AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    AyaHashMap<MapData, [u8; 16], [u8; 16]>,
    AyaArray<MapData, [u8; 32]>,
    AyaHashMap<MapData, [u8; 40], [u8; 88]>,
);
type RecoveredServiceConfig = (u64, u64, u32, u32, u32, u8);

struct DataplaneConfig {
    object: PathBuf,
    interface: Option<String>,
    all_interfaces: bool,
    direction: Direction,
    hook_coverage: HookCoverage,
    controller_url: Option<String>,
    controller_ca_path: PathBuf,
    identity_sync_interval: Duration,
    service_sync_interval: Duration,
    service_state_path: PathBuf,
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

struct ResolvedCniProvider {
    provider: NodeBlockProvider,
    snapshot: Option<NodeBlockSnapshot>,
}

struct RemoteRouteRuntime {
    controller_url: String,
    client: ReloadingControllerClient,
    token_path: PathBuf,
    node_block_state_path: PathBuf,
    state_path: PathBuf,
    local: NodeBlockSnapshot,
    ipv4_output_interface: u32,
    ipv6_output_interface: u32,
    ipv4_onlink: bool,
    ipv6_onlink: bool,
    interval: Duration,
    applied: AppliedRemoteRoutes,
}

struct AppliedRemoteRoutes {
    snapshot: RemoteRouteSnapshot,
    plan: NativeRemoteRoutePlan,
}

#[derive(Clone, Copy)]
struct RemoteRouteApplyContext<'a> {
    local: &'a NodeBlockSnapshot,
    ipv4_output_interface: u32,
    ipv6_output_interface: u32,
    ipv4_onlink: bool,
    ipv6_onlink: bool,
    state_path: &'a Path,
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
    service_epoch: Option<u64>,
    service_revision: Option<u64>,
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

struct InterfaceAttachments<'ebpf> {
    ebpf: &'ebpf mut Ebpf,
    interface: Option<String>,
    all_interfaces: bool,
    primary_direction: Direction,
    hook_coverage: HookCoverage,
    mode: TcAttachmentMode,
    pin_root: PathBuf,
    ingress_attached: HashMap<String, u32>,
    egress_attached: HashMap<String, u32>,
}

impl InterfaceAttachments<'_> {
    fn refresh(&mut self) -> Result<()> {
        let discovered = if self.all_interfaces {
            discover_interfaces()?
        } else if let Some(interface) = self.interface.as_deref() {
            HashMap::from([(interface.to_owned(), interface_index(interface)?)])
        } else {
            HashMap::new()
        };
        if self.hook_coverage == HookCoverage::Both || self.primary_direction == Direction::Ingress
        {
            refresh_direction(
                self.ebpf,
                Direction::Ingress,
                self.mode,
                &self.pin_root,
                &discovered,
                &mut self.ingress_attached,
            )?;
        }
        if self.hook_coverage == HookCoverage::Both || self.primary_direction == Direction::Egress {
            refresh_direction(
                self.ebpf,
                Direction::Egress,
                self.mode,
                &self.pin_root,
                &discovered,
                &mut self.egress_attached,
            )?;
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.ingress_attached.is_empty() && self.egress_attached.is_empty()
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

enum SupervisedFailure {
    Dataplane(anyhow::Error),
    CniTransaction(anyhow::Error),
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider()?;
    init_tracing();
    let args = Args::parse();
    if let Some(AgentCommand::Cleanup(cleanup)) = &args.command {
        return run_cleanup(cleanup);
    }
    let state = Arc::new(initial_agent_state(&args));
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let service_dataplane =
        args.ebpf_object.is_some() && (args.interface.is_some() || args.all_interfaces);
    spawn_control_plane_tasks(&args, &state, &cancellation, &mut tasks, service_dataplane)?;
    let (service_failure_tx, mut service_failure_rx) = mpsc::channel(1);
    let mut supervised_service_configured = false;

    let cni_provider = resolve_cni_provider(&args, &state).await?;
    let remote_routes = initialize_remote_routes(&args, cni_provider.as_ref(), &state).await?;
    supervised_service_configured |= spawn_cni_transaction_server(
        &args,
        cni_provider,
        &cancellation,
        &mut tasks,
        &service_failure_tx,
    )?;
    if let Some(runtime) = remote_routes {
        spawn_remote_route_task(runtime, &state, &cancellation, &mut tasks);
    }

    match (&args.ebpf_object, &args.interface, args.all_interfaces) {
        (Some(object), interface, all_interfaces) if interface.is_some() || all_interfaces => {
            supervised_service_configured = true;
            let state = Arc::clone(&state);
            let cancellation = cancellation.clone();
            let failure_tx = service_failure_tx.clone();
            let object = object.clone();
            let interface = interface.clone();
            let direction = args.direction;
            let hook_coverage = args.hook_coverage;
            let controller_url = args.controller_url.clone();
            let controller_ca_path = args.controller_ca_path.clone();
            let identity_sync_interval = Duration::from_secs(args.identity_sync_seconds.max(1));
            let service_sync_interval = Duration::from_secs(args.service_sync_seconds.max(1));
            let service_state_path = args.service_state_path.clone();
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
                    hook_coverage,
                    controller_url,
                    controller_ca_path,
                    identity_sync_interval,
                    service_sync_interval,
                    service_state_path,
                    node_name,
                    agent_token_path,
                    flow_export_interval,
                    bpf_pin_path,
                    tc_attachment_preference,
                };
                if let Err(error) = run_dataplane(config, Arc::clone(&state), cancellation).await {
                    error!(?error, "eBPF dataplane stopped");
                    state.ready.store(false, Ordering::Release);
                    let _ = failure_tx.send(SupervisedFailure::Dataplane(error)).await;
                }
            });
        }
        (None, None, false) => {
            warn!("no eBPF object/interface configured; capability-only mode");
            state.ready.store(true, Ordering::Release);
        }
        _ => bail!("--ebpf-object must be paired with either --interface or --all-interfaces"),
    }
    drop(service_failure_tx);

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

    let service_failure = tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.context("listen for shutdown signal")?;
            None
        }
        failure = service_failure_rx.recv(), if supervised_service_configured => failure,
    };
    finish_agent_tasks(cancellation, tasks, service_failure, &state).await
}

fn spawn_remote_route_task(
    runtime: RemoteRouteRuntime,
    state: &Arc<AgentState>,
    cancellation: &CancellationToken,
    tasks: &mut JoinSet<()>,
) {
    let route_state = Arc::clone(state);
    let route_cancellation = cancellation.clone();
    tasks.spawn(async move {
        run_remote_route_reconciler(runtime, route_state, route_cancellation).await;
    });
}

fn initial_agent_state(args: &Args) -> AgentState {
    new_state(
        detect_capabilities(),
        args.node_name.clone(),
        args.pod_name.clone(),
        args.pod_uid.clone(),
        args.version_transition.into(),
    )
}

async fn finish_agent_tasks(
    cancellation: CancellationToken,
    mut tasks: JoinSet<()>,
    service_failure: Option<SupervisedFailure>,
    state: &AgentState,
) -> Result<()> {
    let dataplane_failure = match service_failure.as_ref() {
        Some(SupervisedFailure::Dataplane(error)) => Some(error),
        _ => None,
    };
    hold_blocked_transition_reporting_window(dataplane_failure, state).await;
    cancellation.cancel();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            error!(%error, "agent task failed");
        }
    }
    match service_failure {
        Some(SupervisedFailure::Dataplane(error)) => Err(error).context("eBPF dataplane failed"),
        Some(SupervisedFailure::CniTransaction(error)) => {
            Err(error).context("CNI transaction API failed")
        }
        None => Ok(()),
    }
}

async fn resolve_cni_provider(
    args: &Args,
    state: &AgentState,
) -> Result<Option<ResolvedCniProvider>> {
    if args.cni_socket.is_none() {
        if args.cni_ipv4_block.is_some() || args.cni_ipv6_block.is_some() {
            bail!("CNI node blocks require --cni-socket");
        }
        return Ok(None);
    }
    match (args.cni_ipv4_block, args.cni_ipv6_block) {
        (Some(ipv4), Some(ipv6)) => Ok(Some(ResolvedCniProvider {
            provider: NodeBlockProvider::new(ipv4, ipv6),
            snapshot: None,
        })),
        (Some(_), None) | (None, Some(_)) => {
            bail!("manual CNI node blocks require both IPv4 and IPv6 values")
        }
        (None, None) => {
            let controller_url = args
                .controller_url
                .as_deref()
                .context("controller-distributed CNI blocks require --controller-url")?
                .trim_end_matches('/');
            let client =
                dataplane_controller_client(Some(controller_url), &args.controller_ca_path, state)?;
            let request = authenticated_get(
                &client,
                format!("{controller_url}/v1/state/node-block"),
                &args.agent_token_path,
            )?;
            let snapshot = match request.send().await {
                Ok(response) => response
                    .error_for_status()
                    .context("controller rejected node-block snapshot request")?
                    .json::<NodeBlockSnapshot>()
                    .await
                    .context("decode controller node-block snapshot")?,
                Err(transport_error) => {
                    let snapshot: NodeBlockSnapshot =
                        load_secure_json(&args.cni_node_block_state_path, "node-block")
                            .with_context(|| {
                                format!(
                                    "controller node-block transport failed ({transport_error}); no usable last-known-good snapshot"
                                )
                            })?;
                    warn!(
                        %transport_error,
                        path = %args.cni_node_block_state_path.display(),
                        "restored last-known-good node-block snapshot during controller outage"
                    );
                    state
                        .applied_node_block_revision
                        .store(snapshot.revision, Ordering::Release);
                    snapshot
                }
            };
            validate_node_block_snapshot(&snapshot, &args.node_name)?;
            state
                .desired_node_block_revision
                .store(snapshot.revision, Ordering::Release);
            AttachmentJournal::open(&args.cni_state_path, snapshot.provider)
                .context("validate controller node blocks against durable attachments")?;
            persist_node_block_snapshot(&args.cni_node_block_state_path, &snapshot)?;
            state
                .applied_node_block_revision
                .store(snapshot.revision, Ordering::Release);
            Ok(Some(ResolvedCniProvider {
                provider: snapshot.provider,
                snapshot: Some(snapshot),
            }))
        }
    }
}

async fn fetch_node_block_snapshot(
    controller_url: &str,
    client: &ReloadingControllerClient,
    token_path: &Path,
) -> Result<NodeBlockSnapshot> {
    authenticated_get(
        client,
        format!("{controller_url}/v1/state/node-block"),
        token_path,
    )?
    .send()
    .await
    .context("request controller node-block snapshot")?
    .error_for_status()
    .context("controller rejected node-block snapshot request")?
    .json()
    .await
    .context("decode controller node-block snapshot")
}

fn validate_node_block_snapshot(snapshot: &NodeBlockSnapshot, node_name: &str) -> Result<()> {
    if snapshot.schema_version != NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION {
        bail!(
            "unsupported node-block snapshot schema {}; expected {}",
            snapshot.schema_version,
            NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION
        );
    }
    if snapshot.revision == 0 {
        bail!("node-block snapshot revision must be nonzero");
    }
    if snapshot.node_name != node_name {
        bail!(
            "node-block snapshot targets {:?}, local node is {:?}",
            snapshot.node_name,
            node_name
        );
    }
    if snapshot.node_uid.is_empty() {
        bail!("node-block snapshot has no authoritative Node UID");
    }
    Ok(())
}

fn persist_node_block_snapshot(path: &Path, snapshot: &NodeBlockSnapshot) -> Result<()> {
    persist_secure_json(path, snapshot, "node-block")
}

fn persist_secure_json<T: Serialize>(path: &Path, value: &T, description: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{description} state path must be absolute");
    }
    let parent = path
        .parent()
        .with_context(|| format!("{description} state path must have a parent directory"))?;
    reject_node_block_symlinks(path)?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create {description} state directory {}", parent.display()))?;
    reject_node_block_symlinks(path)?;
    let file_name = path
        .file_name()
        .with_context(|| format!("{description} state path must name a file"))?
        .to_string_lossy();
    let temporary = path.with_file_name(format!(".{file_name}.tmp"));
    remove_stale_secure_temporary(&temporary, description)?;
    let bytes =
        serde_json::to_vec_pretty(value).with_context(|| format!("encode {description} state"))?;
    if bytes.len() as u64 > MAX_DURABLE_STATE_BYTES {
        bail!("{description} state exceeds the 64 MiB durable-state limit");
    }
    let write_result = (|| -> Result<()> {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("create {description} state {}", temporary.display()))?;
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn remove_stale_secure_temporary(path: &Path, description: &str) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() {
        bail!(
            "temporary {description} state {} is not a regular file",
            path.display()
        );
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "temporary {description} state {} is accessible outside its owner",
            path.display()
        );
    }
    fs::remove_file(path).with_context(|| {
        format!(
            "remove stale temporary {description} state {}",
            path.display()
        )
    })?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn load_secure_json<T: DeserializeOwned>(path: &Path, description: &str) -> Result<T> {
    if !path.is_absolute() {
        bail!("{description} state path must be absolute");
    }
    reject_node_block_symlinks(path)?;
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect {description} state {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_DURABLE_STATE_BYTES {
        bail!("{description} state must be a regular file no larger than 64 MiB");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "{description} state {} is accessible outside its owner",
            path.display()
        );
    }
    serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("decode {description} state {}", path.display()))
}

fn reject_node_block_symlinks(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "node-block state path cannot contain symlink {}",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn initialize_remote_routes(
    args: &Args,
    resolved: Option<&ResolvedCniProvider>,
    state: &Arc<AgentState>,
) -> Result<Option<RemoteRouteRuntime>> {
    let (Some(ipv4_uplink), Some(ipv6_uplink)) = (
        args.cni_native_ipv4_uplink.as_deref(),
        args.cni_native_ipv6_uplink.as_deref(),
    ) else {
        if args.cni_native_ipv4_uplink.is_some() || args.cni_native_ipv6_uplink.is_some() {
            bail!("native remote routing requires both IPv4 and IPv6 uplinks");
        }
        return Ok(None);
    };
    validate_cleanup_interface_name(ipv4_uplink)?;
    validate_cleanup_interface_name(ipv6_uplink)?;
    let local = resolved
        .and_then(|resolved| resolved.snapshot.clone())
        .context("native remote routing requires a controller-issued node-block snapshot")?;
    let controller_url = args
        .controller_url
        .as_deref()
        .context("native remote routing requires --controller-url")?
        .trim_end_matches('/')
        .to_owned();
    let client =
        dataplane_controller_client(Some(&controller_url), &args.controller_ca_path, state)?;
    let ipv4_output_interface = interface_index(ipv4_uplink)?;
    let ipv6_output_interface = interface_index(ipv6_uplink)?;
    let apply_context = RemoteRouteApplyContext {
        local: &local,
        ipv4_output_interface,
        ipv6_output_interface,
        ipv4_onlink: args.cni_native_ipv4_onlink,
        ipv6_onlink: args.cni_native_ipv6_onlink,
        state_path: &args.cni_remote_route_state_path,
    };
    let (mut applied, restored_is_current) = restore_remote_routes(apply_context, state).await?;

    let fetched =
        fetch_remote_route_snapshot(&controller_url, &client, &args.agent_token_path).await;
    match fetched {
        Ok(snapshot) => {
            applied = Some(
                apply_remote_route_snapshot(snapshot, apply_context, applied.as_ref(), state)
                    .await?,
            );
        }
        Err(error) if restored_is_current => {
            record_remote_route_error(state);
            warn!(%error, "controller unavailable; retaining last-known-good remote routes");
        }
        Err(error) => return Err(error).context("initial remote-route snapshot is unavailable"),
    }

    Ok(Some(RemoteRouteRuntime {
        controller_url,
        client,
        token_path: args.agent_token_path.clone(),
        node_block_state_path: args.cni_node_block_state_path.clone(),
        state_path: args.cni_remote_route_state_path.clone(),
        local,
        ipv4_output_interface,
        ipv6_output_interface,
        ipv4_onlink: args.cni_native_ipv4_onlink,
        ipv6_onlink: args.cni_native_ipv6_onlink,
        interval: Duration::from_secs(args.cni_route_sync_seconds.max(1)),
        applied: applied.expect("remote routing initialization establishes desired state"),
    }))
}

async fn restore_remote_routes(
    context: RemoteRouteApplyContext<'_>,
    state: &AgentState,
) -> Result<(Option<AppliedRemoteRoutes>, bool)> {
    let restored = load_remote_route_snapshot_for_startup(
        context.state_path,
        context.local,
        context.ipv4_output_interface,
        context.ipv6_output_interface,
        context.ipv4_onlink,
        context.ipv6_onlink,
    )?;
    let current = restored.as_ref().is_some_and(|(_, current)| *current);
    let applied = match restored {
        Some((restored, true)) => {
            restored
                .plan
                .apply()
                .await
                .context("repair last-known-good remote routes")?;
            publish_desired_remote_routes(state, &restored.snapshot);
            publish_applied_remote_routes(state, &restored.snapshot, &restored.plan);
            info!(
                epoch = restored.snapshot.source_epoch,
                revision = restored.snapshot.revision,
                routes = restored.plan.routes().len(),
                path = %context.state_path.display(),
                "restored last-known-good remote routes"
            );
            Some(restored)
        }
        Some((historic_routes, false)) => {
            warn!(
                epoch = historic_routes.snapshot.source_epoch,
                revision = historic_routes.snapshot.revision,
                path = %context.state_path.display(),
                "durable remote routes predate the drained local block assignment; controller replacement is required"
            );
            Some(historic_routes)
        }
        None => None,
    };
    Ok((applied, current))
}

async fn run_remote_route_reconciler(
    mut runtime: RemoteRouteRuntime,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
) {
    let mut interval = tokio::time::interval(runtime.interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = interval.tick() => {
                let local = match fetch_node_block_snapshot(
                    &runtime.controller_url,
                    &runtime.client,
                    &runtime.token_path,
                ).await {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        record_remote_route_error(&state);
                        warn!(%error, "node-block refresh failed; retaining last-known-good routes");
                        repair_last_known_good_routes(&runtime.applied, &state).await;
                        continue;
                    }
                };
                if let Err(error) = adopt_node_block_refresh(
                    &mut runtime.local,
                    local,
                    &runtime.node_block_state_path,
                    &state,
                ) {
                    record_remote_route_error(&state);
                    warn!(%error, "node-block refresh rejected; retaining last-known-good routes");
                    repair_last_known_good_routes(&runtime.applied, &state).await;
                    continue;
                }
                match fetch_remote_route_snapshot(
                    &runtime.controller_url,
                    &runtime.client,
                    &runtime.token_path,
                ).await {
                    Ok(snapshot) => {
                        match apply_remote_route_snapshot(
                            snapshot,
                            RemoteRouteApplyContext {
                                local: &runtime.local,
                                ipv4_output_interface: runtime.ipv4_output_interface,
                                ipv6_output_interface: runtime.ipv6_output_interface,
                                ipv4_onlink: runtime.ipv4_onlink,
                                ipv6_onlink: runtime.ipv6_onlink,
                                state_path: &runtime.state_path,
                            },
                            Some(&runtime.applied),
                            &state,
                        ).await {
                            Ok(applied) => runtime.applied = applied,
                            Err(error) => {
                                record_remote_route_error(&state);
                                warn!(%error, "remote-route snapshot rejected; retaining last-known-good routes");
                                repair_last_known_good_routes(&runtime.applied, &state).await;
                            }
                        }
                    }
                    Err(error) => {
                        record_remote_route_error(&state);
                        warn!(%error, "remote-route sync failed; retaining last-known-good routes");
                        repair_last_known_good_routes(&runtime.applied, &state).await;
                    }
                }
            }
        }
    }
}

fn adopt_node_block_refresh(
    current: &mut NodeBlockSnapshot,
    candidate: NodeBlockSnapshot,
    state_path: &Path,
    state: &AgentState,
) -> Result<bool> {
    validate_node_block_snapshot(&candidate, &current.node_name)?;
    state
        .desired_node_block_revision
        .store(candidate.revision, Ordering::Release);
    if candidate.node_uid != current.node_uid {
        bail!(
            "refreshed node-block snapshot changed Node UID from {:?} to {:?}",
            current.node_uid,
            candidate.node_uid
        );
    }
    if candidate.provider != current.provider {
        bail!(
            "live node-block address changes require a drained CNI restart; refusing to replace active attachments"
        );
    }
    if candidate == *current {
        return Ok(false);
    }
    persist_node_block_snapshot(state_path, &candidate)?;
    info!(
        old_revision = current.revision,
        new_revision = candidate.revision,
        path = %state_path.display(),
        "adopted refreshed controller node-block assignment provenance"
    );
    *current = candidate;
    state
        .applied_node_block_revision
        .store(current.revision, Ordering::Release);
    Ok(true)
}

async fn repair_last_known_good_routes(applied: &AppliedRemoteRoutes, state: &AgentState) {
    match applied.plan.apply().await {
        Ok(_) => publish_applied_remote_routes(state, &applied.snapshot, &applied.plan),
        Err(error) => {
            state.applied_remote_route_epoch.store(0, Ordering::Release);
            state
                .applied_remote_route_revision
                .store(0, Ordering::Release);
            state.remote_route_entries.store(0, Ordering::Release);
            state.metrics.applied_remote_route_revision.set(0);
            state.metrics.remote_route_entries.set(0);
            error!(%error, "last-known-good remote routes could not be repaired");
        }
    }
}

async fn fetch_remote_route_snapshot(
    controller_url: &str,
    client: &ReloadingControllerClient,
    token_path: &Path,
) -> Result<RemoteRouteSnapshot> {
    authenticated_get(
        client,
        format!("{controller_url}/v1/state/remote-routes"),
        token_path,
    )?
    .send()
    .await
    .context("request controller remote-route snapshot")?
    .error_for_status()
    .context("controller rejected remote-route snapshot request")?
    .json()
    .await
    .context("decode controller remote-route snapshot")
}

fn load_optional_remote_route_snapshot(
    path: &Path,
    local: &NodeBlockSnapshot,
    ipv4_output_interface: u32,
    ipv6_output_interface: u32,
    ipv4_onlink: bool,
    ipv6_onlink: bool,
) -> Result<Option<AppliedRemoteRoutes>> {
    if !path.exists() {
        return Ok(None);
    }
    let snapshot: RemoteRouteSnapshot = load_secure_json(path, "remote-route")?;
    let plan = lower_remote_route_snapshot(
        &snapshot,
        local,
        ipv4_output_interface,
        ipv6_output_interface,
        ipv4_onlink,
        ipv6_onlink,
    )?;
    Ok(Some(AppliedRemoteRoutes { snapshot, plan }))
}

fn load_remote_route_snapshot_for_startup(
    path: &Path,
    local: &NodeBlockSnapshot,
    ipv4_output_interface: u32,
    ipv6_output_interface: u32,
    ipv4_onlink: bool,
    ipv6_onlink: bool,
) -> Result<Option<(AppliedRemoteRoutes, bool)>> {
    if !path.exists() {
        return Ok(None);
    }
    match load_optional_remote_route_snapshot(
        path,
        local,
        ipv4_output_interface,
        ipv6_output_interface,
        ipv4_onlink,
        ipv6_onlink,
    ) {
        Ok(Some(applied)) => Ok(Some((applied, true))),
        Ok(None) => Ok(None),
        Err(current_error) => {
            let snapshot: RemoteRouteSnapshot = load_secure_json(path, "remote-route")
                .with_context(|| {
                    format!("current route snapshot validation failed: {current_error}")
                })?;
            if snapshot.node_name != local.node_name || snapshot.node_uid != local.node_uid {
                return Err(current_error)
                    .context("durable remote routes belong to another local Node identity");
            }
            let historic_local = NodeBlockSnapshot {
                schema_version: NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION,
                revision: snapshot.local_assignment_revision,
                node_name: snapshot.node_name.clone(),
                node_uid: snapshot.node_uid.clone(),
                provider: snapshot.local_blocks,
            };
            let plan = lower_remote_route_snapshot(
                &snapshot,
                &historic_local,
                ipv4_output_interface,
                ipv6_output_interface,
                ipv4_onlink,
                ipv6_onlink,
            )
            .with_context(|| {
                format!("current route snapshot validation failed: {current_error}")
            })?;
            Ok(Some((AppliedRemoteRoutes { snapshot, plan }, false)))
        }
    }
}

async fn apply_remote_route_snapshot(
    snapshot: RemoteRouteSnapshot,
    context: RemoteRouteApplyContext<'_>,
    previous: Option<&AppliedRemoteRoutes>,
    state: &AgentState,
) -> Result<AppliedRemoteRoutes> {
    validate_remote_route_snapshot(&snapshot, context.local)?;
    publish_desired_remote_routes(state, &snapshot);
    validate_remote_route_transition(&snapshot, previous.map(|value| &value.snapshot))?;
    let plan = lower_remote_route_snapshot(
        &snapshot,
        context.local,
        context.ipv4_output_interface,
        context.ipv6_output_interface,
        context.ipv4_onlink,
        context.ipv6_onlink,
    )?;
    match previous {
        Some(previous) => plan.reconcile_from(&previous.plan).await?,
        None => plan.apply().await?,
    };
    if let Err(cause) = persist_secure_json(context.state_path, &snapshot, "remote-route") {
        let rollback = match previous {
            Some(previous) => previous.plan.reconcile_from(&plan).await.map(|_| ()),
            None => plan.delete().await.map(|_| ()),
        };
        return match rollback {
            Ok(()) => Err(cause).context("persist applied remote-route snapshot"),
            Err(rollback) => Err(anyhow!(
                "persist applied remote-route snapshot failed ({cause}); kernel rollback also failed ({rollback})"
            )),
        };
    }
    publish_applied_remote_routes(state, &snapshot, &plan);
    Ok(AppliedRemoteRoutes { snapshot, plan })
}

fn validate_remote_route_snapshot(
    snapshot: &RemoteRouteSnapshot,
    local: &NodeBlockSnapshot,
) -> Result<()> {
    if snapshot.schema_version != REMOTE_ROUTE_SNAPSHOT_SCHEMA_VERSION {
        bail!(
            "unsupported remote-route snapshot schema {}; expected {}",
            snapshot.schema_version,
            REMOTE_ROUTE_SNAPSHOT_SCHEMA_VERSION
        );
    }
    if snapshot.source_epoch == 0 || snapshot.revision == 0 {
        bail!("remote-route snapshot epoch and revision must be nonzero");
    }
    if snapshot.node_name != local.node_name
        || snapshot.node_uid != local.node_uid
        || snapshot.local_assignment_revision != local.revision
        || snapshot.local_blocks != local.provider
    {
        bail!("remote-route snapshot does not match the durable local Node-block assignment");
    }
    Ok(())
}

fn validate_remote_route_transition(
    snapshot: &RemoteRouteSnapshot,
    previous: Option<&RemoteRouteSnapshot>,
) -> Result<()> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if previous.source_epoch != snapshot.source_epoch {
        return Ok(());
    }
    if snapshot.revision < previous.revision {
        bail!(
            "remote-route revision regressed from {} to {} in controller epoch {}",
            previous.revision,
            snapshot.revision,
            snapshot.source_epoch
        );
    }
    if snapshot.revision == previous.revision && snapshot != previous {
        bail!("remote-route snapshot content changed without a revision change");
    }
    Ok(())
}

fn lower_remote_route_snapshot(
    snapshot: &RemoteRouteSnapshot,
    local: &NodeBlockSnapshot,
    ipv4_output_interface: u32,
    ipv6_output_interface: u32,
    ipv4_onlink: bool,
    ipv6_onlink: bool,
) -> Result<NativeRemoteRoutePlan> {
    validate_remote_route_snapshot(snapshot, local)?;
    let provider = NativeRemoteRoutingProvider::new(
        local.node_name.clone(),
        local.node_uid.clone(),
        local.provider,
    )?;
    let remotes = snapshot
        .remote_nodes
        .iter()
        .map(|remote| NativeRemoteNode {
            intent: remote.intent.clone(),
            ipv4_next_hop: NativeIpv4NextHop {
                gateway: remote.ipv4_transport,
                output_interface: ipv4_output_interface,
                onlink: ipv4_onlink,
            },
            ipv6_next_hop: NativeIpv6NextHop {
                gateway: remote.ipv6_transport,
                output_interface: ipv6_output_interface,
                onlink: ipv6_onlink,
            },
        })
        .collect();
    provider.plan(remotes).map_err(Into::into)
}

fn publish_applied_remote_routes(
    state: &AgentState,
    snapshot: &RemoteRouteSnapshot,
    plan: &NativeRemoteRoutePlan,
) {
    let entries = u64::try_from(plan.routes().len()).unwrap_or(u64::MAX);
    state
        .applied_remote_route_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .applied_remote_route_revision
        .store(snapshot.revision, Ordering::Release);
    state.remote_route_entries.store(entries, Ordering::Release);
    state
        .metrics
        .applied_remote_route_revision
        .set(i64::try_from(snapshot.revision).unwrap_or(i64::MAX));
    state
        .metrics
        .remote_route_entries
        .set(i64::try_from(entries).unwrap_or(i64::MAX));
}

fn publish_desired_remote_routes(state: &AgentState, snapshot: &RemoteRouteSnapshot) {
    state
        .desired_remote_route_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .desired_remote_route_revision
        .store(snapshot.revision, Ordering::Release);
    state
        .metrics
        .desired_remote_route_revision
        .set(i64::try_from(snapshot.revision).unwrap_or(i64::MAX));
}

fn record_remote_route_error(state: &AgentState) {
    state
        .remote_route_reconcile_errors
        .fetch_add(1, Ordering::AcqRel);
    state.metrics.remote_route_sync_errors.inc();
}

fn spawn_cni_transaction_server(
    args: &Args,
    resolved: Option<ResolvedCniProvider>,
    cancellation: &CancellationToken,
    tasks: &mut JoinSet<()>,
    failure_tx: &mpsc::Sender<SupervisedFailure>,
) -> Result<bool> {
    let Some(socket_path) = &args.cni_socket else {
        return Ok(false);
    };
    let resolved = resolved.context("CNI node-block provider was not resolved")?;
    let provider = resolved.provider;
    let server = CniTransactionServer::bind(socket_path.clone(), &args.cni_state_path, provider)?;
    let server_cancellation = cancellation.clone();
    let failure_tx = failure_tx.clone();
    info!(
        socket = %socket_path.display(),
        state = %args.cni_state_path.display(),
        ipv4_block = %provider.ipv4_block,
        ipv6_block = %provider.ipv6_block,
        "root-authenticated CNI transaction API enabled"
    );
    tasks.spawn(async move {
        if let Err(error) = server.run(server_cancellation).await {
            error!(?error, "CNI transaction API stopped");
            let _ = failure_tx
                .send(SupervisedFailure::CniTransaction(error))
                .await;
        }
    });
    Ok(true)
}

fn spawn_startup_agent_status_reporter(
    args: &Args,
    state: &Arc<AgentState>,
    cancellation: &CancellationToken,
    tasks: &mut JoinSet<()>,
) -> Result<()> {
    let Some(controller_url) = args.controller_url.as_deref() else {
        return Ok(());
    };
    let controller_url = controller_url.trim_end_matches('/').to_owned();
    let client =
        dataplane_controller_client(Some(&controller_url), &args.controller_ca_path, state)?;
    let token_path = args.agent_token_path.clone();
    let reporter_state = Arc::clone(state);
    let reporter_cancellation = cancellation.clone();
    let interval = Duration::from_secs(args.identity_sync_seconds.max(1));
    tasks.spawn(async move {
        report_agent_status(
            controller_url,
            client,
            token_path,
            reporter_state,
            reporter_cancellation,
            interval,
        )
        .await;
    });
    Ok(())
}

fn spawn_control_plane_tasks(
    args: &Args,
    state: &Arc<AgentState>,
    cancellation: &CancellationToken,
    tasks: &mut JoinSet<()>,
    service_dataplane: bool,
) -> Result<()> {
    spawn_startup_agent_status_reporter(args, state, cancellation, tasks)?;
    if service_dataplane {
        Ok(())
    } else {
        spawn_service_snapshot_reconciler(args, state, cancellation, tasks)
    }
}

fn spawn_service_snapshot_reconciler(
    args: &Args,
    state: &Arc<AgentState>,
    cancellation: &CancellationToken,
    tasks: &mut JoinSet<()>,
) -> Result<()> {
    let Some(controller_url) = args.controller_url.as_deref() else {
        return Ok(());
    };
    let controller_url = controller_url.trim_end_matches('/').to_owned();
    let client =
        dataplane_controller_client(Some(&controller_url), &args.controller_ca_path, state)?;
    let token_path = args.agent_token_path.clone();
    let state_path = args.service_state_path.clone();
    let interval = Duration::from_secs(args.service_sync_seconds.max(1));
    let service_state = Arc::clone(state);
    let service_cancellation = cancellation.clone();
    tasks.spawn(async move {
        reconcile_service_snapshots(
            controller_url,
            client,
            token_path,
            state_path,
            interval,
            service_state,
            service_cancellation,
        )
        .await;
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_service_snapshots(
    controller_url: String,
    client: ReloadingControllerClient,
    token_path: PathBuf,
    state_path: PathBuf,
    interval_duration: Duration,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
) {
    let mut applied = match load_optional_service_snapshot(&state_path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            record_service_snapshot_error(&state, &error);
            warn!(%error, path = %state_path.display(), "rejected durable service snapshot");
            None
        }
    };
    if let Some(snapshot) = &applied {
        publish_desired_service_snapshot(&state, snapshot);
        publish_applied_service_snapshot(&state, snapshot);
        info!(
            epoch = snapshot.source_epoch,
            revision = snapshot.revision.get(),
            path = %state_path.display(),
            "restored last-known-good userspace service snapshot"
        );
    }

    let mut interval = tokio::time::interval(interval_duration);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut compatibility_confirmed = false;
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = interval.tick() => {
                let result = async {
                    if !compatibility_confirmed {
                        ensure_service_controller_compatibility(
                            &client,
                            &controller_url,
                            &token_path,
                        )
                        .await?;
                        compatibility_confirmed = true;
                    }
                    let candidate = fetch_service_snapshot(
                        &controller_url,
                        &client,
                        &token_path,
                    )
                    .await?;
                    adopt_service_snapshot(candidate, &mut applied, &state_path, &state)
                }
                .await;
                if let Err(error) = result {
                    record_service_snapshot_error(&state, &error);
                    warn!(%error, "service snapshot sync failed; retaining last-known-good userspace state");
                }
            }
        }
    }
}

async fn fetch_service_snapshot(
    controller_url: &str,
    client: &ReloadingControllerClient,
    token_path: &Path,
) -> Result<ServiceSnapshot> {
    authenticated_get(
        client,
        format!("{controller_url}/v1/state/services"),
        token_path,
    )?
    .send()
    .await
    .context("request controller service snapshot")?
    .error_for_status()
    .context("controller rejected service snapshot request")?
    .json()
    .await
    .context("decode controller service snapshot")
}

async fn ensure_service_controller_compatibility(
    client: &ReloadingControllerClient,
    controller_url: &str,
    token_path: &Path,
) -> Result<()> {
    let compatibility: ComponentCompatibility =
        authenticated_get(client, format!("{controller_url}/v1/version"), token_path)?
            .send()
            .await
            .context("request controller compatibility for service snapshots")?
            .error_for_status()
            .context("controller rejected service compatibility preflight")?
            .json()
            .await
            .context("decode service compatibility preflight")?;
    ensure_controller_compatibility(&compatibility)
}

fn load_optional_service_snapshot(path: &Path) -> Result<Option<ServiceSnapshot>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("inspect durable service snapshot {}", path.display())),
        Ok(_) => {
            let snapshot: ServiceSnapshot = load_secure_json(path, "service")?;
            Ok(Some(snapshot.validate_and_normalize()?))
        }
    }
}

fn service_pending_state_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .context("service state path must name a file")?
        .to_string_lossy();
    Ok(path.with_file_name(format!("{file_name}.pending")))
}

fn discard_service_pending_state(path: &Path) -> Result<()> {
    let pending = service_pending_state_path(path)?;
    match fs::symlink_metadata(&pending) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("inspect pending service snapshot {}", pending.display())),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "pending service snapshot must be a regular file: {}",
                pending.display()
            )
        }
        Ok(_) => fs::remove_file(&pending)
            .with_context(|| format!("remove pending service snapshot {}", pending.display())),
    }
}

fn prepare_service_snapshot(path: &Path, snapshot: &ServiceSnapshot) -> Result<PathBuf> {
    discard_service_pending_state(path)?;
    let pending = service_pending_state_path(path)?;
    persist_secure_json(&pending, snapshot, "pending service")?;
    Ok(pending)
}

fn commit_prepared_service_snapshot(path: &Path, pending: &Path) -> Result<()> {
    reject_node_block_symlinks(path)?;
    reject_node_block_symlinks(pending)?;
    let parent = path.parent().context("service state path has no parent")?;
    fs::rename(pending, path).with_context(|| {
        format!(
            "commit pending service snapshot {} to {}",
            pending.display(),
            path.display()
        )
    })?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn restore_service_checkpoint(path: &Path, previous: Option<&ServiceSnapshot>) -> Result<()> {
    if let Some(previous) = previous {
        return persist_secure_json(path, previous, "service rollback");
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect service checkpoint during rollback"),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("service checkpoint rollback target is not a regular file")
        }
        Ok(_) => {
            fs::remove_file(path).context("remove first service checkpoint during rollback")?;
        }
    }
    File::open(path.parent().context("service state path has no parent")?)?.sync_all()?;
    Ok(())
}

fn load_service_snapshot_for_active(
    path: &Path,
    epoch: u64,
    revision: u64,
) -> Result<ServiceSnapshot> {
    let current = load_optional_service_snapshot(path)?;
    if let Some(snapshot) = current
        .filter(|snapshot| snapshot.source_epoch == epoch && snapshot.revision.get() == revision)
    {
        discard_service_pending_state(path)?;
        return Ok(snapshot);
    }
    let pending_path = service_pending_state_path(path)?;
    let pending = load_optional_service_snapshot(&pending_path)?;
    if let Some(snapshot) = pending
        .filter(|snapshot| snapshot.source_epoch == epoch && snapshot.revision.get() == revision)
    {
        commit_prepared_service_snapshot(path, &pending_path)?;
        return Ok(snapshot);
    }
    bail!(
        "persistent active service tuple {epoch}/{revision} has no matching durable or prepared snapshot"
    )
}

fn adopt_service_snapshot(
    candidate: ServiceSnapshot,
    applied: &mut Option<ServiceSnapshot>,
    state_path: &Path,
    state: &AgentState,
) -> Result<()> {
    let candidate = candidate.validate_and_normalize()?;
    publish_desired_service_snapshot(state, &candidate);
    if !validate_service_snapshot_transition(&candidate, applied.as_ref())? {
        clear_service_snapshot_error(state);
        return Ok(());
    }
    persist_secure_json(state_path, &candidate, "service")?;
    publish_applied_service_snapshot(state, &candidate);
    info!(
        epoch = candidate.source_epoch,
        revision = candidate.revision.get(),
        services = candidate.services.len(),
        "durably adopted userspace service snapshot"
    );
    *applied = Some(candidate);
    clear_service_snapshot_error(state);
    Ok(())
}

fn validate_service_snapshot_transition(
    candidate: &ServiceSnapshot,
    applied: Option<&ServiceSnapshot>,
) -> Result<bool> {
    let Some(applied) = applied else {
        return Ok(true);
    };
    if candidate.source_epoch != applied.source_epoch {
        return Ok(true);
    }
    if candidate.revision < applied.revision {
        bail!(
            "service revision regressed from {} to {} in controller epoch {}",
            applied.revision.get(),
            candidate.revision.get(),
            candidate.source_epoch
        );
    }
    if candidate.revision == applied.revision {
        if candidate != applied {
            bail!("service snapshot content changed without a revision change");
        }
        return Ok(false);
    }
    Ok(true)
}

async fn restore_or_populate_service_state(
    synchronizer: &mut ServiceSynchronizer,
    state: &AgentState,
) -> Result<()> {
    if synchronizer.applied.is_some() {
        return Ok(());
    }
    if let Some(snapshot) = load_optional_service_snapshot(&synchronizer.state_path)? {
        publish_desired_service_snapshot(state, &snapshot);
        activate_service_snapshot(synchronizer, &snapshot, false, state)?;
        return Ok(());
    }
    if synchronizer.controller_url.is_some() {
        synchronize_services(synchronizer, state).await?;
    }
    Ok(())
}

async fn synchronize_services(
    synchronizer: &mut ServiceSynchronizer,
    state: &AgentState,
) -> Result<()> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("service synchronization requires a controller URL")?;
    let candidate = fetch_service_snapshot(
        controller_url,
        &synchronizer.client,
        &synchronizer.agent_token_path,
    )
    .await?
    .validate_and_normalize()?;
    publish_desired_service_snapshot(state, &candidate);
    if !validate_service_snapshot_transition(&candidate, synchronizer.applied.as_ref())? {
        return Ok(());
    }
    activate_service_snapshot(synchronizer, &candidate, true, state)
}

#[allow(clippy::too_many_lines)]
fn activate_service_snapshot(
    synchronizer: &mut ServiceSynchronizer,
    candidate: &ServiceSnapshot,
    persist: bool,
    state: &AgentState,
) -> Result<()> {
    let staging_bank = (synchronizer.active_bank + 1) % SERVICE_BANK_COUNT;
    let staging_index = usize::from(staging_bank);
    let desired = compile_service_dataplane(candidate, staging_bank)?;
    let previous = synchronizer.banks[staging_index]
        .clone()
        .unwrap_or_else(|| empty_service_bank(staging_bank));

    macro_rules! stage {
        ($map:expr, $current:expr, $desired:expr, $label:literal) => {
            if let Err(error) = replace_encoded_entries($map, $current, $desired) {
                return Err(rollback_service_stages(
                    synchronizer,
                    &previous,
                    &error.context(concat!("stage ", $label)),
                ));
            }
        };
    }
    stage!(
        &mut synchronizer.ipv4_frontends,
        &previous.ipv4_frontends,
        &desired.ipv4_frontends,
        "IPv4 service frontends"
    );
    stage!(
        &mut synchronizer.ipv6_frontends,
        &previous.ipv6_frontends,
        &desired.ipv6_frontends,
        "IPv6 service frontends"
    );
    stage!(
        &mut synchronizer.ipv4_backends,
        &previous.ipv4_backends,
        &desired.ipv4_backends,
        "IPv4 service backends"
    );
    stage!(
        &mut synchronizer.ipv6_backends,
        &previous.ipv6_backends,
        &desired.ipv6_backends,
        "IPv6 service backends"
    );
    stage!(
        &mut synchronizer.backend_slots,
        &previous.backend_slots,
        &desired.backend_slots,
        "service backend slots"
    );

    let validation = validate_encoded_entries(
        &synchronizer.ipv4_frontends,
        &desired.ipv4_frontends,
        "IPv4 service frontend",
    )
    .and_then(|()| {
        validate_encoded_entries(
            &synchronizer.ipv6_frontends,
            &desired.ipv6_frontends,
            "IPv6 service frontend",
        )
    })
    .and_then(|()| {
        validate_encoded_entries(
            &synchronizer.ipv4_backends,
            &desired.ipv4_backends,
            "IPv4 service backend",
        )
    })
    .and_then(|()| {
        validate_encoded_entries(
            &synchronizer.ipv6_backends,
            &desired.ipv6_backends,
            "IPv6 service backend",
        )
    })
    .and_then(|()| {
        validate_encoded_entries(
            &synchronizer.backend_slots,
            &desired.backend_slots,
            "service backend slot",
        )
    });
    if let Err(error) = validation {
        return Err(rollback_service_stages(synchronizer, &previous, &error));
    }

    let previous_config = synchronizer
        .config
        .get(&0, 0)
        .context("read service activation pointer before update")?;
    let prepared = if persist {
        match prepare_service_snapshot(&synchronizer.state_path, candidate) {
            Ok(path) => Some(path),
            Err(error) => {
                return Err(rollback_service_stages(
                    synchronizer,
                    &previous,
                    &error.context("prepare durable service snapshot before activation"),
                ));
            }
        }
    } else {
        None
    };
    if let Err(error) = synchronizer.config.set(0, desired.config, 0) {
        let pending_cleanup = discard_service_pending_state(&synchronizer.state_path);
        let activation_error = anyhow!(error).context("atomically activate staged service bank");
        if let Err(cleanup_error) = pending_cleanup {
            return Err(rollback_service_stages(
                synchronizer,
                &previous,
                &anyhow!(
                    "{activation_error:#}; pending snapshot cleanup failed: {cleanup_error:#}"
                ),
            ));
        }
        return Err(rollback_service_stages(
            synchronizer,
            &previous,
            &activation_error,
        ));
    }
    if let Some(prepared) = prepared
        && let Err(error) = commit_prepared_service_snapshot(&synchronizer.state_path, &prepared)
    {
        let config_rollback = synchronizer.config.set(0, previous_config, 0);
        let stage_rollback = restore_service_bank(synchronizer, &previous);
        let checkpoint_rollback =
            restore_service_checkpoint(&synchronizer.state_path, synchronizer.applied.as_ref());
        let pending_cleanup = discard_service_pending_state(&synchronizer.state_path);
        return match (
            config_rollback,
            stage_rollback,
            checkpoint_rollback,
            pending_cleanup,
        ) {
            (Ok(()), Ok(()), Ok(()), Ok(())) => Err(error.context(
                "commit active service snapshot failed; activation pointer and staging bank rolled back",
            )),
            (config_result, stage_result, checkpoint_result, pending_result) => Err(anyhow!(
                "commit active service snapshot failed: {error:#}; config rollback: {config_result:?}; staging rollback: {stage_result:?}; checkpoint rollback: {checkpoint_result:?}; pending cleanup: {pending_result:?}"
            )),
        };
    }

    let previous_active = synchronizer.active_bank;
    synchronizer.banks[staging_index] = Some(desired);
    synchronizer.active_bank = staging_bank;
    synchronizer.applied = Some(candidate.clone());
    publish_applied_service_snapshot(state, candidate);
    clear_service_snapshot_error(state);
    if previous_active != staging_bank {
        let previous_index = usize::from(previous_active);
        if let Some(old) = synchronizer.banks[previous_index].clone() {
            match clear_service_bank(synchronizer, &old) {
                Ok(()) => synchronizer.banks[previous_index] = None,
                Err(error) => warn!(
                    %error,
                    bank = previous_active,
                    "could not garbage-collect old service bank; restored it for a later retry"
                ),
            }
        }
    }
    info!(
        service_epoch = candidate.source_epoch,
        service_revision = candidate.revision.get(),
        active_bank = synchronizer.active_bank,
        services = candidate.services.len(),
        "service snapshot activated in persistent BPF maps"
    );
    Ok(())
}

fn replace_encoded_entries<const K: usize, const V: usize>(
    map: &mut AyaHashMap<MapData, [u8; K], [u8; V]>,
    current: &BTreeMap<[u8; K], [u8; V]>,
    desired: &BTreeMap<[u8; K], [u8; V]>,
) -> Result<()>
where
    [u8; K]: aya::Pod,
    [u8; V]: aya::Pod,
{
    for key in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(key)?;
    }
    for (key, value) in desired {
        map.insert(key, value, 0)?;
    }
    Ok(())
}

fn validate_encoded_entries<const K: usize, const V: usize>(
    map: &AyaHashMap<MapData, [u8; K], [u8; V]>,
    desired: &BTreeMap<[u8; K], [u8; V]>,
    label: &str,
) -> Result<()>
where
    [u8; K]: aya::Pod,
    [u8; V]: aya::Pod,
{
    for (key, expected) in desired {
        let actual = map
            .get(key, 0)
            .with_context(|| format!("read staged {label} entry"))?;
        if &actual != expected {
            bail!("staged {label} readback mismatch");
        }
    }
    Ok(())
}

fn restore_encoded_bank<const K: usize, const V: usize>(
    map: &mut AyaHashMap<MapData, [u8; K], [u8; V]>,
    previous: &BTreeMap<[u8; K], [u8; V]>,
    bank: u8,
    bank_offset: usize,
) -> Result<()>
where
    [u8; K]: aya::Pod,
    [u8; V]: aya::Pod,
{
    let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
    for key in keys.into_iter().filter(|key| key[bank_offset] == bank) {
        map.remove(&key)?;
    }
    for (key, value) in previous {
        map.insert(key, value, 0)?;
    }
    Ok(())
}

fn restore_service_bank(
    synchronizer: &mut ServiceSynchronizer,
    previous: &ServiceDataplaneState,
) -> Result<()> {
    let results = [
        restore_encoded_bank(
            &mut synchronizer.ipv4_frontends,
            &previous.ipv4_frontends,
            previous.bank,
            7,
        ),
        restore_encoded_bank(
            &mut synchronizer.ipv6_frontends,
            &previous.ipv6_frontends,
            previous.bank,
            19,
        ),
        restore_encoded_bank(
            &mut synchronizer.ipv4_backends,
            &previous.ipv4_backends,
            previous.bank,
            8,
        ),
        restore_encoded_bank(
            &mut synchronizer.ipv6_backends,
            &previous.ipv6_backends,
            previous.bank,
            8,
        ),
        restore_encoded_bank(
            &mut synchronizer.backend_slots,
            &previous.backend_slots,
            previous.bank,
            12,
        ),
    ];
    let failures: Vec<_> = results.into_iter().filter_map(Result::err).collect();
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("restore service bank failed: {failures:?}")
    }
}

fn rollback_service_stages(
    synchronizer: &mut ServiceSynchronizer,
    previous: &ServiceDataplaneState,
    cause: &anyhow::Error,
) -> anyhow::Error {
    match restore_service_bank(synchronizer, previous) {
        Ok(()) => anyhow!("service update failed and staging bank was rolled back: {cause:#}"),
        Err(rollback) => anyhow!("service update failed: {cause:#}; rollback failed: {rollback:#}"),
    }
}

fn clear_service_bank(
    synchronizer: &mut ServiceSynchronizer,
    old: &ServiceDataplaneState,
) -> Result<()> {
    let empty = empty_service_bank(old.bank);
    let clear = restore_service_bank(synchronizer, &empty);
    if let Err(error) = clear {
        let restore = restore_service_bank(synchronizer, old);
        return match restore {
            Ok(()) => Err(error.context("old service bank cleanup failed and was restored")),
            Err(restore) => Err(anyhow!(
                "old service bank cleanup failed: {error:#}; restoration failed: {restore:#}"
            )),
        };
    }
    Ok(())
}

fn service_snapshot_counts(snapshot: &ServiceSnapshot) -> (u64, u64, u64) {
    let services = snapshot.services.len() as u64;
    let frontends = snapshot
        .services
        .iter()
        .map(|service| service.frontends.len() as u64)
        .sum();
    let backends = snapshot
        .services
        .iter()
        .map(|service| service.backends.len() as u64)
        .sum();
    (services, frontends, backends)
}

fn publish_desired_service_snapshot(state: &AgentState, snapshot: &ServiceSnapshot) {
    state
        .desired_service_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .desired_service_revision
        .store(snapshot.revision.get(), Ordering::Release);
    state
        .metrics
        .desired_service_revision
        .set(metric_value(snapshot.revision.get()));
}

fn publish_applied_service_snapshot(state: &AgentState, snapshot: &ServiceSnapshot) {
    let (services, frontends, backends) = service_snapshot_counts(snapshot);
    state
        .applied_service_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .applied_service_revision
        .store(snapshot.revision.get(), Ordering::Release);
    state.service_count.store(services, Ordering::Release);
    state
        .service_frontend_count
        .store(frontends, Ordering::Release);
    state
        .service_backend_count
        .store(backends, Ordering::Release);
    state
        .metrics
        .applied_service_revision
        .set(metric_value(snapshot.revision.get()));
    state.metrics.service_count.set(metric_value(services));
    state
        .metrics
        .service_frontend_count
        .set(metric_value(frontends));
    state
        .metrics
        .service_backend_count
        .set(metric_value(backends));
}

fn record_service_snapshot_error(state: &AgentState, error: &anyhow::Error) {
    state
        .service_reconcile_errors
        .fetch_add(1, Ordering::AcqRel);
    state.metrics.service_sync_errors.inc();
    state.failed_service_epoch.store(
        state.desired_service_epoch.load(Ordering::Acquire),
        Ordering::Release,
    );
    state.failed_service_revision.store(
        state.desired_service_revision.load(Ordering::Acquire),
        Ordering::Release,
    );
    let mut message = error.to_string();
    if message.len() > MAX_SERVICE_ERROR_BYTES {
        let boundary = message
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= MAX_SERVICE_ERROR_BYTES)
            .last()
            .unwrap_or(0);
        message.truncate(boundary);
    }
    *mutex_lock(&state.service_last_error) = Some(message);
}

fn clear_service_snapshot_error(state: &AgentState) {
    state.failed_service_epoch.store(0, Ordering::Release);
    state.failed_service_revision.store(0, Ordering::Release);
    mutex_lock(&state.service_last_error).take();
}

async fn hold_blocked_transition_reporting_window(
    dataplane_failure: Option<&anyhow::Error>,
    state: &AgentState,
) {
    if dataplane_failure.is_none()
        || current_version_transition(state) != VersionTransition::BlockedRollback
    {
        return;
    }
    warn!(
        reporting_seconds = BLOCKED_TRANSITION_REPORTING_WINDOW.as_secs(),
        "blocked rollback remains fail-closed and observable before orchestrator retry"
    );
    tokio::time::sleep(BLOCKED_TRANSITION_REPORTING_WINDOW).await;
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
    if abi_version == 0 || abi_version > CURRENT_BPF_ABI_VERSION {
        bail!(
            "unsupported ABI version {abi_version}; this binary recognizes v1 through v{CURRENT_BPF_ABI_VERSION}"
        );
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
        3 => &ABI_V3_MAP_NAMES,
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

#[allow(clippy::too_many_lines)]
fn new_state(
    capabilities: KernelCapabilities,
    node_name: String,
    pod_name: String,
    pod_uid: String,
    version_transition: VersionTransition,
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
        service_sync_errors: Counter::default(),
        desired_service_revision: Gauge::default(),
        applied_service_revision: Gauge::default(),
        service_count: Gauge::default(),
        service_frontend_count: Gauge::default(),
        service_backend_count: Gauge::default(),
        service_dataplane_events: Counter::default(),
        service_translations: Counter::default(),
        service_drops: Counter::default(),
        service_expirations: Counter::default(),
        invalid_service_events: Counter::default(),
        remote_route_sync_errors: Counter::default(),
        desired_remote_route_revision: Gauge::default(),
        applied_remote_route_revision: Gauge::default(),
        remote_route_entries: Gauge::default(),
        telemetry_dropped_events: Counter::default(),
        telemetry_export_errors: Counter::default(),
        telemetry_exported_events: Counter::default(),
        controller_trust_reloads: Counter::default(),
        controller_trust_reload_errors: Counter::default(),
        version_transition_state: Gauge::default(),
        compatible_rollbacks: Counter::default(),
        blocked_rollbacks: Counter::default(),
        transition_recoveries: Counter::default(),
    };
    let mut registry = Registry::default();
    register_agent_metrics(&mut registry, &metrics);
    let state = AgentState {
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
        desired_service_epoch: AtomicU64::new(0),
        desired_service_revision: AtomicU64::new(0),
        applied_service_epoch: AtomicU64::new(0),
        applied_service_revision: AtomicU64::new(0),
        failed_service_epoch: AtomicU64::new(0),
        failed_service_revision: AtomicU64::new(0),
        service_count: AtomicU64::new(0),
        service_frontend_count: AtomicU64::new(0),
        service_backend_count: AtomicU64::new(0),
        service_reconcile_errors: AtomicU64::new(0),
        service_last_error: Mutex::new(None),
        service_dataplane_events: AtomicU64::new(0),
        service_translations: AtomicU64::new(0),
        service_drops: AtomicU64::new(0),
        service_expirations: AtomicU64::new(0),
        invalid_service_events: AtomicU64::new(0),
        last_service_id: AtomicU64::new(0),
        last_backend_id: AtomicU64::new(0),
        last_service_revision: AtomicU64::new(0),
        last_service_action: AtomicU64::new(0),
        last_service_reason: AtomicU64::new(0),
        desired_node_block_revision: AtomicU64::new(0),
        applied_node_block_revision: AtomicU64::new(0),
        desired_remote_route_epoch: AtomicU64::new(0),
        applied_remote_route_epoch: AtomicU64::new(0),
        desired_remote_route_revision: AtomicU64::new(0),
        applied_remote_route_revision: AtomicU64::new(0),
        remote_route_entries: AtomicU64::new(0),
        remote_route_reconcile_errors: AtomicU64::new(0),
        queued_flow_exports: AtomicU64::new(0),
        dropped_flow_exports: AtomicU64::new(0),
        exported_flow_events: AtomicU64::new(0),
        tc_attachment_mode: AtomicU64::new(TcAttachmentMode::None as u64),
        version_transition: AtomicU64::new(version_transition_code(VersionTransition::Normal)),
        capabilities,
        registry: Mutex::new(registry),
        metrics,
    };
    record_version_transition(&state, version_transition);
    state
}

fn record_version_transition(state: &AgentState, transition: VersionTransition) {
    let code = version_transition_code(transition);
    let previous = state.version_transition.swap(code, Ordering::AcqRel);
    state
        .metrics
        .version_transition_state
        .set(i64::try_from(code).expect("transition state fits in i64"));
    if previous == code {
        return;
    }
    match transition {
        VersionTransition::Normal => {}
        VersionTransition::CompatibleRollback => {
            state.metrics.compatible_rollbacks.inc();
        }
        VersionTransition::BlockedRollback => {
            state.metrics.blocked_rollbacks.inc();
        }
        VersionTransition::Recovery => {
            state.metrics.transition_recoveries.inc();
        }
    }
    info!(
        previous = version_transition_label(version_transition_from_code(previous)),
        transition = version_transition_label(transition),
        "version transition state changed"
    );
}

fn current_version_transition(state: &AgentState) -> VersionTransition {
    version_transition_from_code(state.version_transition.load(Ordering::Acquire))
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
    register_service_metrics(registry, metrics);
    register_remote_route_metrics(registry, metrics);
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
    register_version_transition_metrics(registry, metrics);
}

fn register_service_metrics(registry: &mut Registry, metrics: &AgentMetrics) {
    registry.register(
        "unf_service_sync_errors",
        "Service snapshots rejected or not durably adopted",
        metrics.service_sync_errors.clone(),
    );
    registry.register(
        "unf_service_revision_desired",
        "Latest valid service revision observed from the controller",
        metrics.desired_service_revision.clone(),
    );
    registry.register(
        "unf_service_revision_applied",
        "Service revision fully applied to the configured agent state boundary",
        metrics.applied_service_revision.clone(),
    );
    registry.register(
        "unf_service_count",
        "Services in the active durable service snapshot",
        metrics.service_count.clone(),
    );
    registry.register(
        "unf_service_frontend_count",
        "Frontends in the active durable service snapshot",
        metrics.service_frontend_count.clone(),
    );
    registry.register(
        "unf_service_backend_count",
        "Backends in the active durable service snapshot",
        metrics.service_backend_count.clone(),
    );
    registry.register(
        "unf_service_dataplane_events",
        "Validated service dataplane outcomes consumed from eBPF",
        metrics.service_dataplane_events.clone(),
    );
    registry.register(
        "unf_service_translations",
        "Successful forward and reverse service translations",
        metrics.service_translations.clone(),
    );
    registry.register(
        "unf_service_drops",
        "Service packets dropped with a machine-readable reason",
        metrics.service_drops.clone(),
    );
    registry.register(
        "unf_service_expirations",
        "Expired or corrupt service connection pairs retired by eBPF",
        metrics.service_expirations.clone(),
    );
    registry.register(
        "unf_service_invalid_events",
        "Service event records rejected due to ABI or semantic mismatch",
        metrics.invalid_service_events.clone(),
    );
}

fn register_remote_route_metrics(registry: &mut Registry, metrics: &AgentMetrics) {
    registry.register(
        "unf_remote_route_sync_errors",
        "Complete remote-route snapshots rejected or not applied",
        metrics.remote_route_sync_errors.clone(),
    );
    registry.register(
        "unf_remote_route_revision_desired",
        "Latest complete remote-route revision observed from the controller",
        metrics.desired_remote_route_revision.clone(),
    );
    registry.register(
        "unf_remote_route_revision_applied",
        "Remote-route revision applied and durably committed",
        metrics.applied_remote_route_revision.clone(),
    );
    registry.register(
        "unf_remote_route_entries",
        "Exact remote Pod-block routes in the applied snapshot",
        metrics.remote_route_entries.clone(),
    );
}

fn register_version_transition_metrics(registry: &mut Registry, metrics: &AgentMetrics) {
    registry.register(
        "unf_version_transition_state",
        "Version transition state: 0 normal, 1 compatible rollback, 2 blocked rollback, 3 recovery",
        metrics.version_transition_state.clone(),
    );
    registry.register(
        "unf_version_transition_compatible_rollbacks",
        "Agent processes started for an explicitly compatible rollback",
        metrics.compatible_rollbacks.clone(),
    );
    registry.register(
        "unf_version_transition_blocked_rollbacks",
        "Newer persistent-state downgrade attempts blocked before BPF access",
        metrics.blocked_rollbacks.clone(),
    );
    registry.register(
        "unf_version_transition_recoveries",
        "Agent processes started to recover a version transition",
        metrics.transition_recoveries.clone(),
    );
}

#[allow(clippy::too_many_lines)]
async fn run_dataplane(
    config: DataplaneConfig,
    state: Arc<AgentState>,
    cancellation: CancellationToken,
) -> Result<()> {
    if let Err(error) = ensure_bpf_pin_path_abi(&config.bpf_pin_path) {
        if configured_abi_version(&config.bpf_pin_path)
            .is_some_and(|version| version > CURRENT_BPF_ABI_VERSION)
        {
            record_version_transition(&state, VersionTransition::BlockedRollback);
            error!(
                configured_path = %config.bpf_pin_path.display(),
                compiled_abi = CURRENT_BPF_ABI_VERSION,
                "version transition blocked before persistent BPF access"
            );
        }
        return Err(error);
    }
    let (controller_url, controller_client) =
        preflight_dataplane_controller(&config, &state).await?;

    // Compatibility is checked before this call because opening the persistent
    // map set may create pins or adopt existing kernel state.
    let (mut ebpf, pins_existed) = load_persistent_ebpf(&config)?;
    let flow_ring = RingBuf::try_from(
        ebpf.take_map("FLOW_EVENTS")
            .context("eBPF object does not contain FLOW_EVENTS ring buffer")?,
    )
    .context("open FLOW_EVENTS ring buffer")?;
    let service_ring = RingBuf::try_from(
        ebpf.take_map("SERVICE_EVENTS")
            .context("eBPF object does not contain SERVICE_EVENTS ring buffer")?,
    )
    .context("open SERVICE_EVENTS ring buffer")?;
    let identity_maps = take_identity_maps(&mut ebpf)?;
    let policy_maps = take_policy_maps(&mut ebpf)?;
    let service_maps = take_service_maps(&mut ebpf)?;
    let controller_management_port = controller_url.as_deref().map(controller_port).transpose()?;
    let (mut identities, mut policies, mut services) = new_synchronizers(
        identity_maps,
        policy_maps,
        service_maps,
        controller_url.clone(),
        controller_management_port,
        controller_client.clone(),
        config.agent_token_path.clone(),
        config.identity_sync_interval,
        config.service_sync_interval,
        config.service_state_path.clone(),
    );
    let recovered =
        recover_persistent_dataplane(&mut identities, &mut policies, &mut services, pins_existed)?;
    apply_recovered_state(&state, &identities, &policies, &services, &recovered);
    let recovered_ready = recovered_dataplane_is_ready(&recovered);
    if !recovered_ready {
        populate_dataplane_before_attachment(&mut identities, &mut policies, &mut services, &state)
            .await?;
    } else if services.applied.is_none() {
        restore_or_populate_service_state(&mut services, &state).await?;
    }
    let mut attachments = attach_dataplane_programs(
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
    state.ready.store(true, Ordering::Release);
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
            service_epoch = recovered.service_epoch,
            service_revision = recovered.service_revision,
            "validated pinned last-known-good dataplane"
        );
    }
    let (flow_export_sender, flow_export_task) = spawn_flow_exporter(
        controller_url,
        controller_client,
        &config,
        &state,
        &cancellation,
    );
    consume_events(
        flow_ring,
        service_ring,
        &mut attachments,
        &mut identities,
        &mut policies,
        &mut services,
        &state,
        flow_export_sender.as_ref(),
        cancellation,
    )
    .await;
    drop(flow_export_sender);
    await_background_task(flow_export_task, "flow exporter").await;
    state.ready.store(false, Ordering::Release);
    state.bpf_loaded.store(false, Ordering::Release);
    state.metrics.bpf_loaded.set(0);
    Ok(())
}

fn attach_dataplane_programs<'ebpf>(
    ebpf: &'ebpf mut Ebpf,
    config: &DataplaneConfig,
    mode: TcAttachmentMode,
) -> Result<InterfaceAttachments<'ebpf>> {
    if config.hook_coverage == HookCoverage::Both || config.direction == Direction::Ingress {
        load_dataplane_program(ebpf, Direction::Ingress)?;
    }
    if config.hook_coverage == HookCoverage::Both || config.direction == Direction::Egress {
        load_dataplane_program(ebpf, Direction::Egress)?;
    }
    let mut attachments = InterfaceAttachments {
        ebpf,
        interface: config.interface.clone(),
        all_interfaces: config.all_interfaces,
        primary_direction: config.direction,
        hook_coverage: config.hook_coverage,
        mode,
        pin_root: config.bpf_pin_path.join("links"),
        ingress_attached: HashMap::new(),
        egress_attached: HashMap::new(),
    };
    attachments.refresh()?;
    if attachments.is_empty() {
        bail!("no non-loopback network interfaces are available");
    }
    Ok(attachments)
}

fn load_dataplane_program(ebpf: &mut Ebpf, direction: Direction) -> Result<()> {
    let program_name = dataplane_program_name(direction);
    let program: &mut SchedClassifier = ebpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF object does not contain program {program_name}"))?
        .try_into()
        .context("UNF dataplane program is not a TC classifier")?;
    program
        .load()
        .with_context(|| format!("load {program_name} TC classifier into kernel"))
}

const fn dataplane_program_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Ingress => "unf_observe_ingress",
        Direction::Egress => "unf_observe_egress",
    }
}

const fn tc_attach_type(direction: Direction) -> TcAttachType {
    match direction {
        Direction::Ingress => TcAttachType::Ingress,
        Direction::Egress => TcAttachType::Egress,
    }
}

fn recovered_dataplane_is_ready(recovered: &RecoveredDataplane) -> bool {
    recovered.identity_epoch.is_some()
        && recovered.identity_revision.is_some()
        && recovered.policy_epoch.is_some()
        && recovered.policy_revision.is_some()
}

async fn populate_dataplane_before_attachment(
    identities: &mut IdentitySynchronizer,
    policies: &mut PolicySynchronizer,
    services: &mut ServiceSynchronizer,
    state: &AgentState,
) -> Result<()> {
    if identities.controller_url.is_none() || policies.controller_url.is_none() {
        bail!("persistent BPF state is uninitialized and cannot be attached without a controller");
    }
    synchronize_identities(identities, state)
        .await
        .context("populate identity maps before dataplane attachment")?;
    synchronize_policies(policies, state)
        .await
        .context("populate policy maps before dataplane attachment")?;
    restore_or_populate_service_state(services, state)
        .await
        .context("populate service maps before dataplane attachment")?;
    let active_policy_bank = usize::from(policies.active_bank);
    info!(
        identity_epoch = identities.applied_epoch,
        identity_revision = state.applied_identity_revision.load(Ordering::Acquire),
        policy_epoch = policies.applied_epoch,
        policy_revision = state.applied_policy_revision.load(Ordering::Acquire),
        active_identity_bank = identities.active_bank,
        active_policy_bank = policies.active_bank,
        identity_policy_entries = policies.identity_banks[active_policy_bank].len(),
        ipv4_policy_entries = policies.ipv4_banks[active_policy_bank].len(),
        ipv6_policy_entries = policies.ipv6_banks[active_policy_bank].len(),
        egress_ipv4_entries = policies.egress_ipv4_banks[active_policy_bank].len(),
        egress_ipv6_entries = policies.egress_ipv6_banks[active_policy_bank].len(),
        "fresh persistent BPF state populated before attachment"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn new_synchronizers(
    identity_maps: IdentityMaps,
    policy_maps: PolicyMaps,
    service_maps: ServiceMaps,
    controller_url: Option<String>,
    controller_management_port: Option<u16>,
    client: ReloadingControllerClient,
    agent_token_path: PathBuf,
    interval: Duration,
    service_interval: Duration,
    service_state_path: PathBuf,
) -> (
    IdentitySynchronizer,
    PolicySynchronizer,
    ServiceSynchronizer,
) {
    let (ipv4_maps, ipv6_maps, identity_config) = identity_maps;
    let (identity_map, ipv4_policy_map, ipv6_policy_map, egress_ipv4_map, egress_ipv6_map, config) =
        policy_maps;
    let (
        ipv4_frontends,
        ipv6_frontends,
        ipv4_backends,
        ipv6_backends,
        backend_slots,
        service_config,
        connections,
    ) = service_maps;
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
            controller_url: controller_url.clone(),
            client: client.clone(),
            agent_token_path: agent_token_path.clone(),
            interval,
        },
        ServiceSynchronizer {
            ipv4_frontends,
            ipv6_frontends,
            ipv4_backends,
            ipv6_backends,
            backend_slots,
            config: service_config,
            connections,
            banks: [None, None],
            active_bank: 0,
            applied: None,
            controller_url,
            client,
            agent_token_path,
            state_path: service_state_path,
            interval: service_interval,
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

async fn preflight_dataplane_controller(
    config: &DataplaneConfig,
    state: &AgentState,
) -> Result<(Option<String>, ReloadingControllerClient)> {
    let controller_url = config
        .controller_url
        .as_deref()
        .map(|url| url.trim_end_matches('/').to_owned());
    let client =
        dataplane_controller_client(controller_url.as_deref(), &config.controller_ca_path, state)?;
    if let Some(controller_url) = controller_url.as_deref() {
        preflight_controller_compatibility(&client, controller_url, &config.agent_token_path)
            .await?;
    }
    Ok((controller_url, client))
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

async fn preflight_controller_compatibility(
    client: &ReloadingControllerClient,
    controller_url: &str,
    token_path: &Path,
) -> Result<()> {
    let response = match authenticated_get(
        client,
        format!("{controller_url}/v1/version"),
        token_path,
    )?
    .send()
    .await
    {
        Ok(response) => response,
        Err(error) => {
            warn!(
                %error,
                "controller compatibility preflight unavailable; retaining offline-start recovery"
            );
            return Ok(());
        }
    };
    let compatibility: ComponentCompatibility = response
        .error_for_status()
        .context("controller compatibility preflight was rejected")?
        .json()
        .await
        .context("decode controller compatibility preflight")?;
    ensure_controller_compatibility(&compatibility)?;
    info!(
        controller_revision = %compatibility.build_revision,
        persistent_bpf_state_abi_version = compatibility.persistent_bpf_state_abi_version,
        policy_snapshot_schema_version = compatibility.policy_snapshot_schema_version,
        service_snapshot_schema_version = compatibility.service_snapshot_schema_version,
        "controller compatibility preflight passed before persistent BPF state access"
    );
    Ok(())
}

fn ensure_controller_compatibility(controller: &ComponentCompatibility) -> Result<()> {
    let local = component_compatibility();
    let mismatches = [
        (
            "compatibility schema",
            controller.schema_version,
            local.schema_version,
        ),
        (
            "persistent BPF-state ABI",
            controller.persistent_bpf_state_abi_version,
            local.persistent_bpf_state_abi_version,
        ),
        (
            "identity snapshot schema",
            controller.identity_snapshot_schema_version,
            local.identity_snapshot_schema_version,
        ),
        (
            "policy snapshot schema",
            controller.policy_snapshot_schema_version,
            local.policy_snapshot_schema_version,
        ),
        (
            "service snapshot schema",
            controller.service_snapshot_schema_version,
            local.service_snapshot_schema_version,
        ),
        (
            "agent-status schema",
            controller.agent_status_schema_version,
            local.agent_status_schema_version,
        ),
        (
            "flow-export schema",
            controller.flow_export_schema_version,
            local.flow_export_schema_version,
        ),
    ]
    .into_iter()
    .filter(|(_, remote, expected)| remote != expected)
    .map(|(name, remote, expected)| format!("{name} controller={remote} agent={expected}"))
    .collect::<Vec<_>>();
    if controller.component != "unf-controller" {
        bail!(
            "incompatible controller compatibility response: component={}; expected unf-controller",
            controller.component
        );
    }
    if !mismatches.is_empty() {
        bail!(
            "incompatible controller compatibility tuple: {}",
            mismatches.join(", ")
        );
    }
    Ok(())
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

fn ensure_bpf_pin_path_abi(path: &Path) -> Result<()> {
    let expected = format!("v{CURRENT_BPF_ABI_VERSION}");
    if path.file_name().and_then(std::ffi::OsStr::to_str) != Some(expected.as_str()) {
        bail!(
            "configured BPF pin path {} is incompatible with persistent BPF-state ABI v{CURRENT_BPF_ABI_VERSION}; expected a /{expected} directory",
            path.display()
        );
    }
    Ok(())
}

fn configured_abi_version(path: &Path) -> Option<u16> {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)?
        .strip_prefix('v')?
        .parse()
        .ok()
}

#[allow(clippy::too_many_lines)]
fn recover_persistent_dataplane(
    identities: &mut IdentitySynchronizer,
    policies: &mut PolicySynchronizer,
    services: &mut ServiceSynchronizer,
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
    validate_map_capacity(
        "SERVICE_FRONTENDS_V4",
        services.ipv4_frontends.map(),
        SERVICE_FRONTEND_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "SERVICE_FRONTENDS_V6",
        services.ipv6_frontends.map(),
        SERVICE_FRONTEND_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "SERVICE_BACKENDS_V4",
        services.ipv4_backends.map(),
        SERVICE_BACKEND_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "SERVICE_BACKENDS_V6",
        services.ipv6_backends.map(),
        SERVICE_BACKEND_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "SERVICE_BACKEND_SLOTS",
        services.backend_slots.map(),
        SERVICE_BACKEND_SLOT_MAP_CAPACITY,
    )?;
    validate_map_capacity("SERVICE_CONFIG", services.config.map(), 1)?;
    validate_map_capacity(
        "SERVICE_CONNECTIONS",
        services.connections.map(),
        SERVICE_CONNECTION_MAP_CAPACITY,
    )?;

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
    let (service_epoch, service_revision) = recover_service_state(services)?;

    if pins_existed {
        info!(
            identity_entries = identity_entry_count(identities),
            identity_epoch,
            identity_revision,
            policy_epoch,
            policy_revision,
            service_epoch,
            service_revision,
            "persistent BPF maps reopened"
        );
    }
    Ok(RecoveredDataplane {
        identity_epoch,
        identity_revision,
        policy_epoch,
        policy_revision,
        service_epoch,
        service_revision,
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

fn empty_service_bank(bank: u8) -> ServiceDataplaneState {
    ServiceDataplaneState {
        source_epoch: 0,
        revision: 0,
        bank,
        ipv4_frontends: BTreeMap::new(),
        ipv6_frontends: BTreeMap::new(),
        ipv4_backends: BTreeMap::new(),
        ipv6_backends: BTreeMap::new(),
        backend_slots: BTreeMap::new(),
        config: [0; 32],
    }
}

#[allow(clippy::too_many_lines)]
fn recover_service_state(services: &mut ServiceSynchronizer) -> Result<(Option<u64>, Option<u64>)> {
    let mut banks = [empty_service_bank(0), empty_service_bank(1)];
    for entry in &services.ipv4_frontends {
        let (key, value) = entry.context("iterate persistent IPv4 service frontends")?;
        let bank = service_bank(key[7])?;
        validate_service_frontend_entry(&key, &value, 7)?;
        banks[bank].ipv4_frontends.insert(key, value);
    }
    for entry in &services.ipv6_frontends {
        let (key, value) = entry.context("iterate persistent IPv6 service frontends")?;
        let bank = service_bank(key[19])?;
        validate_service_frontend_entry(&key, &value, 19)?;
        banks[bank].ipv6_frontends.insert(key, value);
    }
    for entry in &services.ipv4_backends {
        let (key, value) = entry.context("iterate persistent IPv4 service backends")?;
        let bank = service_bank(key[8])?;
        validate_service_backend_entry(&key, &value, 14, 16, 17, 18)?;
        banks[bank].ipv4_backends.insert(key, value);
    }
    for entry in &services.ipv6_backends {
        let (key, value) = entry.context("iterate persistent IPv6 service backends")?;
        let bank = service_bank(key[8])?;
        validate_service_backend_entry(&key, &value, 26, 28, 29, 30)?;
        banks[bank].ipv6_backends.insert(key, value);
    }
    for entry in &services.backend_slots {
        let (key, value) = entry.context("iterate persistent service backend slots")?;
        let bank = service_bank(key[12])?;
        validate_service_backend_slot_entry(&key, &value)?;
        banks[bank].backend_slots.insert(key, value);
    }
    for bank in &banks {
        validate_recovered_service_bank_capacity(bank)?;
    }

    let config = services
        .config
        .get(&0, 0)
        .context("read persistent service config")?;
    let Some((epoch, revision, frontend_count, backend_count, slot_count, bank)) =
        decode_recovered_service_config(config)?
    else {
        discard_service_pending_state(&services.state_path)?;
        services.banks = banks.map(Some);
        return Ok((None, None));
    };
    let durable = load_service_snapshot_for_active(&services.state_path, epoch, revision)?;
    let expected = compile_service_dataplane(&durable, bank)?;
    let active = &banks[usize::from(bank)];
    if active.ipv4_frontends != expected.ipv4_frontends
        || active.ipv6_frontends != expected.ipv6_frontends
        || active.ipv4_backends != expected.ipv4_backends
        || active.ipv6_backends != expected.ipv6_backends
        || active.backend_slots != expected.backend_slots
        || config != expected.config
    {
        bail!("persistent active service bank does not match durable last-known-good snapshot");
    }
    if frontend_count as usize != active.ipv4_frontends.len() + active.ipv6_frontends.len()
        || backend_count as usize != active.ipv4_backends.len() + active.ipv6_backends.len()
        || slot_count as usize != active.backend_slots.len()
    {
        bail!("persistent service config counts do not match active maps");
    }
    banks[usize::from(bank)] = expected;
    services.banks = banks.map(Some);
    services.active_bank = bank;
    services.applied = Some(durable);
    Ok((Some(epoch), Some(revision)))
}

fn validate_recovered_service_bank_capacity(bank: &ServiceDataplaneState) -> Result<()> {
    for (name, actual, limit) in [
        (
            "IPv4 frontends",
            bank.ipv4_frontends.len(),
            SERVICE_FRONTEND_BANK_CAPACITY,
        ),
        (
            "IPv6 frontends",
            bank.ipv6_frontends.len(),
            SERVICE_FRONTEND_BANK_CAPACITY,
        ),
        (
            "IPv4 backends",
            bank.ipv4_backends.len(),
            SERVICE_BACKEND_BANK_CAPACITY,
        ),
        (
            "IPv6 backends",
            bank.ipv6_backends.len(),
            SERVICE_BACKEND_BANK_CAPACITY,
        ),
        (
            "backend slots",
            bank.backend_slots.len(),
            SERVICE_BACKEND_SLOT_BANK_CAPACITY,
        ),
    ] {
        if actual > limit {
            bail!(
                "persistent service bank {} has {actual} {name}; limit is {limit}",
                bank.bank
            );
        }
    }
    Ok(())
}

fn service_bank(bank: u8) -> Result<usize> {
    if bank >= SERVICE_BANK_COUNT {
        bail!("persistent service map contains invalid bank {bank}");
    }
    Ok(usize::from(bank))
}

fn validate_service_frontend_entry<const N: usize>(
    key: &[u8; N],
    value: &[u8; 32],
    bank_offset: usize,
) -> Result<()> {
    service_bank(key[bank_offset])?;
    let port_offset = bank_offset - 3;
    let port = u16::from_be_bytes(key[port_offset..port_offset + 2].try_into().unwrap());
    let protocol = key[bank_offset - 1];
    let service_id = u32::from_ne_bytes(value[0..4].try_into().unwrap());
    let backend_count = u32::from_ne_bytes(value[8..12].try_into().unwrap());
    let schema = u16::from_ne_bytes(value[12..14].try_into().unwrap());
    let revision = u64::from_ne_bytes(value[16..24].try_into().unwrap());
    if !recovered_service_address_is_valid(&key[..port_offset])
        || port == 0
        || !matches!(protocol, 6 | 17 | 132)
        || service_id == 0
        || backend_count > u32::try_from(MAX_BACKENDS_PER_SERVICE).unwrap_or(u32::MAX)
        || schema != SERVICE_MAP_ABI_VERSION
        || value[14..16] != [0; 2]
        || revision == 0
        || value[24..32] != [0; 8]
    {
        bail!("persistent service frontend map contains an incompatible entry");
    }
    Ok(())
}

fn validate_service_backend_entry<const N: usize>(
    key: &[u8; 12],
    value: &[u8; N],
    schema_offset: usize,
    protocol_offset: usize,
    flags_offset: usize,
    reserved_offset: usize,
) -> Result<()> {
    service_bank(key[8])?;
    let service_id = u32::from_ne_bytes(key[0..4].try_into().unwrap());
    let backend_id = u32::from_ne_bytes(key[4..8].try_into().unwrap());
    let revision = u64::from_ne_bytes(value[0..8].try_into().unwrap());
    let port_offset = schema_offset - 2;
    let port = u16::from_be_bytes(value[port_offset..schema_offset].try_into().unwrap());
    let schema = u16::from_ne_bytes(value[schema_offset..schema_offset + 2].try_into().unwrap());
    let flags = value[flags_offset];
    if service_id == 0
        || backend_id == 0
        || key[9..12] != [0; 3]
        || revision == 0
        || !recovered_service_address_is_valid(&value[8..port_offset])
        || port == 0
        || schema != SERVICE_MAP_ABI_VERSION
        || !matches!(value[protocol_offset], 6 | 17 | 132)
        || flags & !0b111 != 0
        || value[reserved_offset..].iter().any(|byte| *byte != 0)
    {
        bail!("persistent service backend map contains an incompatible entry");
    }
    Ok(())
}

fn recovered_service_address_is_valid(address: &[u8]) -> bool {
    match address {
        [a, b, c, d] => {
            let address = Ipv4Addr::new(*a, *b, *c, *d);
            !address.is_unspecified() && !address.is_multicast()
        }
        bytes if bytes.len() == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            let address = Ipv6Addr::from(octets);
            !address.is_unspecified() && !address.is_multicast()
        }
        _ => false,
    }
}

fn validate_service_backend_slot_entry(key: &[u8; 16], value: &[u8; 16]) -> Result<()> {
    service_bank(key[12])?;
    let service_id = u32::from_ne_bytes(key[0..4].try_into().unwrap());
    let backend_id = u32::from_ne_bytes(value[0..4].try_into().unwrap());
    let schema = u16::from_ne_bytes(value[4..6].try_into().unwrap());
    let revision = u64::from_ne_bytes(value[8..16].try_into().unwrap());
    if service_id == 0
        || backend_id == 0
        || key[13..16] != [0; 3]
        || schema != SERVICE_MAP_ABI_VERSION
        || value[6..8] != [0; 2]
        || revision == 0
    {
        bail!("persistent service backend-slot map contains an incompatible entry");
    }
    Ok(())
}

fn decode_recovered_service_config(config: [u8; 32]) -> Result<Option<RecoveredServiceConfig>> {
    if config == [0; 32] {
        return Ok(None);
    }
    let epoch = u64::from_ne_bytes(config[0..8].try_into().unwrap());
    let revision = u64::from_ne_bytes(config[8..16].try_into().unwrap());
    let frontend_count = u32::from_ne_bytes(config[16..20].try_into().unwrap());
    let backend_count = u32::from_ne_bytes(config[20..24].try_into().unwrap());
    let slot_count = u32::from_ne_bytes(config[24..28].try_into().unwrap());
    let schema = u16::from_ne_bytes(config[28..30].try_into().unwrap());
    let bank = config[30];
    if epoch == 0
        || revision == 0
        || schema != SERVICE_MAP_ABI_VERSION
        || bank >= SERVICE_BANK_COUNT
        || config[31] != 0
    {
        bail!("persistent service config is invalid or incompatible");
    }
    Ok(Some((
        epoch,
        revision,
        frontend_count,
        backend_count,
        slot_count,
        bank,
    )))
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
    services: &ServiceSynchronizer,
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
    if recovered.service_epoch.is_some()
        && recovered.service_revision.is_some()
        && let Some(snapshot) = &services.applied
    {
        publish_desired_service_snapshot(state, snapshot);
        publish_applied_service_snapshot(state, snapshot);
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

fn take_service_maps(ebpf: &mut Ebpf) -> Result<ServiceMaps> {
    let ipv4_frontends = AyaHashMap::<_, [u8; 8], [u8; 32]>::try_from(
        ebpf.take_map("SERVICE_FRONTENDS_V4")
            .context("eBPF object does not contain SERVICE_FRONTENDS_V4 map")?,
    )
    .context("open SERVICE_FRONTENDS_V4 map")?;
    let ipv6_frontends = AyaHashMap::<_, [u8; 20], [u8; 32]>::try_from(
        ebpf.take_map("SERVICE_FRONTENDS_V6")
            .context("eBPF object does not contain SERVICE_FRONTENDS_V6 map")?,
    )
    .context("open SERVICE_FRONTENDS_V6 map")?;
    let ipv4_backends = AyaHashMap::<_, [u8; 12], [u8; 24]>::try_from(
        ebpf.take_map("SERVICE_BACKENDS_V4")
            .context("eBPF object does not contain SERVICE_BACKENDS_V4 map")?,
    )
    .context("open SERVICE_BACKENDS_V4 map")?;
    let ipv6_backends = AyaHashMap::<_, [u8; 12], [u8; 32]>::try_from(
        ebpf.take_map("SERVICE_BACKENDS_V6")
            .context("eBPF object does not contain SERVICE_BACKENDS_V6 map")?,
    )
    .context("open SERVICE_BACKENDS_V6 map")?;
    let backend_slots = AyaHashMap::<_, [u8; 16], [u8; 16]>::try_from(
        ebpf.take_map("SERVICE_BACKEND_SLOTS")
            .context("eBPF object does not contain SERVICE_BACKEND_SLOTS map")?,
    )
    .context("open SERVICE_BACKEND_SLOTS map")?;
    let config = AyaArray::<_, [u8; 32]>::try_from(
        ebpf.take_map("SERVICE_CONFIG")
            .context("eBPF object does not contain SERVICE_CONFIG map")?,
    )
    .context("open SERVICE_CONFIG map")?;
    let connections = AyaHashMap::<_, [u8; 40], [u8; 88]>::try_from(
        ebpf.take_map("SERVICE_CONNECTIONS")
            .context("eBPF object does not contain SERVICE_CONNECTIONS map")?,
    )
    .context("open SERVICE_CONNECTIONS map")?;
    Ok((
        ipv4_frontends,
        ipv6_frontends,
        ipv4_backends,
        ipv6_backends,
        backend_slots,
        config,
        connections,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn consume_events(
    mut flow_ring: RingBuf<aya::maps::MapData>,
    mut service_ring: RingBuf<aya::maps::MapData>,
    attachments: &mut InterfaceAttachments<'_>,
    identities: &mut IdentitySynchronizer,
    policies: &mut PolicySynchronizer,
    services: &mut ServiceSynchronizer,
    state: &AgentState,
    flow_export_sender: Option<&mpsc::Sender<FlowExportRecord>>,
    cancellation: CancellationToken,
) {
    let mut event_interval = tokio::time::interval(Duration::from_millis(25));
    let mut interface_interval = tokio::time::interval(Duration::from_secs(1));
    let mut identity_interval = tokio::time::interval(identities.interval);
    let mut policy_interval = tokio::time::interval(policies.interval);
    let mut service_interval = tokio::time::interval(services.interval);
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
            _ = service_interval.tick(), if services.controller_url.is_some() => {
                if let Err(error) = synchronize_services(services, state).await {
                    record_service_snapshot_error(state, &error);
                    warn!(%error, "service map synchronization failed; retaining active bank");
                } else {
                    clear_service_snapshot_error(state);
                    refresh_controller_readiness(state);
                }
            }
            _ = event_interval.tick() => {
                while let Some(item) = flow_ring.next() {
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
                drain_service_events(&mut service_ring, state, flow_export_sender);
            }
        }
    }
}

fn drain_service_events(
    ring: &mut RingBuf<MapData>,
    state: &AgentState,
    flow_export_sender: Option<&mpsc::Sender<FlowExportRecord>>,
) {
    while let Some(item) = ring.next() {
        let Some(event) = decode_service_event(&item) else {
            state.invalid_service_events.fetch_add(1, Ordering::Relaxed);
            state.metrics.invalid_service_events.inc();
            continue;
        };
        record_service_event(state, &event);
        if let Some(sender) = flow_export_sender {
            enqueue_flow_export(sender, state, service_flow_export_record(&event));
        }
        info!(
            service_id = event.service_id.get(),
            backend_id = event.backend_id.get(),
            service_revision = event.service_revision,
            client = ?event.client_address,
            frontend = ?event.frontend_address,
            backend = ?event.backend_address,
            client_port = u16::from_be_bytes(event.client_port),
            frontend_port = u16::from_be_bytes(event.frontend_port),
            backend_port = u16::from_be_bytes(event.backend_port),
            protocol = event.protocol,
            address_family = event.address_family,
            action = event.action,
            reason = event.reason,
            "service dataplane outcome"
        );
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
            service: None,
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
        service: None,
        observed_events: 1,
    }
}

fn service_flow_export_record(event: &ServiceEvent) -> FlowExportRecord {
    let backend_id = (event.backend_id.get() != 0).then_some(event.backend_id);
    let (backend_ipv4, backend_ipv6) = service_event_backend_address(event);
    FlowExportRecord {
        key: FlowHistoryKey {
            direction: PolicyDirection::Ingress,
            source_identity: IdentityId::new(0),
            destination_identity: IdentityId::new(0),
            source_ipv4: event_ipv4(event.address_family, event.client_address),
            destination_ipv4: event_ipv4(event.address_family, event.frontend_address),
            source_ipv6: event_ipv6(event.address_family, event.client_address),
            destination_ipv6: event_ipv6(event.address_family, event.frontend_address),
            protocol: event.protocol,
            destination_port: u16::from_be_bytes(event.frontend_port),
            service: Some(ServiceFlowKey {
                service_id: event.service_id,
                backend_id,
                service_revision: Revision::new(event.service_revision),
                action: event.action,
                reason: event.reason,
            }),
        },
        policy_revision: Revision::default(),
        decision: FlowExportDecision {
            verdict: match event.action {
                SERVICE_EVENT_ACTION_TRANSLATE => Verdict::Allow,
                SERVICE_EVENT_ACTION_DROP => Verdict::Deny,
                SERVICE_EVENT_ACTION_EXPIRE => Verdict::Audit,
                _ => unreachable!("validated service event action"),
            },
            reason: event.reason,
            policy_id: None,
            rule_id: None,
        },
        shadow: None,
        service: Some(ServiceFlowOutcome {
            service_id: event.service_id,
            backend_id,
            service_revision: Revision::new(event.service_revision),
            backend_ipv4,
            backend_ipv6,
            frontend_port: u16::from_be_bytes(event.frontend_port),
            backend_port: backend_id.map(|_| u16::from_be_bytes(event.backend_port)),
            action: event.action,
            reason: event.reason,
        }),
        observed_events: 1,
    }
}

fn service_event_backend_address(event: &ServiceEvent) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    if event.backend_id.get() == 0 || event.backend_address.iter().all(|byte| *byte == 0) {
        return (None, None);
    }
    (
        event_ipv4(event.address_family, event.backend_address),
        event_ipv6(event.address_family, event.backend_address),
    )
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

fn record_service_event(state: &AgentState, event: &ServiceEvent) {
    state
        .service_dataplane_events
        .fetch_add(1, Ordering::Relaxed);
    state.metrics.service_dataplane_events.inc();
    match event.action {
        SERVICE_EVENT_ACTION_TRANSLATE => {
            state.service_translations.fetch_add(1, Ordering::Relaxed);
            state.metrics.service_translations.inc();
        }
        SERVICE_EVENT_ACTION_DROP => {
            state.service_drops.fetch_add(1, Ordering::Relaxed);
            state.metrics.service_drops.inc();
        }
        SERVICE_EVENT_ACTION_EXPIRE => {
            state.service_expirations.fetch_add(1, Ordering::Relaxed);
            state.metrics.service_expirations.inc();
        }
        _ => return,
    }
    state
        .last_service_id
        .store(u64::from(event.service_id.get()), Ordering::Release);
    state
        .last_backend_id
        .store(u64::from(event.backend_id.get()), Ordering::Release);
    state
        .last_service_revision
        .store(event.service_revision, Ordering::Release);
    state
        .last_service_action
        .store(u64::from(event.action), Ordering::Release);
    state
        .last_service_reason
        .store(u64::from(event.reason), Ordering::Release);
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
        version_transition: current_version_transition(state),
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
        desired_service_epoch: state.desired_service_epoch.load(Ordering::Acquire),
        desired_service_revision: state.desired_service_revision.load(Ordering::Acquire),
        applied_service_epoch: state.applied_service_epoch.load(Ordering::Acquire),
        applied_service_revision: state.applied_service_revision.load(Ordering::Acquire),
        failed_service_epoch: state.failed_service_epoch.load(Ordering::Acquire),
        failed_service_revision: state.failed_service_revision.load(Ordering::Acquire),
        service_count: state.service_count.load(Ordering::Acquire),
        service_frontend_count: state.service_frontend_count.load(Ordering::Acquire),
        service_backend_count: state.service_backend_count.load(Ordering::Acquire),
        service_reconcile_errors: state.service_reconcile_errors.load(Ordering::Acquire),
        service_last_error: mutex_lock(&state.service_last_error).clone(),
        service_dataplane_events: state.service_dataplane_events.load(Ordering::Acquire),
        service_translations: state.service_translations.load(Ordering::Acquire),
        service_drops: state.service_drops.load(Ordering::Acquire),
        service_expirations: state.service_expirations.load(Ordering::Acquire),
        invalid_service_events: state.invalid_service_events.load(Ordering::Acquire),
        last_service_id: u32::try_from(state.last_service_id.load(Ordering::Acquire))
            .expect("stored service ID fits u32"),
        last_backend_id: u32::try_from(state.last_backend_id.load(Ordering::Acquire))
            .expect("stored backend ID fits u32"),
        last_service_revision: state.last_service_revision.load(Ordering::Acquire),
        last_service_action: u8::try_from(state.last_service_action.load(Ordering::Acquire))
            .expect("stored service action fits u8"),
        last_service_reason: u8::try_from(state.last_service_reason.load(Ordering::Acquire))
            .expect("stored service reason fits u8"),
        desired_node_block_revision: state.desired_node_block_revision.load(Ordering::Acquire),
        applied_node_block_revision: state.applied_node_block_revision.load(Ordering::Acquire),
        desired_remote_route_epoch: state.desired_remote_route_epoch.load(Ordering::Acquire),
        applied_remote_route_epoch: state.applied_remote_route_epoch.load(Ordering::Acquire),
        desired_remote_route_revision: state.desired_remote_route_revision.load(Ordering::Acquire),
        applied_remote_route_revision: state.applied_remote_route_revision.load(Ordering::Acquire),
        remote_route_entries: state.remote_route_entries.load(Ordering::Acquire),
        remote_route_reconcile_errors: state.remote_route_reconcile_errors.load(Ordering::Acquire),
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
        existing.service = record.service;
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
    if entry.key.destination_identity.get() == 0
        && !(entry.key.source_address != Ipv4Addr::UNSPECIFIED
            && entry.key.protocol == 0
            && entry.key.destination_port == 0
            && platform_node_exception(&entry.decision, entry.shadow.as_ref()))
    {
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
    if entry.key.destination_identity.get() == 0
        && !(entry.key.source_network != Ipv6Addr::UNSPECIFIED
            && entry.key.source_prefix_len == 128
            && entry.key.protocol == 0
            && entry.key.destination_port == 0
            && platform_node_exception(&entry.decision, entry.shadow.as_ref()))
    {
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
    if entry.key.source_identity.get() == 0
        && !(entry.key.destination_address != Ipv4Addr::UNSPECIFIED
            && entry.key.protocol == 0
            && entry.key.destination_port == 0
            && platform_node_exception(&entry.decision, entry.shadow.as_ref()))
    {
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
    if entry.key.source_identity.get() == 0
        && !(entry.key.destination_network != Ipv6Addr::UNSPECIFIED
            && entry.key.destination_prefix_len == 128
            && entry.key.protocol == 0
            && entry.key.destination_port == 0
            && platform_node_exception(&entry.decision, entry.shadow.as_ref()))
    {
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

fn platform_node_exception(
    decision: &PolicyDecisionRecord,
    shadow: Option<&PolicyDecisionRecord>,
) -> bool {
    decision.verdict == Verdict::Allow
        && decision.reason == PolicyReason::NoApplicablePolicy
        && decision.policy_id.is_none()
        && decision.rule_id.is_none()
        && shadow.is_none()
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

fn refresh_direction(
    ebpf: &mut Ebpf,
    direction: Direction,
    mode: TcAttachmentMode,
    pin_root: &Path,
    discovered: &HashMap<String, u32>,
    attached: &mut HashMap<String, u32>,
) -> Result<()> {
    attached.retain(|interface, if_index| discovered.get(interface) == Some(if_index));
    let unattached: Vec<_> = discovered
        .iter()
        .filter(|(interface, if_index)| attached.get(*interface) != Some(*if_index))
        .map(|(interface, if_index)| (interface.clone(), *if_index))
        .collect();
    let program_name = dataplane_program_name(direction);
    let program: &mut SchedClassifier = ebpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF object does not contain program {program_name}"))?
        .try_into()
        .context("UNF dataplane program is not a TC classifier")?;
    let attach_type = tc_attach_type(direction);
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

fn decode_service_event(bytes: &[u8]) -> Option<ServiceEvent> {
    if bytes.len() != size_of::<ServiceEvent>() {
        return None;
    }
    let version = u16::from_ne_bytes(copy_bytes(bytes, 78)?);
    let size = u16::from_ne_bytes(copy_bytes(bytes, 80)?);
    let protocol = bytes[82];
    let address_family = bytes[83];
    let action = bytes[84];
    let reason = bytes[85];
    if version != SERVICE_EVENT_ABI_VERSION
        || usize::from(size) != size_of::<ServiceEvent>()
        || !matches!(protocol, 6 | 17)
        || !matches!(address_family, 4 | 6)
        || !service_event_action_reason_is_valid(action, reason)
        || bytes[86..96] != [0; 10]
    {
        return None;
    }
    Some(ServiceEvent {
        timestamp_ns: u64::from_ne_bytes(copy_bytes(bytes, 0)?),
        service_revision: u64::from_ne_bytes(copy_bytes(bytes, 8)?),
        client_address: copy_bytes(bytes, 16)?,
        frontend_address: copy_bytes(bytes, 32)?,
        backend_address: copy_bytes(bytes, 48)?,
        service_id: unf_common::ServiceId::new(u32::from_ne_bytes(copy_bytes(bytes, 64)?)),
        backend_id: unf_common::BackendId::new(u32::from_ne_bytes(copy_bytes(bytes, 68)?)),
        client_port: copy_bytes(bytes, 72)?,
        frontend_port: copy_bytes(bytes, 74)?,
        backend_port: copy_bytes(bytes, 76)?,
        version,
        size,
        protocol,
        address_family,
        action,
        reason,
        reserved: copy_bytes(bytes, 86)?,
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
        healthy: current_version_transition(&state) != VersionTransition::BlockedRollback,
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
        limitation: "ClusterIP translation is qualified only for primary-CNI Pod-veth IPv4/IPv6 TCP/UDP on recorded tuples; NodePort schema-v2 intent is not yet distributed or lowered to a host-facing dataplane",
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
    use aya::programs::{TestRun, TestRunOptions};
    use tempfile::tempdir;
    use unf_route::{RemoteNodeIntent, RemoteRouteSnapshotNode};

    #[test]
    fn cni_node_block_arguments_support_manual_or_controller_distribution() {
        let defaults = Args::try_parse_from(["unf-agent"]).expect("default arguments parse");
        assert_eq!(defaults.cni_socket, None);
        assert_eq!(
            defaults.cni_state_path,
            Path::new("/var/lib/unf/cni/v1/attachments.json")
        );
        let distributed = Args::try_parse_from(["unf-agent", "--cni-socket", "/run/unf/cni.sock"])
            .expect("controller-distributed block mode parses");
        assert!(distributed.cni_ipv4_block.is_none());
        assert!(distributed.cni_ipv6_block.is_none());
        assert!(
            Args::try_parse_from([
                "unf-agent",
                "--cni-socket",
                "/run/unf/cni.sock",
                "--cni-ipv4-block",
                "10.42.0.0/24",
            ])
            .is_err()
        );

        let enabled = Args::try_parse_from([
            "unf-agent",
            "--cni-socket",
            "/run/unf/cni.sock",
            "--cni-state-path",
            "/var/lib/unf/cni/v1/test.json",
            "--cni-ipv4-block",
            "10.42.0.0/24",
            "--cni-ipv6-block",
            "fd00:42::/64",
        ])
        .expect("CNI transaction arguments parse");
        assert_eq!(
            enabled.cni_socket.as_deref(),
            Some(Path::new("/run/unf/cni.sock"))
        );
        assert_eq!(
            enabled.cni_ipv4_block.expect("IPv4 block").to_string(),
            "10.42.0.0/24"
        );

        assert!(
            Args::try_parse_from([
                "unf-agent",
                "--cni-socket",
                "/run/unf/cni.sock",
                "--cni-native-ipv4-uplink",
                "eth0",
            ])
            .is_err()
        );
        let native = Args::try_parse_from([
            "unf-agent",
            "--cni-socket",
            "/run/unf/cni.sock",
            "--cni-native-ipv4-uplink",
            "eth0",
            "--cni-native-ipv6-uplink",
            "eth1",
            "--cni-native-ipv4-onlink",
        ])
        .expect("dual-stack native route arguments parse");
        assert_eq!(native.cni_native_ipv4_uplink.as_deref(), Some("eth0"));
        assert_eq!(native.cni_native_ipv6_uplink.as_deref(), Some("eth1"));
        assert!(native.cni_native_ipv4_onlink);
        assert!(!native.cni_native_ipv6_onlink);
    }

    #[test]
    fn controller_node_block_snapshot_is_validated_and_persisted_atomically() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("node-block.json");
        let snapshot = NodeBlockSnapshot {
            schema_version: NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION,
            revision: 4,
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
            provider: NodeBlockProvider::new(
                "10.42.0.0/24".parse().unwrap(),
                "fd00:42::/64".parse().unwrap(),
            ),
        };
        validate_node_block_snapshot(&snapshot, "worker-a").unwrap();
        persist_node_block_snapshot(&path, &snapshot).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            serde_json::from_slice::<NodeBlockSnapshot>(&fs::read(&path).unwrap()).unwrap(),
            snapshot
        );

        let mut wrong = snapshot.clone();
        wrong.node_name = "worker-b".to_owned();
        assert!(validate_node_block_snapshot(&wrong, "worker-a").is_err());
        wrong = snapshot.clone();
        wrong.schema_version += 1;
        assert!(validate_node_block_snapshot(&wrong, "worker-a").is_err());

        let target = directory.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(persist_node_block_snapshot(&link.join("state.json"), &snapshot).is_err());
    }

    #[test]
    fn secure_json_persistence_recovers_only_private_regular_temporary_files() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("node-block.json");
        let temporary = directory.path().join(".node-block.json.tmp");
        let snapshot = NodeBlockSnapshot {
            schema_version: NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION,
            revision: 4,
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
            provider: NodeBlockProvider::new(
                "10.42.0.0/24".parse().unwrap(),
                "fd00:42::/64".parse().unwrap(),
            ),
        };
        let mut stale = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .unwrap();
        stale.write_all(b"{\n").unwrap();
        stale.sync_all().unwrap();

        persist_node_block_snapshot(&path, &snapshot)
            .expect("private regular stale temporary state is recoverable");
        assert!(!temporary.exists());
        assert_eq!(
            load_secure_json::<NodeBlockSnapshot>(&path, "node-block").unwrap(),
            snapshot
        );

        fs::remove_file(&path).unwrap();
        let outside = directory.path().join("outside");
        fs::write(&outside, b"preserve").unwrap();
        std::os::unix::fs::symlink(&outside, &temporary).unwrap();
        assert!(persist_node_block_snapshot(&path, &snapshot).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"preserve");
        assert!(
            fs::symlink_metadata(&temporary)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn node_block_refresh_adopts_revision_only_epoch_changes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("node-block.json");
        let state = test_agent_state();
        let (mut current, _) = route_test_snapshots();
        let mut refreshed = current.clone();
        refreshed.revision = 1;

        assert!(
            adopt_node_block_refresh(&mut current, refreshed.clone(), &path, &state)
                .expect("revision-only refresh is adopted")
        );
        assert_eq!(current, refreshed);
        assert_eq!(state.desired_node_block_revision.load(Ordering::Acquire), 1);
        assert_eq!(state.applied_node_block_revision.load(Ordering::Acquire), 1);
        assert_eq!(
            load_secure_json::<NodeBlockSnapshot>(&path, "node-block").unwrap(),
            refreshed
        );
        assert!(
            !adopt_node_block_refresh(&mut current, refreshed.clone(), &path, &state)
                .expect("idempotent refresh succeeds")
        );

        let mut changed_provider = refreshed.clone();
        changed_provider.revision = 2;
        changed_provider.provider = NodeBlockProvider::new(
            "10.99.0.0/24".parse().unwrap(),
            "fd00:99::/64".parse().unwrap(),
        );
        assert!(adopt_node_block_refresh(&mut current, changed_provider, &path, &state).is_err());
        assert_eq!(current, refreshed);

        let mut replaced_node = refreshed.clone();
        replaced_node.revision = 3;
        replaced_node.node_uid = "replacement-uid".to_owned();
        assert!(adopt_node_block_refresh(&mut current, replaced_node, &path, &state).is_err());
        assert_eq!(current, refreshed);
    }

    fn route_test_snapshots() -> (NodeBlockSnapshot, RemoteRouteSnapshot) {
        let local = NodeBlockSnapshot {
            schema_version: NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION,
            revision: 4,
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
            provider: NodeBlockProvider::new(
                "10.42.0.0/24".parse().unwrap(),
                "fd00:42::/64".parse().unwrap(),
            ),
        };
        let snapshot = RemoteRouteSnapshot {
            schema_version: REMOTE_ROUTE_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 9,
            revision: 7,
            node_name: local.node_name.clone(),
            node_uid: local.node_uid.clone(),
            local_assignment_revision: local.revision,
            local_blocks: local.provider,
            remote_nodes: vec![RemoteRouteSnapshotNode {
                intent: RemoteNodeIntent {
                    node_name: "worker-b".to_owned(),
                    node_uid: "worker-b-uid".to_owned(),
                    assignment_revision: 6,
                    blocks: NodeBlockProvider::new(
                        "10.43.0.0/24".parse().unwrap(),
                        "fd00:43::/64".parse().unwrap(),
                    ),
                },
                ipv4_transport: "192.0.2.2".parse().unwrap(),
                ipv6_transport: "fdff::2".parse().unwrap(),
            }],
        };
        (local, snapshot)
    }

    fn service_test_snapshot(epoch: u64, revision: u64) -> ServiceSnapshot {
        unf_service::compile_service_snapshot(
            epoch,
            Revision::new(revision),
            vec![unf_service::ServiceSource {
                namespace: "default".to_owned(),
                name: "api".to_owned(),
                cluster_ips: vec!["10.96.0.10".parse().unwrap()],
                external_traffic_policy: unf_service::ServiceTrafficPolicy::Cluster,
                ports: vec![unf_service::ServiceSourcePort {
                    name: Some("http".to_owned()),
                    protocol: unf_common::Protocol::Tcp,
                    port: 80,
                    app_protocol: Some("kubernetes.io/h2c".to_owned()),
                    node_port: None,
                }],
            }],
            Vec::new(),
        )
        .expect("test service snapshot compiles")
    }

    fn service_test_snapshot_with_backend(epoch: u64, revision: u64) -> ServiceSnapshot {
        unf_service::compile_service_snapshot(
            epoch,
            Revision::new(revision),
            vec![unf_service::ServiceSource {
                namespace: "default".to_owned(),
                name: "api".to_owned(),
                cluster_ips: vec!["10.96.0.10".parse().unwrap()],
                external_traffic_policy: unf_service::ServiceTrafficPolicy::Cluster,
                ports: vec![unf_service::ServiceSourcePort {
                    name: Some("http".to_owned()),
                    protocol: unf_common::Protocol::Tcp,
                    port: 80,
                    app_protocol: None,
                    node_port: None,
                }],
            }],
            vec![unf_service::EndpointSliceSource {
                namespace: "default".to_owned(),
                name: "api-v4".to_owned(),
                service_name: "api".to_owned(),
                address_family: unf_service::AddressFamily::Ipv4,
                endpoints: vec![unf_service::EndpointSource {
                    addresses: vec!["10.42.0.20".parse().unwrap()],
                    target_workload: Some("default/api-0".to_owned()),
                    node_name: Some("worker-a".to_owned()),
                    zone: None,
                    ready: true,
                    serving: true,
                    terminating: false,
                    ports: vec![unf_service::EndpointPortSource {
                        name: Some("http".to_owned()),
                        protocol: unf_common::Protocol::Tcp,
                        port: Some(8080),
                        app_protocol: None,
                    }],
                }],
            }],
        )
        .expect("test service snapshot with backend compiles")
    }

    fn dual_stack_service_snapshot(
        revision: u64,
        ipv4_backend: Ipv4Addr,
        ipv6_backend: Ipv6Addr,
        include_backends: bool,
    ) -> ServiceSnapshot {
        let ports = vec![
            unf_service::ServiceSourcePort {
                name: Some("http".to_owned()),
                protocol: unf_common::Protocol::Tcp,
                port: 80,
                app_protocol: None,
                node_port: None,
            },
            unf_service::ServiceSourcePort {
                name: Some("dns".to_owned()),
                protocol: unf_common::Protocol::Udp,
                port: 53,
                app_protocol: None,
                node_port: None,
            },
        ];
        let endpoint_ports = vec![
            unf_service::EndpointPortSource {
                name: Some("http".to_owned()),
                protocol: unf_common::Protocol::Tcp,
                port: Some(8080),
                app_protocol: None,
            },
            unf_service::EndpointPortSource {
                name: Some("dns".to_owned()),
                protocol: unf_common::Protocol::Udp,
                port: Some(5353),
                app_protocol: None,
            },
        ];
        let slices = if include_backends {
            vec![
                unf_service::EndpointSliceSource {
                    namespace: "default".to_owned(),
                    name: "api-v4".to_owned(),
                    service_name: "api".to_owned(),
                    address_family: unf_service::AddressFamily::Ipv4,
                    endpoints: vec![unf_service::EndpointSource {
                        addresses: vec![ipv4_backend.into()],
                        target_workload: Some("default/api-v4".to_owned()),
                        node_name: Some("worker-a".to_owned()),
                        zone: None,
                        ready: true,
                        serving: true,
                        terminating: false,
                        ports: endpoint_ports.clone(),
                    }],
                },
                unf_service::EndpointSliceSource {
                    namespace: "default".to_owned(),
                    name: "api-v6".to_owned(),
                    service_name: "api".to_owned(),
                    address_family: unf_service::AddressFamily::Ipv6,
                    endpoints: vec![unf_service::EndpointSource {
                        addresses: vec![ipv6_backend.into()],
                        target_workload: Some("default/api-v6".to_owned()),
                        node_name: Some("worker-a".to_owned()),
                        zone: None,
                        ready: true,
                        serving: true,
                        terminating: false,
                        ports: endpoint_ports,
                    }],
                },
            ]
        } else {
            Vec::new()
        };
        unf_service::compile_service_snapshot(
            7,
            Revision::new(revision),
            vec![unf_service::ServiceSource {
                namespace: "default".to_owned(),
                name: "api".to_owned(),
                cluster_ips: vec![
                    Ipv4Addr::new(10, 96, 0, 10).into(),
                    "fd00:96::10".parse::<Ipv6Addr>().unwrap().into(),
                ],
                external_traffic_policy: unf_service::ServiceTrafficPolicy::Cluster,
                ports,
            }],
            slices,
        )
        .expect("dual-stack service snapshot compiles")
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0_u32;
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(byte) = chunks.remainder().first() {
            sum += u32::from(*byte) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !u16::try_from(sum).expect("folded checksum fits u16")
    }

    fn transport_segment(protocol: u8, source_port: u16, destination_port: u16) -> Vec<u8> {
        if protocol == 6 {
            let mut segment = vec![0_u8; 20];
            segment[0..2].copy_from_slice(&source_port.to_be_bytes());
            segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
            segment[12] = 5 << 4;
            segment[13] = 0x02;
            segment[14..16].copy_from_slice(&65_535_u16.to_be_bytes());
            segment
        } else {
            let mut segment = vec![0_u8; 12];
            let segment_length = u16::try_from(segment.len()).expect("test segment fits u16");
            segment[0..2].copy_from_slice(&source_port.to_be_bytes());
            segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
            segment[4..6].copy_from_slice(&segment_length.to_be_bytes());
            segment[8..12].copy_from_slice(b"unf!");
            segment
        }
    }

    fn ipv4_packet(
        protocol: u8,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut transport = transport_segment(protocol, source_port, destination_port);
        let mut pseudo = Vec::with_capacity(12 + transport.len());
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(
            &u16::try_from(transport.len())
                .expect("test segment fits u16")
                .to_be_bytes(),
        );
        pseudo.extend_from_slice(&transport);
        let checksum_offset = if protocol == 6 { 16 } else { 6 };
        let mut transport_checksum = checksum(&pseudo);
        if protocol == 17 && transport_checksum == 0 {
            transport_checksum = u16::MAX;
        }
        transport[checksum_offset..checksum_offset + 2]
            .copy_from_slice(&transport_checksum.to_be_bytes());

        let mut packet = vec![0_u8; 14 + 20];
        packet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(
            &u16::try_from(20 + transport.len())
                .expect("test packet fits u16")
                .to_be_bytes(),
        );
        packet[22] = 64;
        packet[23] = protocol;
        packet[26..30].copy_from_slice(&source.octets());
        packet[30..34].copy_from_slice(&destination.octets());
        let header_checksum = checksum(&packet[14..34]);
        packet[24..26].copy_from_slice(&header_checksum.to_be_bytes());
        packet.extend_from_slice(&transport);
        packet
    }

    fn ipv6_packet(
        protocol: u8,
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut transport = transport_segment(protocol, source_port, destination_port);
        let mut pseudo = Vec::with_capacity(40 + transport.len());
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(
            &u32::try_from(transport.len())
                .expect("test segment fits u32")
                .to_be_bytes(),
        );
        pseudo.extend_from_slice(&[0, 0, 0, protocol]);
        pseudo.extend_from_slice(&transport);
        let checksum_offset = if protocol == 6 { 16 } else { 6 };
        let mut transport_checksum = checksum(&pseudo);
        if transport_checksum == 0 {
            transport_checksum = u16::MAX;
        }
        transport[checksum_offset..checksum_offset + 2]
            .copy_from_slice(&transport_checksum.to_be_bytes());

        let mut packet = vec![0_u8; 14 + 40];
        packet[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        packet[14] = 0x60;
        packet[18..20].copy_from_slice(
            &u16::try_from(transport.len())
                .expect("test segment fits u16")
                .to_be_bytes(),
        );
        packet[20] = protocol;
        packet[21] = 64;
        packet[22..38].copy_from_slice(&source.octets());
        packet[38..54].copy_from_slice(&destination.octets());
        packet.extend_from_slice(&transport);
        packet
    }

    fn run_tc(ebpf: &mut Ebpf, program_name: &str, packet: &[u8]) -> (u32, Vec<u8>) {
        let mut output = vec![0_u8; packet.len() + 64];
        let program: &mut SchedClassifier = ebpf
            .program_mut(program_name)
            .expect("service TC program exists")
            .try_into()
            .expect("service program is a TC classifier");
        let result = program
            .test_run(TestRunOptions {
                data_in: Some(packet),
                data_out: Some(&mut output),
                ..Default::default()
            })
            .expect("TC packet test run succeeds");
        output.truncate(result.data_size_out as usize);
        (result.return_value, output)
    }

    fn assert_ipv4_packet(
        packet: &[u8],
        protocol: u8,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) {
        assert_eq!(&packet[26..30], &source.octets());
        assert_eq!(&packet[30..34], &destination.octets());
        assert_eq!(u16::from_be_bytes([packet[34], packet[35]]), source_port);
        assert_eq!(
            u16::from_be_bytes([packet[36], packet[37]]),
            destination_port
        );
        assert_eq!(checksum(&packet[14..34]), 0);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(&[0, protocol]);
        pseudo.extend_from_slice(
            &u16::try_from(packet.len() - 34)
                .expect("test segment fits u16")
                .to_be_bytes(),
        );
        pseudo.extend_from_slice(&packet[34..]);
        assert_eq!(checksum(&pseudo), 0);
    }

    fn assert_ipv6_packet(
        packet: &[u8],
        protocol: u8,
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) {
        assert_eq!(&packet[22..38], &source.octets());
        assert_eq!(&packet[38..54], &destination.octets());
        assert_eq!(u16::from_be_bytes([packet[54], packet[55]]), source_port);
        assert_eq!(
            u16::from_be_bytes([packet[56], packet[57]]),
            destination_port
        );
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(
            &u32::try_from(packet.len() - 54)
                .expect("test segment fits u32")
                .to_be_bytes(),
        );
        pseudo.extend_from_slice(&[0, 0, 0, protocol]);
        pseudo.extend_from_slice(&packet[54..]);
        assert_eq!(checksum(&pseudo), 0);
    }

    #[test]
    fn service_snapshot_reconciliation_is_durable_fenced_and_reported() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("service-snapshot.json");
        let state = test_agent_state();
        let first = service_test_snapshot(7, 4);
        let mut applied = None;

        adopt_service_snapshot(first.clone(), &mut applied, &path, &state)
            .expect("first snapshot is durably adopted");
        assert_eq!(applied.as_ref(), Some(&first));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_optional_service_snapshot(&path).unwrap(),
            Some(first.clone())
        );
        let report = agent_state_report(&state);
        assert_eq!(report.desired_service_epoch, 7);
        assert_eq!(report.applied_service_epoch, 7);
        assert_eq!(report.desired_service_revision, 4);
        assert_eq!(report.applied_service_revision, 4);
        assert_eq!(report.service_count, 1);
        assert_eq!(report.service_frontend_count, 1);
        assert_eq!(report.service_backend_count, 0);
        assert!(report.service_last_error.is_none());

        let regressed = service_test_snapshot(7, 3);
        let error = adopt_service_snapshot(regressed, &mut applied, &path, &state)
            .expect_err("same-epoch regression is rejected");
        record_service_snapshot_error(&state, &error);
        assert_eq!(applied.as_ref(), Some(&first));
        let report = agent_state_report(&state);
        assert_eq!(report.desired_service_revision, 3);
        assert_eq!(report.applied_service_revision, 4);
        assert_eq!(report.failed_service_epoch, 7);
        assert_eq!(report.failed_service_revision, 3);
        assert_eq!(report.service_reconcile_errors, 1);
        assert!(report.service_last_error.is_some());

        let mut mutated = first.clone();
        mutated.services[0].frontends[0].app_protocol = Some("example.com/other".to_owned());
        assert!(validate_service_snapshot_transition(&mutated, applied.as_ref()).is_err());

        let replacement = service_test_snapshot(8, 1);
        adopt_service_snapshot(replacement.clone(), &mut applied, &path, &state)
            .expect("new controller epoch is accepted");
        assert_eq!(applied.as_ref(), Some(&replacement));
        let report = agent_state_report(&state);
        assert_eq!(report.desired_service_epoch, 8);
        assert_eq!(report.applied_service_epoch, 8);
        assert_eq!(report.applied_service_revision, 1);
        assert_eq!(report.failed_service_epoch, 0);
        assert_eq!(report.failed_service_revision, 0);
        assert!(report.service_last_error.is_none());
    }

    #[test]
    fn malformed_durable_service_snapshot_is_not_restored() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("service-snapshot.json");
        let mut snapshot = service_test_snapshot(7, 4);
        snapshot.schema_version += 1;
        persist_secure_json(&path, &snapshot, "service").unwrap();
        assert!(load_optional_service_snapshot(&path).is_err());
    }

    #[test]
    fn service_map_config_and_entries_reject_corrupt_persistent_state() {
        let compiled = compile_service_dataplane(&service_test_snapshot(7, 4), 1).unwrap();
        assert_eq!(
            decode_recovered_service_config(compiled.config).unwrap(),
            Some((7, 4, 1, 0, 0, 1))
        );
        let (key, value) = compiled.ipv4_frontends.first_key_value().unwrap();
        validate_service_frontend_entry(key, value, 7).unwrap();

        let mut corrupt_config = compiled.config;
        corrupt_config[28..30].copy_from_slice(&(SERVICE_MAP_ABI_VERSION + 1).to_ne_bytes());
        assert!(decode_recovered_service_config(corrupt_config).is_err());
        let mut corrupt_value = *value;
        corrupt_value[24] = 1;
        assert!(validate_service_frontend_entry(key, &corrupt_value, 7).is_err());
        let mut corrupt_key = *key;
        corrupt_key[7] = SERVICE_BANK_COUNT;
        assert!(validate_service_frontend_entry(&corrupt_key, value, 7).is_err());
    }

    #[test]
    fn service_map_checkpoint_recovers_each_two_phase_crash_boundary() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("service.json");
        let first = service_test_snapshot(7, 1);
        let second = service_test_snapshot(7, 2);
        persist_secure_json(&path, &first, "service").unwrap();

        let pending = prepare_service_snapshot(&path, &second).unwrap();
        assert!(pending.exists());
        let recovered = load_service_snapshot_for_active(&path, 7, 1).unwrap();
        assert_eq!(recovered, first);
        assert!(!pending.exists());

        let pending = prepare_service_snapshot(&path, &second).unwrap();
        let recovered = load_service_snapshot_for_active(&path, 7, 2).unwrap();
        assert_eq!(recovered, second);
        assert!(!pending.exists());
        assert_eq!(load_optional_service_snapshot(&path).unwrap(), Some(second));
    }

    #[test]
    #[ignore = "requires root BPF map creation and UNF_EBPF_OBJECT"]
    fn privileged_service_map_partial_capacity_failure_rolls_back_inactive_bank() {
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut loader = EbpfLoader::new();
        loader
            .map_max_entries("SERVICE_FRONTENDS_V4", 4)
            .map_max_entries("SERVICE_FRONTENDS_V6", 4)
            .map_max_entries("SERVICE_BACKENDS_V4", 4)
            .map_max_entries("SERVICE_BACKENDS_V6", 4)
            .map_max_entries("SERVICE_BACKEND_SLOTS", 1);
        let mut ebpf = loader
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("service TC program exists")
                .try_into()
                .expect("service program is a TC classifier");
            program
                .load()
                .expect("kernel verifier accepts service TC program");
        }
        let (
            ipv4_frontends,
            ipv6_frontends,
            ipv4_backends,
            ipv6_backends,
            backend_slots,
            config,
            connections,
        ) = take_service_maps(&mut ebpf).expect("take service maps");
        let directory = tempdir().unwrap();
        let mut synchronizer = ServiceSynchronizer {
            ipv4_frontends,
            ipv6_frontends,
            ipv4_backends,
            ipv6_backends,
            backend_slots,
            config,
            connections,
            banks: [None, None],
            active_bank: 0,
            applied: None,
            controller_url: None,
            client: ReloadingControllerClient::without_custom_trust(
                Counter::default(),
                Counter::default(),
            ),
            agent_token_path: PathBuf::new(),
            state_path: directory.path().join("service.json"),
            interval: Duration::from_secs(1),
        };
        let state = test_agent_state();
        let first = service_test_snapshot_with_backend(7, 1);
        activate_service_snapshot(&mut synchronizer, &first, false, &state)
            .expect("first service bank activates");
        let active_config = synchronizer.config.get(&0, 0).unwrap();
        assert_eq!(active_config[30], 1);

        let second = service_test_snapshot_with_backend(7, 2);
        let error = activate_service_snapshot(&mut synchronizer, &second, false, &state)
            .expect_err("full backend-slot map rejects the partial inactive stage");
        assert!(error.to_string().contains("staging bank was rolled back"));
        assert_eq!(synchronizer.config.get(&0, 0).unwrap(), active_config);
        assert_eq!(synchronizer.active_bank, 1);
        assert_eq!(synchronizer.applied.as_ref(), Some(&first));
        assert!(
            synchronizer
                .ipv4_frontends
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .iter()
                .all(|key| key[7] == 1)
        );
        assert!(
            synchronizer
                .ipv4_backends
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .iter()
                .all(|key| key[8] == 1)
        );
    }

    #[test]
    #[ignore = "requires root BPF program execution and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_service_packets_translate_dual_stack_and_survive_churn() {
        const TC_ACT_SHOT: u32 = 2;
        const TC_ACT_PIPE: u32 = 3;
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("service TC program exists")
                .try_into()
                .expect("service program is a TC classifier");
            program
                .load()
                .expect("kernel verifier accepts service TC program");
        }
        let mut service_events = RingBuf::try_from(
            ebpf.take_map("SERVICE_EVENTS")
                .expect("service event ring exists"),
        )
        .expect("service event ring opens");
        let (
            ipv4_frontends,
            ipv6_frontends,
            ipv4_backends,
            ipv6_backends,
            backend_slots,
            config,
            connections,
        ) = take_service_maps(&mut ebpf).expect("take service maps");
        let directory = tempdir().unwrap();
        let mut synchronizer = ServiceSynchronizer {
            ipv4_frontends,
            ipv6_frontends,
            ipv4_backends,
            ipv6_backends,
            backend_slots,
            config,
            connections,
            banks: [None, None],
            active_bank: 0,
            applied: None,
            controller_url: None,
            client: ReloadingControllerClient::without_custom_trust(
                Counter::default(),
                Counter::default(),
            ),
            agent_token_path: PathBuf::new(),
            state_path: directory.path().join("service.json"),
            interval: Duration::from_secs(1),
        };
        let state = test_agent_state();
        let service_v4 = Ipv4Addr::new(10, 96, 0, 10);
        let backend_v4 = Ipv4Addr::new(10, 42, 0, 20);
        let client_v4 = Ipv4Addr::new(10, 42, 0, 5);
        let service_v6 = "fd00:96::10".parse::<Ipv6Addr>().unwrap();
        let backend_v6 = "fd00:42::20".parse::<Ipv6Addr>().unwrap();
        let client_v6 = "fd00:42::5".parse::<Ipv6Addr>().unwrap();
        let first = dual_stack_service_snapshot(1, backend_v4, backend_v6, true);
        activate_service_snapshot(&mut synchronizer, &first, false, &state)
            .expect("dual-stack service activates");

        let ipv4_tcp = ipv4_packet(6, client_v4, service_v4, 40_000, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 40_000, 8080);
        let reverse = ipv4_packet(6, backend_v4, client_v4, 8080, 40_000);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, service_v4, client_v4, 80, 40_000);

        let ipv4_udp = ipv4_packet(17, client_v4, service_v4, 40_001, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, client_v4, backend_v4, 40_001, 5353);
        let reverse = ipv4_packet(17, backend_v4, client_v4, 5353, 40_001);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, service_v4, client_v4, 53, 40_001);

        let ipv6_tcp = ipv6_packet(6, client_v6, service_v6, 40_002, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, client_v6, backend_v6, 40_002, 8080);
        let reverse = ipv6_packet(6, backend_v6, client_v6, 8080, 40_002);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, service_v6, client_v6, 80, 40_002);

        let ipv6_udp = ipv6_packet(17, client_v6, service_v6, 40_003, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, client_v6, backend_v6, 40_003, 5353);
        let reverse = ipv6_packet(17, backend_v6, client_v6, 5353, 40_003);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, service_v6, client_v6, 53, 40_003);
        assert_eq!(
            synchronizer
                .connections
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            8
        );

        let replacement_v4 = Ipv4Addr::new(10, 42, 0, 21);
        let replacement_v6 = "fd00:42::21".parse::<Ipv6Addr>().unwrap();
        let second = dual_stack_service_snapshot(2, replacement_v4, replacement_v6, true);
        activate_service_snapshot(&mut synchronizer, &second, false, &state)
            .expect("replacement backend activates");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 40_000, 8080);
        let new_flow = ipv4_packet(6, client_v4, service_v4, 41_000, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &new_flow);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, replacement_v4, 41_000, 8080);

        let connection_keys = synchronizer
            .connections
            .keys()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut expired_pair_entries = 0;
        for key in connection_keys {
            let mut value = synchronizer.connections.get(&key, 0).unwrap();
            if value[72..74] == 40_000_u16.to_be_bytes() {
                value[0..8].copy_from_slice(&0_u64.to_ne_bytes());
                synchronizer.connections.insert(key, value, 0).unwrap();
                expired_pair_entries += 1;
            }
        }
        assert_eq!(expired_pair_entries, 2);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, replacement_v4, 40_000, 8080);
        let refreshed_pair = synchronizer
            .connections
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .filter(|(_, value)| value[72..74] == 40_000_u16.to_be_bytes())
            .collect::<Vec<_>>();
        assert_eq!(refreshed_pair.len(), 2);
        assert!(refreshed_pair.iter().all(|(_, value)| {
            u64::from_ne_bytes(value[8..16].try_into().unwrap()) == 2
                && u32::from_ne_bytes(value[64..68].try_into().unwrap()) != 0
                && u32::from_ne_bytes(value[68..72].try_into().unwrap()) != 0
                && value[48..52] == replacement_v4.octets()
                && value[52..64] == [0; 12]
        }));

        let backendless = dual_stack_service_snapshot(3, replacement_v4, replacement_v6, false);
        activate_service_snapshot(&mut synchronizer, &backendless, false, &state)
            .expect("backendless frontend activates");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, replacement_v4, 40_000, 8080);
        let no_backend = ipv4_packet(6, client_v4, service_v4, 42_000, 80);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &no_backend);
        assert_eq!(action, TC_ACT_SHOT);
        let unrelated = ipv4_packet(6, client_v4, Ipv4Addr::new(192, 0, 2, 10), 42_001, 80);
        let (action, output) = run_tc(&mut ebpf, "unf_observe_ingress", &unrelated);
        assert_eq!(action, TC_ACT_PIPE);
        assert_eq!(output, unrelated);

        let mut events = Vec::new();
        while let Some(item) = service_events.next() {
            events.push(decode_service_event(&item).expect("kernel service event is valid"));
        }
        assert_eq!(events.len(), 14);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.action == SERVICE_EVENT_ACTION_TRANSLATE)
                .count(),
            12
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.action == SERVICE_EVENT_ACTION_EXPIRE)
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.action == SERVICE_EVENT_ACTION_DROP)
                .count(),
            1
        );
        let no_backend = events
            .iter()
            .find(|event| event.reason == unf_ebpf_common::SERVICE_EVENT_REASON_NO_BACKEND)
            .expect("backendless drop has explicit provenance");
        assert_ne!(no_backend.service_id.get(), 0);
        assert_eq!(no_backend.backend_id.get(), 0);
        assert_eq!(no_backend.service_revision, 3);
    }

    #[test]
    fn remote_route_snapshot_is_strict_lowerable_and_durable() {
        let (local, snapshot) = route_test_snapshots();
        let plan = lower_remote_route_snapshot(&snapshot, &local, 3, 4, true, false).unwrap();
        assert_eq!(plan.local_node_name(), "worker-a");
        assert_eq!(plan.remote_nodes().len(), 1);
        assert_eq!(plan.routes().len(), 2);
        assert!(plan.routes().iter().any(|route| route.onlink));
        assert!(plan.routes().iter().any(|route| !route.onlink));

        let directory = tempdir().unwrap();
        let path = directory.path().join("remote-routes.json");
        persist_secure_json(&path, &snapshot, "remote-route").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let restored = load_optional_remote_route_snapshot(&path, &local, 3, 4, true, false)
            .unwrap()
            .unwrap();
        assert_eq!(restored.snapshot, snapshot);
        assert_eq!(restored.plan.routes(), plan.routes());

        let mut wrong = snapshot.clone();
        wrong.node_uid = "another-uid".to_owned();
        assert!(validate_remote_route_snapshot(&wrong, &local).is_err());
        let encoded = serde_json::to_value(&snapshot).unwrap();
        let mut encoded = encoded.as_object().unwrap().clone();
        encoded.insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<RemoteRouteSnapshot>(encoded.into()).is_err());

        let mut rotated = local.clone();
        rotated.revision += 1;
        rotated.provider = NodeBlockProvider::new(
            "10.45.0.0/24".parse().unwrap(),
            "fd00:45::/64".parse().unwrap(),
        );
        let (_, current) =
            load_remote_route_snapshot_for_startup(&path, &rotated, 3, 4, true, false)
                .unwrap()
                .unwrap();
        assert!(!current);
        rotated.node_uid = "replacement-node-uid".to_owned();
        assert!(
            load_remote_route_snapshot_for_startup(&path, &rotated, 3, 4, true, false).is_err()
        );
    }

    #[test]
    fn remote_route_revision_replay_rejects_regression_and_mutation() {
        let (_, snapshot) = route_test_snapshots();
        assert!(validate_remote_route_transition(&snapshot, Some(&snapshot)).is_ok());

        let mut regressed = snapshot.clone();
        regressed.revision -= 1;
        assert!(validate_remote_route_transition(&regressed, Some(&snapshot)).is_err());

        let mut mutated = snapshot.clone();
        mutated.remote_nodes[0].ipv4_transport = "192.0.2.22".parse().unwrap();
        assert!(validate_remote_route_transition(&mutated, Some(&snapshot)).is_err());

        mutated.source_epoch += 1;
        assert!(validate_remote_route_transition(&mutated, Some(&snapshot)).is_ok());
    }

    #[test]
    fn remote_route_status_distinguishes_desired_applied_and_errors() {
        let capabilities = KernelCapabilities {
            kernel_release: "test".to_owned(),
            btf: true,
            bpffs: true,
            cgroup_v2: true,
        };
        let state = new_state(
            capabilities,
            "worker-a".to_owned(),
            "agent-a".to_owned(),
            "agent-a-uid".to_owned(),
            VersionTransition::Normal,
        );
        let (local, snapshot) = route_test_snapshots();
        let plan = lower_remote_route_snapshot(&snapshot, &local, 3, 4, false, false).unwrap();
        publish_desired_remote_routes(&state, &snapshot);
        publish_applied_remote_routes(&state, &snapshot, &plan);
        record_remote_route_error(&state);

        let report = agent_state_report(&state);
        assert_eq!(report.desired_remote_route_epoch, 9);
        assert_eq!(report.applied_remote_route_epoch, 9);
        assert_eq!(report.desired_remote_route_revision, 7);
        assert_eq!(report.applied_remote_route_revision, 7);
        assert_eq!(report.remote_route_entries, 2);
        assert_eq!(report.remote_route_reconcile_errors, 1);
    }

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
        assert!(plan_abi_cleanup(&root, CURRENT_BPF_ABI_VERSION + 1, true).is_err());
        assert!(plan_abi_cleanup(&root, 0, false).is_err());
        assert!(plan_abi_cleanup(&root, 2, false).is_ok());
        assert!(plan_abi_cleanup(Path::new("relative"), 1, false).is_err());
        assert!(plan_abi_cleanup(Path::new("/"), 1, false).is_err());
    }

    #[test]
    fn only_complete_recovered_state_can_attach_without_initial_population() {
        let complete = RecoveredDataplane {
            identity_epoch: Some(7),
            identity_revision: Some(11),
            policy_epoch: Some(7),
            policy_revision: Some(13),
            service_epoch: None,
            service_revision: None,
        };
        assert!(recovered_dataplane_is_ready(&complete));

        for incomplete in [
            RecoveredDataplane {
                identity_epoch: None,
                identity_revision: None,
                policy_epoch: None,
                policy_revision: None,
                service_epoch: None,
                service_revision: None,
            },
            RecoveredDataplane {
                identity_epoch: Some(7),
                identity_revision: Some(11),
                policy_epoch: None,
                policy_revision: None,
                service_epoch: None,
                service_revision: None,
            },
            RecoveredDataplane {
                identity_epoch: None,
                identity_revision: None,
                policy_epoch: Some(7),
                policy_revision: Some(13),
                service_epoch: None,
                service_revision: None,
            },
        ] {
            assert!(!recovered_dataplane_is_ready(&incomplete));
        }
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
    fn service_event_decoder_and_status_preserve_bounded_provenance() {
        let mut bytes = [0_u8; size_of::<ServiceEvent>()];
        bytes[8..16].copy_from_slice(&7_u64.to_ne_bytes());
        bytes[16..20].copy_from_slice(&[10, 42, 0, 10]);
        bytes[32..36].copy_from_slice(&[10, 96, 0, 80]);
        bytes[48..52].copy_from_slice(&[10, 42, 1, 20]);
        bytes[64..68].copy_from_slice(&11_u32.to_ne_bytes());
        bytes[68..72].copy_from_slice(&13_u32.to_ne_bytes());
        bytes[72..74].copy_from_slice(&40_000_u16.to_be_bytes());
        bytes[74..76].copy_from_slice(&80_u16.to_be_bytes());
        bytes[76..78].copy_from_slice(&8080_u16.to_be_bytes());
        bytes[78..80].copy_from_slice(&SERVICE_EVENT_ABI_VERSION.to_ne_bytes());
        bytes[80..82].copy_from_slice(
            &u16::try_from(size_of::<ServiceEvent>())
                .expect("service event size fits u16")
                .to_ne_bytes(),
        );
        bytes[82] = 6;
        bytes[83] = 4;
        bytes[84] = SERVICE_EVENT_ACTION_TRANSLATE;
        bytes[85] = unf_ebpf_common::SERVICE_EVENT_REASON_FORWARD_TRANSLATED;
        let event = decode_service_event(&bytes).expect("service event ABI is valid");
        let record = service_flow_export_record(&event);
        assert_eq!(record.key.source_ipv4, Some(Ipv4Addr::new(10, 42, 0, 10)));
        assert_eq!(
            record.key.destination_ipv4,
            Some(Ipv4Addr::new(10, 96, 0, 80))
        );
        assert_eq!(record.key.destination_port, 80);
        assert_eq!(record.decision.verdict, Verdict::Allow);
        let outcome = record.service.expect("service provenance is exported");
        assert_eq!(outcome.service_id.get(), 11);
        assert_eq!(outcome.backend_id.expect("backend ID").get(), 13);
        assert_eq!(outcome.backend_ipv4, Some(Ipv4Addr::new(10, 42, 1, 20)));
        assert_eq!(outcome.backend_port, Some(8080));
        let state = test_agent_state();
        record_service_event(&state, &event);
        let report = agent_state_report(&state);
        assert_eq!(report.service_dataplane_events, 1);
        assert_eq!(report.service_translations, 1);
        assert_eq!(report.service_drops, 0);
        assert_eq!(report.last_service_id, 11);
        assert_eq!(report.last_backend_id, 13);
        assert_eq!(report.last_service_revision, 7);
        assert_eq!(report.last_service_action, SERVICE_EVENT_ACTION_TRANSLATE);
        assert_eq!(
            report.last_service_reason,
            unf_ebpf_common::SERVICE_EVENT_REASON_FORWARD_TRANSLATED
        );

        bytes[85] = unf_ebpf_common::SERVICE_EVENT_REASON_NO_BACKEND;
        assert!(decode_service_event(&bytes).is_none());
        bytes[86] = 1;
        assert!(decode_service_event(&bytes).is_none());
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
                Path::new("/sys/fs/bpf/unf/v4/links"),
                Direction::Ingress,
                17
            ),
            Path::new("/sys/fs/bpf/unf/v4/links/tcx-ingress-17")
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
            VersionTransition::Normal,
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
        assert_eq!(
            version.service_snapshot_schema_version,
            unf_service::SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
    }

    #[test]
    fn controller_preflight_accepts_only_the_exact_local_tuple() {
        let mut controller = ComponentCompatibility::current(
            "unf-controller",
            env!("CARGO_PKG_VERSION"),
            "controller-revision",
        );
        assert!(ensure_controller_compatibility(&controller).is_ok());

        controller.policy_snapshot_schema_version += 1;
        let error = ensure_controller_compatibility(&controller)
            .expect_err("a policy-schema mismatch is rejected");
        assert!(
            error
                .to_string()
                .contains("policy snapshot schema controller=5 agent=4")
        );

        controller.policy_snapshot_schema_version -= 1;
        controller.persistent_bpf_state_abi_version += 1;
        let error = ensure_controller_compatibility(&controller)
            .expect_err("a persistent-ABI mismatch is rejected");
        assert!(
            error
                .to_string()
                .contains("persistent BPF-state ABI controller=5 agent=4")
        );

        controller.persistent_bpf_state_abi_version -= 1;
        controller.service_snapshot_schema_version += 1;
        let error = ensure_controller_compatibility(&controller)
            .expect_err("a service-schema mismatch is rejected");
        assert!(error.to_string().contains(&format!(
            "service snapshot schema controller={} agent={}",
            unf_service::SERVICE_SNAPSHOT_SCHEMA_VERSION + 1,
            unf_service::SERVICE_SNAPSHOT_SCHEMA_VERSION
        )));
    }

    #[test]
    fn controller_preflight_rejects_a_non_controller_response() {
        let response = component_compatibility();
        let error = ensure_controller_compatibility(&response)
            .expect_err("an agent response cannot satisfy controller preflight");
        assert!(
            error
                .to_string()
                .contains("component=unf-agent; expected unf-controller")
        );
    }

    #[test]
    fn persistent_abi_requires_its_exact_versioned_pin_directory() {
        assert!(ensure_bpf_pin_path_abi(Path::new("/sys/fs/bpf/unf/v4")).is_ok());
        assert_eq!(
            configured_abi_version(Path::new("/sys/fs/bpf/unf/v5")),
            Some(5)
        );
        let error = ensure_bpf_pin_path_abi(Path::new("/sys/fs/bpf/unf/v2"))
            .expect_err("a stale ABI directory is rejected before access");
        assert!(
            error.to_string().contains(
                "incompatible with persistent BPF-state ABI v4; expected a /v4 directory"
            )
        );
        assert!(ensure_bpf_pin_path_abi(Path::new("/sys/fs/bpf/unf-v4")).is_err());
        assert_eq!(
            configured_abi_version(Path::new("/sys/fs/bpf/unf-v3")),
            None
        );
    }

    #[test]
    fn version_transition_reporting_is_idempotent_and_machine_readable() {
        let state = test_agent_state();
        record_version_transition(&state, VersionTransition::BlockedRollback);
        record_version_transition(&state, VersionTransition::BlockedRollback);

        assert_eq!(
            agent_state_report(&state).version_transition,
            VersionTransition::BlockedRollback
        );
        assert_eq!(state.metrics.version_transition_state.get(), 2);
        assert_eq!(state.metrics.blocked_rollbacks.get(), 1);
        assert_eq!(state.metrics.compatible_rollbacks.get(), 0);
        assert_eq!(state.metrics.transition_recoveries.get(), 0);
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
                service: None,
            },
            policy_revision: Revision::new(7),
            decision: FlowExportDecision {
                verdict: Verdict::Allow,
                reason: 1,
                policy_id: Some(PolicyId::new(9)),
                rule_id: Some(RuleId::new(0)),
            },
            shadow: None,
            service: None,
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
    fn exact_platform_node_fallback_is_the_only_reserved_address_policy_shape() {
        let decision = PolicyDecisionRecord {
            verdict: Verdict::Allow,
            reason: PolicyReason::NoApplicablePolicy,
            policy_id: None,
            rule_id: None,
        };
        let mut ingress_v4 = Ipv4PolicyMapEntry {
            key: unf_state::Ipv4PolicyMapKey {
                source_address: "192.0.2.1".parse().unwrap(),
                destination_identity: IdentityId::new(0),
                protocol: 0,
                destination_port: 0,
            },
            decision,
            shadow: None,
        };
        let ingress_v6 = Ipv6PolicyMapEntry {
            key: unf_state::Ipv6PolicyMapKey {
                source_network: "fdff::1".parse().unwrap(),
                source_prefix_len: 128,
                destination_identity: IdentityId::new(0),
                protocol: 0,
                destination_port: 0,
            },
            decision,
            shadow: None,
        };
        let egress_v4 = EgressIpv4PolicyMapEntry {
            key: unf_state::EgressIpv4PolicyMapKey {
                source_identity: IdentityId::new(0),
                destination_address: "192.0.2.1".parse().unwrap(),
                protocol: 0,
                destination_port: 0,
            },
            decision,
            shadow: None,
        };
        let egress_v6 = EgressIpv6PolicyMapEntry {
            key: unf_state::EgressIpv6PolicyMapKey {
                source_identity: IdentityId::new(0),
                destination_network: "fdff::1".parse().unwrap(),
                destination_prefix_len: 128,
                protocol: 0,
                destination_port: 0,
            },
            decision,
            shadow: None,
        };
        assert!(desired_ipv4_policy_entries(&[ingress_v4], 17, 1).is_ok());
        assert!(desired_ipv6_policy_entries(&[ingress_v6], 17, 1).is_ok());
        assert!(desired_egress_ipv4_policy_entries(&[egress_v4], 17, 1).is_ok());
        assert!(desired_egress_ipv6_policy_entries(&[egress_v6], 17, 1).is_ok());

        ingress_v4.decision.verdict = Verdict::Deny;
        assert!(desired_ipv4_policy_entries(&[ingress_v4], 17, 1).is_err());
        ingress_v4.decision = decision;
        ingress_v4.key.source_address = Ipv4Addr::UNSPECIFIED;
        assert!(desired_ipv4_policy_entries(&[ingress_v4], 17, 1).is_err());
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
