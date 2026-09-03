use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
use aya::maps::{
    Array as AyaArray, HashMap as AyaHashMap, IterableMap, MapData, PerCpuArray as AyaPerCpuArray,
    ProgramArray as AyaProgramArray, RingBuf,
};
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
use rustix::time::{ClockId, clock_gettime};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use unf_cni_state::AttachmentJournal;
use unf_common::{IdentityId, PolicyDirection, PolicyId, PolicyReason, Revision, RuleId, Verdict};
use unf_ebpf_common::{
    EGRESS_BANK_COUNT, EGRESS_EVENT_ABI_VERSION, EGRESS_EVENT_ACTION_CREATE,
    EGRESS_EVENT_ACTION_DROP, EGRESS_EVENT_ACTION_EXPIRE, EGRESS_EVENT_COUNTER_ATTEMPTED,
    EGRESS_EVENT_COUNTER_DROPPED, EGRESS_MAP_ABI_VERSION, EgressEvent, FLOW_ABI_VERSION, FlowEvent,
    FlowKey, IDENTITY_BANK_COUNT, IdentityMapValue, Ipv4IdentityKey, Ipv6IdentityKey,
    POLICY_BANK_COUNT, POLICY_FLAG_HAS_POLICY, POLICY_FLAG_HAS_RULE, POLICY_FLAG_HAS_SHADOW,
    POLICY_FLAG_SHADOW_HAS_POLICY, POLICY_FLAG_SHADOW_HAS_RULE, POLICY_MAP_ABI_VERSION,
    SERVICE_AFFINITY_MAX_TIMEOUT_SECONDS, SERVICE_AFFINITY_MIN_TIMEOUT_SECONDS,
    SERVICE_AFFINITY_OUTCOME_CREATED, SERVICE_AFFINITY_OUTCOME_NONE,
    SERVICE_AFFINITY_OUTCOME_RESELECTED, SERVICE_AFFINITY_OUTCOME_REUSED, SERVICE_BANK_COUNT,
    SERVICE_EVENT_ABI_VERSION, SERVICE_EVENT_ACTION_DROP, SERVICE_EVENT_ACTION_EXPIRE,
    SERVICE_EVENT_ACTION_TRANSLATE, SERVICE_EVENT_FRONTEND_CLUSTER_IP,
    SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER, SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL,
    SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER, SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL,
    SERVICE_EVENT_REASON_NO_BACKEND, SERVICE_EVENT_REASON_SOURCE_RANGE_DENIED,
    SERVICE_MAP_ABI_VERSION, ServiceEvent, egress_event_action_reason_is_valid,
    service_event_action_reason_is_valid, service_event_frontend_kind_is_valid,
    service_selection_algorithm_is_valid, service_selection_tier_is_valid,
};
use unf_egress::{
    AddressFamily as EgressAddressFamily, AdmittedEgressGatewayAddressProjection,
    AuthenticatedEgressAgent, EGRESS_AGENT_SERVICE_ACCOUNT, EGRESS_AGENT_TOKEN_AUDIENCE,
    EGRESS_DISTRIBUTION_SCHEMA_VERSION, EGRESS_HOST_STATE_SCHEMA_VERSION, EgressAdmissionGuard,
    EgressAgentAdvertisement, EgressCapability, EgressDataplaneState,
    EgressGatewayAddressAcknowledgement, EgressGatewayAddressProjection,
    EgressGatewayApplicationAcknowledgement, EgressGatewayDrainEvidence, EgressGatewayHostBank,
    EgressGatewayProjection, EgressGatewayProjectionLedger, EgressGatewayRetirementChallenges,
    EgressNodeProjectionEnvelope, EgressPathCertificate, EgressPathMode, EgressProjectionLedger,
    EgressSourceActivationGrant, EgressSourceApplicationAcknowledgement, EgressSourceFenceEvidence,
    EgressSourceRetirementChallenges, compile_egress_dataplane, compile_egress_gateway_dataplane,
};
use unf_ipam::{
    Ipv4NodeBlock, Ipv6NodeBlock, NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION, NodeBlockProvider,
    NodeBlockSnapshot,
};
use unf_link::GatewayAddressPlan;
use unf_loadbalancer::{
    LOAD_BALANCER_FRONTEND_BANK_CAPACITY, LoadBalancerDataplaneState,
    NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION, NodeReachabilityCheckpoint,
    NodeReachabilitySnapshot, compile_load_balancer_dataplane,
    compile_load_balancer_selection_dataplane,
};
use unf_route::{
    NativeIpv4NextHop, NativeIpv6NextHop, NativeRemoteNode, NativeRemoteRoutePlan,
    NativeRemoteRoutingProvider, REMOTE_ROUTE_SNAPSHOT_SCHEMA_VERSION, RemoteRouteSnapshot,
};
#[cfg(test)]
use unf_service::compile_service_dataplane;
use unf_service::{
    LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION, LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION,
    NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION, NetworkBehaviorContract, NodePortDataplaneState,
    NodePortNodeSnapshot, SELECTION_CONTRACT_SCHEMA_VERSION, SERVICE_BACKEND_BANK_CAPACITY,
    SERVICE_BACKEND_SLOT_BANK_CAPACITY, SERVICE_FRONTEND_BANK_CAPACITY,
    SERVICE_SNAPSHOT_SCHEMA_VERSION, SelectionCapability, SelectionNode, ServiceDataplaneState,
    ServiceSnapshot, ServiceTrafficPolicy, compile_node_port_fabric_dataplane,
    compile_node_port_selection_fabric_dataplane, compile_service_load_balancer_fabric_dataplane,
    compile_service_selection_dataplane, has_advanced_selection_intent,
};
use unf_state::{
    AGENT_STATUS_SCHEMA_VERSION, AgentStateReport, ComponentCompatibility,
    EgressIpv4PolicyMapEntry, EgressIpv6PolicyMapEntry, FLOW_EXPORT_BATCH_LIMIT,
    FLOW_EXPORT_SCHEMA_VERSION, FlowExportBatch, FlowExportDecision, FlowExportRecord,
    FlowHistoryKey, IDENTITY_SNAPSHOT_SCHEMA_VERSION, IdentityStateSnapshot, Ipv4IdentityMapping,
    Ipv4PolicyMapEntry, Ipv6IdentityMapping, Ipv6PolicyMapEntry, PERSISTENT_BPF_STATE_ABI_VERSION,
    POLICY_MAP_BANK_ENTRY_LIMIT, POLICY_SNAPSHOT_SCHEMA_VERSION,
    PRE_OPERATIONS_AGENT_STATUS_SCHEMA_VERSION, PRE_OPERATIONS_FLOW_EXPORT_SCHEMA_VERSION,
    PRE_SELECTION_AGENT_STATUS_SCHEMA_VERSION, PolicyDecisionRecord, PolicyMapEntry,
    PolicyStateSnapshot, ServiceAffinityOutcome, ServiceFlowKey, ServiceFlowOutcome,
    ServiceForwardingModeOutcome, ServiceFrontendKind, ServiceSelectionAlgorithmOutcome,
    ServiceSelectionTier, VersionTransition,
};

mod cni_server;

use cni_server::CniTransactionServer;

const FLOW_EXPORT_CHANNEL_CAPACITY: usize = 4_096;
const FLOW_EXPORT_PENDING_CAPACITY: usize = 2_048;
const DEFAULT_BPF_PIN_PATH: &str = "/sys/fs/bpf/unf/v14";
const DEFAULT_AGENT_TOKEN_PATH: &str = "/var/run/secrets/unf-agent/token";
const DEFAULT_CONTROLLER_CA_PATH: &str = "/var/run/secrets/unf-internal-ca/ca.crt";
const DEFAULT_CNI_STATE_PATH: &str = "/var/lib/unf/cni/v1/attachments.json";
const DEFAULT_CNI_NODE_BLOCK_STATE_PATH: &str = "/var/lib/unf/cni/v1/node-block.json";
const DEFAULT_CNI_REMOTE_ROUTE_STATE_PATH: &str = "/var/lib/unf/cni/v1/remote-routes.json";
const DEFAULT_CNI_STATUS_LEASE_PATH: &str = "/run/unf/cni-status.lease";
const DEFAULT_SERVICE_STATE_PATH: &str = "/var/lib/unf/cni/v1/service-snapshot.json";
const DEFAULT_LOAD_BALANCER_REACHABILITY_STATE_PATH: &str =
    "/var/lib/unf/cni/v1/load-balancer-reachability.json";
const MAX_SERVICE_ERROR_BYTES: usize = 1_024;
const MAX_DURABLE_STATE_BYTES: u64 = 64 * 1024 * 1024;
const NODE_PORT_SERVICE_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const SELECTION_CONTRACT_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const SELECTION_BANK_COUNT: u8 = 2;
const CURRENT_BPF_ABI_VERSION: u16 = PERSISTENT_BPF_STATE_ABI_VERSION;
const BLOCKED_TRANSITION_REPORTING_WINDOW: Duration = Duration::from_secs(30);
const DATAPLANE_TAIL_PROGRAM_NAMES: [&str; 6] = [
    "unf_policy_v4",
    "unf_policy_v6",
    "unf_dsr_v4",
    "unf_dsr_v6",
    "unf_egress_gateway_v4",
    "unf_egress_gateway_v6",
];
const DATAPLANE_TAIL_CALL_MAP_NAME: &str = "SERVICE_DATAPLANE_TAIL_CALLS";
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
const ABI_V4_MAP_NAMES: [&str; 18] = [
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
const ABI_V5_MAP_NAMES: [&str; 21] = [
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
    "NODE_PORT_FRONTENDS_V4",
    "NODE_PORT_FRONTENDS_V6",
    "NODE_PORT_CONFIG",
];
const ABI_V8_MAP_NAMES: [&str; 24] = [
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
    "NODE_PORT_FRONTENDS_V4",
    "NODE_PORT_FRONTENDS_V6",
    "NODE_PORT_CONFIG",
    "LOAD_BALANCER_FRONTENDS_V4",
    "LOAD_BALANCER_FRONTENDS_V6",
    "LOAD_BALANCER_CONFIG",
];
const ABI_V11_MAP_NAMES: [&str; 25] = [
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
    "SERVICE_AFFINITY",
    "NODE_PORT_FRONTENDS_V4",
    "NODE_PORT_FRONTENDS_V6",
    "NODE_PORT_CONFIG",
    "LOAD_BALANCER_FRONTENDS_V4",
    "LOAD_BALANCER_FRONTENDS_V6",
    "LOAD_BALANCER_CONFIG",
];
const ABI_V12_MAP_NAMES: [&str; 31] = [
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
    "SERVICE_AFFINITY",
    "NODE_PORT_FRONTENDS_V4",
    "NODE_PORT_FRONTENDS_V6",
    "NODE_PORT_CONFIG",
    "LOAD_BALANCER_FRONTENDS_V4",
    "LOAD_BALANCER_FRONTENDS_V6",
    "LOAD_BALANCER_CONFIG",
    "EGRESS_SOURCES",
    "EGRESS_ADDRESSES",
    "EGRESS_GATEWAYS",
    "EGRESS_SELECTIONS",
    "EGRESS_CONFIG",
    "EGRESS_CONNECTIONS",
];
const ABI_V13_MAP_NAMES: [&str; 33] = [
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
    "SERVICE_AFFINITY",
    "NODE_PORT_FRONTENDS_V4",
    "NODE_PORT_FRONTENDS_V6",
    "NODE_PORT_CONFIG",
    "LOAD_BALANCER_FRONTENDS_V4",
    "LOAD_BALANCER_FRONTENDS_V6",
    "LOAD_BALANCER_CONFIG",
    "EGRESS_SOURCES",
    "EGRESS_DESTINATIONS_V4",
    "EGRESS_DESTINATIONS_V6",
    "EGRESS_ADDRESSES",
    "EGRESS_GATEWAYS",
    "EGRESS_SELECTIONS",
    "EGRESS_CONFIG",
    "EGRESS_CONNECTIONS",
];
const PERSISTENT_MAP_NAMES: [&str; 40] = [
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
    "SERVICE_AFFINITY",
    "NODE_PORT_FRONTENDS_V4",
    "NODE_PORT_FRONTENDS_V6",
    "NODE_PORT_CONFIG",
    "LOAD_BALANCER_FRONTENDS_V4",
    "LOAD_BALANCER_FRONTENDS_V6",
    "LOAD_BALANCER_CONFIG",
    "EGRESS_SOURCES",
    "EGRESS_DESTINATIONS_V4",
    "EGRESS_DESTINATIONS_V6",
    "EGRESS_ADDRESSES",
    "EGRESS_GATEWAYS",
    "EGRESS_SELECTIONS",
    "EGRESS_CONFIG",
    "EGRESS_CONNECTIONS",
    "EGRESS_GATEWAY_NAT_SOURCES",
    "EGRESS_GATEWAY_NAT_DESTINATIONS_V4",
    "EGRESS_GATEWAY_NAT_DESTINATIONS_V6",
    "EGRESS_GATEWAY_NAT_ADDRESSES",
    "EGRESS_GATEWAY_NAT_GATEWAYS",
    "EGRESS_GATEWAY_NAT_SELECTIONS",
    "EGRESS_GATEWAY_NAT_CONFIG",
];
const IDENTITY_MAP_CAPACITY: u32 = 65_536;
const POLICY_MAP_CAPACITY: u32 = 262_144;
const SERVICE_FRONTEND_MAP_CAPACITY: u32 = 262_144;
const SERVICE_BACKEND_MAP_CAPACITY: u32 = 524_288;
const SERVICE_BACKEND_SLOT_MAP_CAPACITY: u32 = 1_048_576;
const SERVICE_CONNECTION_MAP_CAPACITY: u32 = 262_144;
const EGRESS_SOURCE_MAP_CAPACITY: u32 = 131_072;
const EGRESS_DESTINATION_MAP_CAPACITY: u32 = 262_144;
const EGRESS_ADDRESS_MAP_CAPACITY: u32 = 131_072;
const EGRESS_GATEWAY_MAP_CAPACITY: u32 = 262_144;
const EGRESS_SELECTION_MAP_CAPACITY: u32 = 4_112_384;
const EGRESS_CONNECTION_MAP_CAPACITY: u32 = 262_144;
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
    /// Durable owner-only last-known-good `LoadBalancer` reachability state.
    #[arg(
        long,
        env = "UNF_LOAD_BALANCER_REACHABILITY_STATE_PATH",
        default_value = DEFAULT_LOAD_BALANCER_REACHABILITY_STATE_PATH
    )]
    load_balancer_reachability_state_path: PathBuf,
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
    /// Owner-only readiness heartbeat consumed by the primary-CNI STATUS grace path.
    #[arg(
        long,
        env = "UNF_CNI_STATUS_LEASE_PATH",
        default_value = DEFAULT_CNI_STATUS_LEASE_PATH
    )]
    cni_status_lease_path: PathBuf,
    /// Refresh interval for the owner-only primary-CNI readiness heartbeat.
    #[arg(long, env = "UNF_CNI_STATUS_HEARTBEAT_SECONDS", default_value_t = 2)]
    cni_status_heartbeat_seconds: u64,
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
    node_port_frontend_count: Gauge,
    node_port_cluster_frontend_count: Gauge,
    node_port_local_frontend_count: Gauge,
    load_balancer_revision_desired: Gauge,
    load_balancer_revision_applied: Gauge,
    load_balancer_allocation_revision_desired: Gauge,
    load_balancer_allocation_revision_applied: Gauge,
    load_balancer_frontend_count: Gauge,
    load_balancer_cluster_frontend_count: Gauge,
    load_balancer_local_frontend_count: Gauge,
    load_balancer_source_range_count: Gauge,
    load_balancer_health_check_count: Gauge,
    load_balancer_health_check_ready_count: Gauge,
    load_balancer_reconcile_errors: Counter,
    service_dataplane_events: Counter,
    service_translations: Counter,
    service_drops: Counter,
    service_expirations: Counter,
    node_port_cluster_translations: Counter,
    node_port_local_translations: Counter,
    node_port_no_backend_drops: Counter,
    load_balancer_cluster_translations: Counter,
    load_balancer_local_translations: Counter,
    load_balancer_no_backend_drops: Counter,
    load_balancer_source_range_drops: Counter,
    invalid_service_events: Counter,
    egress_dataplane_events: Counter,
    egress_nat_creations: Counter,
    egress_nat_drops: Counter,
    egress_nat_expirations: Counter,
    invalid_egress_events: Counter,
    egress_event_attempts: Counter,
    egress_event_ring_drops: Counter,
    service_same_node_selections: Counter,
    service_same_zone_selections: Counter,
    service_cluster_selections: Counter,
    service_stable_hash_selections: Counter,
    service_maglev_selections: Counter,
    service_affinity_reuses: Counter,
    service_affinity_creations: Counter,
    service_affinity_reselections: Counter,
    service_nat_forwards: Counter,
    service_dsr_forwards: Counter,
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
    desired_selection_contract_revision: AtomicU64,
    applied_selection_contract_revision: AtomicU64,
    desired_selection_contract_digest: Mutex<Option<String>>,
    applied_selection_contract_digest: Mutex<Option<String>>,
    active_selection_bank: AtomicU64,
    desired_node_port_frontend_count: AtomicU64,
    applied_node_port_frontend_count: AtomicU64,
    node_port_cluster_frontend_count: AtomicU64,
    node_port_local_frontend_count: AtomicU64,
    desired_load_balancer_epoch: AtomicU64,
    desired_load_balancer_revision: AtomicU64,
    desired_load_balancer_allocation_revision: AtomicU64,
    applied_load_balancer_epoch: AtomicU64,
    applied_load_balancer_revision: AtomicU64,
    applied_load_balancer_allocation_revision: AtomicU64,
    load_balancer_frontend_count: AtomicU64,
    load_balancer_cluster_frontend_count: AtomicU64,
    load_balancer_local_frontend_count: AtomicU64,
    load_balancer_source_range_count: AtomicU64,
    load_balancer_health_check_count: AtomicU64,
    load_balancer_health_check_ready_count: AtomicU64,
    active_load_balancer_bank: AtomicU64,
    load_balancer_reconcile_errors: AtomicU64,
    load_balancer_last_error: Mutex<Option<String>>,
    service_reconcile_errors: AtomicU64,
    service_last_error: Mutex<Option<String>>,
    service_dataplane_events: AtomicU64,
    service_translations: AtomicU64,
    service_drops: AtomicU64,
    service_expirations: AtomicU64,
    node_port_cluster_translations: AtomicU64,
    node_port_local_translations: AtomicU64,
    node_port_no_backend_drops: AtomicU64,
    load_balancer_cluster_translations: AtomicU64,
    load_balancer_local_translations: AtomicU64,
    load_balancer_no_backend_drops: AtomicU64,
    load_balancer_source_range_drops: AtomicU64,
    invalid_service_events: AtomicU64,
    last_service_id: AtomicU64,
    last_backend_id: AtomicU64,
    last_service_revision: AtomicU64,
    last_service_action: AtomicU64,
    last_service_reason: AtomicU64,
    service_same_node_selections: AtomicU64,
    service_same_zone_selections: AtomicU64,
    service_cluster_selections: AtomicU64,
    service_stable_hash_selections: AtomicU64,
    service_maglev_selections: AtomicU64,
    service_affinity_reuses: AtomicU64,
    service_affinity_creations: AtomicU64,
    service_affinity_reselections: AtomicU64,
    service_nat_forwards: AtomicU64,
    service_dsr_forwards: AtomicU64,
    last_service_selection_tier: AtomicU64,
    last_service_affinity_outcome: AtomicU64,
    last_service_selection_algorithm: AtomicU64,
    last_service_forwarding_mode: AtomicU64,
    desired_node_block_revision: AtomicU64,
    applied_node_block_revision: AtomicU64,
    desired_remote_route_epoch: AtomicU64,
    applied_remote_route_epoch: AtomicU64,
    desired_remote_route_revision: AtomicU64,
    applied_remote_route_revision: AtomicU64,
    remote_route_entries: AtomicU64,
    remote_route_reconcile_errors: AtomicU64,
    applied_remote_routes: Mutex<Option<RemoteRouteSnapshot>>,
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

struct EgressSynchronizer {
    sources: AyaHashMap<MapData, [u8; 8], [u8; 128]>,
    ipv4_destinations: AyaLpmTrie<MapData, [u8; 12], [u8; 32]>,
    ipv6_destinations: AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    addresses: AyaHashMap<MapData, [u8; 8], [u8; 56]>,
    gateways: AyaHashMap<MapData, [u8; 8], [u8; 88]>,
    selections: AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    config: AyaArray<MapData, [u8; 56]>,
    gateway_nat_sources: AyaHashMap<MapData, [u8; 8], [u8; 128]>,
    gateway_nat_ipv4_destinations: AyaLpmTrie<MapData, [u8; 12], [u8; 32]>,
    gateway_nat_ipv6_destinations: AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    gateway_nat_addresses: AyaHashMap<MapData, [u8; 8], [u8; 56]>,
    gateway_nat_gateways: AyaHashMap<MapData, [u8; 8], [u8; 88]>,
    gateway_nat_selections: AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    gateway_nat_config: AyaArray<MapData, [u8; 56]>,
    connections: AyaHashMap<MapData, [u8; 44], [u8; 208]>,
    banks: [EncodedEgressBank; EGRESS_BANK_COUNT as usize],
    gateway_nat_banks: [EncodedEgressBank; EGRESS_BANK_COUNT as usize],
    active_bank: u8,
    gateway_nat_active_bank: u8,
    ledger: EgressProjectionLedger,
    gateway_ledger: EgressGatewayProjectionLedger,
    applied_authority: Option<EgressAppliedAuthority>,
    path_provider: Option<NativeEgressPathProvider>,
    node_name: String,
    controller_url: Option<String>,
    client: ReloadingControllerClient,
    agent_token_path: PathBuf,
    interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeEgressPathProvider {
    ipv4_interface: String,
    ipv6_interface: String,
    ipv4_output_interface: u32,
    ipv6_output_interface: u32,
    ipv4_onlink: bool,
    ipv6_onlink: bool,
    sys_class_net: PathBuf,
}

impl NativeEgressPathProvider {
    async fn acquire(
        &self,
        source: &unf_egress::AdmittedEgressProjection,
        state: &AgentState,
    ) -> Result<Vec<EgressPathCertificate>> {
        let snapshot = mutex_lock(&state.applied_remote_routes)
            .clone()
            .context("no read-back native remote-route snapshot is applied")?;
        let contract = &source.projection().contract;
        if contract.plans.is_empty() {
            bail!("an empty egress contract cannot be activated");
        }
        if contract.plans.iter().any(|plan| {
            plan.source.node.name != snapshot.node_name || plan.source.node.uid != snapshot.node_uid
        }) {
            bail!("egress source contract does not match remote-route Node provenance");
        }
        let local = NodeBlockSnapshot {
            schema_version: NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION,
            revision: snapshot.local_assignment_revision,
            node_name: snapshot.node_name.clone(),
            node_uid: snapshot.node_uid.clone(),
            provider: snapshot.local_blocks,
        };
        let plan = lower_remote_route_snapshot(
            &snapshot,
            &local,
            self.ipv4_output_interface,
            self.ipv6_output_interface,
            self.ipv4_onlink,
            self.ipv6_onlink,
        )?;
        plan.readback()
            .await
            .context("read back exact native gateway routes")?;
        let ipv4_mtu = interface_mtu_at(
            &self.sys_class_net,
            &self.ipv4_interface,
            self.ipv4_output_interface,
        )?;
        let ipv6_mtu = interface_mtu_at(
            &self.sys_class_net,
            &self.ipv6_interface,
            self.ipv6_output_interface,
        )?;
        let certificates =
            build_egress_path_certificates(self, source, &snapshot, ipv4_mtu, ipv6_mtu)?;
        if mutex_lock(&state.applied_remote_routes).as_ref() != Some(&snapshot) {
            bail!("remote-route snapshot changed during egress path acquisition");
        }
        Ok(certificates)
    }
}

fn build_egress_path_certificates(
    provider: &NativeEgressPathProvider,
    source: &unf_egress::AdmittedEgressProjection,
    snapshot: &RemoteRouteSnapshot,
    ipv4_mtu: u32,
    ipv6_mtu: u32,
) -> Result<Vec<EgressPathCertificate>> {
    let contract = &source.projection().contract;
    let remotes = snapshot
        .remote_nodes
        .iter()
        .map(|remote| {
            (
                (
                    remote.intent.node_name.as_str(),
                    remote.intent.node_uid.as_str(),
                ),
                remote,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut certificates = BTreeMap::new();
    for behavior in &contract.plans {
        let families = behavior
            .allocation
            .addresses
            .iter()
            .map(|address| match address {
                IpAddr::V4(_) => EgressAddressFamily::Ipv4,
                IpAddr::V6(_) => EgressAddressFamily::Ipv6,
            })
            .collect::<BTreeSet<_>>();
        for gateway in &behavior.gateways {
            let remote = remotes
                .get(&(gateway.node.name.as_str(), gateway.node.uid.as_str()))
                .with_context(|| {
                    format!(
                        "selected gateway {}/{} has no exact remote-route ownership",
                        gateway.node.name, gateway.node.uid
                    )
                })?;
            for family in &families {
                let (transport, output_interface, mtu) = match family {
                    EgressAddressFamily::Ipv4 => (
                        IpAddr::V4(remote.ipv4_transport),
                        provider.ipv4_output_interface,
                        ipv4_mtu,
                    ),
                    EgressAddressFamily::Ipv6 => (
                        IpAddr::V6(remote.ipv6_transport),
                        provider.ipv6_output_interface,
                        ipv6_mtu,
                    ),
                };
                let certificate = EgressPathCertificate::issue(
                    behavior.source.node.clone(),
                    gateway.node.clone(),
                    *family,
                    transport,
                    transport,
                    output_interface,
                    mtu,
                    EgressPathMode::DirectNeighbor,
                    Revision::new(snapshot.revision),
                    gateway.lease_epoch,
                )
                .context("seal exact source-local egress path")?;
                certificates.insert(
                    (
                        behavior.source.node.uid.clone(),
                        gateway.node.uid.clone(),
                        *family,
                        gateway.lease_epoch,
                    ),
                    certificate,
                );
            }
        }
    }
    Ok(certificates.into_values().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EgressAppliedAuthority {
    controller_epoch: u64,
    projection_revision: u64,
    contract_revision: u64,
    contract_digest: Option<[u8; 32]>,
}

struct ServiceSynchronizer {
    ipv4_frontends: AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    ipv6_frontends: AyaHashMap<MapData, [u8; 20], [u8; 32]>,
    ipv4_backends: AyaHashMap<MapData, [u8; 12], [u8; 24]>,
    ipv6_backends: AyaHashMap<MapData, [u8; 12], [u8; 32]>,
    backend_slots: AyaHashMap<MapData, [u8; 16], [u8; 16]>,
    config: AyaArray<MapData, [u8; 32]>,
    connections: AyaHashMap<MapData, [u8; 40], [u8; 104]>,
    affinity: AyaHashMap<MapData, [u8; 40], [u8; 32]>,
    node_port_ipv4_frontends: AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    node_port_ipv6_frontends: AyaHashMap<MapData, [u8; 20], [u8; 32]>,
    node_port_config: AyaArray<MapData, [u8; 40]>,
    load_balancer_ipv4_frontends: AyaHashMap<MapData, [u8; 8], [u8; 48]>,
    load_balancer_ipv6_frontends: AyaHashMap<MapData, [u8; 20], [u8; 48]>,
    load_balancer_ipv4_source_ranges: AyaLpmTrie<MapData, [u8; 12], [u8; 32]>,
    load_balancer_ipv6_source_ranges: AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    load_balancer_config: AyaArray<MapData, [u8; 48]>,
    load_balancer_node_source: AyaArray<MapData, [u8; 40]>,
    health_checks: HealthCheckManager,
    banks: [Option<ServiceDataplaneState>; SERVICE_BANK_COUNT as usize],
    node_port_banks:
        [Option<NodePortDataplaneState>; unf_ebpf_common::NODE_PORT_BANK_COUNT as usize],
    load_balancer_banks:
        [Option<LoadBalancerDataplaneState>; unf_ebpf_common::LOAD_BALANCER_BANK_COUNT as usize],
    selection_banks: [Option<NetworkBehaviorContract>; SELECTION_BANK_COUNT as usize],
    active_bank: u8,
    active_node_port_bank: u8,
    active_load_balancer_bank: u8,
    applied: Option<ServiceSnapshot>,
    applied_node_port_node: Option<NodePortNodeSnapshot>,
    applied_load_balancer_reachability: Option<NodeReachabilitySnapshot>,
    applied_selection_contract: Option<NetworkBehaviorContract>,
    active_selection_bank: u8,
    node_name: String,
    controller_url: Option<String>,
    client: ReloadingControllerClient,
    agent_token_path: PathBuf,
    state_path: PathBuf,
    load_balancer_state_path: PathBuf,
    interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HealthCheckPlan {
    port: u16,
    service_id: unf_common::ServiceId,
    local_endpoints: u64,
}

#[derive(Default)]
struct HealthCheckManager {
    listeners: BTreeMap<u16, HealthCheckListener>,
}

struct HealthCheckListener {
    service_id: unf_common::ServiceId,
    local_endpoints: Arc<AtomicU64>,
    cancellation: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for HealthCheckManager {
    fn drop(&mut self) {
        for listener in self.listeners.values() {
            listener.cancellation.cancel();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NodePortServiceCheckpoint {
    schema_version: u16,
    service: ServiceSnapshot,
    node_port_node: NodePortNodeSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SelectionContractCheckpoint {
    schema_version: u16,
    active_bank: u8,
    node: NodePortNodeSnapshot,
    contract: NetworkBehaviorContract,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StoredServiceCheckpoint {
    Legacy(ServiceSnapshot),
    NodePort(NodePortServiceCheckpoint),
}

type EncodedPolicyMap = AyaHashMap<MapData, [u8; 12], [u8; 32]>;
type EncodedIpv4IdentityMap = AyaHashMap<MapData, [u8; 4], [u8; 16]>;
type EncodedIpv6IdentityMap = AyaHashMap<MapData, [u8; 16], [u8; 16]>;
type EncodedIpv4IdentityBank = BTreeMap<[u8; 4], [u8; 16]>;
type EncodedIpv6IdentityBank = BTreeMap<[u8; 16], [u8; 16]>;
type EncodedIpv6PolicyKey = (u32, [u8; 24]);
type EncodedIpv6PolicyBank = BTreeMap<EncodedIpv6PolicyKey, [u8; 32]>;
#[derive(Debug, Clone, PartialEq, Eq)]
struct EncodedEgressBank {
    sources: BTreeMap<[u8; 8], [u8; 128]>,
    ipv4_destinations: BTreeMap<(u32, [u8; 12]), [u8; 32]>,
    ipv6_destinations: BTreeMap<(u32, [u8; 24]), [u8; 32]>,
    addresses: BTreeMap<[u8; 8], [u8; 56]>,
    gateways: BTreeMap<[u8; 8], [u8; 88]>,
    selections: BTreeMap<[u8; 8], [u8; 32]>,
    config: [u8; 56],
}

impl Default for EncodedEgressBank {
    fn default() -> Self {
        Self {
            sources: BTreeMap::new(),
            ipv4_destinations: BTreeMap::new(),
            ipv6_destinations: BTreeMap::new(),
            addresses: BTreeMap::new(),
            gateways: BTreeMap::new(),
            selections: BTreeMap::new(),
            config: [0; 56],
        }
    }
}
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
    AyaHashMap<MapData, [u8; 40], [u8; 104]>,
    AyaHashMap<MapData, [u8; 40], [u8; 32]>,
    AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    AyaHashMap<MapData, [u8; 20], [u8; 32]>,
    AyaArray<MapData, [u8; 40]>,
    AyaHashMap<MapData, [u8; 8], [u8; 48]>,
    AyaHashMap<MapData, [u8; 20], [u8; 48]>,
    AyaLpmTrie<MapData, [u8; 12], [u8; 32]>,
    AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    AyaArray<MapData, [u8; 48]>,
    AyaArray<MapData, [u8; 40]>,
);
type ServiceAffinityMap = AyaHashMap<MapData, [u8; 40], [u8; 32]>;
type EgressMaps = (
    AyaHashMap<MapData, [u8; 8], [u8; 128]>,
    AyaLpmTrie<MapData, [u8; 12], [u8; 32]>,
    AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    AyaHashMap<MapData, [u8; 8], [u8; 56]>,
    AyaHashMap<MapData, [u8; 8], [u8; 88]>,
    AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    AyaArray<MapData, [u8; 56]>,
    AyaHashMap<MapData, [u8; 8], [u8; 128]>,
    AyaLpmTrie<MapData, [u8; 12], [u8; 32]>,
    AyaLpmTrie<MapData, [u8; 24], [u8; 32]>,
    AyaHashMap<MapData, [u8; 8], [u8; 56]>,
    AyaHashMap<MapData, [u8; 8], [u8; 88]>,
    AyaHashMap<MapData, [u8; 8], [u8; 32]>,
    AyaArray<MapData, [u8; 56]>,
    AyaHashMap<MapData, [u8; 44], [u8; 208]>,
);
type RecoveredServiceConfig = (u64, u64, u32, u32, u32, u8);
type RecoveredNodePortConfig = (u64, u64, u64, u32, u32, u8);

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
    load_balancer_reachability_state_path: PathBuf,
    node_name: String,
    agent_token_path: PathBuf,
    flow_export_interval: Duration,
    bpf_pin_path: PathBuf,
    tc_attachment_preference: TcAttachmentPreference,
    service_dsr_transport_interfaces: [u32; 4],
    egress_path_provider: Option<NativeEgressPathProvider>,
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
    program_pins: Vec<PathBuf>,
    links_directory: Option<PathBuf>,
    programs_directory: Option<PathBuf>,
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
    let service_dsr_transport_interfaces = service_dsr_transport_interfaces(
        args.cni_native_ipv4_uplink.as_deref(),
        args.cni_native_ipv6_uplink.as_deref(),
    )?;
    let egress_path_provider = native_egress_path_provider(&args)?;
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
            let load_balancer_reachability_state_path =
                args.load_balancer_reachability_state_path.clone();
            let node_name = args.node_name.clone();
            let agent_token_path = args.agent_token_path.clone();
            let flow_export_interval = Duration::from_secs(args.flow_export_seconds.max(1));
            let bpf_pin_path = args.bpf_pin_path.clone();
            let tc_attachment_preference = args.tc_attachment_mode;
            let egress_path_provider = egress_path_provider.clone();
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
                    load_balancer_reachability_state_path,
                    node_name,
                    agent_token_path,
                    flow_export_interval,
                    bpf_pin_path,
                    tc_attachment_preference,
                    service_dsr_transport_interfaces,
                    egress_path_provider,
                };
                if let Err(error) =
                    Box::pin(run_dataplane(config, Arc::clone(&state), cancellation)).await
                {
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
            *mutex_lock(&state.applied_remote_routes) = None;
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
    *mutex_lock(&state.applied_remote_routes) = Some(snapshot.clone());
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
    let heartbeat = Duration::from_secs(args.cni_status_heartbeat_seconds);
    let server = CniTransactionServer::bind(
        socket_path.clone(),
        &args.cni_state_path,
        provider,
        args.cni_status_lease_path.clone(),
        heartbeat,
    )?;
    let server_cancellation = cancellation.clone();
    let failure_tx = failure_tx.clone();
    info!(
        socket = %socket_path.display(),
        state = %args.cni_state_path.display(),
        readiness_lease = %args.cni_status_lease_path.display(),
        readiness_heartbeat_seconds = args.cni_status_heartbeat_seconds,
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
        spawn_load_balancer_reachability_reconciler(args, state, cancellation, tasks)?;
        spawn_service_snapshot_reconciler(args, state, cancellation, tasks)
    }
}

fn spawn_load_balancer_reachability_reconciler(
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
    let state_path = args.load_balancer_reachability_state_path.clone();
    let node_name = args.node_name.clone();
    let interval = Duration::from_secs(args.service_sync_seconds.max(1));
    let task_cancellation = cancellation.clone();
    tasks.spawn(async move {
        reconcile_load_balancer_reachability(
            controller_url,
            client,
            token_path,
            state_path,
            node_name,
            interval,
            task_cancellation,
        )
        .await;
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_load_balancer_reachability(
    controller_url: String,
    client: ReloadingControllerClient,
    token_path: PathBuf,
    state_path: PathBuf,
    node_name: String,
    interval_duration: Duration,
    cancellation: CancellationToken,
) {
    let mut applied = match load_optional_load_balancer_reachability(&state_path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            warn!(%error, path = %state_path.display(), "rejected durable LoadBalancer reachability state");
            None
        }
    };
    if let Some(snapshot) = &applied {
        info!(
            epoch = snapshot.source_epoch,
            revision = snapshot.revision.get(),
            targets = snapshot.targets.len(),
            path = %state_path.display(),
            "restored last-known-good LoadBalancer reachability state"
        );
    }
    let mut interval = tokio::time::interval(interval_duration);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = interval.tick() => {
                let result = async {
                    let compatibility = fetch_controller_compatibility(
                        &client,
                        &controller_url,
                        &token_path,
                    ).await?;
                    if compatibility.load_balancer_reachability_schema_version == 0 {
                        return Ok::<(), anyhow::Error>(());
                    }
                    ensure_controller_compatibility(&compatibility)?;
                    let candidate = fetch_load_balancer_reachability(
                        &controller_url,
                        &client,
                        &token_path,
                    ).await?;
                    if candidate.node.name != node_name {
                        bail!(
                            "controller projected LoadBalancer state for node {:?}; expected {:?}",
                            candidate.node.name,
                            node_name
                        );
                    }
                    if !candidate.validate_transition(applied.as_ref())? {
                        return Ok(());
                    }
                    let checkpoint = NodeReachabilityCheckpoint {
                        schema_version: NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION,
                        applied: candidate.clone(),
                    };
                    persist_secure_json(
                        &state_path,
                        &checkpoint,
                        "LoadBalancer reachability",
                    )?;
                    info!(
                        epoch = candidate.source_epoch,
                        revision = candidate.revision.get(),
                        targets = candidate.targets.len(),
                        "persisted LoadBalancer reachability intent pending host adoption"
                    );
                    applied = Some(candidate);
                    Ok(())
                }.await;
                if let Err(error) = result {
                    warn!(%error, "LoadBalancer reachability sync failed; retaining last-known-good state");
                }
            }
        }
    }
}

async fn fetch_controller_compatibility(
    client: &ReloadingControllerClient,
    controller_url: &str,
    token_path: &Path,
) -> Result<ComponentCompatibility> {
    authenticated_get(
        client,
        format!(
            "{controller_url}/v1/version?serviceSnapshotSchemaVersion={SERVICE_SNAPSHOT_SCHEMA_VERSION}"
        ),
        token_path,
    )?
    .send()
    .await
    .context("request controller LoadBalancer compatibility")?
    .error_for_status()
    .context("controller rejected LoadBalancer compatibility request")?
    .json()
    .await
    .context("decode controller LoadBalancer compatibility")
}

async fn fetch_load_balancer_reachability(
    controller_url: &str,
    client: &ReloadingControllerClient,
    token_path: &Path,
) -> Result<NodeReachabilitySnapshot> {
    authenticated_get(
        client,
        format!("{controller_url}/v1/state/load-balancer-reachability"),
        token_path,
    )?
    .send()
    .await
    .context("request controller LoadBalancer reachability")?
    .error_for_status()
    .context("controller rejected LoadBalancer reachability request")?
    .json()
    .await
    .context("decode controller LoadBalancer reachability")
}

fn load_optional_load_balancer_reachability(
    path: &Path,
) -> Result<Option<NodeReachabilitySnapshot>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "inspect durable LoadBalancer reachability {}",
                path.display()
            )
        }),
        Ok(_) => {
            let checkpoint: NodeReachabilityCheckpoint =
                load_secure_json(path, "LoadBalancer reachability")?;
            Ok(Some(checkpoint.validate()?.applied))
        }
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
        format!(
            "{controller_url}/v1/state/services?serviceSnapshotSchemaVersion={SERVICE_SNAPSHOT_SCHEMA_VERSION}"
        ),
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

async fn fetch_node_port_node_snapshot(
    controller_url: &str,
    client: &ReloadingControllerClient,
    token_path: &Path,
) -> Result<NodePortNodeSnapshot> {
    authenticated_get(
        client,
        format!("{controller_url}/v1/state/node-port-node"),
        token_path,
    )?
    .send()
    .await
    .context("request controller local NodePort Node snapshot")?
    .error_for_status()
    .context("controller rejected local NodePort Node snapshot request")?
    .json()
    .await
    .context("decode controller local NodePort Node snapshot")
}

async fn fetch_selection_contract(
    controller_url: &str,
    client: &ReloadingControllerClient,
    token_path: &Path,
) -> Result<NetworkBehaviorContract> {
    authenticated_get(
        client,
        format!(
            "{controller_url}/v1/state/service-selection?selectionContractSchemaVersion={SELECTION_CONTRACT_SCHEMA_VERSION}&stableHash=true&maglev=true&nat=true&dsrIpv4=true&dsrIpv6=true"
        ),
        token_path,
    )?
    .send()
    .await
    .context("request controller service selection contract")?
    .error_for_status()
    .context("controller rejected service selection contract request")?
    .json()
    .await
    .context("decode controller service selection contract")
}

async fn ensure_service_controller_compatibility(
    client: &ReloadingControllerClient,
    controller_url: &str,
    token_path: &Path,
) -> Result<()> {
    let requested = authenticated_get(
        client,
        format!(
            "{controller_url}/v1/version?serviceSnapshotSchemaVersion={SERVICE_SNAPSHOT_SCHEMA_VERSION}&selectionContractSchemaVersion={SELECTION_CONTRACT_SCHEMA_VERSION}"
        ),
        token_path,
    )?
    .send()
    .await
    .context("request controller compatibility for selection contracts")?;
    let response = if requested.status() == reqwest::StatusCode::BAD_REQUEST {
        authenticated_get(
            client,
            format!(
                "{controller_url}/v1/version?serviceSnapshotSchemaVersion={SERVICE_SNAPSHOT_SCHEMA_VERSION}"
            ),
            token_path,
        )?
        .send()
        .await
        .context("retry compatibility against a pre-selection controller")?
    } else {
        requested
    };
    let compatibility: ComponentCompatibility = response
        .error_for_status()
        .context("controller rejected service compatibility preflight")?
        .json()
        .await
        .context("decode service compatibility preflight")?;
    ensure_controller_compatibility(&compatibility)
}

fn load_optional_service_snapshot(path: &Path) -> Result<Option<ServiceSnapshot>> {
    Ok(load_optional_service_checkpoint(path)?.map(|(service, _)| service))
}

fn load_optional_service_checkpoint(
    path: &Path,
) -> Result<Option<(ServiceSnapshot, Option<NodePortNodeSnapshot>)>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("inspect durable service snapshot {}", path.display())),
        Ok(_) => {
            let stored: StoredServiceCheckpoint = load_secure_json(path, "service")?;
            match stored {
                StoredServiceCheckpoint::Legacy(snapshot) => {
                    let snapshot = snapshot.validate_and_normalize()?;
                    if snapshot
                        .services
                        .iter()
                        .any(|service| !service.node_ports.is_empty())
                    {
                        bail!("durable NodePort service snapshot has no local Node checkpoint");
                    }
                    Ok(Some((snapshot, None)))
                }
                StoredServiceCheckpoint::NodePort(checkpoint) => {
                    if checkpoint.schema_version != NODE_PORT_SERVICE_CHECKPOINT_SCHEMA_VERSION {
                        bail!(
                            "unsupported NodePort service checkpoint schema {}; expected {}",
                            checkpoint.schema_version,
                            NODE_PORT_SERVICE_CHECKPOINT_SCHEMA_VERSION
                        );
                    }
                    let service = checkpoint.service.validate_and_normalize()?;
                    let node = checkpoint.node_port_node.validate_and_normalize()?;
                    if service.source_epoch != node.source_epoch {
                        bail!("durable service and local Node checkpoints have different epochs");
                    }
                    if !service_requires_local_node(&service) {
                        bail!("durable local Node checkpoint has no Service host intent");
                    }
                    Ok(Some((service, Some(node))))
                }
            }
        }
    }
}

fn persist_service_snapshot(
    path: &Path,
    snapshot: &ServiceSnapshot,
    description: &str,
) -> Result<()> {
    if snapshot
        .services
        .iter()
        .all(|service| service.node_ports.is_empty() && service.load_balancer.is_none())
    {
        let legacy = snapshot.legacy_v1_projection()?;
        persist_secure_json(path, &legacy, description)
    } else {
        persist_secure_json(path, snapshot, description)
    }
}

fn persist_service_checkpoint(
    path: &Path,
    service: &ServiceSnapshot,
    node_port_node: Option<&NodePortNodeSnapshot>,
    description: &str,
) -> Result<()> {
    let service = service.clone().validate_and_normalize()?;
    let requires_local_node = service_requires_local_node(&service);
    match (requires_local_node, node_port_node) {
        (false, None) => persist_service_snapshot(path, &service, description),
        (true, Some(node)) => {
            let node = node.clone().validate_and_normalize()?;
            if service.source_epoch != node.source_epoch {
                bail!("service and local Node checkpoint epochs differ");
            }
            persist_secure_json(
                path,
                &NodePortServiceCheckpoint {
                    schema_version: NODE_PORT_SERVICE_CHECKPOINT_SCHEMA_VERSION,
                    service,
                    node_port_node: node,
                },
                description,
            )
        }
        (true, None) => bail!("Service host intent checkpoint requires local Node state"),
        (false, Some(_)) => bail!("local Node checkpoint requires Service host intent"),
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

fn prepare_service_checkpoint(
    path: &Path,
    service: &ServiceSnapshot,
    node_port_node: Option<&NodePortNodeSnapshot>,
) -> Result<PathBuf> {
    discard_service_pending_state(path)?;
    let pending = service_pending_state_path(path)?;
    persist_service_checkpoint(
        &pending,
        service,
        node_port_node,
        "pending NodePort service",
    )?;
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
        return persist_service_snapshot(path, previous, "service rollback");
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

fn restore_service_fabric_checkpoint(
    path: &Path,
    previous_service: Option<&ServiceSnapshot>,
    previous_node_port_node: Option<&NodePortNodeSnapshot>,
) -> Result<()> {
    if let Some(previous) = previous_service {
        return persist_service_checkpoint(
            path,
            previous,
            previous_node_port_node,
            "NodePort service rollback",
        );
    }
    restore_service_checkpoint(path, None)
}

fn local_selection_capabilities() -> BTreeSet<SelectionCapability> {
    BTreeSet::from([
        SelectionCapability::StableHash,
        SelectionCapability::Maglev,
        SelectionCapability::Nat,
        SelectionCapability::DsrIpv4,
        SelectionCapability::DsrIpv6,
    ])
}

fn local_selection_node(node: &NodePortNodeSnapshot, zone: Option<String>) -> SelectionNode {
    SelectionNode {
        name: node.node_name.clone(),
        uid: node.node_uid.clone(),
        zone,
        capabilities: local_selection_capabilities(),
    }
}

fn selection_contract_state_path(service_path: &Path) -> Result<PathBuf> {
    let file_name = service_path
        .file_name()
        .context("service state path must name a file")?
        .to_string_lossy();
    Ok(service_path.with_file_name(format!("{file_name}.selection")))
}

fn selection_contract_pending_path(service_path: &Path) -> Result<PathBuf> {
    let path = selection_contract_state_path(service_path)?;
    let file_name = path
        .file_name()
        .context("selection contract state path must name a file")?
        .to_string_lossy();
    Ok(path.with_file_name(format!("{file_name}.pending")))
}

fn load_optional_selection_checkpoint(path: &Path) -> Result<Option<SelectionContractCheckpoint>> {
    let Some(checkpoint) = decode_optional_selection_checkpoint(path)? else {
        return Ok(None);
    };
    let snapshot = load_optional_service_snapshot_for_contract(path, &checkpoint.contract)?;
    verify_selection_checkpoint(&checkpoint, &snapshot)?;
    Ok(Some(checkpoint))
}

fn decode_optional_selection_checkpoint(
    path: &Path,
) -> Result<Option<SelectionContractCheckpoint>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("inspect selection checkpoint {}", path.display()))
        }
        Ok(_) => {
            let checkpoint: SelectionContractCheckpoint =
                load_secure_json(path, "service selection")?;
            if checkpoint.schema_version != SELECTION_CONTRACT_CHECKPOINT_SCHEMA_VERSION {
                bail!(
                    "unsupported selection checkpoint schema {}; expected {}",
                    checkpoint.schema_version,
                    SELECTION_CONTRACT_CHECKPOINT_SCHEMA_VERSION
                );
            }
            if checkpoint.active_bank >= SELECTION_BANK_COUNT {
                bail!("selection checkpoint has invalid active bank");
            }
            let node = checkpoint.node.clone().validate_and_normalize()?;
            Ok(Some(SelectionContractCheckpoint { node, ..checkpoint }))
        }
    }
}

fn verify_selection_checkpoint(
    checkpoint: &SelectionContractCheckpoint,
    snapshot: &ServiceSnapshot,
) -> Result<()> {
    checkpoint.contract.verify(
        snapshot,
        &local_selection_node(&checkpoint.node, checkpoint.contract.node.zone.clone()),
    )?;
    Ok(())
}

fn load_optional_service_snapshot_for_contract(
    selection_path: &Path,
    contract: &NetworkBehaviorContract,
) -> Result<ServiceSnapshot> {
    let file_name = selection_path
        .file_name()
        .context("selection checkpoint path must name a file")?
        .to_string_lossy();
    let service_name = file_name
        .strip_suffix(".selection.pending")
        .or_else(|| file_name.strip_suffix(".selection"))
        .context("selection checkpoint path is not derived from service state")?;
    let service_path = selection_path.with_file_name(service_name);
    let pending_service_path = service_pending_state_path(&service_path)?;
    for path in [&service_path, &pending_service_path] {
        if let Some(snapshot) = load_optional_service_snapshot(path)?
            && snapshot.source_epoch == contract.source_epoch
            && snapshot.revision == contract.service_revision
        {
            return Ok(snapshot);
        }
    }
    bail!("selection checkpoint has no matching durable or prepared service snapshot")
}

fn persist_selection_checkpoint(
    path: &Path,
    contract: &NetworkBehaviorContract,
    node: &NodePortNodeSnapshot,
    active_bank: u8,
    description: &str,
) -> Result<()> {
    if active_bank >= SELECTION_BANK_COUNT {
        bail!("selection checkpoint has invalid active bank");
    }
    let node = node.clone().validate_and_normalize()?;
    if node.source_epoch != contract.source_epoch
        || node.node_name != contract.node.name
        || node.node_uid != contract.node.uid
    {
        bail!("selection checkpoint Node does not match its contract ownership tuple");
    }
    persist_secure_json(
        path,
        &SelectionContractCheckpoint {
            schema_version: SELECTION_CONTRACT_CHECKPOINT_SCHEMA_VERSION,
            active_bank,
            node,
            contract: contract.clone(),
        },
        description,
    )
}

fn prepare_selection_checkpoint(
    service_path: &Path,
    contract: &NetworkBehaviorContract,
    node: &NodePortNodeSnapshot,
    active_bank: u8,
) -> Result<PathBuf> {
    let pending = selection_contract_pending_path(service_path)?;
    remove_secure_optional_file(&pending, "pending selection checkpoint")?;
    persist_selection_checkpoint(
        &pending,
        contract,
        node,
        active_bank,
        "pending service selection",
    )?;
    Ok(pending)
}

fn commit_prepared_selection_checkpoint(service_path: &Path, pending: &Path) -> Result<()> {
    let current = selection_contract_state_path(service_path)?;
    reject_node_block_symlinks(&current)?;
    reject_node_block_symlinks(pending)?;
    fs::rename(pending, &current).with_context(|| {
        format!(
            "commit pending selection checkpoint {} to {}",
            pending.display(),
            current.display()
        )
    })?;
    File::open(
        current
            .parent()
            .context("selection state path has no parent")?,
    )?
    .sync_all()?;
    Ok(())
}

fn restore_selection_checkpoint(
    service_path: &Path,
    contract: Option<&NetworkBehaviorContract>,
    node: Option<&NodePortNodeSnapshot>,
    active_bank: u8,
) -> Result<()> {
    let current = selection_contract_state_path(service_path)?;
    match (contract, node) {
        (Some(contract), Some(node)) => persist_selection_checkpoint(
            &current,
            contract,
            node,
            active_bank,
            "service selection rollback",
        ),
        (None, None) => remove_secure_optional_file(&current, "selection rollback checkpoint"),
        _ => bail!("selection rollback contract and Node checkpoint are incomplete"),
    }
}

fn remove_secure_optional_file(path: &Path, description: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {description}")),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{description} is not a regular file: {}", path.display())
        }
        Ok(_) => {
            fs::remove_file(path).with_context(|| format!("remove {description}"))?;
            File::open(path.parent().context("owned state path has no parent")?)?.sync_all()?;
            Ok(())
        }
    }
}

fn recover_selection_contract_state(services: &mut ServiceSynchronizer) -> Result<()> {
    let Some(applied) = services.applied.as_ref() else {
        return Ok(());
    };
    let current_path = selection_contract_state_path(&services.state_path)?;
    let pending_path = selection_contract_pending_path(&services.state_path)?;
    let current = decode_optional_selection_checkpoint(&current_path)?;
    let pending = decode_optional_selection_checkpoint(&pending_path)?;
    let preferred_digest = services
        .applied_selection_contract
        .as_ref()
        .map(|contract| contract.contract_digest);
    let selected = match preferred_digest {
        Some(digest) => [(false, current.clone()), (true, pending.clone())]
            .into_iter()
            .find_map(|(is_pending, checkpoint)| {
                checkpoint
                    .filter(|checkpoint| {
                        checkpoint.contract.source_epoch == applied.source_epoch
                            && checkpoint.contract.service_revision == applied.revision
                            && checkpoint.contract.contract_digest == digest
                    })
                    .map(|checkpoint| (is_pending, checkpoint))
            }),
        None => select_recovered_selection_checkpoint(applied, current, pending),
    };
    let Some((selected_pending, checkpoint)) = selected else {
        remove_secure_optional_file(&pending_path, "stale pending selection checkpoint")?;
        if has_advanced_selection_intent(applied) {
            bail!("advanced Service selection intent has no matching durable contract");
        }
        return Ok(());
    };
    verify_selection_checkpoint(&checkpoint, applied)
        .context("verify recovered selection checkpoint against active service state")?;
    if selected_pending {
        commit_prepared_selection_checkpoint(&services.state_path, &pending_path)?;
    } else {
        remove_secure_optional_file(&pending_path, "stale pending selection checkpoint")?;
    }
    let bank = usize::from(checkpoint.active_bank);
    services.selection_banks = [None, None];
    services.selection_banks[bank] = Some(checkpoint.contract.clone());
    services.active_selection_bank = checkpoint.active_bank;
    services.applied_selection_contract = Some(checkpoint.contract);
    services.applied_node_port_node = Some(checkpoint.node);
    Ok(())
}

fn select_recovered_selection_checkpoint(
    applied: &ServiceSnapshot,
    current: Option<SelectionContractCheckpoint>,
    pending: Option<SelectionContractCheckpoint>,
) -> Option<(bool, SelectionContractCheckpoint)> {
    current
        .filter(|checkpoint| {
            checkpoint.contract.source_epoch == applied.source_epoch
                && checkpoint.contract.service_revision == applied.revision
        })
        .map(|checkpoint| (false, checkpoint))
        .or_else(|| {
            pending
                .filter(|checkpoint| {
                    checkpoint.contract.source_epoch == applied.source_epoch
                        && checkpoint.contract.service_revision == applied.revision
                })
                .map(|checkpoint| (true, checkpoint))
        })
}

#[cfg(test)]
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
    let node_port_count = candidate
        .services
        .iter()
        .map(|service| service.node_ports.len())
        .sum::<usize>();
    if node_port_count != 0 {
        bail!(
            "NodePort intent contains {node_port_count} frontends but host-facing lowering is not implemented"
        );
    }
    if !validate_service_snapshot_transition(&candidate, applied.as_ref())? {
        clear_service_snapshot_error(state);
        return Ok(());
    }
    persist_service_snapshot(state_path, &candidate, "service")?;
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
    if let Some((snapshot, node)) = load_optional_service_checkpoint(&synchronizer.state_path)? {
        let selection_path = selection_contract_state_path(&synchronizer.state_path)?;
        let selection = load_optional_selection_checkpoint(&selection_path)?.filter(|checkpoint| {
            checkpoint.contract.source_epoch == snapshot.source_epoch
                && checkpoint.contract.service_revision == snapshot.revision
        });
        let health = load_balancer_health_check_plan(&snapshot, &synchronizer.node_name)?;
        let health_staged = synchronizer.health_checks.prepare(&health)?;
        publish_desired_service_snapshot(state, &snapshot);
        publish_desired_selection_contract(
            state,
            selection.as_ref().map(|checkpoint| &checkpoint.contract),
        );
        let restored_node = node
            .as_ref()
            .or_else(|| selection.as_ref().map(|checkpoint| &checkpoint.node));
        activate_service_snapshot_with_contract(
            synchronizer,
            &snapshot,
            restored_node,
            selection.as_ref().map(|checkpoint| &checkpoint.contract),
            false,
            state,
        )?;
        synchronizer.health_checks.commit(&health, health_staged);
        publish_load_balancer_health(state, &health);
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
    let selection_contract = match fetch_selection_contract(
        controller_url,
        &synchronizer.client,
        &synchronizer.agent_token_path,
    )
    .await
    {
        Ok(contract) => Some(contract),
        Err(error) if !has_advanced_selection_intent(&candidate) => {
            warn!(%error, "controller has no selection-contract projection; using safe legacy selection for default intent");
            None
        }
        Err(error) => return Err(error.context("advanced selection intent requires a contract")),
    };
    let node_port_node = if service_requires_local_node(&candidate) || selection_contract.is_some()
    {
        let node = fetch_node_port_node_snapshot(
            controller_url,
            &synchronizer.client,
            &synchronizer.agent_token_path,
        )
        .await?
        .validate_and_normalize()?;
        if node.node_name != synchronizer.node_name {
            bail!(
                "controller returned NodePort state for Node {}; authenticated agent owns {}",
                node.node_name,
                synchronizer.node_name
            );
        }
        Some(node)
    } else {
        None
    };
    if let Some(contract) = &selection_contract {
        let node = node_port_node
            .as_ref()
            .context("selection contract requires authenticated local Node identity")?;
        let local_node = local_selection_node(node, contract.node.zone.clone());
        contract
            .verify(&candidate, &local_node)
            .context("verify controller service selection contract")?;
    }
    let health = load_balancer_health_check_plan(&candidate, &synchronizer.node_name)?;
    publish_desired_service_snapshot(state, &candidate);
    publish_desired_selection_contract(state, selection_contract.as_ref());
    let service_changed =
        validate_service_snapshot_transition(&candidate, synchronizer.applied.as_ref())?;
    let node_changed = validate_node_port_node_transition(
        node_port_node.as_ref(),
        synchronizer.applied_node_port_node.as_ref(),
    )?;
    let selection_changed =
        synchronizer.applied_selection_contract.as_ref() != selection_contract.as_ref();
    if !service_changed && !node_changed && !selection_changed {
        synchronizer.health_checks.reconcile(&health)?;
        publish_load_balancer_health(state, &health);
        return Ok(());
    }
    let health_staged = synchronizer.health_checks.prepare(&health)?;
    activate_service_snapshot_with_contract(
        synchronizer,
        &candidate,
        node_port_node.as_ref(),
        selection_contract.as_ref(),
        true,
        state,
    )?;
    synchronizer.health_checks.commit(&health, health_staged);
    publish_load_balancer_health(state, &health);
    Ok(())
}

async fn synchronize_load_balancer_maps(
    synchronizer: &mut ServiceSynchronizer,
    state: &AgentState,
) -> Result<()> {
    let services = synchronizer
        .applied
        .as_ref()
        .context("LoadBalancer synchronization requires active service state")?;
    // Fetch even when no current Service carries LoadBalancer intent. The
    // controller's allocation revision is a cluster-wide fence that can stay
    // non-initial after the final LoadBalancer is deleted, and a recovery reset
    // must replay that empty projection instead of remaining at revision 0/0.
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("LoadBalancer synchronization requires a controller URL")?;
    let candidate = fetch_load_balancer_reachability(
        controller_url,
        &synchronizer.client,
        &synchronizer.agent_token_path,
    )
    .await?
    .validate()?;
    if candidate.node.name != synchronizer.node_name {
        bail!(
            "controller returned LoadBalancer state for Node {}; authenticated agent owns {}",
            candidate.node.name,
            synchronizer.node_name
        );
    }
    publish_desired_load_balancer(state, &candidate);
    let reachability_changed =
        candidate.validate_transition(synchronizer.applied_load_balancer_reachability.as_ref())?;
    let active = synchronizer.load_balancer_banks
        [usize::from(synchronizer.active_load_balancer_bank)]
    .as_ref();
    let linkage_changed = active.is_none_or(|active| {
        active.service_revision != services.revision
            || active.service_bank != synchronizer.active_bank
    });
    if !reachability_changed && !linkage_changed {
        return Ok(());
    }
    activate_load_balancer_snapshot(synchronizer, &candidate, state)
}

#[allow(clippy::too_many_lines)]
fn activate_load_balancer_snapshot(
    synchronizer: &mut ServiceSynchronizer,
    candidate: &NodeReachabilitySnapshot,
    state: &AgentState,
) -> Result<()> {
    let services = synchronizer
        .applied
        .as_ref()
        .context("LoadBalancer activation requires active service state")?
        .clone();
    let bank = 1_u8.saturating_sub(synchronizer.active_load_balancer_bank);
    let desired = match synchronizer.applied_selection_contract.as_ref() {
        Some(contract) => compile_load_balancer_selection_dataplane(
            &services,
            candidate,
            contract,
            synchronizer.active_bank,
            bank,
        )?,
        None => {
            compile_load_balancer_dataplane(&services, candidate, synchronizer.active_bank, bank)?
        }
    };
    let desired_index = usize::from(bank);
    let previous_stage = synchronizer.load_balancer_banks[desired_index]
        .clone()
        .unwrap_or_else(|| empty_load_balancer_bank(&desired));
    stage_load_balancer_bank(synchronizer, &previous_stage, &desired)?;

    let pending = service_pending_state_path(&synchronizer.load_balancer_state_path)?;
    if let Err(error) = discard_service_pending_state(&synchronizer.load_balancer_state_path)
        .and_then(|()| {
            persist_secure_json(
                &pending,
                &NodeReachabilityCheckpoint {
                    schema_version: NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION,
                    applied: candidate.clone(),
                },
                "pending LoadBalancer reachability",
            )
        })
    {
        let rollback = restore_load_balancer_bank(synchronizer, &previous_stage);
        bail!("prepare LoadBalancer checkpoint failed: {error:#}; staging rollback: {rollback:?}");
    }

    let previous_config = synchronizer
        .load_balancer_config
        .get(&0, 0)
        .context("read active LoadBalancer config")?;
    let previous_checkpoint = synchronizer.applied_load_balancer_reachability.clone();
    let transaction = synchronizer
        .load_balancer_config
        .set(0, desired.config, 0)
        .context("atomically activate LoadBalancer bank")
        .and_then(|()| {
            commit_prepared_service_snapshot(&synchronizer.load_balancer_state_path, &pending)
                .context("commit active LoadBalancer checkpoint")
        });
    if let Err(error) = transaction {
        let config_rollback = synchronizer.load_balancer_config.set(0, previous_config, 0);
        let stage_rollback = restore_load_balancer_bank(synchronizer, &previous_stage);
        let checkpoint_rollback = restore_load_balancer_checkpoint(
            &synchronizer.load_balancer_state_path,
            previous_checkpoint.as_ref(),
        );
        let pending_cleanup = discard_service_pending_state(&synchronizer.load_balancer_state_path);
        bail!(
            "LoadBalancer transaction failed: {error:#}; config rollback: {config_rollback:?}; staging rollback: {stage_rollback:?}; checkpoint rollback: {checkpoint_rollback:?}; pending cleanup: {pending_cleanup:?}"
        );
    }

    let purged_connections =
        purge_stale_load_balancer_connections(&mut synchronizer.connections, &desired).context(
            "purge connections that no longer belong to the active LoadBalancer frontend",
        )?;

    let previous_active = synchronizer.active_load_balancer_bank;
    synchronizer.load_balancer_banks[desired_index] = Some(desired);
    synchronizer.active_load_balancer_bank = bank;
    synchronizer.applied_load_balancer_reachability = Some(candidate.clone());
    publish_applied_load_balancer(
        state,
        candidate,
        synchronizer.load_balancer_banks[desired_index]
            .as_ref()
            .expect("activated LoadBalancer bank is retained"),
    );
    if previous_active != bank {
        let previous_index = usize::from(previous_active);
        if let Some(old) = synchronizer.load_balancer_banks[previous_index].clone() {
            match clear_load_balancer_bank(synchronizer, &old) {
                Ok(()) => synchronizer.load_balancer_banks[previous_index] = None,
                Err(error) => warn!(
                    %error,
                    bank = previous_active,
                    "could not garbage-collect old LoadBalancer bank; retained for retry"
                ),
            }
        }
    }
    info!(
        service_revision = services.revision.get(),
        reachability_revision = candidate.revision.get(),
        allocation_revision = candidate.allocation_revision.get(),
        active_bank = bank,
        targets = candidate.targets.len(),
        purged_connections,
        "LoadBalancer host state activated in persistent BPF maps"
    );
    Ok(())
}

fn publish_desired_load_balancer(state: &AgentState, snapshot: &NodeReachabilitySnapshot) {
    state
        .desired_load_balancer_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .desired_load_balancer_revision
        .store(snapshot.revision.get(), Ordering::Release);
    state
        .desired_load_balancer_allocation_revision
        .store(snapshot.allocation_revision.get(), Ordering::Release);
    state
        .metrics
        .load_balancer_revision_desired
        .set(metric_value(snapshot.revision.get()));
    state
        .metrics
        .load_balancer_allocation_revision_desired
        .set(metric_value(snapshot.allocation_revision.get()));
}

fn publish_applied_load_balancer(
    state: &AgentState,
    snapshot: &NodeReachabilitySnapshot,
    dataplane: &LoadBalancerDataplaneState,
) {
    let (cluster_frontends, local_frontends) = dataplane
        .ipv4_frontends
        .values()
        .chain(dataplane.ipv6_frontends.values())
        .fold((0_u64, 0_u64), |(cluster, local), value| {
            let flags = u16::from_ne_bytes([value[14], value[15]]);
            if flags & unf_ebpf_common::LOAD_BALANCER_FRONTEND_FLAG_LOCAL != 0 {
                (cluster, local.saturating_add(1))
            } else {
                (cluster.saturating_add(1), local)
            }
        });
    let frontend_count = cluster_frontends.saturating_add(local_frontends);
    let source_range_count = u64::try_from(
        dataplane
            .ipv4_source_ranges
            .len()
            .saturating_add(dataplane.ipv6_source_ranges.len()),
    )
    .unwrap_or(u64::MAX);
    state
        .applied_load_balancer_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .applied_load_balancer_revision
        .store(snapshot.revision.get(), Ordering::Release);
    state
        .applied_load_balancer_allocation_revision
        .store(snapshot.allocation_revision.get(), Ordering::Release);
    state
        .load_balancer_frontend_count
        .store(frontend_count, Ordering::Release);
    state
        .load_balancer_cluster_frontend_count
        .store(cluster_frontends, Ordering::Release);
    state
        .load_balancer_local_frontend_count
        .store(local_frontends, Ordering::Release);
    state
        .load_balancer_source_range_count
        .store(source_range_count, Ordering::Release);
    state
        .active_load_balancer_bank
        .store(u64::from(dataplane.bank), Ordering::Release);
    state
        .metrics
        .load_balancer_revision_applied
        .set(metric_value(snapshot.revision.get()));
    state
        .metrics
        .load_balancer_allocation_revision_applied
        .set(metric_value(snapshot.allocation_revision.get()));
    state
        .metrics
        .load_balancer_frontend_count
        .set(metric_value(frontend_count));
    state
        .metrics
        .load_balancer_cluster_frontend_count
        .set(metric_value(cluster_frontends));
    state
        .metrics
        .load_balancer_local_frontend_count
        .set(metric_value(local_frontends));
    state
        .metrics
        .load_balancer_source_range_count
        .set(metric_value(source_range_count));
    *mutex_lock(&state.load_balancer_last_error) = None;
}

fn record_load_balancer_error(state: &AgentState, error: &anyhow::Error) {
    state
        .load_balancer_reconcile_errors
        .fetch_add(1, Ordering::AcqRel);
    state.metrics.load_balancer_reconcile_errors.inc();
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
    *mutex_lock(&state.load_balancer_last_error) = Some(message);
}

fn empty_load_balancer_bank(desired: &LoadBalancerDataplaneState) -> LoadBalancerDataplaneState {
    let mut empty = desired.clone();
    empty.ipv4_frontends.clear();
    empty.ipv6_frontends.clear();
    empty.ipv4_source_ranges.clear();
    empty.ipv6_source_ranges.clear();
    empty.config = [0; 48];
    empty
}

fn load_balancer_connection_owner(
    value: &[u8; 104],
    desired: &LoadBalancerDataplaneState,
) -> Option<u32> {
    if !matches!(
        value[102],
        SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER | SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL
    ) {
        return None;
    }
    let frontend = match value[97] {
        4 => {
            let mut key = [0_u8; 8];
            key[0..4].copy_from_slice(&value[32..36]);
            key[4..6].copy_from_slice(&value[90..92]);
            key[6] = value[96];
            key[7] = desired.bank;
            desired.ipv4_frontends.get(&key)
        }
        6 => {
            let mut key = [0_u8; 20];
            key[0..16].copy_from_slice(&value[32..48]);
            key[16..18].copy_from_slice(&value[90..92]);
            key[18] = value[96];
            key[19] = desired.bank;
            desired.ipv6_frontends.get(&key)
        }
        _ => None,
    }?;
    Some(u32::from_ne_bytes(frontend[0..4].try_into().ok()?))
}

fn purge_stale_load_balancer_connections(
    connections: &mut AyaHashMap<MapData, [u8; 40], [u8; 104]>,
    desired: &LoadBalancerDataplaneState,
) -> Result<usize> {
    let stale = connections
        .iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|(key, value)| {
            if !matches!(
                value[102],
                SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER
                    | SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL
            ) {
                return None;
            }
            let stored_owner = u32::from_ne_bytes(value[80..84].try_into().ok()?);
            (load_balancer_connection_owner(&value, desired) != Some(stored_owner)).then_some(key)
        })
        .collect::<Vec<_>>();
    for key in &stale {
        connections.remove(key)?;
    }
    Ok(stale.len())
}

fn restore_load_balancer_checkpoint(
    path: &Path,
    previous: Option<&NodeReachabilitySnapshot>,
) -> Result<()> {
    if let Some(previous) = previous {
        return persist_secure_json(
            path,
            &NodeReachabilityCheckpoint {
                schema_version: NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION,
                applied: previous.clone(),
            },
            "LoadBalancer reachability rollback",
        );
    }
    restore_service_checkpoint(path, None)
}

fn service_has_node_ports(snapshot: &ServiceSnapshot) -> bool {
    snapshot
        .services
        .iter()
        .any(|service| !service.node_ports.is_empty())
}

fn active_load_balancer_references_service_bank(
    synchronizer: &ServiceSynchronizer,
    service_bank: u8,
) -> bool {
    synchronizer.load_balancer_banks[usize::from(synchronizer.active_load_balancer_bank)]
        .as_ref()
        .is_some_and(|load_balancer| {
            load_balancer.service_bank == service_bank
                && (!load_balancer.ipv4_frontends.is_empty()
                    || !load_balancer.ipv6_frontends.is_empty())
        })
}

fn service_requires_local_node(snapshot: &ServiceSnapshot) -> bool {
    service_has_node_ports(snapshot)
        || has_advanced_selection_intent(snapshot)
        || snapshot
            .services
            .iter()
            .any(|service| service.load_balancer.is_some())
}

fn encode_load_balancer_node_source(node: Option<&NodePortNodeSnapshot>) -> [u8; 40] {
    let Some(node) = node else {
        return [0; 40];
    };
    let preferred = |ipv4: bool| {
        node.addresses
            .iter()
            .find(|address| {
                address.kind == unf_service::NodeAddressKind::Internal
                    && address.address.is_ipv4() == ipv4
            })
            .or_else(|| {
                node.addresses
                    .iter()
                    .find(|address| address.address.is_ipv4() == ipv4)
            })
            .map(|address| address.address)
    };
    let mut config = [0_u8; 40];
    config[0..8].copy_from_slice(&node.revision.get().to_ne_bytes());
    let mut flags = 0_u8;
    if let Some(IpAddr::V4(address)) = preferred(true) {
        config[8..12].copy_from_slice(&address.octets());
        flags |= unf_ebpf_common::LOAD_BALANCER_NODE_SOURCE_FLAG_IPV4;
    }
    if let Some(IpAddr::V6(address)) = preferred(false) {
        config[12..28].copy_from_slice(&address.octets());
        flags |= unf_ebpf_common::LOAD_BALANCER_NODE_SOURCE_FLAG_IPV6;
    }
    config[28..30]
        .copy_from_slice(&unf_ebpf_common::LOAD_BALANCER_NODE_SOURCE_SCHEMA_VERSION.to_ne_bytes());
    config[30] = flags;
    config
}

fn load_balancer_health_check_plan(
    snapshot: &ServiceSnapshot,
    node_name: &str,
) -> Result<BTreeMap<u16, HealthCheckPlan>> {
    let mut plan = BTreeMap::new();
    for service in &snapshot.services {
        let Some(load_balancer) = service.load_balancer.as_ref() else {
            continue;
        };
        let Some(port) = load_balancer.health_check_node_port else {
            continue;
        };
        if load_balancer.traffic_policy != ServiceTrafficPolicy::Local {
            bail!("healthCheckNodePort {port} belongs to a non-Local LoadBalancer");
        }
        let referenced = load_balancer
            .frontends
            .iter()
            .flat_map(|frontend| frontend.backend_ids.iter().copied())
            .collect::<BTreeSet<_>>();
        let local_endpoints = service
            .backends
            .iter()
            .filter(|backend| {
                referenced.contains(&backend.id)
                    && backend.ready
                    && !backend.terminating
                    && backend.node_name.as_deref() == Some(node_name)
            })
            .count() as u64;
        let candidate = HealthCheckPlan {
            port,
            service_id: service.id,
            local_endpoints,
        };
        if let Some(existing) = plan.insert(port, candidate)
            && existing.service_id != service.id
        {
            bail!(
                "healthCheckNodePort {port} is claimed by services {:?} and {:?}",
                existing.service_id,
                service.id
            );
        }
    }
    Ok(plan)
}

fn publish_load_balancer_health(state: &AgentState, plan: &BTreeMap<u16, HealthCheckPlan>) {
    let listeners = u64::try_from(plan.len()).unwrap_or(u64::MAX);
    let ready = u64::try_from(
        plan.values()
            .filter(|entry| entry.local_endpoints != 0)
            .count(),
    )
    .unwrap_or(u64::MAX);
    state
        .load_balancer_health_check_count
        .store(listeners, Ordering::Release);
    state
        .load_balancer_health_check_ready_count
        .store(ready, Ordering::Release);
    state
        .metrics
        .load_balancer_health_check_count
        .set(metric_value(listeners));
    state
        .metrics
        .load_balancer_health_check_ready_count
        .set(metric_value(ready));
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthCheckResponse {
    local_endpoints: u64,
}

async fn load_balancer_health_response(State(local_endpoints): State<Arc<AtomicU64>>) -> Response {
    let local_endpoints = local_endpoints.load(Ordering::Acquire);
    let status = if local_endpoints == 0 {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (status, Json(HealthCheckResponse { local_endpoints })).into_response()
}

fn bind_health_check_listener(port: u16) -> Result<tokio::net::TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(SocketProtocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port).into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    Ok(tokio::net::TcpListener::from_std(socket.into())?)
}

fn spawn_health_check_listener(
    plan: &HealthCheckPlan,
    listener: tokio::net::TcpListener,
) -> HealthCheckListener {
    let local_endpoints = Arc::new(AtomicU64::new(plan.local_endpoints));
    let cancellation = CancellationToken::new();
    let app = Router::new()
        .route("/healthz", get(load_balancer_health_response))
        .with_state(Arc::clone(&local_endpoints));
    let shutdown = cancellation.clone();
    let port = plan.port;
    let task = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
        {
            warn!(%error, port, "LoadBalancer health-check listener stopped");
        }
    });
    HealthCheckListener {
        service_id: plan.service_id,
        local_endpoints,
        cancellation,
        task,
    }
}

impl HealthCheckManager {
    fn prepare(
        &self,
        desired: &BTreeMap<u16, HealthCheckPlan>,
    ) -> Result<Vec<(HealthCheckPlan, tokio::net::TcpListener)>> {
        let mut staged = Vec::new();
        for plan in desired.values() {
            let needs_listener = self
                .listeners
                .get(&plan.port)
                .is_none_or(|listener| listener.task.is_finished());
            if needs_listener {
                staged.push((plan.clone(), bind_health_check_listener(plan.port)?));
            }
        }
        Ok(staged)
    }

    fn commit(
        &mut self,
        desired: &BTreeMap<u16, HealthCheckPlan>,
        staged: Vec<(HealthCheckPlan, tokio::net::TcpListener)>,
    ) {
        let failed = self
            .listeners
            .iter()
            .filter_map(|(port, listener)| listener.task.is_finished().then_some(*port))
            .collect::<Vec<_>>();
        for port in failed {
            if let Some(listener) = self.listeners.remove(&port) {
                listener.cancellation.cancel();
            }
        }

        let stale = self
            .listeners
            .keys()
            .filter(|port| !desired.contains_key(*port))
            .copied()
            .collect::<Vec<_>>();
        for port in stale {
            if let Some(listener) = self.listeners.remove(&port) {
                listener.cancellation.cancel();
            }
        }
        for (port, plan) in desired {
            if let Some(listener) = self.listeners.get_mut(port) {
                listener.service_id = plan.service_id;
                listener
                    .local_endpoints
                    .store(plan.local_endpoints, Ordering::Release);
            }
        }
        for (plan, listener) in staged {
            self.listeners
                .insert(plan.port, spawn_health_check_listener(&plan, listener));
        }
    }

    fn reconcile(&mut self, desired: &BTreeMap<u16, HealthCheckPlan>) -> Result<()> {
        let staged = self.prepare(desired)?;
        self.commit(desired, staged);
        Ok(())
    }
}

fn compile_service_host_dataplane(
    snapshot: &ServiceSnapshot,
    bank: u8,
) -> Result<ServiceDataplaneState> {
    Ok(compile_service_load_balancer_fabric_dataplane(
        snapshot, bank,
    )?)
}

fn compile_node_port_host_fabric(
    snapshot: &ServiceSnapshot,
    node: &NodePortNodeSnapshot,
    service_bank: u8,
    node_port_bank: u8,
) -> Result<unf_service::NodePortFabricDataplaneState> {
    Ok(compile_node_port_fabric_dataplane(
        snapshot,
        node,
        service_bank,
        node_port_bank,
    )?)
}

struct RecoveredServiceFabric {
    selection: Option<(bool, SelectionContractCheckpoint)>,
    service: ServiceDataplaneState,
    node_port: Option<NodePortDataplaneState>,
}

fn selection_checkpoint_candidates(
    service_path: &Path,
    snapshot: &ServiceSnapshot,
) -> Result<Vec<(bool, SelectionContractCheckpoint)>> {
    let current_path = selection_contract_state_path(service_path)?;
    let pending_path = selection_contract_pending_path(service_path)?;
    let mut candidates = Vec::new();
    for (pending, checkpoint) in [
        (false, decode_optional_selection_checkpoint(&current_path)?),
        (true, decode_optional_selection_checkpoint(&pending_path)?),
    ] {
        let Some(checkpoint) = checkpoint else {
            continue;
        };
        if checkpoint.contract.source_epoch == snapshot.source_epoch
            && checkpoint.contract.service_revision == snapshot.revision
        {
            verify_selection_checkpoint(&checkpoint, snapshot)?;
            candidates.push((pending, checkpoint));
        }
    }
    Ok(candidates)
}

fn compile_recovered_service_fabrics(
    service_path: &Path,
    snapshot: &ServiceSnapshot,
    checkpoint_node: Option<&NodePortNodeSnapshot>,
    service_bank: u8,
    node_port_bank: Option<u8>,
) -> Result<Vec<RecoveredServiceFabric>> {
    let candidates = selection_checkpoint_candidates(service_path, snapshot)?;
    if candidates.is_empty() {
        if has_advanced_selection_intent(snapshot) {
            bail!("advanced Service selection intent has no matching durable contract");
        }
        let (service, node_port) = if service_has_node_ports(snapshot) {
            let node = checkpoint_node
                .context("durable NodePort checkpoint lost its local Node snapshot")?;
            let node_port_bank = node_port_bank
                .context("durable NodePort checkpoint lost its activation pointer")?;
            let fabric =
                compile_node_port_host_fabric(snapshot, node, service_bank, node_port_bank)?;
            (fabric.service, Some(fabric.node_port))
        } else {
            (
                compile_service_host_dataplane(snapshot, service_bank)?,
                None,
            )
        };
        return Ok(vec![RecoveredServiceFabric {
            selection: None,
            service,
            node_port,
        }]);
    }
    candidates
        .into_iter()
        .map(|(pending, checkpoint)| {
            if checkpoint_node.is_some_and(|node| node != &checkpoint.node) {
                bail!("service and selection checkpoints disagree on local Node state");
            }
            let (service, node_port) = if service_has_node_ports(snapshot) {
                let node_port_bank = node_port_bank
                    .context("durable NodePort checkpoint lost its activation pointer")?;
                let fabric = compile_node_port_selection_fabric_dataplane(
                    snapshot,
                    &checkpoint.node,
                    &checkpoint.contract,
                    service_bank,
                    node_port_bank,
                )?;
                (fabric.service, Some(fabric.node_port))
            } else {
                (
                    compile_service_selection_dataplane(
                        snapshot,
                        &checkpoint.contract,
                        service_bank,
                    )?,
                    None,
                )
            };
            Ok(RecoveredServiceFabric {
                selection: Some((pending, checkpoint)),
                service,
                node_port,
            })
        })
        .collect()
}

fn validate_node_port_node_transition(
    candidate: Option<&NodePortNodeSnapshot>,
    applied: Option<&NodePortNodeSnapshot>,
) -> Result<bool> {
    let (Some(candidate), Some(applied)) = (candidate, applied) else {
        return Ok(candidate != applied);
    };
    if candidate.source_epoch != applied.source_epoch || candidate.node_uid != applied.node_uid {
        return Ok(true);
    }
    if candidate.revision < applied.revision {
        bail!(
            "NodePort Node revision regressed from {} to {} in controller epoch {}",
            applied.revision.get(),
            candidate.revision.get(),
            candidate.source_epoch
        );
    }
    if candidate.revision == applied.revision {
        if candidate != applied {
            bail!("NodePort Node snapshot content changed without a revision change");
        }
        return Ok(false);
    }
    Ok(true)
}

fn stage_selection_contract(
    banks: &mut [Option<NetworkBehaviorContract>; SELECTION_BANK_COUNT as usize],
    bank: u8,
    contract: &NetworkBehaviorContract,
    snapshot: &ServiceSnapshot,
    node: &NodePortNodeSnapshot,
) -> Result<Option<NetworkBehaviorContract>> {
    if bank >= SELECTION_BANK_COUNT {
        bail!("selection stage has invalid inactive bank");
    }
    let previous = banks[usize::from(bank)].clone();
    banks[usize::from(bank)] = Some(contract.clone());
    let verification = banks[usize::from(bank)]
        .as_ref()
        .context("staged selection contract disappeared before readback")?
        .verify(
            snapshot,
            &local_selection_node(node, contract.node.zone.clone()),
        )
        .context("verify staged selection contract readback");
    if let Err(error) = verification {
        banks[usize::from(bank)] = previous;
        return Err(error);
    }
    Ok(previous)
}

#[allow(clippy::too_many_lines)]
#[cfg(test)]
fn activate_service_snapshot(
    synchronizer: &mut ServiceSynchronizer,
    candidate: &ServiceSnapshot,
    node_port_node: Option<&NodePortNodeSnapshot>,
    persist: bool,
    state: &AgentState,
) -> Result<()> {
    activate_service_snapshot_with_contract(
        synchronizer,
        candidate,
        node_port_node,
        None,
        persist,
        state,
    )
}

#[allow(clippy::too_many_lines)]
fn activate_service_snapshot_with_contract(
    synchronizer: &mut ServiceSynchronizer,
    candidate: &ServiceSnapshot,
    node_port_node: Option<&NodePortNodeSnapshot>,
    selection_contract: Option<&NetworkBehaviorContract>,
    persist: bool,
    state: &AgentState,
) -> Result<()> {
    let candidate = candidate.clone().validate_and_normalize()?;
    let node_port_node = node_port_node
        .cloned()
        .map(NodePortNodeSnapshot::validate_and_normalize)
        .transpose()?;
    if service_has_node_ports(&candidate) && node_port_node.is_none() {
        bail!("NodePort intent requires authenticated local Node state");
    }
    if !service_requires_local_node(&candidate)
        && node_port_node.is_some()
        && selection_contract.is_none()
    {
        bail!("local Node state was supplied without Service host intent");
    }
    if let Some(node) = &node_port_node {
        if node.node_name != synchronizer.node_name {
            bail!("local Node state does not belong to this agent");
        }
        if node.source_epoch != candidate.source_epoch {
            bail!("service and local Node state have different controller epochs");
        }
    }
    if let Some(contract) = selection_contract {
        let node = node_port_node
            .as_ref()
            .context("selection contract requires authenticated local Node state")?;
        contract.verify(
            &candidate,
            &local_selection_node(node, contract.node.zone.clone()),
        )?;
    } else if has_advanced_selection_intent(&candidate) {
        bail!("advanced Service selection intent cannot activate without a verified contract");
    }
    let service_changed = synchronizer.applied.as_ref() != Some(&candidate);
    let local_node_changed =
        synchronizer.applied_node_port_node.as_ref() != node_port_node.as_ref();
    let selection_changed = synchronizer.applied_selection_contract.as_ref() != selection_contract;
    if !service_changed && !local_node_changed && !selection_changed {
        return Ok(());
    }

    let selection_bank = if selection_changed {
        (synchronizer.active_selection_bank + 1) % SELECTION_BANK_COUNT
    } else {
        synchronizer.active_selection_bank
    };
    let mut previous_selection_stage = selection_changed
        .then(|| synchronizer.selection_banks[usize::from(selection_bank)].clone());

    let service_dataplane_changed = service_changed || selection_changed;
    let service_bank = if service_dataplane_changed {
        (synchronizer.active_bank + 1) % SERVICE_BANK_COUNT
    } else {
        synchronizer.active_bank
    };
    let candidate_has_node_ports = service_has_node_ports(&candidate);
    let applied_had_node_ports = synchronizer
        .applied
        .as_ref()
        .is_some_and(service_has_node_ports);
    let node_port_must_change = (candidate_has_node_ports
        && (local_node_changed || selection_changed))
        || (service_changed && (candidate_has_node_ports || applied_had_node_ports));
    let node_port_bank = if node_port_must_change {
        (synchronizer.active_node_port_bank + 1) % unf_ebpf_common::NODE_PORT_BANK_COUNT
    } else {
        synchronizer.active_node_port_bank
    };

    let (desired_service, desired_node_port) = if candidate_has_node_ports {
        let node = node_port_node
            .as_ref()
            .expect("NodePort intent requires validated local Node state");
        let desired = if let Some(contract) = selection_contract {
            compile_node_port_selection_fabric_dataplane(
                &candidate,
                node,
                contract,
                service_bank,
                node_port_bank,
            )?
        } else {
            compile_node_port_fabric_dataplane(&candidate, node, service_bank, node_port_bank)?
        };
        (
            service_dataplane_changed.then_some(desired.service),
            Some(desired.node_port),
        )
    } else {
        let desired_service = service_dataplane_changed
            .then(|| match selection_contract {
                Some(contract) => {
                    compile_service_selection_dataplane(&candidate, contract, service_bank)
                }
                None => compile_service_load_balancer_fabric_dataplane(&candidate, service_bank),
            })
            .transpose()?;
        let desired_node_port = node_port_must_change.then(|| empty_node_port_bank(node_port_bank));
        (desired_service, desired_node_port)
    };

    let previous_service_stage = desired_service.as_ref().map(|desired| {
        synchronizer.banks[usize::from(desired.bank)]
            .clone()
            .unwrap_or_else(|| empty_service_bank(desired.bank))
    });
    let previous_node_port_stage = desired_node_port.as_ref().map(|desired| {
        synchronizer.node_port_banks[usize::from(desired.bank)]
            .clone()
            .unwrap_or_else(|| empty_node_port_bank(desired.bank))
    });
    let previous_service_config = synchronizer
        .config
        .get(&0, 0)
        .context("read service activation pointer before staging")?;
    let previous_node_port_config = synchronizer
        .node_port_config
        .get(&0, 0)
        .context("read NodePort activation pointer before staging")?;
    let previous_load_balancer_node_source = synchronizer
        .load_balancer_node_source
        .get(&0, 0)
        .context("read LoadBalancer Node source before activation")?;
    if desired_service.is_some()
        && active_load_balancer_references_service_bank(synchronizer, service_bank)
    {
        bail!(
            "inactive service bank {service_bank} is still referenced by the active LoadBalancer bank; wait for LoadBalancer linkage reconciliation"
        );
    }
    if let (Some(previous), Some(desired)) = (&previous_service_stage, &desired_service)
        && let Err(error) = stage_service_bank(synchronizer, previous, desired)
    {
        return Err(error);
    }
    if let (Some(previous), Some(desired)) = (&previous_node_port_stage, &desired_node_port)
        && let Err(error) = stage_node_port_bank(synchronizer, previous, desired)
    {
        let service_rollback = previous_service_stage
            .as_ref()
            .map_or(Ok(()), |bank| restore_service_bank(synchronizer, bank));
        return match service_rollback {
            Ok(()) => Err(error),
            Err(rollback) => Err(anyhow!(
                "{error:#}; service staging rollback also failed: {rollback:#}"
            )),
        };
    }

    if let Some(contract) = selection_contract.filter(|_| selection_changed) {
        let node = node_port_node
            .as_ref()
            .context("selection contract readback requires local Node state")?;
        match stage_selection_contract(
            &mut synchronizer.selection_banks,
            selection_bank,
            contract,
            &candidate,
            node,
        ) {
            Ok(previous) => previous_selection_stage = Some(previous),
            Err(error) => {
                let service_rollback = previous_service_stage
                    .as_ref()
                    .map_or(Ok(()), |bank| restore_service_bank(synchronizer, bank));
                let node_port_rollback = previous_node_port_stage
                    .as_ref()
                    .map_or(Ok(()), |bank| restore_node_port_bank(synchronizer, bank));
                bail!(
                    "selection staging failed: {error:#}; service staging rollback: {service_rollback:?}; NodePort staging rollback: {node_port_rollback:?}"
                );
            }
        }
    }

    let selection_prepared = if persist && selection_changed {
        match selection_contract {
            Some(contract) => match prepare_selection_checkpoint(
                &synchronizer.state_path,
                contract,
                node_port_node
                    .as_ref()
                    .context("selection checkpoint requires local Node state")?,
                selection_bank,
            )
            .context("prepare service selection checkpoint")
            {
                Ok(pending) => Some(pending),
                Err(error) => {
                    synchronizer.selection_banks[usize::from(selection_bank)] =
                        previous_selection_stage.clone().flatten();
                    let service_rollback = previous_service_stage
                        .as_ref()
                        .map_or(Ok(()), |bank| restore_service_bank(synchronizer, bank));
                    let node_port_rollback = previous_node_port_stage
                        .as_ref()
                        .map_or(Ok(()), |bank| restore_node_port_bank(synchronizer, bank));
                    bail!(
                        "prepare selection checkpoint failed: {error:#}; service staging rollback: {service_rollback:?}; NodePort staging rollback: {node_port_rollback:?}"
                    );
                }
            },
            None => None,
        }
    } else {
        None
    };
    let prepared = if persist {
        match prepare_service_checkpoint(
            &synchronizer.state_path,
            &candidate,
            node_port_node
                .as_ref()
                .filter(|_| service_requires_local_node(&candidate)),
        ) {
            Ok(prepared) => Some(prepared),
            Err(error) => {
                if selection_changed {
                    synchronizer.selection_banks[usize::from(selection_bank)] =
                        previous_selection_stage.clone().flatten();
                }
                let service_rollback = previous_service_stage
                    .as_ref()
                    .map_or(Ok(()), |bank| restore_service_bank(synchronizer, bank));
                let node_port_rollback = previous_node_port_stage
                    .as_ref()
                    .map_or(Ok(()), |bank| restore_node_port_bank(synchronizer, bank));
                let selection_cleanup = selection_prepared.as_ref().map_or(Ok(()), |path| {
                    remove_secure_optional_file(path, "pending selection checkpoint")
                });
                bail!(
                    "prepare NodePort service checkpoint failed: {error:#}; service staging rollback: {service_rollback:?}; NodePort staging rollback: {node_port_rollback:?}; selection staging cleanup: {selection_cleanup:?}"
                );
            }
        }
    } else {
        None
    };

    let activation = (|| -> Result<()> {
        synchronizer
            .load_balancer_node_source
            .set(
                0,
                encode_load_balancer_node_source(node_port_node.as_ref()),
                0,
            )
            .context("publish runtime LoadBalancer Node source addresses")?;
        if let Some(desired) = &desired_service {
            synchronizer
                .config
                .set(0, desired.config, 0)
                .context("atomically activate staged service bank")?;
        }
        if let Some(desired) = &desired_node_port {
            synchronizer
                .node_port_config
                .set(0, desired.config, 0)
                .context("atomically activate staged NodePort bank")?;
        }
        if let Some(prepared) = &prepared {
            commit_prepared_service_snapshot(&synchronizer.state_path, prepared)
                .context("commit active NodePort service checkpoint")?;
        }
        if let Some(prepared) = &selection_prepared {
            commit_prepared_selection_checkpoint(&synchronizer.state_path, prepared)
                .context("commit active service selection checkpoint")?;
        } else if persist && selection_changed && selection_contract.is_none() {
            let current = selection_contract_state_path(&synchronizer.state_path)?;
            remove_secure_optional_file(&current, "obsolete selection checkpoint")?;
        }
        Ok(())
    })();
    if let Err(error) = activation {
        let service_config_rollback = synchronizer.config.set(0, previous_service_config, 0);
        let node_port_config_rollback =
            synchronizer
                .node_port_config
                .set(0, previous_node_port_config, 0);
        let load_balancer_node_source_rollback =
            synchronizer
                .load_balancer_node_source
                .set(0, previous_load_balancer_node_source, 0);
        let service_stage_rollback = previous_service_stage
            .as_ref()
            .map_or(Ok(()), |bank| restore_service_bank(synchronizer, bank));
        let node_port_stage_rollback = previous_node_port_stage
            .as_ref()
            .map_or(Ok(()), |bank| restore_node_port_bank(synchronizer, bank));
        if selection_changed {
            synchronizer.selection_banks[usize::from(selection_bank)] =
                previous_selection_stage.clone().flatten();
        }
        let checkpoint_rollback = restore_service_fabric_checkpoint(
            &synchronizer.state_path,
            synchronizer.applied.as_ref(),
            synchronizer.applied_node_port_node.as_ref().filter(|_| {
                synchronizer
                    .applied
                    .as_ref()
                    .is_some_and(service_requires_local_node)
            }),
        );
        let selection_checkpoint_rollback = if persist && selection_changed {
            restore_selection_checkpoint(
                &synchronizer.state_path,
                synchronizer.applied_selection_contract.as_ref(),
                synchronizer.applied_node_port_node.as_ref(),
                synchronizer.active_selection_bank,
            )
        } else {
            Ok(())
        };
        let pending_cleanup = discard_service_pending_state(&synchronizer.state_path);
        let selection_pending_cleanup = selection_prepared.as_ref().map_or(Ok(()), |path| {
            remove_secure_optional_file(path, "pending selection checkpoint")
        });
        bail!(
            "NodePort service transaction failed: {error:#}; service config rollback: {service_config_rollback:?}; NodePort config rollback: {node_port_config_rollback:?}; LoadBalancer Node source rollback: {load_balancer_node_source_rollback:?}; service stage rollback: {service_stage_rollback:?}; NodePort stage rollback: {node_port_stage_rollback:?}; checkpoint rollback: {checkpoint_rollback:?}; selection checkpoint rollback: {selection_checkpoint_rollback:?}; pending cleanup: {pending_cleanup:?}; selection pending cleanup: {selection_pending_cleanup:?}"
        );
    }

    let previous_active = synchronizer.active_bank;
    let previous_node_port_active = synchronizer.active_node_port_bank;
    let previous_selection_active = synchronizer.active_selection_bank;
    if let Some(desired) = desired_service {
        let desired_index = usize::from(desired.bank);
        synchronizer.banks[desired_index] = Some(desired);
        synchronizer.active_bank = service_bank;
    }
    if let Some(desired) = desired_node_port {
        let desired_index = usize::from(desired.bank);
        synchronizer.node_port_banks[desired_index] = Some(desired);
        synchronizer.active_node_port_bank = node_port_bank;
    }
    synchronizer.applied = Some(candidate.clone());
    synchronizer
        .applied_node_port_node
        .clone_from(&node_port_node);
    if selection_changed {
        synchronizer.active_selection_bank = selection_bank;
        synchronizer.applied_selection_contract = selection_contract.cloned();
    }
    if service_dataplane_changed
        && let Some(reachability) = synchronizer.applied_load_balancer_reachability.clone()
        && active_load_balancer_references_service_bank(synchronizer, previous_active)
        && let Err(error) = activate_load_balancer_snapshot(synchronizer, &reachability, state)
    {
        record_load_balancer_error(state, &error);
        warn!(
            %error,
            retained_service_bank = previous_active,
            "LoadBalancer linkage could not follow the Service activation immediately; prior packet state remains active and reconciliation will retry"
        );
    }
    publish_applied_service_snapshot(state, &candidate);
    publish_applied_selection_contract(
        state,
        synchronizer.applied_selection_contract.as_ref(),
        synchronizer.active_selection_bank,
    );
    clear_service_snapshot_error(state);
    if previous_node_port_active != synchronizer.active_node_port_bank {
        let previous_index = usize::from(previous_node_port_active);
        if let Some(old) = synchronizer.node_port_banks[previous_index].clone() {
            match clear_node_port_bank(synchronizer, &old) {
                Ok(()) => synchronizer.node_port_banks[previous_index] = None,
                Err(error) => warn!(
                    %error,
                    bank = previous_node_port_active,
                    "could not garbage-collect old NodePort bank; retained for retry"
                ),
            }
        }
    }
    if previous_active != synchronizer.active_bank {
        let previous_index = usize::from(previous_active);
        if let Some(old) = synchronizer.banks[previous_index].clone() {
            if active_load_balancer_references_service_bank(synchronizer, previous_active) {
                warn!(
                    bank = previous_active,
                    "retaining previous service bank while the active LoadBalancer bank references it"
                );
            } else {
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
    }
    if previous_selection_active != synchronizer.active_selection_bank {
        synchronizer.selection_banks[usize::from(previous_selection_active)] = None;
    }
    info!(
        service_epoch = candidate.source_epoch,
        service_revision = candidate.revision.get(),
        active_bank = synchronizer.active_bank,
        node_port_revision = node_port_node.as_ref().map(|node| node.revision.get()),
        active_node_port_bank = synchronizer.active_node_port_bank,
        selection_contract_revision =
            selection_contract.map(|contract| contract.contract_revision.get()),
        selection_contract_digest =
            selection_contract.map(|contract| contract.contract_digest.to_string()),
        active_selection_bank = synchronizer.active_selection_bank,
        services = candidate.services.len(),
        "service and NodePort snapshot activated in persistent BPF maps"
    );
    Ok(())
}

fn stage_service_bank(
    synchronizer: &mut ServiceSynchronizer,
    previous: &ServiceDataplaneState,
    desired: &ServiceDataplaneState,
) -> Result<()> {
    macro_rules! stage {
        ($map:expr, $current:expr, $next:expr, $label:literal) => {
            if let Err(error) = replace_encoded_entries($map, $current, $next) {
                return Err(rollback_service_stages(
                    synchronizer,
                    previous,
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
        return Err(rollback_service_stages(synchronizer, previous, &error));
    }
    Ok(())
}

fn stage_node_port_bank(
    synchronizer: &mut ServiceSynchronizer,
    previous: &NodePortDataplaneState,
    desired: &NodePortDataplaneState,
) -> Result<()> {
    if let Err(error) = replace_encoded_entries(
        &mut synchronizer.node_port_ipv4_frontends,
        &previous.ipv4_frontends,
        &desired.ipv4_frontends,
    )
    .context("stage IPv4 NodePort frontends")
    .and_then(|()| {
        replace_encoded_entries(
            &mut synchronizer.node_port_ipv6_frontends,
            &previous.ipv6_frontends,
            &desired.ipv6_frontends,
        )
        .context("stage IPv6 NodePort frontends")
    })
    .and_then(|()| {
        validate_encoded_entries(
            &synchronizer.node_port_ipv4_frontends,
            &desired.ipv4_frontends,
            "IPv4 NodePort frontend",
        )
    })
    .and_then(|()| {
        validate_encoded_entries(
            &synchronizer.node_port_ipv6_frontends,
            &desired.ipv6_frontends,
            "IPv6 NodePort frontend",
        )
    }) {
        return match restore_node_port_bank(synchronizer, previous) {
            Ok(()) => Err(error.context("NodePort staging bank rolled back")),
            Err(rollback) => Err(anyhow!(
                "NodePort staging failed: {error:#}; rollback failed: {rollback:#}"
            )),
        };
    }
    Ok(())
}

fn stage_load_balancer_bank(
    synchronizer: &mut ServiceSynchronizer,
    previous: &LoadBalancerDataplaneState,
    desired: &LoadBalancerDataplaneState,
) -> Result<()> {
    if let Err(error) = replace_encoded_entries(
        &mut synchronizer.load_balancer_ipv4_frontends,
        &previous.ipv4_frontends,
        &desired.ipv4_frontends,
    )
    .context("stage IPv4 LoadBalancer frontends")
    .and_then(|()| {
        replace_encoded_entries(
            &mut synchronizer.load_balancer_ipv6_frontends,
            &previous.ipv6_frontends,
            &desired.ipv6_frontends,
        )
        .context("stage IPv6 LoadBalancer frontends")
    })
    .and_then(|()| {
        replace_lpm_entries(
            &mut synchronizer.load_balancer_ipv4_source_ranges,
            &previous.ipv4_source_ranges,
            &desired.ipv4_source_ranges,
        )
        .context("stage IPv4 LoadBalancer source ranges")
    })
    .and_then(|()| {
        replace_lpm_entries(
            &mut synchronizer.load_balancer_ipv6_source_ranges,
            &previous.ipv6_source_ranges,
            &desired.ipv6_source_ranges,
        )
        .context("stage IPv6 LoadBalancer source ranges")
    })
    .and_then(|()| {
        validate_encoded_entries(
            &synchronizer.load_balancer_ipv4_frontends,
            &desired.ipv4_frontends,
            "IPv4 LoadBalancer frontend",
        )
    })
    .and_then(|()| {
        validate_encoded_entries(
            &synchronizer.load_balancer_ipv6_frontends,
            &desired.ipv6_frontends,
            "IPv6 LoadBalancer frontend",
        )
    })
    .and_then(|()| {
        validate_lpm_bank(
            &synchronizer.load_balancer_ipv4_source_ranges,
            &desired.ipv4_source_ranges,
            desired.bank,
        )
        .context("validate IPv4 LoadBalancer source ranges")
    })
    .and_then(|()| {
        validate_lpm_bank(
            &synchronizer.load_balancer_ipv6_source_ranges,
            &desired.ipv6_source_ranges,
            desired.bank,
        )
        .context("validate IPv6 LoadBalancer source ranges")
    }) {
        return match restore_load_balancer_bank(synchronizer, previous) {
            Ok(()) => Err(error.context("LoadBalancer staging bank rolled back")),
            Err(rollback) => Err(anyhow!(
                "LoadBalancer staging failed: {error:#}; rollback failed: {rollback:#}"
            )),
        };
    }
    Ok(())
}

fn replace_lpm_entries<const K: usize>(
    map: &mut AyaLpmTrie<MapData, [u8; K], [u8; 32]>,
    current: &BTreeMap<(u32, [u8; K]), [u8; 32]>,
    desired: &BTreeMap<(u32, [u8; K]), [u8; 32]>,
) -> Result<()>
where
    [u8; K]: aya::Pod,
{
    for (prefix, data) in current.keys().filter(|key| !desired.contains_key(*key)) {
        map.remove(&LpmKey::new(*prefix, *data))?;
    }
    for ((prefix, data), value) in desired {
        map.insert(&LpmKey::new(*prefix, *data), value, 0)?;
    }
    Ok(())
}

fn validate_lpm_bank<const K: usize>(
    map: &AyaLpmTrie<MapData, [u8; K], [u8; 32]>,
    desired: &BTreeMap<(u32, [u8; K]), [u8; 32]>,
    bank: u8,
) -> Result<()>
where
    [u8; K]: aya::Pod,
{
    let actual = map
        .iter()
        .filter_map(|entry| match entry {
            Ok((key, value)) if key.data()[4] == bank => {
                Some(Ok(((key.prefix_len(), key.data()), value)))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if &actual != desired {
        bail!("LoadBalancer source-range bank readback differs from staged state");
    }
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

fn restore_node_port_bank(
    synchronizer: &mut ServiceSynchronizer,
    previous: &NodePortDataplaneState,
) -> Result<()> {
    let results = [
        restore_encoded_bank(
            &mut synchronizer.node_port_ipv4_frontends,
            &previous.ipv4_frontends,
            previous.bank,
            7,
        ),
        restore_encoded_bank(
            &mut synchronizer.node_port_ipv6_frontends,
            &previous.ipv6_frontends,
            previous.bank,
            19,
        ),
    ];
    let failures: Vec<_> = results.into_iter().filter_map(Result::err).collect();
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("restore NodePort bank failed: {failures:?}")
    }
}

fn restore_load_balancer_bank(
    synchronizer: &mut ServiceSynchronizer,
    previous: &LoadBalancerDataplaneState,
) -> Result<()> {
    let results = [
        restore_encoded_bank(
            &mut synchronizer.load_balancer_ipv4_frontends,
            &previous.ipv4_frontends,
            previous.bank,
            7,
        ),
        restore_encoded_bank(
            &mut synchronizer.load_balancer_ipv6_frontends,
            &previous.ipv6_frontends,
            previous.bank,
            19,
        ),
        restore_lpm_bank(
            &mut synchronizer.load_balancer_ipv4_source_ranges,
            &previous.ipv4_source_ranges,
            previous.bank,
        ),
        restore_lpm_bank(
            &mut synchronizer.load_balancer_ipv6_source_ranges,
            &previous.ipv6_source_ranges,
            previous.bank,
        ),
    ];
    let failures = results
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("restore LoadBalancer bank failed: {failures:?}")
    }
}

fn restore_lpm_bank<const K: usize>(
    map: &mut AyaLpmTrie<MapData, [u8; K], [u8; 32]>,
    previous: &BTreeMap<(u32, [u8; K]), [u8; 32]>,
    bank: u8,
) -> Result<()>
where
    [u8; K]: aya::Pod,
{
    let keys = map.keys().collect::<Result<Vec<_>, _>>()?;
    for key in keys.into_iter().filter(|key| key.data()[4] == bank) {
        map.remove(&key)?;
    }
    for ((prefix, data), value) in previous {
        map.insert(&LpmKey::new(*prefix, *data), value, 0)?;
    }
    Ok(())
}

fn clear_load_balancer_bank(
    synchronizer: &mut ServiceSynchronizer,
    previous: &LoadBalancerDataplaneState,
) -> Result<()> {
    restore_load_balancer_bank(synchronizer, &empty_load_balancer_bank(previous))
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

fn clear_node_port_bank(
    synchronizer: &mut ServiceSynchronizer,
    old: &NodePortDataplaneState,
) -> Result<()> {
    let empty = empty_node_port_bank(old.bank);
    let clear = restore_node_port_bank(synchronizer, &empty);
    if let Err(error) = clear {
        let restore = restore_node_port_bank(synchronizer, old);
        return match restore {
            Ok(()) => Err(error.context("old NodePort bank cleanup failed and was restored")),
            Err(restore) => Err(anyhow!(
                "old NodePort bank cleanup failed: {error:#}; restoration failed: {restore:#}"
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

fn service_snapshot_node_port_counts(snapshot: &ServiceSnapshot) -> (u64, u64, u64) {
    let mut cluster = 0_u64;
    let mut local = 0_u64;
    for node_port in snapshot
        .services
        .iter()
        .flat_map(|service| &service.node_ports)
    {
        match node_port.traffic_policy {
            ServiceTrafficPolicy::Cluster => cluster = cluster.saturating_add(1),
            ServiceTrafficPolicy::Local => local = local.saturating_add(1),
        }
    }
    (cluster.saturating_add(local), cluster, local)
}

fn publish_desired_service_snapshot(state: &AgentState, snapshot: &ServiceSnapshot) {
    let (node_ports, _, _) = service_snapshot_node_port_counts(snapshot);
    state
        .desired_service_epoch
        .store(snapshot.source_epoch, Ordering::Release);
    state
        .desired_service_revision
        .store(snapshot.revision.get(), Ordering::Release);
    state
        .desired_node_port_frontend_count
        .store(node_ports, Ordering::Release);
    state
        .metrics
        .desired_service_revision
        .set(metric_value(snapshot.revision.get()));
}

fn publish_applied_service_snapshot(state: &AgentState, snapshot: &ServiceSnapshot) {
    let (services, frontends, backends) = service_snapshot_counts(snapshot);
    let (node_ports, cluster_node_ports, local_node_ports) =
        service_snapshot_node_port_counts(snapshot);
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
        .applied_node_port_frontend_count
        .store(node_ports, Ordering::Release);
    state
        .node_port_cluster_frontend_count
        .store(cluster_node_ports, Ordering::Release);
    state
        .node_port_local_frontend_count
        .store(local_node_ports, Ordering::Release);
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
    state
        .metrics
        .node_port_frontend_count
        .set(metric_value(node_ports));
    state
        .metrics
        .node_port_cluster_frontend_count
        .set(metric_value(cluster_node_ports));
    state
        .metrics
        .node_port_local_frontend_count
        .set(metric_value(local_node_ports));
}

fn publish_desired_selection_contract(
    state: &AgentState,
    contract: Option<&NetworkBehaviorContract>,
) {
    state.desired_selection_contract_revision.store(
        contract.map_or(0, |contract| contract.contract_revision.get()),
        Ordering::Release,
    );
    *mutex_lock(&state.desired_selection_contract_digest) =
        contract.map(|contract| contract.contract_digest.to_string());
}

fn publish_applied_selection_contract(
    state: &AgentState,
    contract: Option<&NetworkBehaviorContract>,
    active_bank: u8,
) {
    state.applied_selection_contract_revision.store(
        contract.map_or(0, |contract| contract.contract_revision.get()),
        Ordering::Release,
    );
    *mutex_lock(&state.applied_selection_contract_digest) =
        contract.map(|contract| contract.contract_digest.to_string());
    state
        .active_selection_bank
        .store(u64::from(active_bank), Ordering::Release);
}

fn publish_recovered_selection_contract(
    state: &AgentState,
    contract: Option<&NetworkBehaviorContract>,
    active_bank: u8,
) {
    // A recovered contract is both the last durable desired state and the
    // exact contract verified against the active pinned Service bank. Publish
    // both sides of the convergence contract before the agent becomes Ready.
    publish_desired_selection_contract(state, contract);
    publish_applied_selection_contract(state, contract, active_bank);
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
        for path in &plan.program_pins {
            println!("  remove tail program pin: {}", path.display());
        }
        if let Some(path) = &plan.links_directory {
            println!("  remove empty link directory: {}", path.display());
        }
        if let Some(path) = &plan.programs_directory {
            println!("  remove empty program directory: {}", path.display());
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
        program_pins: Vec::new(),
        links_directory: None,
        programs_directory: None,
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
        4 => &ABI_V4_MAP_NAMES,
        5 => &ABI_V5_MAP_NAMES,
        6..=8 => &ABI_V8_MAP_NAMES,
        9..=11 => &ABI_V11_MAP_NAMES,
        12 => &ABI_V12_MAP_NAMES,
        13 => &ABI_V13_MAP_NAMES,
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
        } else if name_text == "programs" && file_type.is_dir() && !file_type.is_symlink() {
            plan.programs_directory = Some(entry.path());
            inspect_cleanup_program_directory(&entry.path(), &mut plan.program_pins, &mut unknown)?;
        } else {
            unknown.push(entry.path());
        }
    }
    plan.map_pins.sort();
    plan.link_pins.sort();
    plan.program_pins.sort();
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

fn inspect_cleanup_program_directory(
    directory: &Path,
    program_pins: &mut Vec<PathBuf>,
    unknown: &mut Vec<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("inspect tail program directory {}", directory.display()))?
    {
        let entry = entry.context("read tail program cleanup entry")?;
        let file_type = entry
            .file_type()
            .context("inspect tail program cleanup entry type")?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(recognized_tail_program_pin_name)
            && !file_type.is_dir()
            && !file_type.is_symlink()
        {
            program_pins.push(entry.path());
        } else {
            unknown.push(entry.path());
        }
    }
    Ok(())
}

fn recognized_tail_program_pin_name(name: &str) -> bool {
    name == DATAPLANE_TAIL_CALL_MAP_NAME
        || DATAPLANE_TAIL_PROGRAM_NAMES.iter().any(|program| {
            name == *program
                || name
                    .strip_prefix(&format!("{program}-"))
                    .and_then(|generation| generation.split_once('-'))
                    .is_some_and(|(pid, timestamp)| {
                        !pid.is_empty()
                            && pid.bytes().all(|byte| byte.is_ascii_digit())
                            && !timestamp.is_empty()
                            && timestamp.bytes().all(|byte| byte.is_ascii_digit())
                    })
        })
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
    for path in plan
        .link_pins
        .iter()
        .chain(&plan.program_pins)
        .chain(&plan.map_pins)
    {
        fs::remove_file(path)
            .with_context(|| format!("remove owned BPF pin {}", path.display()))?;
        println!("removed BPF pin: {}", path.display());
    }
    if let Some(directory) = &plan.links_directory {
        fs::remove_dir(directory)
            .with_context(|| format!("remove empty TCX link directory {}", directory.display()))?;
    }
    if let Some(directory) = &plan.programs_directory {
        fs::remove_dir(directory).with_context(|| {
            format!(
                "remove empty tail program directory {}",
                directory.display()
            )
        })?;
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
        node_port_frontend_count: Gauge::default(),
        node_port_cluster_frontend_count: Gauge::default(),
        node_port_local_frontend_count: Gauge::default(),
        load_balancer_revision_desired: Gauge::default(),
        load_balancer_revision_applied: Gauge::default(),
        load_balancer_allocation_revision_desired: Gauge::default(),
        load_balancer_allocation_revision_applied: Gauge::default(),
        load_balancer_frontend_count: Gauge::default(),
        load_balancer_cluster_frontend_count: Gauge::default(),
        load_balancer_local_frontend_count: Gauge::default(),
        load_balancer_source_range_count: Gauge::default(),
        load_balancer_health_check_count: Gauge::default(),
        load_balancer_health_check_ready_count: Gauge::default(),
        load_balancer_reconcile_errors: Counter::default(),
        service_dataplane_events: Counter::default(),
        service_translations: Counter::default(),
        service_drops: Counter::default(),
        service_expirations: Counter::default(),
        node_port_cluster_translations: Counter::default(),
        node_port_local_translations: Counter::default(),
        node_port_no_backend_drops: Counter::default(),
        load_balancer_cluster_translations: Counter::default(),
        load_balancer_local_translations: Counter::default(),
        load_balancer_no_backend_drops: Counter::default(),
        load_balancer_source_range_drops: Counter::default(),
        invalid_service_events: Counter::default(),
        egress_dataplane_events: Counter::default(),
        egress_nat_creations: Counter::default(),
        egress_nat_drops: Counter::default(),
        egress_nat_expirations: Counter::default(),
        invalid_egress_events: Counter::default(),
        egress_event_attempts: Counter::default(),
        egress_event_ring_drops: Counter::default(),
        service_same_node_selections: Counter::default(),
        service_same_zone_selections: Counter::default(),
        service_cluster_selections: Counter::default(),
        service_stable_hash_selections: Counter::default(),
        service_maglev_selections: Counter::default(),
        service_affinity_reuses: Counter::default(),
        service_affinity_creations: Counter::default(),
        service_affinity_reselections: Counter::default(),
        service_nat_forwards: Counter::default(),
        service_dsr_forwards: Counter::default(),
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
        desired_selection_contract_revision: AtomicU64::new(0),
        applied_selection_contract_revision: AtomicU64::new(0),
        desired_selection_contract_digest: Mutex::new(None),
        applied_selection_contract_digest: Mutex::new(None),
        active_selection_bank: AtomicU64::new(0),
        desired_node_port_frontend_count: AtomicU64::new(0),
        applied_node_port_frontend_count: AtomicU64::new(0),
        node_port_cluster_frontend_count: AtomicU64::new(0),
        node_port_local_frontend_count: AtomicU64::new(0),
        desired_load_balancer_epoch: AtomicU64::new(0),
        desired_load_balancer_revision: AtomicU64::new(0),
        desired_load_balancer_allocation_revision: AtomicU64::new(0),
        applied_load_balancer_epoch: AtomicU64::new(0),
        applied_load_balancer_revision: AtomicU64::new(0),
        applied_load_balancer_allocation_revision: AtomicU64::new(0),
        load_balancer_frontend_count: AtomicU64::new(0),
        load_balancer_cluster_frontend_count: AtomicU64::new(0),
        load_balancer_local_frontend_count: AtomicU64::new(0),
        load_balancer_source_range_count: AtomicU64::new(0),
        load_balancer_health_check_count: AtomicU64::new(0),
        load_balancer_health_check_ready_count: AtomicU64::new(0),
        active_load_balancer_bank: AtomicU64::new(0),
        load_balancer_reconcile_errors: AtomicU64::new(0),
        load_balancer_last_error: Mutex::new(None),
        service_reconcile_errors: AtomicU64::new(0),
        service_last_error: Mutex::new(None),
        service_dataplane_events: AtomicU64::new(0),
        service_translations: AtomicU64::new(0),
        service_drops: AtomicU64::new(0),
        service_expirations: AtomicU64::new(0),
        node_port_cluster_translations: AtomicU64::new(0),
        node_port_local_translations: AtomicU64::new(0),
        node_port_no_backend_drops: AtomicU64::new(0),
        load_balancer_cluster_translations: AtomicU64::new(0),
        load_balancer_local_translations: AtomicU64::new(0),
        load_balancer_no_backend_drops: AtomicU64::new(0),
        load_balancer_source_range_drops: AtomicU64::new(0),
        invalid_service_events: AtomicU64::new(0),
        last_service_id: AtomicU64::new(0),
        last_backend_id: AtomicU64::new(0),
        last_service_revision: AtomicU64::new(0),
        last_service_action: AtomicU64::new(0),
        last_service_reason: AtomicU64::new(0),
        service_same_node_selections: AtomicU64::new(0),
        service_same_zone_selections: AtomicU64::new(0),
        service_cluster_selections: AtomicU64::new(0),
        service_stable_hash_selections: AtomicU64::new(0),
        service_maglev_selections: AtomicU64::new(0),
        service_affinity_reuses: AtomicU64::new(0),
        service_affinity_creations: AtomicU64::new(0),
        service_affinity_reselections: AtomicU64::new(0),
        service_nat_forwards: AtomicU64::new(0),
        service_dsr_forwards: AtomicU64::new(0),
        last_service_selection_tier: AtomicU64::new(0),
        last_service_affinity_outcome: AtomicU64::new(0),
        last_service_selection_algorithm: AtomicU64::new(0),
        last_service_forwarding_mode: AtomicU64::new(0),
        desired_node_block_revision: AtomicU64::new(0),
        applied_node_block_revision: AtomicU64::new(0),
        desired_remote_route_epoch: AtomicU64::new(0),
        applied_remote_route_epoch: AtomicU64::new(0),
        desired_remote_route_revision: AtomicU64::new(0),
        applied_remote_route_revision: AtomicU64::new(0),
        remote_route_entries: AtomicU64::new(0),
        remote_route_reconcile_errors: AtomicU64::new(0),
        applied_remote_routes: Mutex::new(None),
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

#[allow(clippy::too_many_lines)]
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
        "unf_nodeport_frontend_count",
        "NodePort frontends in the active durable service snapshot",
        metrics.node_port_frontend_count.clone(),
    );
    registry.register(
        "unf_nodeport_cluster_frontend_count",
        "Cluster-traffic-policy NodePort frontends in the active durable service snapshot",
        metrics.node_port_cluster_frontend_count.clone(),
    );
    registry.register(
        "unf_nodeport_local_frontend_count",
        "Local-traffic-policy NodePort frontends in the active durable service snapshot",
        metrics.node_port_local_frontend_count.clone(),
    );
    registry.register(
        "unf_loadbalancer_revision_desired",
        "Latest valid LoadBalancer reachability revision observed from the controller",
        metrics.load_balancer_revision_desired.clone(),
    );
    registry.register(
        "unf_loadbalancer_revision_applied",
        "LoadBalancer reachability revision atomically activated in the VIP map set",
        metrics.load_balancer_revision_applied.clone(),
    );
    registry.register(
        "unf_loadbalancer_allocation_revision_desired",
        "Latest LoadBalancer allocation revision referenced by desired reachability",
        metrics.load_balancer_allocation_revision_desired.clone(),
    );
    registry.register(
        "unf_loadbalancer_allocation_revision_applied",
        "LoadBalancer allocation revision referenced by the active VIP map set",
        metrics.load_balancer_allocation_revision_applied.clone(),
    );
    registry.register(
        "unf_loadbalancer_frontend_count",
        "LoadBalancer VIP frontends in the active transactional bank",
        metrics.load_balancer_frontend_count.clone(),
    );
    registry.register(
        "unf_loadbalancer_cluster_frontend_count",
        "Cluster-traffic-policy LoadBalancer VIP frontends in the active bank",
        metrics.load_balancer_cluster_frontend_count.clone(),
    );
    registry.register(
        "unf_loadbalancer_local_frontend_count",
        "Local-traffic-policy LoadBalancer VIP frontends in the active bank",
        metrics.load_balancer_local_frontend_count.clone(),
    );
    registry.register(
        "unf_loadbalancer_source_range_count",
        "IPv4 and IPv6 LoadBalancer source prefixes in the active bank",
        metrics.load_balancer_source_range_count.clone(),
    );
    registry.register(
        "unf_loadbalancer_health_check_count",
        "Owned LoadBalancer health-check listeners",
        metrics.load_balancer_health_check_count.clone(),
    );
    registry.register(
        "unf_loadbalancer_health_check_ready_count",
        "Owned LoadBalancer health checks reporting local endpoints",
        metrics.load_balancer_health_check_ready_count.clone(),
    );
    registry.register(
        "unf_loadbalancer_reconcile_errors",
        "LoadBalancer reachability or host-state reconciliation failures",
        metrics.load_balancer_reconcile_errors.clone(),
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
        "unf_nodeport_cluster_translations",
        "Successful forward and reverse Cluster-policy NodePort translations",
        metrics.node_port_cluster_translations.clone(),
    );
    registry.register(
        "unf_nodeport_local_translations",
        "Successful forward and reverse Local-policy NodePort translations",
        metrics.node_port_local_translations.clone(),
    );
    registry.register(
        "unf_nodeport_no_backend_drops",
        "NodePort packets dropped because the selected traffic policy had no eligible backend",
        metrics.node_port_no_backend_drops.clone(),
    );
    registry.register(
        "unf_loadbalancer_cluster_translations",
        "Successful forward and reverse Cluster-policy LoadBalancer translations",
        metrics.load_balancer_cluster_translations.clone(),
    );
    registry.register(
        "unf_loadbalancer_local_translations",
        "Successful forward and reverse Local-policy LoadBalancer translations",
        metrics.load_balancer_local_translations.clone(),
    );
    registry.register(
        "unf_loadbalancer_no_backend_drops",
        "LoadBalancer packets dropped because the selected policy had no eligible backend",
        metrics.load_balancer_no_backend_drops.clone(),
    );
    registry.register(
        "unf_loadbalancer_source_range_drops",
        "LoadBalancer packets denied by source-range policy",
        metrics.load_balancer_source_range_drops.clone(),
    );
    registry.register(
        "unf_service_invalid_events",
        "Service event records rejected due to ABI or semantic mismatch",
        metrics.invalid_service_events.clone(),
    );
    for (name, help, counter) in [
        (
            "unf_egress_dataplane_events",
            "Validated sparse egress NAT lifecycle witnesses consumed from eBPF",
            &metrics.egress_dataplane_events,
        ),
        (
            "unf_egress_nat_creations",
            "New proof-bound egress NAT flow pairs created",
            &metrics.egress_nat_creations,
        ),
        (
            "unf_egress_nat_drops",
            "Egress NAT lifecycle operations dropped with a machine-readable reason",
            &metrics.egress_nat_drops,
        ),
        (
            "unf_egress_nat_expirations",
            "Expired or corrupt egress NAT pairs retired",
            &metrics.egress_nat_expirations,
        ),
        (
            "unf_egress_invalid_events",
            "Egress event records rejected due to ABI or semantic mismatch",
            &metrics.invalid_egress_events,
        ),
        (
            "unf_egress_event_attempts",
            "Sparse egress NAT lifecycle witnesses attempted by eBPF",
            &metrics.egress_event_attempts,
        ),
        (
            "unf_egress_event_ring_drops",
            "Egress NAT lifecycle witnesses dropped because telemetry capacity was unavailable",
            &metrics.egress_event_ring_drops,
        ),
    ] {
        registry.register(name, help, counter.clone());
    }
    for (name, help, counter) in [
        (
            "unf_service_selection_same_node",
            "Translated service packets selecting the same-Node tier",
            &metrics.service_same_node_selections,
        ),
        (
            "unf_service_selection_same_zone",
            "Translated service packets selecting the same-zone tier",
            &metrics.service_same_zone_selections,
        ),
        (
            "unf_service_selection_cluster",
            "Translated service packets selecting the cluster tier",
            &metrics.service_cluster_selections,
        ),
        (
            "unf_service_selection_stable_hash",
            "Translated service packets using stable-hash selection",
            &metrics.service_stable_hash_selections,
        ),
        (
            "unf_service_selection_maglev",
            "Translated service packets using measured Maglev selection",
            &metrics.service_maglev_selections,
        ),
        (
            "unf_service_affinity_reused",
            "Translated service packets reusing ClientIP affinity",
            &metrics.service_affinity_reuses,
        ),
        (
            "unf_service_affinity_created",
            "Translated service packets creating ClientIP affinity",
            &metrics.service_affinity_creations,
        ),
        (
            "unf_service_affinity_reselected",
            "Translated service packets replacing ineligible or expired affinity",
            &metrics.service_affinity_reselections,
        ),
        (
            "unf_service_forwarding_nat",
            "Translated service packets using NAT forwarding",
            &metrics.service_nat_forwards,
        ),
        (
            "unf_service_forwarding_dsr",
            "Translated service packets using acknowledged DSR forwarding",
            &metrics.service_dsr_forwards,
        ),
    ] {
        registry.register(name, help, counter.clone());
    }
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
    let egress_ring = RingBuf::try_from(
        ebpf.take_map("EGRESS_EVENTS")
            .context("eBPF object does not contain EGRESS_EVENTS ring buffer")?,
    )
    .context("open EGRESS_EVENTS ring buffer")?;
    let egress_event_counters = AyaPerCpuArray::<_, u64>::try_from(
        ebpf.take_map("EGRESS_EVENT_COUNTERS")
            .context("eBPF object does not contain EGRESS_EVENT_COUNTERS map")?,
    )
    .context("open EGRESS_EVENT_COUNTERS map")?;
    let identity_maps = take_identity_maps(&mut ebpf)?;
    let policy_maps = take_policy_maps(&mut ebpf)?;
    let service_maps = take_service_maps(&mut ebpf)?;
    let egress_maps = take_egress_maps(&mut ebpf)?;
    let controller_management_port = controller_url.as_deref().map(controller_port).transpose()?;
    let (mut identities, mut policies, mut services, mut egress) = new_synchronizers(
        identity_maps,
        policy_maps,
        service_maps,
        egress_maps,
        controller_url.clone(),
        controller_management_port,
        controller_client.clone(),
        config.agent_token_path.clone(),
        config.identity_sync_interval,
        config.service_sync_interval,
        config.service_state_path.clone(),
        config.load_balancer_reachability_state_path.clone(),
        config.node_name.clone(),
        config.egress_path_provider.clone(),
    );
    let recovered = recover_persistent_dataplane(
        &mut identities,
        &mut policies,
        &mut services,
        &mut egress,
        pins_existed,
    )?;
    apply_recovered_state(&state, &identities, &policies, &services, &recovered);
    let recovered_ready = recovered_dataplane_is_ready(&recovered);
    if !recovered_ready {
        populate_dataplane_before_attachment(&mut identities, &mut policies, &mut services, &state)
            .await?;
    } else if services.applied.is_none() {
        restore_or_populate_service_state(&mut services, &state).await?;
    }
    if let Some(snapshot) = services.applied.as_ref() {
        let health = load_balancer_health_check_plan(snapshot, &services.node_name)?;
        services.health_checks.reconcile(&health)?;
        publish_load_balancer_health(&state, &health);
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
        egress_ring,
        egress_event_counters,
        &mut attachments,
        &mut identities,
        &mut policies,
        &mut services,
        &mut egress,
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
    load_dataplane_tail_programs(ebpf)?;
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

fn load_dataplane_tail_programs(ebpf: &mut Ebpf) -> Result<()> {
    let mut program_fds = Vec::with_capacity(DATAPLANE_TAIL_PROGRAM_NAMES.len());
    for program_name in DATAPLANE_TAIL_PROGRAM_NAMES {
        let program: &mut SchedClassifier = ebpf
            .program_mut(program_name)
            .with_context(|| format!("eBPF object does not contain program {program_name}"))?
            .try_into()
            .context("UNF dataplane tail program is not a TC classifier")?;
        program
            .load()
            .with_context(|| format!("load {program_name} TC classifier into kernel"))?;
        program_fds.push(
            program
                .fd()
                .with_context(|| format!("obtain {program_name} program descriptor"))?
                .try_clone()
                .with_context(|| format!("clone {program_name} program descriptor"))?,
        );
    }
    let mut tail_calls =
        AyaProgramArray::try_from(ebpf.map_mut(DATAPLANE_TAIL_CALL_MAP_NAME).with_context(
            || format!("eBPF object does not contain {DATAPLANE_TAIL_CALL_MAP_NAME}"),
        )?)
        .with_context(|| format!("open {DATAPLANE_TAIL_CALL_MAP_NAME} program array"))?;
    for (index, program_fd) in program_fds.iter().enumerate() {
        let index = u32::try_from(index).context("dataplane tail program index exceeds u32")?;
        tail_calls
            .set(index, program_fd, 0)
            .with_context(|| format!("install dataplane tail program at index {index}"))?;
    }
    Ok(())
}

fn validate_tail_program_pin_directory(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut pins = Vec::new();
    let mut unknown = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("inspect tail program pin directory {}", directory.display()))?
    {
        let entry = entry.context("read tail program pin entry")?;
        let file_type = entry
            .file_type()
            .context("inspect tail program pin entry type")?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(recognized_tail_program_pin_name)
            && !file_type.is_dir()
            && !file_type.is_symlink()
        {
            pins.push(entry.path());
        } else {
            unknown.push(entry.path());
        }
    }
    if !unknown.is_empty() {
        unknown.sort();
        let paths = unknown
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("refusing unrecognized tail program pin content: {paths}");
    }
    pins.sort();
    Ok(pins)
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn new_synchronizers(
    identity_maps: IdentityMaps,
    policy_maps: PolicyMaps,
    service_maps: ServiceMaps,
    egress_maps: EgressMaps,
    controller_url: Option<String>,
    controller_management_port: Option<u16>,
    client: ReloadingControllerClient,
    agent_token_path: PathBuf,
    interval: Duration,
    service_interval: Duration,
    service_state_path: PathBuf,
    load_balancer_state_path: PathBuf,
    node_name: String,
    egress_path_provider: Option<NativeEgressPathProvider>,
) -> (
    IdentitySynchronizer,
    PolicySynchronizer,
    ServiceSynchronizer,
    EgressSynchronizer,
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
        affinity,
        node_port_ipv4_frontends,
        node_port_ipv6_frontends,
        node_port_config,
        load_balancer_ipv4_frontends,
        load_balancer_ipv6_frontends,
        load_balancer_ipv4_source_ranges,
        load_balancer_ipv6_source_ranges,
        load_balancer_config,
        load_balancer_node_source,
    ) = service_maps;
    let (
        egress_sources,
        egress_ipv4_destinations,
        egress_ipv6_destinations,
        egress_addresses,
        egress_gateways,
        egress_selections,
        egress_config,
        gateway_nat_sources,
        gateway_nat_ipv4_destinations,
        gateway_nat_ipv6_destinations,
        gateway_nat_addresses,
        gateway_nat_gateways,
        gateway_nat_selections,
        gateway_nat_config,
        egress_connections,
    ) = egress_maps;
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
            affinity,
            node_port_ipv4_frontends,
            node_port_ipv6_frontends,
            node_port_config,
            load_balancer_ipv4_frontends,
            load_balancer_ipv6_frontends,
            load_balancer_ipv4_source_ranges,
            load_balancer_ipv6_source_ranges,
            load_balancer_config,
            load_balancer_node_source,
            health_checks: HealthCheckManager::default(),
            banks: [None, None],
            node_port_banks: [None, None],
            load_balancer_banks: [None, None],
            selection_banks: [None, None],
            active_bank: 0,
            active_node_port_bank: 0,
            active_load_balancer_bank: 0,
            applied: None,
            applied_node_port_node: None,
            applied_load_balancer_reachability: None,
            applied_selection_contract: None,
            active_selection_bank: 0,
            node_name: node_name.clone(),
            controller_url: controller_url.clone(),
            client: client.clone(),
            agent_token_path: agent_token_path.clone(),
            state_path: service_state_path,
            load_balancer_state_path,
            interval: service_interval,
        },
        EgressSynchronizer {
            sources: egress_sources,
            ipv4_destinations: egress_ipv4_destinations,
            ipv6_destinations: egress_ipv6_destinations,
            addresses: egress_addresses,
            gateways: egress_gateways,
            selections: egress_selections,
            config: egress_config,
            gateway_nat_sources,
            gateway_nat_ipv4_destinations,
            gateway_nat_ipv6_destinations,
            gateway_nat_addresses,
            gateway_nat_gateways,
            gateway_nat_selections,
            gateway_nat_config,
            connections: egress_connections,
            banks: [EncodedEgressBank::default(), EncodedEgressBank::default()],
            gateway_nat_banks: [EncodedEgressBank::default(), EncodedEgressBank::default()],
            active_bank: 0,
            gateway_nat_active_bank: 0,
            ledger: EgressProjectionLedger::default(),
            gateway_ledger: EgressGatewayProjectionLedger::default(),
            applied_authority: None,
            path_provider: egress_path_provider,
            node_name,
            controller_url,
            client,
            agent_token_path,
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
        format!(
            "{controller_url}/v1/version?serviceSnapshotSchemaVersion={SERVICE_SNAPSHOT_SCHEMA_VERSION}"
        ),
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
        selection_contract_schema_version = compatibility.selection_contract_schema_version,
        "controller compatibility preflight passed before persistent BPF state access"
    );
    Ok(())
}

fn ensure_controller_compatibility(controller: &ComponentCompatibility) -> Result<()> {
    let local = component_compatibility();
    let mut mismatches = [
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
    ]
    .into_iter()
    .filter(|(_, remote, expected)| remote != expected)
    .map(|(name, remote, expected)| format!("{name} controller={remote} agent={expected}"))
    .collect::<Vec<_>>();
    if !matches!(
        controller.flow_export_schema_version,
        PRE_OPERATIONS_FLOW_EXPORT_SCHEMA_VERSION | FLOW_EXPORT_SCHEMA_VERSION
    ) {
        mismatches.push(format!(
            "flow-export schema controller={} agent={}",
            controller.flow_export_schema_version, local.flow_export_schema_version
        ));
    }
    if controller.service_snapshot_schema_version != local.service_snapshot_schema_version
        && controller.service_snapshot_schema_version != LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION
        && controller.service_snapshot_schema_version != NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION
        && controller.service_snapshot_schema_version
            != LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION
    {
        mismatches.push(format!(
            "service snapshot schema controller={} agent={}",
            controller.service_snapshot_schema_version, local.service_snapshot_schema_version
        ));
    }
    if !matches!(
        controller.agent_status_schema_version,
        PRE_SELECTION_AGENT_STATUS_SCHEMA_VERSION
            | PRE_OPERATIONS_AGENT_STATUS_SCHEMA_VERSION
            | AGENT_STATUS_SCHEMA_VERSION
    ) {
        mismatches.push(format!(
            "agent-status schema controller={} agent={}",
            controller.agent_status_schema_version, local.agent_status_schema_version
        ));
    }
    if controller.selection_contract_schema_version > local.selection_contract_schema_version {
        mismatches.push(format!(
            "selection contract schema controller={} agent={}",
            controller.selection_contract_schema_version, local.selection_contract_schema_version
        ));
    }
    if controller.load_balancer_reachability_schema_version
        > local.load_balancer_reachability_schema_version
    {
        mismatches.push(format!(
            "LoadBalancer reachability schema controller={} agent={}",
            controller.load_balancer_reachability_schema_version,
            local.load_balancer_reachability_schema_version
        ));
    }
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

    // A root program reference keeps the program-array map object alive, but Linux clears its
    // entries after the final userspace map descriptor closes unless the map itself is pinned.
    // Keep this runtime dispatch state outside the durable 40-map ABI set: it is repopulated on
    // every start, while the pin preserves last-known-good tail targets between agent processes.
    let tail_program_pin_root = config.bpf_pin_path.join("programs");
    fs::create_dir_all(&tail_program_pin_root).with_context(|| {
        format!(
            "create dataplane tail runtime pin directory {}",
            tail_program_pin_root.display()
        )
    })?;
    validate_tail_program_pin_directory(&tail_program_pin_root)?;

    let mut loader = EbpfLoader::new();
    loader.override_global(
        "SERVICE_DSR_TRANSPORT_INTERFACES",
        &config.service_dsr_transport_interfaces,
        true,
    );
    for name in PERSISTENT_MAP_NAMES {
        loader.map_pin_path(name, config.bpf_pin_path.join(name));
    }
    loader.map_pin_path(
        DATAPLANE_TAIL_CALL_MAP_NAME,
        tail_program_pin_root.join(DATAPLANE_TAIL_CALL_MAP_NAME),
    );
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
    egress: &mut EgressSynchronizer,
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
    validate_map_capacity(
        "SERVICE_AFFINITY",
        services.affinity.map(),
        SERVICE_CONNECTION_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "NODE_PORT_FRONTENDS_V4",
        services.node_port_ipv4_frontends.map(),
        SERVICE_FRONTEND_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "NODE_PORT_FRONTENDS_V6",
        services.node_port_ipv6_frontends.map(),
        SERVICE_FRONTEND_MAP_CAPACITY,
    )?;
    validate_map_capacity("NODE_PORT_CONFIG", services.node_port_config.map(), 1)?;
    validate_map_capacity(
        "LOAD_BALANCER_FRONTENDS_V4",
        services.load_balancer_ipv4_frontends.map(),
        u32::try_from(LOAD_BALANCER_FRONTEND_BANK_CAPACITY)
            .expect("LoadBalancer map capacity fits u32"),
    )?;
    validate_map_capacity(
        "LOAD_BALANCER_FRONTENDS_V6",
        services.load_balancer_ipv6_frontends.map(),
        u32::try_from(LOAD_BALANCER_FRONTEND_BANK_CAPACITY)
            .expect("LoadBalancer map capacity fits u32"),
    )?;
    validate_map_capacity(
        "LOAD_BALANCER_SOURCE_RANGES_V4",
        services.load_balancer_ipv4_source_ranges.map(),
        u32::try_from(LOAD_BALANCER_FRONTEND_BANK_CAPACITY)
            .expect("LoadBalancer map capacity fits u32"),
    )?;
    validate_map_capacity(
        "LOAD_BALANCER_SOURCE_RANGES_V6",
        services.load_balancer_ipv6_source_ranges.map(),
        u32::try_from(LOAD_BALANCER_FRONTEND_BANK_CAPACITY)
            .expect("LoadBalancer map capacity fits u32"),
    )?;
    validate_map_capacity(
        "LOAD_BALANCER_CONFIG",
        services.load_balancer_config.map(),
        1,
    )?;
    validate_map_capacity(
        "LOAD_BALANCER_NODE_SOURCE",
        services.load_balancer_node_source.map(),
        1,
    )?;
    validate_map_capacity(
        "EGRESS_SOURCES",
        egress.sources.map(),
        EGRESS_SOURCE_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_DESTINATIONS_V4",
        egress.ipv4_destinations.map(),
        EGRESS_DESTINATION_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_DESTINATIONS_V6",
        egress.ipv6_destinations.map(),
        EGRESS_DESTINATION_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_ADDRESSES",
        egress.addresses.map(),
        EGRESS_ADDRESS_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_GATEWAYS",
        egress.gateways.map(),
        EGRESS_GATEWAY_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_SELECTIONS",
        egress.selections.map(),
        EGRESS_SELECTION_MAP_CAPACITY,
    )?;
    validate_map_capacity("EGRESS_CONFIG", egress.config.map(), 1)?;
    validate_map_capacity(
        "EGRESS_GATEWAY_NAT_SOURCES",
        egress.gateway_nat_sources.map(),
        EGRESS_SOURCE_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_GATEWAY_NAT_DESTINATIONS_V4",
        egress.gateway_nat_ipv4_destinations.map(),
        EGRESS_DESTINATION_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_GATEWAY_NAT_DESTINATIONS_V6",
        egress.gateway_nat_ipv6_destinations.map(),
        EGRESS_DESTINATION_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_GATEWAY_NAT_ADDRESSES",
        egress.gateway_nat_addresses.map(),
        EGRESS_ADDRESS_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_GATEWAY_NAT_GATEWAYS",
        egress.gateway_nat_gateways.map(),
        EGRESS_GATEWAY_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_GATEWAY_NAT_SELECTIONS",
        egress.gateway_nat_selections.map(),
        EGRESS_SELECTION_MAP_CAPACITY,
    )?;
    validate_map_capacity(
        "EGRESS_GATEWAY_NAT_CONFIG",
        egress.gateway_nat_config.map(),
        1,
    )?;
    validate_map_capacity(
        "EGRESS_CONNECTIONS",
        egress.connections.map(),
        EGRESS_CONNECTION_MAP_CAPACITY,
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
    recover_selection_contract_state(services)?;
    recover_load_balancer_state(services)?;
    recover_egress_state(egress)?;

    if pins_existed {
        info!(
            identity_entries = identity_entry_count(identities),
            identity_epoch,
            identity_revision,
            policy_epoch,
            policy_revision,
            service_epoch,
            service_revision,
            egress_active_bank = egress.active_bank,
            egress_sources = egress.banks[usize::from(egress.active_bank)].sources.len(),
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

#[allow(clippy::too_many_lines)]
fn recover_egress_state(egress: &mut EgressSynchronizer) -> Result<()> {
    recover_egress_gateway_nat_state(egress)?;
    for entry in &egress.sources {
        let (key, value) = entry.context("iterate persistent egress sources")?;
        let bank = egress_bank(key[4])?;
        validate_recovered_egress_source(key, &value)?;
        egress.banks[bank].sources.insert(key, value);
    }
    for entry in &egress.ipv4_destinations {
        let (key, value) = entry.context("iterate persistent IPv4 egress destinations")?;
        let data = key.data();
        let bank = egress_bank(data[4])?;
        validate_recovered_egress_destination(key.prefix_len(), &data, &value, 32)?;
        egress.banks[bank]
            .ipv4_destinations
            .insert((key.prefix_len(), data), value);
    }
    for entry in &egress.ipv6_destinations {
        let (key, value) = entry.context("iterate persistent IPv6 egress destinations")?;
        let data = key.data();
        let bank = egress_bank(data[4])?;
        validate_recovered_egress_destination(key.prefix_len(), &data, &value, 128)?;
        egress.banks[bank]
            .ipv6_destinations
            .insert((key.prefix_len(), data), value);
    }
    for entry in &egress.addresses {
        let (key, value) = entry.context("iterate persistent egress addresses")?;
        let bank = egress_bank(key[7])?;
        validate_recovered_egress_candidate_key(key)?;
        validate_recovered_egress_address(&value)?;
        egress.banks[bank].addresses.insert(key, value);
    }
    for entry in &egress.gateways {
        let (key, value) = entry.context("iterate persistent egress gateways")?;
        let bank = egress_bank(key[7])?;
        validate_recovered_egress_candidate_key(key)?;
        validate_recovered_egress_gateway(&value)?;
        egress.banks[bank].gateways.insert(key, value);
    }
    for entry in &egress.selections {
        let (key, value) = entry.context("iterate persistent egress selections")?;
        let bank = egress_bank(key[7])?;
        validate_recovered_egress_selection(key, &value)?;
        egress.banks[bank].selections.insert(key, value);
    }
    for entry in &egress.connections {
        let (key, value) = entry.context("iterate persistent egress connections")?;
        validate_recovered_egress_connection(&key, &value)?;
    }

    let config = egress
        .config
        .get(&0, 0)
        .context("read persistent egress config")?;
    if config == [0; 56] {
        clear_all_egress_banks(egress)?;
        egress.applied_authority = None;
        return Ok(());
    }
    let schema = u16::from_ne_bytes(config[48..50].try_into().expect("fixed egress schema"));
    let active_bank = config[50];
    if schema != EGRESS_MAP_ABI_VERSION || active_bank >= EGRESS_BANK_COUNT || config[51] != 0 {
        bail!("persistent egress config is incompatible");
    }
    let active = &egress.banks[usize::from(active_bank)];
    let expected = [
        active.sources.len(),
        active.addresses.len(),
        active.gateways.len(),
        active.selections.len(),
    ];
    for (offset, actual) in [32_usize, 36, 40, 44].into_iter().zip(expected) {
        let declared = u32::from_ne_bytes(
            config[offset..offset + 4]
                .try_into()
                .expect("fixed egress count"),
        );
        if u64::from(declared) != actual as u64 {
            bail!("persistent egress config count does not match its active bank");
        }
    }
    let destination_count = active.ipv4_destinations.len() + active.ipv6_destinations.len();
    if u64::from(u32::from_ne_bytes(
        config[52..56]
            .try_into()
            .expect("fixed egress destination count"),
    )) != destination_count as u64
    {
        bail!("persistent egress destination count does not match its active bank");
    }
    validate_egress_destination_bindings(active, config)?;
    if u64::from_ne_bytes(config[0..8].try_into().expect("fixed controller epoch")) == 0
        || u64::from_ne_bytes(config[8..16].try_into().expect("fixed projection revision")) == 0
        || u64::from_ne_bytes(config[16..24].try_into().expect("fixed contract revision")) == 0
        || (u64::from_ne_bytes(config[24..32].try_into().expect("fixed path revision")) == 0
            && (expected[1] != 0 || expected[2] != 0 || expected[3] != 0))
    {
        bail!("persistent egress config contains a zero authority revision");
    }

    let applied_authority = recovered_egress_authority(active, config)?;
    egress.banks[usize::from(active_bank)].config = config;
    egress.active_bank = active_bank;
    egress.applied_authority = Some(applied_authority);
    let inactive_bank = active_bank ^ 1;
    clear_egress_bank(egress, inactive_bank)?;
    if fence_active_egress_dataplane(egress)? {
        info!(
            active_bank = egress.active_bank,
            "recovered egress activation was fenced pending fresh controller and path proof"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn recover_egress_gateway_nat_state(egress: &mut EgressSynchronizer) -> Result<()> {
    for entry in &egress.gateway_nat_sources {
        let (key, value) = entry.context("iterate persistent gateway NAT sources")?;
        let bank = egress_bank(key[4])?;
        validate_recovered_egress_gateway_nat_source(key, &value)?;
        egress.gateway_nat_banks[bank].sources.insert(key, value);
    }
    for entry in &egress.gateway_nat_ipv4_destinations {
        let (key, value) = entry.context("iterate persistent gateway NAT IPv4 destinations")?;
        let data = key.data();
        let bank = egress_bank(data[4])?;
        validate_recovered_egress_destination(key.prefix_len(), &data, &value, 32)?;
        egress.gateway_nat_banks[bank]
            .ipv4_destinations
            .insert((key.prefix_len(), data), value);
    }
    for entry in &egress.gateway_nat_ipv6_destinations {
        let (key, value) = entry.context("iterate persistent gateway NAT IPv6 destinations")?;
        let data = key.data();
        let bank = egress_bank(data[4])?;
        validate_recovered_egress_destination(key.prefix_len(), &data, &value, 128)?;
        egress.gateway_nat_banks[bank]
            .ipv6_destinations
            .insert((key.prefix_len(), data), value);
    }
    for entry in &egress.gateway_nat_addresses {
        let (key, value) = entry.context("iterate persistent gateway NAT addresses")?;
        let bank = egress_bank(key[7])?;
        validate_recovered_egress_candidate_key(key)?;
        validate_recovered_egress_address(&value)?;
        egress.gateway_nat_banks[bank].addresses.insert(key, value);
    }
    for entry in &egress.gateway_nat_gateways {
        let (key, value) = entry.context("iterate persistent gateway NAT gateways")?;
        let bank = egress_bank(key[7])?;
        validate_recovered_egress_candidate_key(key)?;
        validate_recovered_egress_gateway_nat_gateway(&value)?;
        egress.gateway_nat_banks[bank].gateways.insert(key, value);
    }
    for entry in &egress.gateway_nat_selections {
        let (key, value) = entry.context("iterate persistent gateway NAT selections")?;
        let bank = egress_bank(key[7])?;
        validate_recovered_egress_selection(key, &value)?;
        egress.gateway_nat_banks[bank].selections.insert(key, value);
    }
    let config = egress
        .gateway_nat_config
        .get(&0, 0)
        .context("read persistent gateway NAT config")?;
    if config == [0; 56] {
        clear_egress_gateway_nat_bank(egress, 0)?;
        clear_egress_gateway_nat_bank(egress, 1)?;
        egress.gateway_nat_active_bank = 0;
        return Ok(());
    }
    let schema = u16::from_ne_bytes(config[48..50].try_into().expect("fixed gateway schema"));
    let active_bank = config[50];
    if schema != EGRESS_MAP_ABI_VERSION
        || active_bank >= EGRESS_BANK_COUNT
        || config[51] != unf_ebpf_common::EGRESS_CONFIG_FLAG_GATEWAY_NAT
        || config[16..32] != [0; 16]
        || u64::from_ne_bytes(config[0..8].try_into().expect("fixed gateway epoch")) == 0
        || u64::from_ne_bytes(config[8..16].try_into().expect("fixed gateway revision")) == 0
    {
        bail!("persistent gateway NAT config is incompatible");
    }
    let active = &egress.gateway_nat_banks[usize::from(active_bank)];
    let expected = [
        active.sources.len(),
        active.addresses.len(),
        active.gateways.len(),
        active.selections.len(),
    ];
    for (offset, actual) in [32_usize, 36, 40, 44].into_iter().zip(expected) {
        if u64::from(u32::from_ne_bytes(
            config[offset..offset + 4]
                .try_into()
                .expect("fixed gateway count"),
        )) != actual as u64
        {
            bail!("persistent gateway NAT config count does not match its bank");
        }
    }
    let destinations = active.ipv4_destinations.len() + active.ipv6_destinations.len();
    if u64::from(u32::from_ne_bytes(
        config[52..56]
            .try_into()
            .expect("fixed gateway destination count"),
    )) != destinations as u64
    {
        bail!("persistent gateway NAT destination count does not match its bank");
    }
    validate_egress_gateway_nat_bindings(active, config)?;
    egress.gateway_nat_banks[usize::from(active_bank)].config = config;
    egress.gateway_nat_active_bank = active_bank;
    clear_egress_gateway_nat_bank(egress, active_bank ^ 1)?;
    Ok(())
}

fn validate_egress_destination_bindings(
    active: &EncodedEgressBank,
    config: [u8; 56],
) -> Result<()> {
    let contract_revision = &config[16..24];
    if !active.sources.is_empty()
        && active.ipv4_destinations.is_empty()
        && active.ipv6_destinations.is_empty()
    {
        bail!("persistent egress sources have no destination ownership state");
    }
    if active
        .sources
        .values()
        .any(|source| source[8..16] != *contract_revision)
    {
        bail!("persistent egress source revision does not match config");
    }
    for ((_, data), value) in &active.ipv4_destinations {
        validate_egress_destination_binding(active, &data[0..4], value, contract_revision)?;
    }
    for ((_, data), value) in &active.ipv6_destinations {
        validate_egress_destination_binding(active, &data[0..4], value, contract_revision)?;
    }
    Ok(())
}

fn validate_egress_destination_binding(
    active: &EncodedEgressBank,
    intent_index: &[u8],
    value: &[u8; 32],
    contract_revision: &[u8],
) -> Result<()> {
    if value[0..8] != *contract_revision
        || !active
            .sources
            .values()
            .any(|source| source[112..116] == *intent_index && source[96..112] == value[8..24])
    {
        bail!("persistent egress destination is not bound to an active-bank source intent");
    }
    Ok(())
}

fn validate_recovered_egress_destination<const K: usize>(
    prefix_len: u32,
    data: &[u8; K],
    value: &[u8; 32],
    family_bits: u32,
) -> Result<()> {
    let base = unf_ebpf_common::EGRESS_DESTINATION_PREFIX_BASE_BITS;
    if prefix_len < base
        || prefix_len > base + family_bits
        || data[5..8] != [0; 3]
        || u64::from_ne_bytes(value[0..8].try_into().expect("fixed destination revision")) == 0
        || value[8..24] == [0; 16]
        || u16::from_ne_bytes(value[24..26].try_into().expect("fixed destination schema"))
            != EGRESS_MAP_ABI_VERSION
        || value[26..28] != [0; 2]
        || value[28..32] != [0; 4]
    {
        bail!("persistent egress destination entry is incompatible");
    }
    Ok(())
}

fn recovered_egress_authority(
    active: &EncodedEgressBank,
    config: [u8; 56],
) -> Result<EgressAppliedAuthority> {
    let contract_digest = active
        .sources
        .values()
        .next()
        .map(|source| source[64..96].try_into().expect("fixed contract digest"));
    if contract_digest.is_some_and(|digest| {
        active
            .sources
            .values()
            .any(|source| source[64..96] != digest)
    }) {
        bail!("persistent egress sources disagree on their contract digest");
    }
    Ok(EgressAppliedAuthority {
        controller_epoch: u64::from_ne_bytes(
            config[0..8].try_into().expect("fixed controller epoch"),
        ),
        projection_revision: u64::from_ne_bytes(
            config[8..16].try_into().expect("fixed projection revision"),
        ),
        contract_revision: u64::from_ne_bytes(
            config[16..24].try_into().expect("fixed contract revision"),
        ),
        contract_digest,
    })
}

fn egress_bank(bank: u8) -> Result<usize> {
    if bank >= EGRESS_BANK_COUNT {
        bail!("persistent egress map contains invalid bank {bank}");
    }
    Ok(usize::from(bank))
}

fn validate_recovered_egress_source(key: [u8; 8], value: &[u8; 128]) -> Result<()> {
    let identity = u32::from_ne_bytes(key[0..4].try_into().expect("fixed identity"));
    let schema = u16::from_ne_bytes(value[120..122].try_into().expect("fixed source schema"));
    let known_flags = unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV4
        | unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV6
        | unf_ebpf_common::EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY;
    let revisions_valid = (0..8).all(|index| {
        let start = index * 8;
        u64::from_ne_bytes(
            value[start..start + 8]
                .try_into()
                .expect("fixed source revision"),
        ) != 0
    });
    if identity == 0
        || !revisions_valid
        || key[5..8] != [0; 3]
        || schema != EGRESS_MAP_ABI_VERSION
        || !unf_ebpf_common::egress_admission_is_valid(value[122])
        || value[123] & !known_flags != 0
        || value[123]
            & (unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV4 | unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV6)
            == 0
        || (value[122] == unf_ebpf_common::EGRESS_ADMISSION_FENCED
            && value[123] & unf_ebpf_common::EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY != 0)
        || value[64..96] == [0; 32]
        || value[96..112] == [0; 16]
        || value[124..128] != [0; 4]
    {
        bail!("persistent egress source entry is incompatible");
    }
    Ok(())
}

fn validate_recovered_egress_gateway_nat_source(key: [u8; 8], value: &[u8; 128]) -> Result<()> {
    let identity = u32::from_ne_bytes(key[0..4].try_into().expect("fixed gateway identity"));
    let namespace =
        u32::from_ne_bytes(value[112..116].try_into().expect("fixed gateway namespace"));
    let local_gateway =
        u16::from_ne_bytes(value[124..126].try_into().expect("fixed local gateway"));
    let gateway_count =
        u16::from_ne_bytes(value[118..120].try_into().expect("fixed gateway count"));
    let known_flags = unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV4
        | unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV6
        | unf_ebpf_common::EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY
        | unf_ebpf_common::EGRESS_SOURCE_FLAG_GATEWAY_NAT;
    if identity == 0
        || namespace != identity
        || key[5..8] != [0; 3]
        || (0..8).any(|index| {
            let start = index * 8;
            u64::from_ne_bytes(
                value[start..start + 8]
                    .try_into()
                    .expect("fixed gateway revision"),
            ) == 0
        })
        || value[64..96] == [0; 32]
        || value[96..112] == [0; 16]
        || u16::from_ne_bytes(value[120..122].try_into().expect("fixed gateway schema"))
            != EGRESS_MAP_ABI_VERSION
        || value[122] != unf_ebpf_common::EGRESS_ADMISSION_ACTIVE
        || value[123] & unf_ebpf_common::EGRESS_SOURCE_FLAG_GATEWAY_NAT == 0
        || value[123] & !known_flags != 0
        || value[123]
            & (unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV4 | unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV6)
            == 0
        || gateway_count == 0
        || local_gateway >= gateway_count
        || value[126..128] != [0; 2]
    {
        bail!("persistent gateway NAT source entry is incompatible");
    }
    Ok(())
}

fn validate_recovered_egress_candidate_key(key: [u8; 8]) -> Result<()> {
    if !matches!(key[6], 4 | 6) || key[7] >= EGRESS_BANK_COUNT {
        bail!("persistent egress candidate key is incompatible");
    }
    Ok(())
}

fn validate_recovered_egress_address(value: &[u8; 56]) -> Result<()> {
    if u64::from_ne_bytes(value[0..8].try_into().expect("fixed address lease")) == 0
        || u64::from_ne_bytes(value[8..16].try_into().expect("fixed address revision")) == 0
        || u16::from_ne_bytes(value[48..50].try_into().expect("fixed address schema"))
            != EGRESS_MAP_ABI_VERSION
        || value[16..32] == [0; 16]
        || value[32..48] == [0; 16]
        || value[50..52] != [0; 2]
        || value[52..56] != [0; 4]
    {
        bail!("persistent egress address entry is incompatible");
    }
    Ok(())
}

fn validate_recovered_egress_gateway(value: &[u8; 88]) -> Result<()> {
    if u64::from_ne_bytes(value[0..8].try_into().expect("fixed gateway lease")) == 0
        || u64::from_ne_bytes(value[8..16].try_into().expect("fixed gateway revision")) == 0
        || u64::from_ne_bytes(value[16..24].try_into().expect("fixed path revision")) == 0
        || value[24..40] == [0; 16]
        || value[40..56] == [0; 16]
        || value[56..72] == [0; 16]
        || u32::from_ne_bytes(value[72..76].try_into().expect("fixed output interface")) == 0
        || !(1280..=65_535).contains(&u32::from_ne_bytes(
            value[76..80].try_into().expect("fixed MTU"),
        ))
        || u16::from_ne_bytes(value[80..82].try_into().expect("fixed gateway schema"))
            != EGRESS_MAP_ABI_VERSION
        || !unf_ebpf_common::egress_path_mode_is_valid(value[82])
        || value[83] != 0
        || value[84..88] != [0; 4]
    {
        bail!("persistent egress gateway entry is incompatible");
    }
    Ok(())
}

fn validate_recovered_egress_gateway_nat_gateway(value: &[u8; 88]) -> Result<()> {
    if u64::from_ne_bytes(value[0..8].try_into().expect("fixed gateway lease")) == 0
        || u64::from_ne_bytes(value[8..16].try_into().expect("fixed gateway contract")) == 0
        || u64::from_ne_bytes(
            value[16..24]
                .try_into()
                .expect("fixed reachability revision"),
        ) == 0
        || value[24..56] != [0; 32]
        || value[56..72] == [0; 16]
        || value[72..80] != [0; 8]
        || u16::from_ne_bytes(value[80..82].try_into().expect("fixed gateway schema"))
            != EGRESS_MAP_ABI_VERSION
        || value[82..88] != [0; 6]
    {
        bail!("persistent gateway NAT gateway entry is incompatible");
    }
    Ok(())
}

fn validate_recovered_egress_selection(key: [u8; 8], value: &[u8; 32]) -> Result<()> {
    let bucket = u16::from_ne_bytes(key[4..6].try_into().expect("fixed selection bucket"));
    let primary = u16::from_ne_bytes(value[18..20].try_into().expect("fixed primary index"));
    let standby = u16::from_ne_bytes(value[20..22].try_into().expect("fixed standby index"));
    let flags = u16::from_ne_bytes(value[24..26].try_into().expect("fixed selection flags"));
    if bucket >= unf_ebpf_common::EGRESS_SELECTION_TABLE_SIZE
        || value[0..16] == [0; 16]
        || u16::from_ne_bytes(value[22..24].try_into().expect("fixed selection schema"))
            != EGRESS_MAP_ABI_VERSION
        || flags & !unf_ebpf_common::EGRESS_SELECTION_FLAG_STANDBY != 0
        || (flags == 0 && standby != primary)
        || (flags & unf_ebpf_common::EGRESS_SELECTION_FLAG_STANDBY != 0 && standby == primary)
        || value[26..32] != [0; 6]
    {
        bail!("persistent egress selection entry is incompatible");
    }
    Ok(())
}

fn validate_recovered_egress_connection(key: &[u8; 44], value: &[u8; 208]) -> Result<()> {
    let identity = u32::from_ne_bytes(key[36..40].try_into().expect("fixed connection identity"));
    let value_identity =
        u32::from_ne_bytes(value[184..188].try_into().expect("fixed value identity"));
    let flags = u16::from_ne_bytes(value[204..206].try_into().expect("fixed connection flags"));
    let known_flags = unf_ebpf_common::EGRESS_CONNECTION_FLAG_STANDBY_CERTIFIED
        | unf_ebpf_common::EGRESS_CONNECTION_FLAG_STANDBY_ACTIVE;
    let forward_tuple = key[0..16] == value[24..40]
        && key[16..32] == value[40..56]
        && key[32..34] == value[188..190]
        && key[34..36] == value[190..192];
    let reverse_tuple = key[0..16] == value[40..56]
        && key[16..32] == value[56..72]
        && key[32..34] == value[190..192]
        && key[34..36] == value[192..194];
    let address_valid = |address: &[u8]| {
        if key[41] == 4 {
            address[0..4] != [0; 4] && address[4..16] == [0; 12]
        } else {
            address != [0; 16]
        }
    };
    if !matches!(key[40], 6 | 17)
        || !matches!(key[41], 4 | 6)
        || !matches!(
            key[42],
            unf_ebpf_common::EGRESS_CONNECTION_ROLE_FORWARD
                | unf_ebpf_common::EGRESS_CONNECTION_ROLE_REVERSE
        )
        || (key[42] == unf_ebpf_common::EGRESS_CONNECTION_ROLE_FORWARD
            && (identity == 0 || identity != value_identity || !forward_tuple))
        || (key[42] == unf_ebpf_common::EGRESS_CONNECTION_ROLE_REVERSE
            && (identity != 0 || !reverse_tuple))
        || value_identity == 0
        || key[43] != 0
        || u64::from_ne_bytes(value[8..16].try_into().expect("fixed contract revision")) == 0
        || u64::from_ne_bytes(value[16..24].try_into().expect("fixed lease epoch")) == 0
        || !address_valid(&value[24..40])
        || !address_valid(&value[40..56])
        || !address_valid(&value[56..72])
        || value[104..120] == [0; 16]
        || value[120..152] == [0; 32]
        || value[152..168] == [0; 16]
        || value[168..184] == [0; 16]
        || u16::from_be_bytes(value[192..194].try_into().expect("fixed translated port"))
            < unf_ebpf_common::EGRESS_SNAT_PORT_BASE
        || u16::from_ne_bytes(value[200..202].try_into().expect("fixed connection schema"))
            != EGRESS_MAP_ABI_VERSION
        || value[202] != key[40]
        || value[203] != key[41]
        || flags & !known_flags != 0
        || value[206..208] != [0; 2]
    {
        bail!("persistent egress connection entry is incompatible");
    }
    Ok(())
}

fn clear_all_egress_banks(egress: &mut EgressSynchronizer) -> Result<()> {
    clear_egress_bank(egress, 0)?;
    clear_egress_bank(egress, 1)
}

fn clear_egress_bank(egress: &mut EgressSynchronizer, bank: u8) -> Result<()> {
    let index = egress_bank(bank)?;
    restore_encoded_bank(&mut egress.sources, &BTreeMap::new(), bank, 4)
        .context("clear egress source bank")?;
    restore_lpm_bank(&mut egress.ipv4_destinations, &BTreeMap::new(), bank)
        .context("clear IPv4 egress destination bank")?;
    restore_lpm_bank(&mut egress.ipv6_destinations, &BTreeMap::new(), bank)
        .context("clear IPv6 egress destination bank")?;
    restore_encoded_bank(&mut egress.addresses, &BTreeMap::new(), bank, 7)
        .context("clear egress address bank")?;
    restore_encoded_bank(&mut egress.gateways, &BTreeMap::new(), bank, 7)
        .context("clear egress gateway bank")?;
    restore_encoded_bank(&mut egress.selections, &BTreeMap::new(), bank, 7)
        .context("clear egress selection bank")?;
    egress.banks[index] = EncodedEgressBank::default();
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn encode_egress_dataplane(state: &EgressDataplaneState) -> Result<EncodedEgressBank> {
    let bank = state.config.active_bank;
    egress_bank(bank)?;
    if state.config.schema_version != EGRESS_MAP_ABI_VERSION
        || usize::try_from(state.config.source_count).ok() != Some(state.sources.len())
        || usize::try_from(state.config.destination_count).ok()
            != Some(state.ipv4_destinations.len() + state.ipv6_destinations.len())
        || usize::try_from(state.config.address_count).ok() != Some(state.addresses.len())
        || usize::try_from(state.config.gateway_count).ok() != Some(state.gateways.len())
        || usize::try_from(state.config.selection_count).ok() != Some(state.selections.len())
        || (!state.sources.is_empty()
            && state.ipv4_destinations.is_empty()
            && state.ipv6_destinations.is_empty())
    {
        bail!("compiled egress state does not match its ABI config");
    }
    let mut encoded = EncodedEgressBank {
        config: encode_egress_config(&state.config),
        ..EncodedEgressBank::default()
    };
    for (key, value) in &state.sources {
        let key = encode_egress_source_key(*key);
        if key[4] != bank
            || encoded
                .sources
                .insert(key, encode_egress_source_value(value))
                .is_some()
        {
            bail!("compiled egress state contains a duplicate or foreign source entry");
        }
    }
    for (prefix, data, value) in &state.ipv4_destinations {
        let key = encode_egress_ipv4_destination(*data);
        let prefix = unf_ebpf_common::EGRESS_DESTINATION_PREFIX_BASE_BITS + prefix;
        if key[4] != bank
            || encoded
                .ipv4_destinations
                .insert((prefix, key), encode_egress_destination_value(value))
                .is_some()
        {
            bail!("compiled egress state contains a duplicate or foreign IPv4 destination");
        }
    }
    for (prefix, data, value) in &state.ipv6_destinations {
        let key = encode_egress_ipv6_destination(*data);
        let prefix = unf_ebpf_common::EGRESS_DESTINATION_PREFIX_BASE_BITS + prefix;
        if key[4] != bank
            || encoded
                .ipv6_destinations
                .insert((prefix, key), encode_egress_destination_value(value))
                .is_some()
        {
            bail!("compiled egress state contains a duplicate or foreign IPv6 destination");
        }
    }
    for (key, value) in &state.addresses {
        let key = encode_egress_candidate_key(*key);
        if key[7] != bank
            || encoded
                .addresses
                .insert(key, encode_egress_address_value(value))
                .is_some()
        {
            bail!("compiled egress state contains a duplicate or foreign address entry");
        }
    }
    for (key, value) in &state.gateways {
        let key = encode_egress_candidate_key(*key);
        if key[7] != bank
            || encoded
                .gateways
                .insert(key, encode_egress_gateway_value(value))
                .is_some()
        {
            bail!("compiled egress state contains a duplicate or foreign gateway entry");
        }
    }
    for (key, value) in &state.selections {
        let key = encode_egress_selection_key(*key);
        if key[7] != bank
            || encoded
                .selections
                .insert(key, encode_egress_selection_value(value))
                .is_some()
        {
            bail!("compiled egress state contains a duplicate or foreign selection entry");
        }
    }
    for ((prefix, data), value) in &encoded.ipv4_destinations {
        validate_recovered_egress_destination(*prefix, data, value, 32)?;
    }
    for ((prefix, data), value) in &encoded.ipv6_destinations {
        validate_recovered_egress_destination(*prefix, data, value, 128)?;
    }
    if state.config.flags == unf_ebpf_common::EGRESS_CONFIG_FLAG_GATEWAY_NAT {
        validate_egress_gateway_nat_bindings(&encoded, encoded.config)?;
    } else if state.config.flags == 0 {
        validate_egress_destination_bindings(&encoded, encoded.config)?;
    } else {
        bail!("compiled egress state contains unknown config flags");
    }
    Ok(encoded)
}

fn validate_egress_gateway_nat_bindings(
    active: &EncodedEgressBank,
    config: [u8; 56],
) -> Result<()> {
    if config[51] != unf_ebpf_common::EGRESS_CONFIG_FLAG_GATEWAY_NAT || config[16..32] != [0; 16] {
        bail!("gateway NAT config is not heterogeneous-contract state");
    }
    for (key, source) in &active.sources {
        let identity = &key[0..4];
        let namespace = &source[112..116];
        let local_gateway = u16::from_ne_bytes(
            source[124..126]
                .try_into()
                .expect("fixed local gateway index"),
        );
        let gateway_count =
            u16::from_ne_bytes(source[118..120].try_into().expect("fixed gateway count"));
        if identity != namespace
            || source[123] & unf_ebpf_common::EGRESS_SOURCE_FLAG_GATEWAY_NAT == 0
            || source[122] != unf_ebpf_common::EGRESS_ADMISSION_ACTIVE
            || local_gateway >= gateway_count
            || source[126..128] != [0; 2]
        {
            bail!("gateway NAT source binding is incompatible");
        }
    }
    for ((_, data), value) in &active.ipv4_destinations {
        validate_egress_gateway_nat_destination(active, &data[0..4], value)?;
    }
    for ((_, data), value) in &active.ipv6_destinations {
        validate_egress_gateway_nat_destination(active, &data[0..4], value)?;
    }
    Ok(())
}

fn validate_egress_gateway_nat_destination(
    active: &EncodedEgressBank,
    identity: &[u8],
    value: &[u8; 32],
) -> Result<()> {
    if !active.sources.iter().any(|(key, source)| {
        key[0..4] == *identity && source[8..16] == value[0..8] && source[96..112] == value[8..24]
    }) {
        bail!("gateway NAT destination is not bound to its source contract");
    }
    Ok(())
}

fn egress_agent_advertisement() -> EgressAgentAdvertisement {
    EgressAgentAdvertisement {
        distribution_schemas: BTreeSet::from([EGRESS_DISTRIBUTION_SCHEMA_VERSION]),
        host_state_schemas: BTreeSet::from([EGRESS_HOST_STATE_SCHEMA_VERSION]),
        capabilities: BTreeSet::from([
            EgressCapability::IdentitySourceSteering,
            EgressCapability::LeaseEpochFencing,
            EgressCapability::OriginalTupleWitness,
            EgressCapability::Ipv4TcpUdpNat,
            EgressCapability::Ipv6TcpUdpNat,
        ]),
    }
}

async fn synchronize_egress(
    synchronizer: &mut EgressSynchronizer,
    state: &AgentState,
) -> Result<bool> {
    let gateway_address_result = synchronize_egress_gateway_addresses(synchronizer, state).await;
    let source_result = synchronize_egress_source(synchronizer, state).await;
    let gateway_result = synchronize_egress_gateway(synchronizer, state).await;
    if (gateway_address_result.is_err() || source_result.is_err() || gateway_result.is_err())
        && let Err(error) = fence_active_egress_dataplane(synchronizer)
    {
        return Err(error)
            .context("egress synchronization failed and active state could not be fenced");
    }
    match (gateway_address_result, source_result, gateway_result) {
        (Ok(address), Ok(source), Ok(gateway)) => Ok(address || source || gateway),
        (address, source, gateway) => {
            let mut failures = Vec::new();
            if let Err(error) = address {
                failures.push(format!("gateway address ownership: {error:#}"));
            }
            if let Err(error) = source {
                failures.push(format!("source distribution: {error:#}"));
            }
            if let Err(error) = gateway {
                failures.push(format!("gateway distribution: {error:#}"));
            }
            Err(anyhow!(
                "egress synchronization failed: {}",
                failures.join("; ")
            ))
        }
    }
}

async fn synchronize_egress_gateway_addresses(
    synchronizer: &EgressSynchronizer,
    state: &AgentState,
) -> Result<bool> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("gateway address synchronization requires a controller URL")?;
    let response = authenticated_get(
        &synchronizer.client,
        format!("{controller_url}/v1/state/egress-gateway-address"),
        &synchronizer.agent_token_path,
    )?
    .send()
    .await
    .context("request authenticated gateway-address projection")?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(false);
    }
    let projection: EgressGatewayAddressProjection = response
        .error_for_status()
        .context("controller rejected gateway-address projection request")?
        .json()
        .await
        .context("decode gateway-address projection")?;
    let node = fetch_node_port_node_snapshot(
        controller_url,
        &synchronizer.client,
        &synchronizer.agent_token_path,
    )
    .await?
    .validate_and_normalize()
    .context("validate authoritative gateway Node identity")?;
    if node.node_name != synchronizer.node_name {
        bail!(
            "controller returned Node identity for {}; gateway-address agent owns {}",
            node.node_name,
            synchronizer.node_name
        );
    }
    let principal = authenticated_egress_principal(synchronizer, state, node.node_uid.clone());
    let admitted = projection
        .admit(&principal)
        .context("admit exact gateway-address projection")?;
    let ipv6_proxy_uplink = synchronizer.path_provider.as_ref().map(|provider| {
        (
            provider.ipv6_interface.clone(),
            provider.ipv6_output_interface,
        )
    });
    let acknowledgement =
        apply_egress_gateway_address_projection(&admitted, node.node_uid, ipv6_proxy_uplink)
            .await?;
    synchronizer
        .client
        .current()
        .post(format!(
            "{controller_url}/v1/state/egress-gateway-address-ack"
        ))
        .bearer_auth(read_agent_token(&synchronizer.agent_token_path)?)
        .json(&acknowledgement)
        .send()
        .await
        .context("publish gateway-address application evidence")?
        .error_for_status()
        .context("controller rejected gateway-address application evidence")?;
    info!(
        projection_revision = admitted.projection().revision.get(),
        addresses = acknowledgement.owned_addresses.len(),
        applied_leases = acknowledgement.applied_desired_revisions.len(),
        quarantined_leases = acknowledgement.quarantined_desired_revisions.len(),
        released_leases = acknowledgement.released_desired_revisions.len(),
        interface_index = acknowledgement.interface_index,
        "applied lease-fenced gateway address ownership"
    );
    Ok(true)
}

async fn apply_egress_gateway_address_projection(
    admitted: &AdmittedEgressGatewayAddressProjection,
    node_uid: String,
    ipv6_proxy_uplink: Option<(String, u32)>,
) -> Result<EgressGatewayAddressAcknowledgement> {
    let desired_addresses = admitted
        .projection()
        .leases
        .iter()
        .flat_map(|lease| lease.addresses.iter().copied())
        .collect::<BTreeSet<_>>();
    let retained_addresses = admitted
        .projection()
        .leases
        .iter()
        .filter(|lease| {
            admitted
                .projection()
                .release_authorized_desired_revisions
                .binary_search(&lease.revision)
                .is_err()
        })
        .flat_map(|lease| lease.addresses.iter().copied())
        .collect::<BTreeSet<_>>();
    let previous_addresses = admitted
        .projection()
        .previous_owned_addresses
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if desired_addresses != retained_addresses && previous_addresses != desired_addresses {
        bail!("release transition does not start from the exact acknowledged desired set");
    }
    if !retained_addresses.is_subset(&previous_addresses)
        && !previous_addresses.is_subset(&retained_addresses)
    {
        bail!("gateway-address ownership cannot add and remove in one transaction");
    }
    let mut previous_plan = GatewayAddressPlan::new(
        node_uid.clone(),
        1_500,
        previous_addresses.iter().copied().collect(),
    )
    .context("compile complete Node-UID-bound gateway-address plan")?;
    let mut plan = GatewayAddressPlan::new(
        node_uid,
        1_500,
        retained_addresses.iter().copied().collect(),
    )
    .context("compile release-authorized gateway-address plan")?;
    if let Some((interface_name, interface_index)) = ipv6_proxy_uplink {
        previous_plan = previous_plan
            .with_ipv6_proxy_uplink(interface_name.clone(), interface_index)
            .context("bind complete gateway-address plan to IPv6 proxy uplink")?;
        plan = plan
            .with_ipv6_proxy_uplink(interface_name, interface_index)
            .context("bind retained gateway-address plan to IPv6 proxy uplink")?;
    }
    let readback = if previous_addresses.is_empty() || previous_addresses == retained_addresses {
        plan.apply()
            .await
            .context("apply and read back gateway-address ownership")?
    } else if previous_addresses.is_subset(&retained_addresses) {
        previous_plan
            .readback()
            .await
            .context("verify exact prior gateway-address ownership before expansion")?;
        plan.apply()
            .await
            .context("expand and read back gateway-address ownership")?
    } else {
        plan.transition_from(&previous_plan)
            .await
            .context("apply and read back authorized gateway-address release")?
    };
    EgressGatewayAddressAcknowledgement::issue(
        admitted,
        readback.interface_name,
        readback.interface_index,
        readback.mtu,
        readback
            .addresses
            .into_iter()
            .map(|address| address.address)
            .collect(),
    )
    .context("build exact gateway-address application evidence")
}

async fn synchronize_egress_source(
    synchronizer: &mut EgressSynchronizer,
    state: &AgentState,
) -> Result<bool> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("egress synchronization requires a controller URL")?;
    let advertisement = egress_agent_advertisement();
    let response = synchronizer
        .client
        .current()
        .post(format!("{controller_url}/v1/state/egress-source"))
        .bearer_auth(read_agent_token(&synchronizer.agent_token_path)?)
        .json(&advertisement)
        .send()
        .await
        .context("request authenticated egress source projection")?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        let changed = fence_active_egress_dataplane(synchronizer)
            .context("fence egress state after source authority withdrawal")?;
        publish_egress_source_retirement_evidence(synchronizer).await?;
        return Ok(changed);
    }
    let envelope: EgressNodeProjectionEnvelope = response
        .error_for_status()
        .context("controller rejected egress source projection request")?
        .json()
        .await
        .context("decode egress source projection envelope")?;
    let node = fetch_node_port_node_snapshot(
        controller_url,
        &synchronizer.client,
        &synchronizer.agent_token_path,
    )
    .await?
    .validate_and_normalize()
    .context("validate authoritative local Node identity for egress")?;
    if node.node_name != synchronizer.node_name {
        bail!(
            "controller returned Node identity for {}; authenticated egress agent owns {}",
            node.node_name,
            synchronizer.node_name
        );
    }
    let principal = authenticated_egress_principal(synchronizer, state, node.node_uid);
    let admitted = envelope
        .admit(&principal, &advertisement)
        .context("independently replay egress source projection")?;
    let projection = admitted.projection();
    let candidate_authority = EgressAppliedAuthority {
        controller_epoch: projection.controller_epoch,
        projection_revision: projection.revision.get(),
        contract_revision: projection.contract.contract_revision.get(),
        contract_digest: Some(projection.contract.contract_digest.0),
    };
    if egress_authority_is_current(synchronizer.applied_authority, candidate_authority)? {
        let source_count = synchronizer.banks[usize::from(synchronizer.active_bank)]
            .sources
            .len();
        acknowledge_current_egress_source(synchronizer, &admitted, source_count).await?;
        return activate_current_egress_source(synchronizer, state, &admitted).await;
    }
    let mut next_ledger = synchronizer.ledger.clone();
    next_ledger
        .adopt(admitted.clone())
        .context("fence egress projection revision")?;
    if synchronizer.ledger.current() == next_ledger.current() {
        return Ok(false);
    }

    let host =
        EgressGatewayHostBank::compile(&admitted).context("compile admitted egress host bank")?;
    let mut guard = EgressAdmissionGuard::default();
    for plan in &host.contract.plans {
        guard
            .fence(
                plan.source.identity,
                plan.intent.clone(),
                plan.revisions.intent,
            )
            .context("install fail-closed egress source admission")?;
    }
    let bank = synchronizer.active_bank ^ 1;
    let candidate = compile_egress_dataplane(&host, &guard, &[], bank)
        .context("compile fenced egress dataplane candidate")?;
    apply_egress_dataplane(synchronizer, &candidate)?;
    synchronizer.ledger = next_ledger;
    synchronizer.applied_authority = Some(candidate_authority);
    acknowledge_current_egress_source(synchronizer, &admitted, candidate.sources.len()).await?;
    info!(
        controller_epoch = host.controller_epoch,
        projection_revision = host.projection_revision.get(),
        contract_revision = host.contract.contract_revision.get(),
        sources = candidate.sources.len(),
        active_bank = synchronizer.active_bank,
        "authenticated egress intent staged as fail-closed source fences"
    );
    Ok(true)
}

async fn activate_current_egress_source(
    synchronizer: &mut EgressSynchronizer,
    state: &AgentState,
    admitted: &unf_egress::AdmittedEgressProjection,
) -> Result<bool> {
    let Some(grant) = fetch_egress_source_activation_grant(synchronizer).await? else {
        return fence_active_egress_dataplane(synchronizer)
            .context("fence egress state while gateway readiness is incomplete");
    };
    grant
        .verify(admitted)
        .context("verify controller egress source activation grant")?;
    let provider = synchronizer
        .path_provider
        .as_ref()
        .context("egress activation requires native dual-stack route ownership")?;
    let paths = provider.acquire(admitted, state).await?;
    let host = EgressGatewayHostBank::compile(admitted)
        .context("compile admitted egress host bank for activation")?;
    let mut guard = EgressAdmissionGuard::default();
    for plan in &host.contract.plans {
        guard
            .fence(
                plan.source.identity,
                plan.intent.clone(),
                plan.revisions.intent,
            )
            .context("install egress activation fence")?;
        guard
            .activate(plan.source.identity, admitted)
            .context("activate exact admitted egress source")?;
    }

    let current = compile_egress_dataplane(&host, &guard, &paths, synchronizer.active_bank)
        .context("compile current-bank egress activation candidate")?;
    if encode_egress_dataplane(&current)?
        == synchronizer.banks[usize::from(synchronizer.active_bank)]
    {
        return Ok(false);
    }
    let bank = synchronizer.active_bank ^ 1;
    let candidate = compile_egress_dataplane(&host, &guard, &paths, bank)
        .context("compile certified active egress dataplane candidate")?;
    apply_egress_dataplane(synchronizer, &candidate)?;
    info!(
        controller_epoch = host.controller_epoch,
        projection_revision = host.projection_revision.get(),
        contract_revision = host.contract.contract_revision.get(),
        path_revision = candidate.config.path_revision,
        paths = paths.len(),
        sources = candidate.sources.len(),
        active_bank = synchronizer.active_bank,
        "activated egress sources after gateway and local-path proof"
    );
    Ok(true)
}

async fn fetch_egress_source_activation_grant(
    synchronizer: &EgressSynchronizer,
) -> Result<Option<EgressSourceActivationGrant>> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("egress activation requires a controller URL")?;
    let response = authenticated_get(
        &synchronizer.client,
        format!("{controller_url}/v1/state/egress-source-activation"),
        &synchronizer.agent_token_path,
    )?
    .send()
    .await
    .context("request egress source activation grant")?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }
    response
        .error_for_status()
        .context("controller rejected egress source activation request")?
        .json()
        .await
        .map(Some)
        .context("decode egress source activation grant")
}

async fn acknowledge_current_egress_source(
    synchronizer: &EgressSynchronizer,
    admitted: &unf_egress::AdmittedEgressProjection,
    source_count: usize,
) -> Result<()> {
    let acknowledgement = EgressSourceApplicationAcknowledgement::issue(
        admitted,
        synchronizer.active_bank,
        source_count,
    )
    .context("build current source application acknowledgement")?;
    publish_egress_source_acknowledgement(synchronizer, &acknowledgement).await
}

async fn synchronize_egress_gateway(
    synchronizer: &mut EgressSynchronizer,
    state: &AgentState,
) -> Result<bool> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("egress synchronization requires a controller URL")?;
    let advertisement = egress_agent_advertisement();
    let response = synchronizer
        .client
        .current()
        .post(format!("{controller_url}/v1/state/egress-gateway"))
        .bearer_auth(read_agent_token(&synchronizer.agent_token_path)?)
        .json(&advertisement)
        .send()
        .await
        .context("request authenticated egress gateway projection")?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(false);
    }
    let projection: EgressGatewayProjection = response
        .error_for_status()
        .context("controller rejected egress gateway projection request")?
        .json()
        .await
        .context("decode egress gateway projection")?;
    let node = fetch_node_port_node_snapshot(
        controller_url,
        &synchronizer.client,
        &synchronizer.agent_token_path,
    )
    .await?
    .validate_and_normalize()
    .context("validate authoritative local Node identity for egress gateway")?;
    if node.node_name != synchronizer.node_name {
        bail!(
            "controller returned Node identity for {}; authenticated egress gateway owns {}",
            node.node_name,
            synchronizer.node_name
        );
    }
    let principal = authenticated_egress_principal(synchronizer, state, node.node_uid);
    let admitted = projection
        .admit(&principal, &advertisement)
        .context("independently admit selected-gateway projection")?;
    let current_candidate =
        compile_egress_gateway_dataplane(&admitted, synchronizer.gateway_nat_active_bank)
            .context("compile current-bank gateway NAT projection")?;
    if encode_egress_dataplane(&current_candidate)?
        != synchronizer.gateway_nat_banks[usize::from(synchronizer.gateway_nat_active_bank)]
    {
        let candidate =
            compile_egress_gateway_dataplane(&admitted, synchronizer.gateway_nat_active_bank ^ 1)
                .context("compile inactive-bank gateway NAT projection")?;
        apply_egress_gateway_dataplane(synchronizer, &candidate)
            .context("transactionally apply selected-gateway NAT projection")?;
    }
    let acknowledgement = EgressGatewayApplicationAcknowledgement::issue(&admitted)
        .context("build gateway application acknowledgement")?;
    let mut next = synchronizer.gateway_ledger.clone();
    next.adopt(admitted)
        .context("fence selected-gateway projection revision")?;
    if next.current() == synchronizer.gateway_ledger.current() {
        publish_egress_gateway_acknowledgement(synchronizer, &acknowledgement).await?;
        publish_egress_gateway_retirement_evidence(synchronizer).await?;
        return Ok(false);
    }
    let current = next
        .current()
        .context("admitted selected-gateway projection disappeared")?;
    let revision = current.revision.get();
    let contracts = current.source_contracts.len();
    let sources = current
        .source_contracts
        .iter()
        .map(|contract| contract.plans.len())
        .sum::<usize>();
    let withdrawal = current.is_withdrawal();
    synchronizer.gateway_ledger = next;
    publish_egress_gateway_acknowledgement(synchronizer, &acknowledgement).await?;
    publish_egress_gateway_retirement_evidence(synchronizer).await?;
    info!(
        revision,
        contracts, sources, withdrawal, "authenticated selected-gateway projection admitted"
    );
    Ok(true)
}

fn authenticated_egress_principal(
    synchronizer: &EgressSynchronizer,
    state: &AgentState,
    node_uid: String,
) -> AuthenticatedEgressAgent {
    AuthenticatedEgressAgent {
        namespace: "unf-system".to_owned(),
        service_account: EGRESS_AGENT_SERVICE_ACCOUNT.to_owned(),
        pod_name: state.pod_name.clone(),
        pod_uid: state.pod_uid.clone(),
        node_name: synchronizer.node_name.clone(),
        node_uid,
        audience: EGRESS_AGENT_TOKEN_AUDIENCE.to_owned(),
    }
}

async fn publish_egress_source_acknowledgement(
    synchronizer: &EgressSynchronizer,
    acknowledgement: &EgressSourceApplicationAcknowledgement,
) -> Result<()> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("egress source acknowledgement requires a controller URL")?;
    synchronizer
        .client
        .current()
        .post(format!("{controller_url}/v1/state/egress-source-ack"))
        .bearer_auth(read_agent_token(&synchronizer.agent_token_path)?)
        .json(acknowledgement)
        .send()
        .await
        .context("publish exact egress source application acknowledgement")?
        .error_for_status()
        .context("controller rejected egress source application acknowledgement")?;
    Ok(())
}

async fn publish_egress_source_retirement_evidence(
    synchronizer: &EgressSynchronizer,
) -> Result<()> {
    let Some(admitted) = synchronizer.ledger.current() else {
        return Ok(());
    };
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("egress source retirement requires a controller URL")?;
    let response = authenticated_get(
        &synchronizer.client,
        format!("{controller_url}/v1/state/egress-source-retirements"),
        &synchronizer.agent_token_path,
    )?
    .send()
    .await
    .context("request authenticated egress source retirement challenges")?;
    let challenges: EgressSourceRetirementChallenges = response
        .error_for_status()
        .context("controller rejected egress source retirement request")?
        .json()
        .await
        .context("decode egress source retirement challenges")?;
    challenges
        .verify()
        .context("verify egress source retirement challenges")?;
    for manifest in &challenges.manifests {
        let evidence = EgressSourceFenceEvidence::issue_for_challenge(
            &challenges,
            manifest,
            admitted,
            synchronizer.active_bank,
        )
        .context("build destination-preserving source-fence evidence")?;
        synchronizer
            .client
            .current()
            .post(format!("{controller_url}/v1/state/egress-source-fence"))
            .bearer_auth(read_agent_token(&synchronizer.agent_token_path)?)
            .json(&evidence)
            .send()
            .await
            .context("publish authenticated egress source-fence evidence")?
            .error_for_status()
            .context("controller rejected egress source-fence evidence")?;
    }
    Ok(())
}

async fn publish_egress_gateway_acknowledgement(
    synchronizer: &EgressSynchronizer,
    acknowledgement: &EgressGatewayApplicationAcknowledgement,
) -> Result<()> {
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("egress gateway acknowledgement requires a controller URL")?;
    synchronizer
        .client
        .current()
        .post(format!("{controller_url}/v1/state/egress-gateway-ack"))
        .bearer_auth(read_agent_token(&synchronizer.agent_token_path)?)
        .json(acknowledgement)
        .send()
        .await
        .context("publish exact egress gateway application acknowledgement")?
        .error_for_status()
        .context("controller rejected egress gateway application acknowledgement")?;
    Ok(())
}

async fn publish_egress_gateway_retirement_evidence(
    synchronizer: &mut EgressSynchronizer,
) -> Result<()> {
    let Some(current) = synchronizer.gateway_ledger.current().cloned() else {
        return Ok(());
    };
    let recipient = current.recipient.clone();
    let controller_url = synchronizer
        .controller_url
        .as_deref()
        .context("egress gateway retirement requires a controller URL")?
        .to_owned();
    let response = authenticated_get(
        &synchronizer.client,
        format!("{controller_url}/v1/state/egress-gateway-retirements"),
        &synchronizer.agent_token_path,
    )?
    .send()
    .await
    .context("request authenticated egress gateway retirement challenges")?;
    let challenges: EgressGatewayRetirementChallenges = response
        .error_for_status()
        .context("controller rejected egress gateway retirement request")?
        .json()
        .await
        .context("decode egress gateway retirement challenges")?;
    challenges
        .verify()
        .context("verify egress gateway retirement challenges")?;
    for manifest in &challenges.manifests {
        let lease_is_absent = current
            .source_contracts
            .iter()
            .flat_map(|contract| &contract.plans)
            .all(|plan| {
                plan.intent != manifest.owner || plan.allocation.lease_epoch != manifest.lease_epoch
            });
        if !lease_is_absent {
            continue;
        }
        if !drain_expired_egress_gateway_lease(&mut synchronizer.connections, manifest.lease_epoch)?
        {
            continue;
        }
        let evidence = EgressGatewayDrainEvidence::issue_for_challenge(
            &challenges,
            manifest,
            recipient.clone(),
            0,
            true,
        )
        .context("build lease-specific zero-flow gateway-drain evidence")?;
        synchronizer
            .client
            .current()
            .post(format!("{controller_url}/v1/state/egress-gateway-drain"))
            .bearer_auth(read_agent_token(&synchronizer.agent_token_path)?)
            .json(&evidence)
            .send()
            .await
            .context("publish authenticated egress gateway-drain evidence")?
            .error_for_status()
            .context("controller rejected egress gateway-drain evidence")?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum EgressGatewayDrainPlan {
    Active(usize),
    Remove(Vec<[u8; 44]>),
}

fn plan_egress_gateway_lease_drain(
    connections: &BTreeMap<[u8; 44], [u8; 208]>,
    lease_epoch: u64,
    now_ns: u64,
) -> Result<EgressGatewayDrainPlan> {
    let mut lease_keys = Vec::new();
    let mut active = 0_usize;
    for (key, value) in connections {
        validate_recovered_egress_connection(key, value)?;
        if u64::from_ne_bytes(value[16..24].try_into().expect("fixed lease epoch")) != lease_epoch {
            continue;
        }
        lease_keys.push(*key);
        let last_seen_ns =
            u64::from_ne_bytes(value[0..8].try_into().expect("fixed last-seen time"));
        let timeout_ns = unf_ebpf_common::connection_timeout_ns(value[202])
            .context("validated egress protocol has no connection timeout")?;
        if now_ns.saturating_sub(last_seen_ns) <= timeout_ns {
            active += 1;
        }
    }
    if active == 0 {
        Ok(EgressGatewayDrainPlan::Remove(lease_keys))
    } else {
        Ok(EgressGatewayDrainPlan::Active(active))
    }
}

fn snapshot_egress_connections(
    connections: &AyaHashMap<MapData, [u8; 44], [u8; 208]>,
) -> Result<BTreeMap<[u8; 44], [u8; 208]>> {
    connections
        .into_iter()
        .map(|entry| entry.context("iterate persistent egress connections"))
        .collect()
}

fn boot_time_ns() -> Result<u64> {
    let now = clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).context("CLOCK_BOOTTIME returned negative seconds")?;
    let nanoseconds =
        u64::try_from(now.tv_nsec).context("CLOCK_BOOTTIME returned negative nanoseconds")?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .context("CLOCK_BOOTTIME nanoseconds overflowed")
}

fn drain_expired_egress_gateway_lease(
    connections: &mut AyaHashMap<MapData, [u8; 44], [u8; 208]>,
    lease_epoch: u64,
) -> Result<bool> {
    let snapshot = snapshot_egress_connections(connections)?;
    let EgressGatewayDrainPlan::Remove(keys) =
        plan_egress_gateway_lease_drain(&snapshot, lease_epoch, boot_time_ns()?)?
    else {
        return Ok(false);
    };
    for key in keys {
        connections
            .remove(&key)
            .context("remove expired lease-bound egress connection")?;
    }
    let verified = snapshot_egress_connections(connections)?;
    Ok(matches!(
        plan_egress_gateway_lease_drain(&verified, lease_epoch, boot_time_ns()?)?,
        EgressGatewayDrainPlan::Remove(keys) if keys.is_empty()
    ))
}

fn egress_authority_is_current(
    applied: Option<EgressAppliedAuthority>,
    candidate: EgressAppliedAuthority,
) -> Result<bool> {
    let Some(applied) = applied else {
        return Ok(false);
    };
    if candidate.controller_epoch < applied.controller_epoch
        || (candidate.controller_epoch == applied.controller_epoch
            && candidate.projection_revision < applied.projection_revision)
    {
        bail!("egress projection epoch or revision regressed from persistent state");
    }
    if candidate.controller_epoch == applied.controller_epoch
        && candidate.projection_revision == applied.projection_revision
    {
        if candidate.contract_revision != applied.contract_revision
            || applied
                .contract_digest
                .is_some_and(|digest| Some(digest) != candidate.contract_digest)
        {
            bail!("egress projection mutated at the persistent epoch and revision");
        }
        return Ok(true);
    }
    Ok(false)
}

#[allow(clippy::too_many_lines)]
fn apply_egress_dataplane(
    egress: &mut EgressSynchronizer,
    state: &EgressDataplaneState,
) -> Result<()> {
    let desired = encode_egress_dataplane(state)?;
    apply_encoded_egress_bank(egress, desired)
}

#[allow(clippy::too_many_lines)]
fn apply_egress_gateway_dataplane(
    egress: &mut EgressSynchronizer,
    state: &EgressDataplaneState,
) -> Result<()> {
    let desired = encode_egress_dataplane(state)?;
    let bank = desired.config[50];
    egress_bank(bank)?;
    if desired.config[51] != unf_ebpf_common::EGRESS_CONFIG_FLAG_GATEWAY_NAT {
        bail!("gateway NAT update requires an aggregate config");
    }
    let current_config = egress
        .gateway_nat_config
        .get(&0, 0)
        .context("read active gateway NAT config before staging")?;
    if bank == egress.gateway_nat_active_bank && current_config != [0; 56] {
        bail!("gateway NAT updates must stage the inactive bank");
    }
    let index = usize::from(bank);
    let previous = egress.gateway_nat_banks[index].clone();
    let staging = replace_encoded_entries(
        &mut egress.gateway_nat_sources,
        &previous.sources,
        &desired.sources,
    )
    .context("stage gateway NAT sources")
    .and_then(|()| {
        replace_lpm_entries(
            &mut egress.gateway_nat_ipv4_destinations,
            &previous.ipv4_destinations,
            &desired.ipv4_destinations,
        )
        .context("stage gateway NAT IPv4 destinations")
    })
    .and_then(|()| {
        replace_lpm_entries(
            &mut egress.gateway_nat_ipv6_destinations,
            &previous.ipv6_destinations,
            &desired.ipv6_destinations,
        )
        .context("stage gateway NAT IPv6 destinations")
    })
    .and_then(|()| {
        replace_encoded_entries(
            &mut egress.gateway_nat_addresses,
            &previous.addresses,
            &desired.addresses,
        )
        .context("stage gateway NAT addresses")
    })
    .and_then(|()| {
        replace_encoded_entries(
            &mut egress.gateway_nat_gateways,
            &previous.gateways,
            &desired.gateways,
        )
        .context("stage gateway NAT gateways")
    })
    .and_then(|()| {
        replace_encoded_entries(
            &mut egress.gateway_nat_selections,
            &previous.selections,
            &desired.selections,
        )
        .context("stage gateway NAT selections")
    })
    .and_then(|()| {
        validate_encoded_entries(
            &egress.gateway_nat_sources,
            &desired.sources,
            "gateway NAT source",
        )
    })
    .and_then(|()| {
        validate_lpm_bank(
            &egress.gateway_nat_ipv4_destinations,
            &desired.ipv4_destinations,
            bank,
        )
        .context("validate gateway NAT IPv4 destinations")
    })
    .and_then(|()| {
        validate_lpm_bank(
            &egress.gateway_nat_ipv6_destinations,
            &desired.ipv6_destinations,
            bank,
        )
        .context("validate gateway NAT IPv6 destinations")
    })
    .and_then(|()| {
        validate_encoded_entries(
            &egress.gateway_nat_addresses,
            &desired.addresses,
            "gateway NAT address",
        )
    })
    .and_then(|()| {
        validate_encoded_entries(
            &egress.gateway_nat_gateways,
            &desired.gateways,
            "gateway NAT gateway",
        )
    })
    .and_then(|()| {
        validate_encoded_entries(
            &egress.gateway_nat_selections,
            &desired.selections,
            "gateway NAT selection",
        )
    });
    if let Err(error) = staging {
        return Err(rollback_egress_gateway_nat_stage(
            egress, &previous, bank, &error,
        ));
    }
    if let Err(error) = egress.gateway_nat_config.set(0, desired.config, 0) {
        return Err(rollback_egress_gateway_nat_stage(
            egress,
            &previous,
            bank,
            &anyhow!(error).context("activate gateway NAT bank"),
        ));
    }
    let retired = egress.gateway_nat_active_bank;
    egress.gateway_nat_banks[index] = desired;
    egress.gateway_nat_active_bank = bank;
    if retired != bank
        && let Err(error) = clear_egress_gateway_nat_bank(egress, retired)
    {
        warn!(?error, bank = retired, "could not retire gateway NAT bank");
    }
    Ok(())
}

fn clear_egress_gateway_nat_bank(egress: &mut EgressSynchronizer, bank: u8) -> Result<()> {
    let index = egress_bank(bank)?;
    restore_encoded_bank(&mut egress.gateway_nat_sources, &BTreeMap::new(), bank, 4)?;
    restore_lpm_bank(
        &mut egress.gateway_nat_ipv4_destinations,
        &BTreeMap::new(),
        bank,
    )?;
    restore_lpm_bank(
        &mut egress.gateway_nat_ipv6_destinations,
        &BTreeMap::new(),
        bank,
    )?;
    restore_encoded_bank(&mut egress.gateway_nat_addresses, &BTreeMap::new(), bank, 7)?;
    restore_encoded_bank(&mut egress.gateway_nat_gateways, &BTreeMap::new(), bank, 7)?;
    restore_encoded_bank(
        &mut egress.gateway_nat_selections,
        &BTreeMap::new(),
        bank,
        7,
    )?;
    egress.gateway_nat_banks[index] = EncodedEgressBank::default();
    Ok(())
}

fn rollback_egress_gateway_nat_stage(
    egress: &mut EgressSynchronizer,
    previous: &EncodedEgressBank,
    bank: u8,
    cause: &anyhow::Error,
) -> anyhow::Error {
    let rollback =
        restore_encoded_bank(&mut egress.gateway_nat_sources, &previous.sources, bank, 4)
            .and_then(|()| {
                restore_lpm_bank(
                    &mut egress.gateway_nat_ipv4_destinations,
                    &previous.ipv4_destinations,
                    bank,
                )
            })
            .and_then(|()| {
                restore_lpm_bank(
                    &mut egress.gateway_nat_ipv6_destinations,
                    &previous.ipv6_destinations,
                    bank,
                )
            })
            .and_then(|()| {
                restore_encoded_bank(
                    &mut egress.gateway_nat_addresses,
                    &previous.addresses,
                    bank,
                    7,
                )
            })
            .and_then(|()| {
                restore_encoded_bank(
                    &mut egress.gateway_nat_gateways,
                    &previous.gateways,
                    bank,
                    7,
                )
            })
            .and_then(|()| {
                restore_encoded_bank(
                    &mut egress.gateway_nat_selections,
                    &previous.selections,
                    bank,
                    7,
                )
            });
    match rollback {
        Ok(()) => anyhow!("gateway NAT update failed and staging bank was rolled back: {cause:#}"),
        Err(error) => anyhow!("gateway NAT update failed: {cause:#}; rollback failed: {error:#}"),
    }
}

#[allow(clippy::too_many_lines)]
fn apply_encoded_egress_bank(
    egress: &mut EgressSynchronizer,
    desired: EncodedEgressBank,
) -> Result<()> {
    let bank = desired.config[50];
    egress_bank(bank)?;
    let current_config = egress
        .config
        .get(&0, 0)
        .context("read active egress map config before staging")?;
    if bank == egress.active_bank && current_config != [0; 56] {
        bail!("egress updates must stage the inactive bank");
    }
    let index = usize::from(bank);
    let previous = egress.banks[index].clone();
    let staging_result =
        replace_encoded_entries(&mut egress.sources, &previous.sources, &desired.sources)
            .context("stage egress sources")
            .and_then(|()| {
                replace_lpm_entries(
                    &mut egress.ipv4_destinations,
                    &previous.ipv4_destinations,
                    &desired.ipv4_destinations,
                )
                .context("stage IPv4 egress destinations")
            })
            .and_then(|()| {
                replace_lpm_entries(
                    &mut egress.ipv6_destinations,
                    &previous.ipv6_destinations,
                    &desired.ipv6_destinations,
                )
                .context("stage IPv6 egress destinations")
            })
            .and_then(|()| {
                replace_encoded_entries(
                    &mut egress.addresses,
                    &previous.addresses,
                    &desired.addresses,
                )
                .context("stage egress addresses")
            })
            .and_then(|()| {
                replace_encoded_entries(&mut egress.gateways, &previous.gateways, &desired.gateways)
                    .context("stage egress gateways")
            })
            .and_then(|()| {
                replace_encoded_entries(
                    &mut egress.selections,
                    &previous.selections,
                    &desired.selections,
                )
                .context("stage egress selections")
            })
            .and_then(|()| {
                validate_encoded_entries(&egress.sources, &desired.sources, "egress source")
            })
            .and_then(|()| {
                validate_lpm_bank(&egress.ipv4_destinations, &desired.ipv4_destinations, bank)
                    .context("validate IPv4 egress destinations")
            })
            .and_then(|()| {
                validate_lpm_bank(&egress.ipv6_destinations, &desired.ipv6_destinations, bank)
                    .context("validate IPv6 egress destinations")
            })
            .and_then(|()| {
                validate_encoded_entries(&egress.addresses, &desired.addresses, "egress address")
            })
            .and_then(|()| {
                validate_encoded_entries(&egress.gateways, &desired.gateways, "egress gateway")
            })
            .and_then(|()| {
                validate_encoded_entries(
                    &egress.selections,
                    &desired.selections,
                    "egress selection",
                )
            });
    if let Err(error) = staging_result {
        return Err(rollback_egress_stage(egress, &previous, bank, &error));
    }
    if let Err(error) = egress.config.set(0, desired.config, 0) {
        return Err(rollback_egress_stage(
            egress,
            &previous,
            bank,
            &anyhow!(error).context("activate egress map bank"),
        ));
    }

    let retired = egress.active_bank;
    egress.banks[index] = desired;
    egress.active_bank = bank;
    if retired != bank
        && let Err(error) = clear_egress_bank(egress, retired)
    {
        warn!(
            ?error,
            bank = retired,
            "could not garbage-collect retired egress bank"
        );
    }
    Ok(())
}

fn fence_active_egress_dataplane(egress: &mut EgressSynchronizer) -> Result<bool> {
    let active = &egress.banks[usize::from(egress.active_bank)];
    let bank = egress.active_bank ^ 1;
    let Some(desired) = compile_fenced_egress_bank(active, bank)? else {
        return Ok(false);
    };
    apply_encoded_egress_bank(egress, desired)?;
    let connection_keys = egress
        .connections
        .iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    for key in connection_keys {
        egress.connections.remove(&key)?;
    }
    Ok(true)
}

fn compile_fenced_egress_bank(
    active: &EncodedEgressBank,
    bank: u8,
) -> Result<Option<EncodedEgressBank>> {
    egress_bank(bank)?;
    let needs_fence = active
        .sources
        .values()
        .any(|source| source[122] == unf_ebpf_common::EGRESS_ADMISSION_ACTIVE)
        || !active.addresses.is_empty()
        || !active.gateways.is_empty()
        || !active.selections.is_empty();
    if !needs_fence {
        return Ok(None);
    }
    let mut desired = active.clone();
    desired.sources = desired
        .sources
        .into_iter()
        .map(|(mut key, mut value)| {
            key[4] = bank;
            value[122] = unf_ebpf_common::EGRESS_ADMISSION_FENCED;
            value[123] &= !unf_ebpf_common::EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY;
            (key, value)
        })
        .collect();
    desired.ipv4_destinations = desired
        .ipv4_destinations
        .into_iter()
        .map(|((prefix, mut key), value)| {
            key[4] = bank;
            ((prefix, key), value)
        })
        .collect();
    desired.ipv6_destinations = desired
        .ipv6_destinations
        .into_iter()
        .map(|((prefix, mut key), value)| {
            key[4] = bank;
            ((prefix, key), value)
        })
        .collect();
    desired.addresses.clear();
    desired.gateways.clear();
    desired.selections.clear();
    desired.config[24..32].copy_from_slice(&0_u64.to_ne_bytes());
    for offset in [36_usize, 40, 44] {
        desired.config[offset..offset + 4].copy_from_slice(&0_u32.to_ne_bytes());
    }
    desired.config[50] = bank;
    validate_egress_destination_bindings(&desired, desired.config)?;
    Ok(Some(desired))
}

fn rollback_egress_stage(
    egress: &mut EgressSynchronizer,
    previous: &EncodedEgressBank,
    bank: u8,
    cause: &anyhow::Error,
) -> anyhow::Error {
    let rollback = restore_encoded_bank(&mut egress.sources, &previous.sources, bank, 4)
        .and_then(|()| {
            restore_lpm_bank(
                &mut egress.ipv4_destinations,
                &previous.ipv4_destinations,
                bank,
            )
        })
        .and_then(|()| {
            restore_lpm_bank(
                &mut egress.ipv6_destinations,
                &previous.ipv6_destinations,
                bank,
            )
        })
        .and_then(|()| restore_encoded_bank(&mut egress.addresses, &previous.addresses, bank, 7))
        .and_then(|()| restore_encoded_bank(&mut egress.gateways, &previous.gateways, bank, 7))
        .and_then(|()| restore_encoded_bank(&mut egress.selections, &previous.selections, bank, 7));
    match rollback {
        Ok(()) => anyhow!("egress map update failed and staging bank was rolled back: {cause:#}"),
        Err(error) => anyhow!("egress map update failed: {cause:#}; rollback failed: {error:#}"),
    }
}

fn encode_egress_source_key(key: unf_ebpf_common::EgressSourceKey) -> [u8; 8] {
    let mut encoded = [0; 8];
    encoded[0..4].copy_from_slice(&key.source_identity.get().to_ne_bytes());
    encoded[4] = key.bank;
    encoded[5..8].copy_from_slice(&key.reserved);
    encoded
}

fn encode_egress_source_value(value: &unf_ebpf_common::EgressSourceValue) -> [u8; 128] {
    let mut encoded = [0; 128];
    for (offset, field) in [
        value.lease_epoch,
        value.contract_revision,
        value.intent_revision,
        value.identity_revision,
        value.policy_revision,
        value.allocation_revision,
        value.gateway_revision,
        value.reachability_revision,
    ]
    .into_iter()
    .enumerate()
    {
        encoded[offset * 8..offset * 8 + 8].copy_from_slice(&field.to_ne_bytes());
    }
    encoded[64..96].copy_from_slice(&value.contract_digest);
    encoded[96..112].copy_from_slice(&value.intent_digest);
    encoded[112..116].copy_from_slice(&value.intent_index.to_ne_bytes());
    encoded[116..118].copy_from_slice(&value.address_count.to_ne_bytes());
    encoded[118..120].copy_from_slice(&value.gateway_count.to_ne_bytes());
    encoded[120..122].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[122] = value.admission;
    encoded[123] = value.flags;
    encoded[124..128].copy_from_slice(&value.reserved);
    encoded
}

fn encode_egress_ipv4_destination(value: unf_ebpf_common::EgressIpv4DestinationData) -> [u8; 12] {
    let mut encoded = [0; 12];
    encoded[0..4].copy_from_slice(&value.intent_index.to_ne_bytes());
    encoded[4] = value.bank;
    encoded[5..8].copy_from_slice(&value.reserved);
    encoded[8..12].copy_from_slice(&value.destination_address);
    encoded
}

fn encode_egress_ipv6_destination(value: unf_ebpf_common::EgressIpv6DestinationData) -> [u8; 24] {
    let mut encoded = [0; 24];
    encoded[0..4].copy_from_slice(&value.intent_index.to_ne_bytes());
    encoded[4] = value.bank;
    encoded[5..8].copy_from_slice(&value.reserved);
    encoded[8..24].copy_from_slice(&value.destination_address);
    encoded
}

fn encode_egress_destination_value(value: &unf_ebpf_common::EgressDestinationValue) -> [u8; 32] {
    let mut encoded = [0; 32];
    encoded[0..8].copy_from_slice(&value.contract_revision.to_ne_bytes());
    encoded[8..24].copy_from_slice(&value.intent_digest);
    encoded[24..26].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[26..28].copy_from_slice(&value.flags.to_ne_bytes());
    encoded[28..32].copy_from_slice(&value.reserved);
    encoded
}

fn encode_egress_candidate_key(key: unf_ebpf_common::EgressCandidateKey) -> [u8; 8] {
    let mut encoded = [0; 8];
    encoded[0..4].copy_from_slice(&key.intent_index.to_ne_bytes());
    encoded[4..6].copy_from_slice(&key.candidate_index.to_ne_bytes());
    encoded[6] = key.address_family;
    encoded[7] = key.bank;
    encoded
}

fn encode_egress_address_value(value: &unf_ebpf_common::EgressAddressValue) -> [u8; 56] {
    let mut encoded = [0; 56];
    encoded[0..8].copy_from_slice(&value.lease_epoch.to_ne_bytes());
    encoded[8..16].copy_from_slice(&value.contract_revision.to_ne_bytes());
    encoded[16..32].copy_from_slice(&value.address);
    encoded[32..48].copy_from_slice(&value.candidate_witness);
    encoded[48..50].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[50..52].copy_from_slice(&value.flags.to_ne_bytes());
    encoded[52..56].copy_from_slice(&value.reserved);
    encoded
}

fn encode_egress_gateway_value(value: &unf_ebpf_common::EgressGatewayValue) -> [u8; 88] {
    let mut encoded = [0; 88];
    encoded[0..8].copy_from_slice(&value.lease_epoch.to_ne_bytes());
    encoded[8..16].copy_from_slice(&value.contract_revision.to_ne_bytes());
    encoded[16..24].copy_from_slice(&value.path_revision.to_ne_bytes());
    encoded[24..40].copy_from_slice(&value.transport_address);
    encoded[40..56].copy_from_slice(&value.next_hop_address);
    encoded[56..72].copy_from_slice(&value.gateway_digest);
    encoded[72..76].copy_from_slice(&value.output_interface.to_ne_bytes());
    encoded[76..80].copy_from_slice(&value.mtu.to_ne_bytes());
    encoded[80..82].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[82] = value.path_mode;
    encoded[83] = value.flags;
    encoded[84..88].copy_from_slice(&value.reserved);
    encoded
}

fn encode_egress_selection_key(key: unf_ebpf_common::EgressSelectionKey) -> [u8; 8] {
    let mut encoded = [0; 8];
    encoded[0..4].copy_from_slice(&key.intent_index.to_ne_bytes());
    encoded[4..6].copy_from_slice(&key.bucket.to_ne_bytes());
    encoded[6] = key.address_family;
    encoded[7] = key.bank;
    encoded
}

fn encode_egress_selection_value(value: &unf_ebpf_common::EgressSelectionValue) -> [u8; 32] {
    let mut encoded = [0; 32];
    encoded[0..16].copy_from_slice(&value.selection_witness);
    encoded[16..18].copy_from_slice(&value.address_index.to_ne_bytes());
    encoded[18..20].copy_from_slice(&value.primary_gateway_index.to_ne_bytes());
    encoded[20..22].copy_from_slice(&value.standby_gateway_index.to_ne_bytes());
    encoded[22..24].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[24..26].copy_from_slice(&value.flags.to_ne_bytes());
    encoded[26..32].copy_from_slice(&value.reserved);
    encoded
}

fn encode_egress_config(value: &unf_ebpf_common::EgressMapConfig) -> [u8; 56] {
    let mut encoded = [0; 56];
    for (offset, field) in [
        value.controller_epoch,
        value.projection_revision,
        value.contract_revision,
        value.path_revision,
    ]
    .into_iter()
    .enumerate()
    {
        encoded[offset * 8..offset * 8 + 8].copy_from_slice(&field.to_ne_bytes());
    }
    for (offset, field) in [
        value.source_count,
        value.address_count,
        value.gateway_count,
        value.selection_count,
    ]
    .into_iter()
    .enumerate()
    {
        let start = 32 + offset * 4;
        encoded[start..start + 4].copy_from_slice(&field.to_ne_bytes());
    }
    encoded[48..50].copy_from_slice(&value.schema_version.to_ne_bytes());
    encoded[50] = value.active_bank;
    encoded[51] = value.flags;
    encoded[52..56].copy_from_slice(&value.destination_count.to_ne_bytes());
    encoded
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

fn empty_node_port_bank(bank: u8) -> NodePortDataplaneState {
    NodePortDataplaneState {
        source_epoch: 0,
        service_revision: 0,
        node_revision: 0,
        service_bank: 0,
        bank,
        ipv4_frontends: BTreeMap::new(),
        ipv6_frontends: BTreeMap::new(),
        service_backend_slots: BTreeMap::new(),
        config: [0; 40],
    }
}

fn empty_recovered_load_balancer_bank(bank: u8) -> LoadBalancerDataplaneState {
    LoadBalancerDataplaneState {
        source_epoch: 0,
        service_revision: Revision::INITIAL,
        reachability_revision: Revision::INITIAL,
        allocation_revision: Revision::INITIAL,
        service_bank: 0,
        bank,
        ipv4_frontends: BTreeMap::new(),
        ipv6_frontends: BTreeMap::new(),
        ipv4_source_ranges: BTreeMap::new(),
        ipv6_source_ranges: BTreeMap::new(),
        config: [0; 48],
    }
}

fn reset_unlinked_recovered_load_balancer_state(services: &mut ServiceSynchronizer) -> Result<()> {
    services
        .load_balancer_config
        .set(0, [0; 48], 0)
        .context("deactivate unlinked persistent LoadBalancer config")?;
    for bank in [0_u8, 1_u8] {
        restore_load_balancer_bank(services, &empty_recovered_load_balancer_bank(bank))?;
    }
    discard_service_pending_state(&services.load_balancer_state_path)?;
    restore_load_balancer_checkpoint(&services.load_balancer_state_path, None)?;
    services.load_balancer_banks = [
        empty_recovered_load_balancer_bank(0),
        empty_recovered_load_balancer_bank(1),
    ]
    .map(Some);
    services.active_load_balancer_bank = 0;
    services.applied_load_balancer_reachability = None;
    Ok(())
}

type RecoveredLoadBalancerConfig = (u64, u64, u64, u64, u32, u32, u8, u8);

#[allow(clippy::too_many_lines)]
fn recover_load_balancer_state(services: &mut ServiceSynchronizer) -> Result<()> {
    let mut banks = [
        empty_recovered_load_balancer_bank(0),
        empty_recovered_load_balancer_bank(1),
    ];
    for entry in &services.load_balancer_ipv4_frontends {
        let (key, value) = entry.context("iterate persistent IPv4 LoadBalancer frontends")?;
        let bank = load_balancer_bank(key[7])?;
        validate_load_balancer_frontend_entry(&key, &value, 7)?;
        banks[bank].ipv4_frontends.insert(key, value);
    }
    for entry in &services.load_balancer_ipv6_frontends {
        let (key, value) = entry.context("iterate persistent IPv6 LoadBalancer frontends")?;
        let bank = load_balancer_bank(key[19])?;
        validate_load_balancer_frontend_entry(&key, &value, 19)?;
        banks[bank].ipv6_frontends.insert(key, value);
    }
    for bank in &banks {
        let count = bank
            .ipv4_frontends
            .len()
            .saturating_add(bank.ipv6_frontends.len());
        if count > LOAD_BALANCER_FRONTEND_BANK_CAPACITY {
            bail!(
                "persistent LoadBalancer bank {} has {count} frontends; limit is {LOAD_BALANCER_FRONTEND_BANK_CAPACITY}",
                bank.bank
            );
        }
    }
    let config = services
        .load_balancer_config
        .get(&0, 0)
        .context("read persistent LoadBalancer config")?;
    let decoded = decode_recovered_load_balancer_config(config)?;
    let pending_path = service_pending_state_path(&services.load_balancer_state_path)?;
    let Some((
        epoch,
        service_revision,
        reachability_revision,
        allocation_revision,
        ipv4_count,
        ipv6_count,
        bank,
        service_bank,
    )) = decoded
    else {
        for bank in [0_u8, 1_u8] {
            restore_load_balancer_bank(services, &empty_recovered_load_balancer_bank(bank))?;
        }
        discard_service_pending_state(&services.load_balancer_state_path)?;
        services.load_balancer_banks = [
            empty_recovered_load_balancer_bank(0),
            empty_recovered_load_balancer_bank(1),
        ]
        .map(Some);
        return Ok(());
    };
    let service = services
        .applied
        .as_ref()
        .context("persistent LoadBalancer state is active without service state")?;
    if service.source_epoch != epoch
        || service.revision.get() != service_revision
        || services.active_bank != service_bank
    {
        warn!(
            load_balancer_epoch = epoch,
            load_balancer_service_revision = service_revision,
            load_balancer_service_bank = service_bank,
            active_service_epoch = service.source_epoch,
            active_service_revision = service.revision.get(),
            active_service_bank = services.active_bank,
            "discarding unlinked derived LoadBalancer state after interrupted cross-domain activation"
        );
        return reset_unlinked_recovered_load_balancer_state(services);
    }
    let current = load_optional_load_balancer_reachability(&services.load_balancer_state_path)?;
    let pending = load_optional_load_balancer_reachability(&pending_path)?;
    let mut selected = None;
    for (is_pending, candidate) in [(false, current), (true, pending)] {
        let Some(candidate) = candidate else {
            continue;
        };
        if candidate.source_epoch == epoch
            && candidate.revision.get() == reachability_revision
            && candidate.allocation_revision.get() == allocation_revision
        {
            selected = Some((is_pending, candidate));
            break;
        }
    }
    let (selected_pending, durable) = selected.context(
        "persistent LoadBalancer activation tuple has no matching durable or prepared checkpoint",
    )?;
    let expected = match services.applied_selection_contract.as_ref() {
        Some(contract) => compile_load_balancer_selection_dataplane(
            service,
            &durable,
            contract,
            service_bank,
            bank,
        )?,
        None => compile_load_balancer_dataplane(service, &durable, service_bank, bank)?,
    };
    let active = &banks[usize::from(bank)];
    if active.ipv4_frontends != expected.ipv4_frontends
        || active.ipv6_frontends != expected.ipv6_frontends
        || config != expected.config
        || ipv4_count as usize != active.ipv4_frontends.len()
        || ipv6_count as usize != active.ipv6_frontends.len()
    {
        bail!("persistent active LoadBalancer bank does not match durable Node state");
    }
    if selected_pending {
        commit_prepared_service_snapshot(&services.load_balancer_state_path, &pending_path)?;
    } else {
        discard_service_pending_state(&services.load_balancer_state_path)?;
    }
    restore_lpm_bank(
        &mut services.load_balancer_ipv4_source_ranges,
        &expected.ipv4_source_ranges,
        bank,
    )?;
    restore_lpm_bank(
        &mut services.load_balancer_ipv6_source_ranges,
        &expected.ipv6_source_ranges,
        bank,
    )?;
    validate_lpm_bank(
        &services.load_balancer_ipv4_source_ranges,
        &expected.ipv4_source_ranges,
        bank,
    )
    .context("validate recovered IPv4 LoadBalancer source ranges")?;
    validate_lpm_bank(
        &services.load_balancer_ipv6_source_ranges,
        &expected.ipv6_source_ranges,
        bank,
    )
    .context("validate recovered IPv6 LoadBalancer source ranges")?;
    let inactive = (bank + 1) % unf_ebpf_common::LOAD_BALANCER_BANK_COUNT;
    restore_load_balancer_bank(services, &empty_recovered_load_balancer_bank(inactive))?;
    banks[usize::from(bank)] = expected;
    banks[usize::from(inactive)] = empty_recovered_load_balancer_bank(inactive);
    services.load_balancer_banks = banks.map(Some);
    services.active_load_balancer_bank = bank;
    services.applied_load_balancer_reachability = Some(durable);
    Ok(())
}

fn load_balancer_bank(bank: u8) -> Result<usize> {
    if bank >= unf_ebpf_common::LOAD_BALANCER_BANK_COUNT {
        bail!("persistent LoadBalancer map contains invalid bank {bank}");
    }
    Ok(usize::from(bank))
}

fn validate_load_balancer_frontend_entry<const K: usize>(
    key: &[u8; K],
    value: &[u8; 48],
    bank_offset: usize,
) -> Result<()> {
    let service_id = u32::from_ne_bytes(value[0..4].try_into().expect("fixed service ID"));
    let schema = u16::from_ne_bytes(value[12..14].try_into().expect("fixed schema"));
    let flags = u16::from_ne_bytes(value[14..16].try_into().expect("fixed flags"));
    let service_revision =
        u64::from_ne_bytes(value[16..24].try_into().expect("fixed service revision"));
    let reachability_revision = u64::from_ne_bytes(
        value[24..32]
            .try_into()
            .expect("fixed reachability revision"),
    );
    let allocation_revision =
        u64::from_ne_bytes(value[32..40].try_into().expect("fixed allocation revision"));
    let service_bank = value[40];
    let known_flags = unf_ebpf_common::LOAD_BALANCER_FRONTEND_FLAG_LOCAL
        | unf_ebpf_common::LOAD_BALANCER_FRONTEND_FLAG_SOURCE_RANGES
        | unf_ebpf_common::LOAD_BALANCER_FRONTEND_FLAG_CLIENT_IP_AFFINITY
        | unf_ebpf_common::LOAD_BALANCER_FRONTEND_FLAG_MAGLEV
        | unf_ebpf_common::LOAD_BALANCER_FRONTEND_FLAG_DSR;
    if service_id == 0
        || schema != unf_ebpf_common::LOAD_BALANCER_MAP_ABI_VERSION
        || flags & !known_flags != 0
        || service_revision == 0
        || reachability_revision == 0
        || allocation_revision == 0
        || service_bank >= SERVICE_BANK_COUNT
        || !service_selection_tier_is_valid(value[41])
        || !affinity_encoding_is_valid(
            flags & unf_ebpf_common::LOAD_BALANCER_FRONTEND_FLAG_CLIENT_IP_AFFINITY != 0,
            value[42..46].try_into().expect("fixed affinity timeout"),
            &value[46..48],
        )
        || !matches!(key[bank_offset - 1], 6 | 17)
    {
        bail!("persistent LoadBalancer frontend contains an incompatible value");
    }
    load_balancer_bank(key[bank_offset]).map(|_| ())
}

fn decode_recovered_load_balancer_config(
    config: [u8; 48],
) -> Result<Option<RecoveredLoadBalancerConfig>> {
    if config == [0; 48] {
        return Ok(None);
    }
    let epoch = u64::from_ne_bytes(config[0..8].try_into().expect("fixed epoch"));
    let service_revision =
        u64::from_ne_bytes(config[8..16].try_into().expect("fixed service revision"));
    let reachability_revision = u64::from_ne_bytes(
        config[16..24]
            .try_into()
            .expect("fixed reachability revision"),
    );
    let allocation_revision = u64::from_ne_bytes(
        config[24..32]
            .try_into()
            .expect("fixed allocation revision"),
    );
    let ipv4_count = u32::from_ne_bytes(config[32..36].try_into().expect("fixed IPv4 count"));
    let ipv6_count = u32::from_ne_bytes(config[36..40].try_into().expect("fixed IPv6 count"));
    let schema = u16::from_ne_bytes(config[40..42].try_into().expect("fixed schema"));
    let bank = config[42];
    let service_bank = config[43];
    if epoch == 0
        || service_revision == 0
        || reachability_revision == 0
        || schema != unf_ebpf_common::LOAD_BALANCER_MAP_ABI_VERSION
        || bank >= unf_ebpf_common::LOAD_BALANCER_BANK_COUNT
        || service_bank >= SERVICE_BANK_COUNT
        || config[44..48] != [0; 4]
    {
        bail!("persistent LoadBalancer config is incompatible");
    }
    Ok(Some((
        epoch,
        service_revision,
        reachability_revision,
        allocation_revision,
        ipv4_count,
        ipv6_count,
        bank,
        service_bank,
    )))
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

    let mut node_port_banks = [empty_node_port_bank(0), empty_node_port_bank(1)];
    for entry in &services.node_port_ipv4_frontends {
        let (key, value) = entry.context("iterate persistent IPv4 NodePort frontends")?;
        let bank = node_port_bank(key[7])?;
        validate_node_port_frontend_entry(&key, &value, 7)?;
        node_port_banks[bank].ipv4_frontends.insert(key, value);
    }
    for entry in &services.node_port_ipv6_frontends {
        let (key, value) = entry.context("iterate persistent IPv6 NodePort frontends")?;
        let bank = node_port_bank(key[19])?;
        validate_node_port_frontend_entry(&key, &value, 19)?;
        node_port_banks[bank].ipv6_frontends.insert(key, value);
    }
    for bank in &node_port_banks {
        validate_recovered_node_port_bank_capacity(bank)?;
    }

    let config = services
        .config
        .get(&0, 0)
        .context("read persistent service config")?;
    let node_port_config = services
        .node_port_config
        .get(&0, 0)
        .context("read persistent NodePort config")?;
    let decoded_node_port = decode_recovered_node_port_config(node_port_config)?;
    let Some((epoch, revision, _frontend_count, _backend_count, _slot_count, bank)) =
        decode_recovered_service_config(config)?
    else {
        if decoded_node_port.is_some() {
            bail!("persistent NodePort state is active without service state");
        }
        discard_service_pending_state(&services.state_path)?;
        services.banks = banks.map(Some);
        services.node_port_banks = node_port_banks.map(Some);
        return Ok((None, None));
    };
    let pending_path = service_pending_state_path(&services.state_path)?;
    let current = load_optional_service_checkpoint(&services.state_path)?;
    let pending = load_optional_service_checkpoint(&pending_path)?;
    let mut selected = None;
    for (is_pending, checkpoint) in [(false, current.clone()), (true, pending.clone())] {
        let Some((durable, node)) = checkpoint else {
            continue;
        };
        if durable.source_epoch != epoch || durable.revision.get() != revision {
            continue;
        }
        let node_matches = match (&node, decoded_node_port) {
            (None, None) => true,
            (Some(node), None) => {
                !service_has_node_ports(&durable)
                    && service_requires_local_node(&durable)
                    && node.source_epoch == durable.source_epoch
            }
            (Some(node), Some((node_epoch, service_revision, node_revision, _, _, _))) => {
                service_has_node_ports(&durable)
                    && node.source_epoch == node_epoch
                    && revision == service_revision
                    && node.revision.get() == node_revision
            }
            _ => false,
        };
        if node_matches {
            selected = Some((is_pending, durable, node));
            break;
        }
    }
    if selected.is_none()
        && let (Some((current_service, current_node)), Some((pending_service, pending_node))) =
            (current.clone(), pending.clone())
        && pending_service.source_epoch == epoch
        && pending_service.revision.get() == revision
        && checkpoint_matches_node_port_config(
            &current_service,
            current_node.as_ref(),
            decoded_node_port,
        )
    {
        let previous_service_bank = (bank + 1) % SERVICE_BANK_COUNT;
        let current_node_port_bank = decoded_node_port.map(|config| config.5);
        let expected_current = compile_recovered_service_fabrics(
            &services.state_path,
            &current_service,
            current_node.as_ref(),
            previous_service_bank,
            current_node_port_bank,
        )?
        .into_iter()
        .find(|candidate| {
            service_bank_matches(
                &banks[usize::from(previous_service_bank)],
                &candidate.service,
            )
        })
        .context("current service checkpoint does not match its inactive recovery bank")?;
        let pending_node_port_bank =
            decoded_node_port.map(|config| (config.5 + 1) % unf_ebpf_common::NODE_PORT_BANK_COUNT);
        let expected_pending = compile_recovered_service_fabrics(
            &services.state_path,
            &pending_service,
            pending_node.as_ref(),
            bank,
            pending_node_port_bank,
        )?
        .into_iter()
        .find(|candidate| service_bank_matches(&banks[usize::from(bank)], &candidate.service))
        .context("pending service checkpoint does not match its active recovery bank")?;
        let expected_current_service = expected_current.service;
        let expected_pending_service = expected_pending.service;
        if !service_bank_matches(
            &banks[usize::from(previous_service_bank)],
            &expected_current_service,
        ) || !service_bank_matches(&banks[usize::from(bank)], &expected_pending_service)
            || config != expected_pending_service.config
        {
            bail!("interrupted service activation cannot be rolled back from exact map state");
        }
        services
            .config
            .set(0, expected_current_service.config, 0)
            .context("roll back interrupted service activation pointer")?;
        restore_service_bank(services, &empty_service_bank(bank))?;
        banks[usize::from(previous_service_bank)] = expected_current_service;
        banks[usize::from(bank)] = empty_service_bank(bank);
        if let (Some(pending_node_port), Some(pending_node_port_bank)) =
            (expected_pending.node_port, pending_node_port_bank)
            && node_port_bank_matches(
                &node_port_banks[usize::from(pending_node_port_bank)],
                &pending_node_port,
            )
        {
            restore_node_port_bank(services, &empty_node_port_bank(pending_node_port_bank))?;
            node_port_banks[usize::from(pending_node_port_bank)] =
                empty_node_port_bank(pending_node_port_bank);
        }
        discard_service_pending_state(&services.state_path)?;
        selected = Some((false, current_service, current_node));
    }
    let (selected_pending, durable, node) = selected.context(
        "persistent service/NodePort activation tuple has no matching durable or prepared checkpoint",
    )?;
    let recovered_config = services
        .config
        .get(&0, 0)
        .context("read repaired persistent service config")?;
    let (epoch, revision, frontend_count, backend_count, slot_count, bank) =
        decode_recovered_service_config(recovered_config)?
            .context("repaired persistent service config became empty")?;
    if durable.source_epoch != epoch || durable.revision.get() != revision {
        bail!("repaired service config does not match selected durable checkpoint");
    }
    let active_node_port_bank = decoded_node_port.map(|config| config.5);
    let candidates = compile_recovered_service_fabrics(
        &services.state_path,
        &durable,
        node.as_ref(),
        bank,
        active_node_port_bank,
    )?;
    let mut matched = candidates.into_iter().filter(|candidate| {
        let active = &banks[usize::from(candidate.service.bank)];
        service_bank_matches(active, &candidate.service)
            && recovered_config == candidate.service.config
            && match (&candidate.node_port, decoded_node_port) {
                (Some(expected), Some((_, _, _, _, _, node_port_bank))) => {
                    let active = &node_port_banks[usize::from(node_port_bank)];
                    node_port_bank_matches(active, expected) && node_port_config == expected.config
                }
                (None, None) => true,
                _ => false,
            }
    });
    let selected_fabric = matched
        .next()
        .context("persistent active service bank does not match any durable selection contract")?;
    if matched.next().is_some() {
        bail!("persistent active service bank ambiguously matches multiple selection contracts");
    }
    let RecoveredServiceFabric {
        selection: recovered_selection,
        service: expected,
        node_port: expected_node_port,
    } = selected_fabric;
    let active_service_bank = expected.bank;
    let active = &banks[usize::from(active_service_bank)];
    if !service_bank_matches(active, &expected) || recovered_config != expected.config {
        bail!("persistent active service bank does not match durable last-known-good snapshot");
    }
    if frontend_count as usize != active.ipv4_frontends.len() + active.ipv6_frontends.len()
        || backend_count as usize != active.ipv4_backends.len() + active.ipv6_backends.len()
        || slot_count as usize != active.backend_slots.len()
    {
        bail!("persistent service config counts do not match active maps");
    }
    if let Some(expected_node_port) = &expected_node_port {
        let (_, _, _, ipv4_count, ipv6_count, node_port_bank) =
            decoded_node_port.expect("NodePort config was checked above");
        let active_node_port = &node_port_banks[usize::from(node_port_bank)];
        if active_node_port.ipv4_frontends != expected_node_port.ipv4_frontends
            || active_node_port.ipv6_frontends != expected_node_port.ipv6_frontends
            || node_port_config != expected_node_port.config
            || ipv4_count as usize != active_node_port.ipv4_frontends.len()
            || ipv6_count as usize != active_node_port.ipv6_frontends.len()
        {
            bail!("persistent active NodePort bank does not match durable local Node state");
        }
        node_port_banks[usize::from(node_port_bank)] = expected_node_port.clone();
        services.active_node_port_bank = node_port_bank;
    }
    if selected_pending {
        commit_prepared_service_snapshot(&services.state_path, &pending_path)?;
    } else {
        discard_service_pending_state(&services.state_path)?;
    }
    banks[usize::from(active_service_bank)] = expected;
    services.banks = banks.map(Some);
    services.node_port_banks = node_port_banks.map(Some);
    services.active_bank = active_service_bank;
    services.applied = Some(durable);
    services
        .load_balancer_node_source
        .set(0, encode_load_balancer_node_source(node.as_ref()), 0)
        .context("restore runtime LoadBalancer Node source addresses")?;
    services.applied_node_port_node = node;
    if let Some((_, checkpoint)) = recovered_selection {
        services.applied_selection_contract = Some(checkpoint.contract);
    }
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

fn validate_recovered_node_port_bank_capacity(bank: &NodePortDataplaneState) -> Result<()> {
    for (name, actual) in [
        ("IPv4 frontends", bank.ipv4_frontends.len()),
        ("IPv6 frontends", bank.ipv6_frontends.len()),
    ] {
        if actual > SERVICE_FRONTEND_BANK_CAPACITY {
            bail!(
                "persistent NodePort bank {} has {actual} {name}; limit is {}",
                bank.bank,
                SERVICE_FRONTEND_BANK_CAPACITY
            );
        }
    }
    Ok(())
}

fn service_bank_matches(actual: &ServiceDataplaneState, expected: &ServiceDataplaneState) -> bool {
    actual.ipv4_frontends == expected.ipv4_frontends
        && actual.ipv6_frontends == expected.ipv6_frontends
        && actual.ipv4_backends == expected.ipv4_backends
        && actual.ipv6_backends == expected.ipv6_backends
        && actual.backend_slots == expected.backend_slots
}

fn node_port_bank_matches(
    actual: &NodePortDataplaneState,
    expected: &NodePortDataplaneState,
) -> bool {
    actual.ipv4_frontends == expected.ipv4_frontends
        && actual.ipv6_frontends == expected.ipv6_frontends
}

fn checkpoint_matches_node_port_config(
    service: &ServiceSnapshot,
    node: Option<&NodePortNodeSnapshot>,
    config: Option<RecoveredNodePortConfig>,
) -> bool {
    match (node, config) {
        (None, None) => !service_has_node_ports(service),
        (Some(node), None) => {
            !service_has_node_ports(service)
                && service_requires_local_node(service)
                && node.source_epoch == service.source_epoch
        }
        (Some(node), Some((epoch, service_revision, node_revision, _, _, _))) => {
            service_has_node_ports(service)
                && node.source_epoch == epoch
                && service.revision.get() == service_revision
                && node.revision.get() == node_revision
        }
        _ => false,
    }
}

fn service_bank(bank: u8) -> Result<usize> {
    if bank >= SERVICE_BANK_COUNT {
        bail!("persistent service map contains invalid bank {bank}");
    }
    Ok(usize::from(bank))
}

fn node_port_bank(bank: u8) -> Result<usize> {
    if bank >= unf_ebpf_common::NODE_PORT_BANK_COUNT {
        bail!("persistent NodePort map contains invalid bank {bank}");
    }
    Ok(usize::from(bank))
}

fn affinity_encoding_is_valid(enabled: bool, timeout: [u8; 4], trailing: &[u8]) -> bool {
    let timeout = u32::from_ne_bytes(timeout);
    enabled
        == (SERVICE_AFFINITY_MIN_TIMEOUT_SECONDS..=SERVICE_AFFINITY_MAX_TIMEOUT_SECONDS)
            .contains(&timeout)
        && trailing.iter().all(|byte| *byte == 0)
}

fn validate_node_port_frontend_entry<const N: usize>(
    key: &[u8; N],
    value: &[u8; 32],
    bank_offset: usize,
) -> Result<()> {
    node_port_bank(key[bank_offset])?;
    let port_offset = bank_offset - 3;
    let port = u16::from_be_bytes(key[port_offset..port_offset + 2].try_into().unwrap());
    let protocol = key[bank_offset - 1];
    let service_id = u32::from_ne_bytes(value[0..4].try_into().unwrap());
    let frontend_index = u32::from_ne_bytes(value[4..8].try_into().unwrap());
    let backend_count = u32::from_ne_bytes(value[8..12].try_into().unwrap());
    let schema = u16::from_ne_bytes(value[12..14].try_into().unwrap());
    let flags = u16::from_ne_bytes(value[14..16].try_into().unwrap());
    let service_revision = u64::from_ne_bytes(value[16..24].try_into().unwrap());
    if !recovered_service_address_is_valid(&key[..port_offset])
        || port == 0
        || !matches!(protocol, 6 | 17)
        || service_id == 0
        || backend_count > u32::try_from(SERVICE_BACKEND_SLOT_BANK_CAPACITY).unwrap_or(u32::MAX)
        || schema != unf_ebpf_common::NODE_PORT_MAP_ABI_VERSION
        || flags
            & !(unf_ebpf_common::NODE_PORT_FRONTEND_FLAG_LOCAL
                | unf_ebpf_common::NODE_PORT_FRONTEND_FLAG_CLIENT_IP_AFFINITY
                | unf_ebpf_common::NODE_PORT_FRONTEND_FLAG_MAGLEV)
            != 0
        || (flags & unf_ebpf_common::NODE_PORT_FRONTEND_FLAG_LOCAL != 0
            && frontend_index & unf_ebpf_common::NODE_PORT_LOCAL_FRONTEND_INDEX_FLAG == 0)
        || service_revision == 0
        || value[24] >= SERVICE_BANK_COUNT
        || !service_selection_tier_is_valid(value[25])
        || !affinity_encoding_is_valid(
            flags & unf_ebpf_common::NODE_PORT_FRONTEND_FLAG_CLIENT_IP_AFFINITY != 0,
            value[26..30].try_into().expect("fixed affinity timeout"),
            &value[30..32],
        )
    {
        bail!("persistent NodePort frontend map contains an incompatible entry");
    }
    Ok(())
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
    let flags = u16::from_ne_bytes(value[14..16].try_into().unwrap());
    let revision = u64::from_ne_bytes(value[16..24].try_into().unwrap());
    if !recovered_service_address_is_valid(&key[..port_offset])
        || port == 0
        || !matches!(protocol, 6 | 17 | 132)
        || service_id == 0
        || backend_count > u32::try_from(SERVICE_BACKEND_SLOT_BANK_CAPACITY).unwrap_or(u32::MAX)
        || schema != SERVICE_MAP_ABI_VERSION
        || flags
            & !(unf_ebpf_common::SERVICE_FRONTEND_FLAG_CLIENT_IP_AFFINITY
                | unf_ebpf_common::SERVICE_FRONTEND_FLAG_MAGLEV)
            != 0
        || revision == 0
        || !service_selection_tier_is_valid(value[24])
        || !affinity_encoding_is_valid(
            flags & unf_ebpf_common::SERVICE_FRONTEND_FLAG_CLIENT_IP_AFFINITY != 0,
            value[25..29].try_into().expect("fixed affinity timeout"),
            &value[29..32],
        )
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

fn decode_recovered_node_port_config(config: [u8; 40]) -> Result<Option<RecoveredNodePortConfig>> {
    if config == [0; 40] {
        return Ok(None);
    }
    let epoch = u64::from_ne_bytes(config[0..8].try_into().unwrap());
    let service_revision = u64::from_ne_bytes(config[8..16].try_into().unwrap());
    let node_revision = u64::from_ne_bytes(config[16..24].try_into().unwrap());
    let ipv4_count = u32::from_ne_bytes(config[24..28].try_into().unwrap());
    let ipv6_count = u32::from_ne_bytes(config[28..32].try_into().unwrap());
    let schema = u16::from_ne_bytes(config[32..34].try_into().unwrap());
    let bank = config[34];
    if epoch == 0
        || service_revision == 0
        || node_revision == 0
        || schema != unf_ebpf_common::NODE_PORT_MAP_ABI_VERSION
        || bank >= unf_ebpf_common::NODE_PORT_BANK_COUNT
        || config[35..40] != [0; 5]
    {
        bail!("persistent NodePort config is invalid or incompatible");
    }
    Ok(Some((
        epoch,
        service_revision,
        node_revision,
        ipv4_count,
        ipv6_count,
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
        publish_recovered_selection_contract(
            state,
            services.applied_selection_contract.as_ref(),
            services.active_selection_bank,
        );
    }
    if let Some(snapshot) = &services.applied_load_balancer_reachability
        && let Some(dataplane) =
            &services.load_balancer_banks[usize::from(services.active_load_balancer_bank)]
    {
        publish_desired_load_balancer(state, snapshot);
        publish_applied_load_balancer(state, snapshot, dataplane);
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

fn take_egress_maps(ebpf: &mut Ebpf) -> Result<EgressMaps> {
    let sources = AyaHashMap::<_, [u8; 8], [u8; 128]>::try_from(
        ebpf.take_map("EGRESS_SOURCES")
            .context("eBPF object does not contain EGRESS_SOURCES map")?,
    )
    .context("open EGRESS_SOURCES map")?;
    let ipv4_destinations = AyaLpmTrie::<_, [u8; 12], [u8; 32]>::try_from(
        ebpf.take_map("EGRESS_DESTINATIONS_V4")
            .context("eBPF object does not contain EGRESS_DESTINATIONS_V4 map")?,
    )
    .context("open EGRESS_DESTINATIONS_V4 map")?;
    let ipv6_destinations = AyaLpmTrie::<_, [u8; 24], [u8; 32]>::try_from(
        ebpf.take_map("EGRESS_DESTINATIONS_V6")
            .context("eBPF object does not contain EGRESS_DESTINATIONS_V6 map")?,
    )
    .context("open EGRESS_DESTINATIONS_V6 map")?;
    let addresses = AyaHashMap::<_, [u8; 8], [u8; 56]>::try_from(
        ebpf.take_map("EGRESS_ADDRESSES")
            .context("eBPF object does not contain EGRESS_ADDRESSES map")?,
    )
    .context("open EGRESS_ADDRESSES map")?;
    let gateways = AyaHashMap::<_, [u8; 8], [u8; 88]>::try_from(
        ebpf.take_map("EGRESS_GATEWAYS")
            .context("eBPF object does not contain EGRESS_GATEWAYS map")?,
    )
    .context("open EGRESS_GATEWAYS map")?;
    let selections = AyaHashMap::<_, [u8; 8], [u8; 32]>::try_from(
        ebpf.take_map("EGRESS_SELECTIONS")
            .context("eBPF object does not contain EGRESS_SELECTIONS map")?,
    )
    .context("open EGRESS_SELECTIONS map")?;
    let config = AyaArray::<_, [u8; 56]>::try_from(
        ebpf.take_map("EGRESS_CONFIG")
            .context("eBPF object does not contain EGRESS_CONFIG map")?,
    )
    .context("open EGRESS_CONFIG map")?;
    let gateway_nat_sources = AyaHashMap::<_, [u8; 8], [u8; 128]>::try_from(
        ebpf.take_map("EGRESS_GATEWAY_NAT_SOURCES")
            .context("eBPF object does not contain EGRESS_GATEWAY_NAT_SOURCES map")?,
    )
    .context("open EGRESS_GATEWAY_NAT_SOURCES map")?;
    let gateway_nat_ipv4_destinations = AyaLpmTrie::<_, [u8; 12], [u8; 32]>::try_from(
        ebpf.take_map("EGRESS_GATEWAY_NAT_DESTINATIONS_V4")
            .context("eBPF object does not contain EGRESS_GATEWAY_NAT_DESTINATIONS_V4 map")?,
    )
    .context("open EGRESS_GATEWAY_NAT_DESTINATIONS_V4 map")?;
    let gateway_nat_ipv6_destinations = AyaLpmTrie::<_, [u8; 24], [u8; 32]>::try_from(
        ebpf.take_map("EGRESS_GATEWAY_NAT_DESTINATIONS_V6")
            .context("eBPF object does not contain EGRESS_GATEWAY_NAT_DESTINATIONS_V6 map")?,
    )
    .context("open EGRESS_GATEWAY_NAT_DESTINATIONS_V6 map")?;
    let gateway_nat_addresses = AyaHashMap::<_, [u8; 8], [u8; 56]>::try_from(
        ebpf.take_map("EGRESS_GATEWAY_NAT_ADDRESSES")
            .context("eBPF object does not contain EGRESS_GATEWAY_NAT_ADDRESSES map")?,
    )
    .context("open EGRESS_GATEWAY_NAT_ADDRESSES map")?;
    let gateway_nat_gateways = AyaHashMap::<_, [u8; 8], [u8; 88]>::try_from(
        ebpf.take_map("EGRESS_GATEWAY_NAT_GATEWAYS")
            .context("eBPF object does not contain EGRESS_GATEWAY_NAT_GATEWAYS map")?,
    )
    .context("open EGRESS_GATEWAY_NAT_GATEWAYS map")?;
    let gateway_nat_selections = AyaHashMap::<_, [u8; 8], [u8; 32]>::try_from(
        ebpf.take_map("EGRESS_GATEWAY_NAT_SELECTIONS")
            .context("eBPF object does not contain EGRESS_GATEWAY_NAT_SELECTIONS map")?,
    )
    .context("open EGRESS_GATEWAY_NAT_SELECTIONS map")?;
    let gateway_nat_config = AyaArray::<_, [u8; 56]>::try_from(
        ebpf.take_map("EGRESS_GATEWAY_NAT_CONFIG")
            .context("eBPF object does not contain EGRESS_GATEWAY_NAT_CONFIG map")?,
    )
    .context("open EGRESS_GATEWAY_NAT_CONFIG map")?;
    let connections = AyaHashMap::<_, [u8; 44], [u8; 208]>::try_from(
        ebpf.take_map("EGRESS_CONNECTIONS")
            .context("eBPF object does not contain EGRESS_CONNECTIONS map")?,
    )
    .context("open EGRESS_CONNECTIONS map")?;
    Ok((
        sources,
        ipv4_destinations,
        ipv6_destinations,
        addresses,
        gateways,
        selections,
        config,
        gateway_nat_sources,
        gateway_nat_ipv4_destinations,
        gateway_nat_ipv6_destinations,
        gateway_nat_addresses,
        gateway_nat_gateways,
        gateway_nat_selections,
        gateway_nat_config,
        connections,
    ))
}

fn take_service_affinity_map(ebpf: &mut Ebpf) -> Result<ServiceAffinityMap> {
    AyaHashMap::<_, [u8; 40], [u8; 32]>::try_from(
        ebpf.take_map("SERVICE_AFFINITY")
            .context("eBPF object does not contain SERVICE_AFFINITY map")?,
    )
    .context("open SERVICE_AFFINITY map")
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
    let connections = AyaHashMap::<_, [u8; 40], [u8; 104]>::try_from(
        ebpf.take_map("SERVICE_CONNECTIONS")
            .context("eBPF object does not contain SERVICE_CONNECTIONS map")?,
    )
    .context("open SERVICE_CONNECTIONS map")?;
    let affinity = take_service_affinity_map(ebpf)?;
    let node_port_ipv4_frontends = AyaHashMap::<_, [u8; 8], [u8; 32]>::try_from(
        ebpf.take_map("NODE_PORT_FRONTENDS_V4")
            .context("eBPF object does not contain NODE_PORT_FRONTENDS_V4 map")?,
    )
    .context("open NODE_PORT_FRONTENDS_V4 map")?;
    let node_port_ipv6_frontends = AyaHashMap::<_, [u8; 20], [u8; 32]>::try_from(
        ebpf.take_map("NODE_PORT_FRONTENDS_V6")
            .context("eBPF object does not contain NODE_PORT_FRONTENDS_V6 map")?,
    )
    .context("open NODE_PORT_FRONTENDS_V6 map")?;
    let node_port_config = AyaArray::<_, [u8; 40]>::try_from(
        ebpf.take_map("NODE_PORT_CONFIG")
            .context("eBPF object does not contain NODE_PORT_CONFIG map")?,
    )
    .context("open NODE_PORT_CONFIG map")?;
    let load_balancer_ipv4_frontends = AyaHashMap::<_, [u8; 8], [u8; 48]>::try_from(
        ebpf.take_map("LOAD_BALANCER_FRONTENDS_V4")
            .context("eBPF object does not contain LOAD_BALANCER_FRONTENDS_V4 map")?,
    )
    .context("open LOAD_BALANCER_FRONTENDS_V4 map")?;
    let load_balancer_ipv6_frontends = AyaHashMap::<_, [u8; 20], [u8; 48]>::try_from(
        ebpf.take_map("LOAD_BALANCER_FRONTENDS_V6")
            .context("eBPF object does not contain LOAD_BALANCER_FRONTENDS_V6 map")?,
    )
    .context("open LOAD_BALANCER_FRONTENDS_V6 map")?;
    let load_balancer_ipv4_source_ranges = AyaLpmTrie::<_, [u8; 12], [u8; 32]>::try_from(
        ebpf.take_map("LOAD_BALANCER_SOURCE_RANGES_V4")
            .context("eBPF object does not contain LOAD_BALANCER_SOURCE_RANGES_V4 map")?,
    )
    .context("open LOAD_BALANCER_SOURCE_RANGES_V4 map")?;
    let load_balancer_ipv6_source_ranges = AyaLpmTrie::<_, [u8; 24], [u8; 32]>::try_from(
        ebpf.take_map("LOAD_BALANCER_SOURCE_RANGES_V6")
            .context("eBPF object does not contain LOAD_BALANCER_SOURCE_RANGES_V6 map")?,
    )
    .context("open LOAD_BALANCER_SOURCE_RANGES_V6 map")?;
    let load_balancer_config = AyaArray::<_, [u8; 48]>::try_from(
        ebpf.take_map("LOAD_BALANCER_CONFIG")
            .context("eBPF object does not contain LOAD_BALANCER_CONFIG map")?,
    )
    .context("open LOAD_BALANCER_CONFIG map")?;
    let load_balancer_node_source = AyaArray::<_, [u8; 40]>::try_from(
        ebpf.take_map("LOAD_BALANCER_NODE_SOURCE")
            .context("eBPF object does not contain LOAD_BALANCER_NODE_SOURCE map")?,
    )
    .context("open LOAD_BALANCER_NODE_SOURCE map")?;
    Ok((
        ipv4_frontends,
        ipv6_frontends,
        ipv4_backends,
        ipv6_backends,
        backend_slots,
        config,
        connections,
        affinity,
        node_port_ipv4_frontends,
        node_port_ipv6_frontends,
        node_port_config,
        load_balancer_ipv4_frontends,
        load_balancer_ipv6_frontends,
        load_balancer_ipv4_source_ranges,
        load_balancer_ipv6_source_ranges,
        load_balancer_config,
        load_balancer_node_source,
    ))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn consume_events(
    mut flow_ring: RingBuf<aya::maps::MapData>,
    mut service_ring: RingBuf<aya::maps::MapData>,
    mut egress_ring: RingBuf<aya::maps::MapData>,
    egress_event_counters: AyaPerCpuArray<aya::maps::MapData, u64>,
    attachments: &mut InterfaceAttachments<'_>,
    identities: &mut IdentitySynchronizer,
    policies: &mut PolicySynchronizer,
    services: &mut ServiceSynchronizer,
    egress: &mut EgressSynchronizer,
    state: &AgentState,
    flow_export_sender: Option<&mpsc::Sender<FlowExportRecord>>,
    cancellation: CancellationToken,
) {
    let mut observed_egress_attempts = 0_u64;
    let mut observed_egress_ring_drops = 0_u64;
    let mut event_interval = tokio::time::interval(Duration::from_millis(25));
    let mut egress_loss_interval = tokio::time::interval(Duration::from_secs(1));
    let mut interface_interval = tokio::time::interval(Duration::from_secs(1));
    let mut identity_interval = tokio::time::interval(identities.interval);
    let mut policy_interval = tokio::time::interval(policies.interval);
    let mut service_interval = tokio::time::interval(services.interval);
    let mut egress_interval = tokio::time::interval(egress.interval);
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
                // A failed Service activation can mean its inactive bank is still referenced by
                // last-known-good LoadBalancer state. Reconcile that derived state against the
                // currently applied Service tuple even after the Service attempt fails; otherwise
                // the two-bank domains wait on each other forever after controller recovery.
                if let Err(error) = synchronize_load_balancer_maps(services, state).await {
                    record_load_balancer_error(state, &error);
                    warn!(%error, "LoadBalancer host-state synchronization failed; retaining active bank");
                }
            }
            _ = egress_interval.tick(), if egress.controller_url.is_some() => {
                if let Err(error) = synchronize_egress(egress, state).await {
                    warn!(%error, "egress synchronization failed; active source state was fenced when possible");
                }
            }
            _ = egress_loss_interval.tick() => {
                refresh_egress_event_loss(
                    &egress_event_counters,
                    state,
                    &mut observed_egress_attempts,
                    &mut observed_egress_ring_drops,
                );
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
                drain_egress_events(&mut egress_ring, state);
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
            frontend_kind = ?service_event_frontend_kind(&event),
            "service dataplane outcome"
        );
    }
}

fn drain_egress_events(ring: &mut RingBuf<MapData>, state: &AgentState) {
    while let Some(item) = ring.next() {
        let Some(event) = decode_egress_event(&item) else {
            state.metrics.invalid_egress_events.inc();
            continue;
        };
        state.metrics.egress_dataplane_events.inc();
        match event.action {
            EGRESS_EVENT_ACTION_CREATE => {
                state.metrics.egress_nat_creations.inc();
            }
            EGRESS_EVENT_ACTION_DROP => {
                state.metrics.egress_nat_drops.inc();
            }
            EGRESS_EVENT_ACTION_EXPIRE => {
                state.metrics.egress_nat_expirations.inc();
            }
            _ => unreachable!("validated egress event action"),
        }
        info!(
            source_identity = event.source_identity.get(),
            contract_revision = event.contract_revision,
            lease_epoch = event.lease_epoch,
            source = ?event.original_source_address,
            destination = ?event.original_destination_address,
            egress_address = ?event.egress_address,
            egress_ipv4 = ?event_ipv4(event.address_family, event.egress_address),
            egress_ipv6 = ?event_ipv6(event.address_family, event.egress_address),
            source_port = u16::from_be_bytes(event.original_source_port),
            destination_port = u16::from_be_bytes(event.original_destination_port),
            translated_source_port = u16::from_be_bytes(event.translated_source_port),
            protocol = event.protocol,
            address_family = event.address_family,
            address_index = event.address_index,
            primary_gateway_index = event.primary_gateway_index,
            standby_gateway_index = event.standby_gateway_index,
            gateway_digest = ?event.gateway_digest,
            standby_gateway_digest = ?event.standby_gateway_digest,
            proof_witness = ?event.proof_witness,
            action = event.action,
            reason = event.reason,
            "egress NAT lifecycle outcome"
        );
    }
}

fn refresh_egress_event_loss(
    counters: &AyaPerCpuArray<MapData, u64>,
    state: &AgentState,
    observed_attempts: &mut u64,
    observed_drops: &mut u64,
) {
    let read_total = |index| {
        counters
            .get(&index, 0)
            .map(|values| values.iter().copied().fold(0_u64, u64::saturating_add))
    };
    let Ok(attempts) = read_total(EGRESS_EVENT_COUNTER_ATTEMPTED) else {
        return;
    };
    let Ok(drops) = read_total(EGRESS_EVENT_COUNTER_DROPPED) else {
        return;
    };
    state
        .metrics
        .egress_event_attempts
        .inc_by(attempts.saturating_sub(*observed_attempts));
    state
        .metrics
        .egress_event_ring_drops
        .inc_by(drops.saturating_sub(*observed_drops));
    *observed_attempts = attempts;
    *observed_drops = drops;
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
    let frontend_kind = service_event_frontend_kind(event);
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
                frontend_kind,
                selection_tier: service_event_selection_tier(event),
                affinity_outcome: service_event_affinity_outcome(event),
                selection_algorithm: service_event_selection_algorithm(event),
                forwarding_mode: service_event_forwarding_mode(event),
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
            frontend_kind,
            selection_tier: service_event_selection_tier(event),
            affinity_outcome: service_event_affinity_outcome(event),
            selection_algorithm: service_event_selection_algorithm(event),
            forwarding_mode: service_event_forwarding_mode(event),
        }),
        observed_events: 1,
    }
}

fn service_event_frontend_kind(event: &ServiceEvent) -> ServiceFrontendKind {
    match event.reserved[0] {
        SERVICE_EVENT_FRONTEND_CLUSTER_IP => ServiceFrontendKind::ClusterIp,
        SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER => ServiceFrontendKind::NodePortCluster,
        SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL => ServiceFrontendKind::NodePortLocal,
        SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER => ServiceFrontendKind::LoadBalancerCluster,
        SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL => ServiceFrontendKind::LoadBalancerLocal,
        _ => unreachable!("validated service event frontend kind"),
    }
}

fn service_event_selection_tier(event: &ServiceEvent) -> ServiceSelectionTier {
    match event.reserved[1] {
        unf_ebpf_common::SERVICE_SELECTION_TIER_SAME_NODE => ServiceSelectionTier::SameNode,
        unf_ebpf_common::SERVICE_SELECTION_TIER_SAME_ZONE => ServiceSelectionTier::SameZone,
        unf_ebpf_common::SERVICE_SELECTION_TIER_CLUSTER => ServiceSelectionTier::Cluster,
        _ => unreachable!("validated service selection tier"),
    }
}

fn service_event_affinity_outcome(event: &ServiceEvent) -> ServiceAffinityOutcome {
    match event.reserved[2] {
        SERVICE_AFFINITY_OUTCOME_NONE => ServiceAffinityOutcome::None,
        SERVICE_AFFINITY_OUTCOME_REUSED => ServiceAffinityOutcome::Reused,
        SERVICE_AFFINITY_OUTCOME_CREATED => ServiceAffinityOutcome::Created,
        SERVICE_AFFINITY_OUTCOME_RESELECTED => ServiceAffinityOutcome::Reselected,
        _ => unreachable!("validated service affinity outcome"),
    }
}

fn service_event_selection_algorithm(event: &ServiceEvent) -> ServiceSelectionAlgorithmOutcome {
    match event.reserved[3] {
        unf_ebpf_common::SERVICE_SELECTION_ALGORITHM_STABLE_HASH => {
            ServiceSelectionAlgorithmOutcome::StableHash
        }
        unf_ebpf_common::SERVICE_SELECTION_ALGORITHM_MAGLEV => {
            ServiceSelectionAlgorithmOutcome::Maglev
        }
        _ => unreachable!("validated service selection algorithm"),
    }
}

fn service_event_forwarding_mode(event: &ServiceEvent) -> ServiceForwardingModeOutcome {
    match event.reserved[4] {
        unf_ebpf_common::SERVICE_EVENT_FORWARDING_NAT => ServiceForwardingModeOutcome::Nat,
        unf_ebpf_common::SERVICE_EVENT_FORWARDING_DSR => ServiceForwardingModeOutcome::Dsr,
        _ => unreachable!("validated service forwarding mode"),
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

fn record_service_translation_selection(state: &AgentState, event: &ServiceEvent) {
    match service_event_selection_tier(event) {
        ServiceSelectionTier::SameNode => increment_outcome(
            &state.service_same_node_selections,
            &state.metrics.service_same_node_selections,
        ),
        ServiceSelectionTier::SameZone => increment_outcome(
            &state.service_same_zone_selections,
            &state.metrics.service_same_zone_selections,
        ),
        ServiceSelectionTier::Cluster => increment_outcome(
            &state.service_cluster_selections,
            &state.metrics.service_cluster_selections,
        ),
        ServiceSelectionTier::Unknown => unreachable!("validated selection tier"),
    }
    match service_event_selection_algorithm(event) {
        ServiceSelectionAlgorithmOutcome::StableHash => increment_outcome(
            &state.service_stable_hash_selections,
            &state.metrics.service_stable_hash_selections,
        ),
        ServiceSelectionAlgorithmOutcome::Maglev => increment_outcome(
            &state.service_maglev_selections,
            &state.metrics.service_maglev_selections,
        ),
        ServiceSelectionAlgorithmOutcome::Unknown => {
            unreachable!("validated selection algorithm")
        }
    }
    match service_event_affinity_outcome(event) {
        ServiceAffinityOutcome::Reused => increment_outcome(
            &state.service_affinity_reuses,
            &state.metrics.service_affinity_reuses,
        ),
        ServiceAffinityOutcome::Created => increment_outcome(
            &state.service_affinity_creations,
            &state.metrics.service_affinity_creations,
        ),
        ServiceAffinityOutcome::Reselected => increment_outcome(
            &state.service_affinity_reselections,
            &state.metrics.service_affinity_reselections,
        ),
        ServiceAffinityOutcome::None => {}
        ServiceAffinityOutcome::Unknown => unreachable!("validated affinity outcome"),
    }
    match service_event_forwarding_mode(event) {
        ServiceForwardingModeOutcome::Nat => increment_outcome(
            &state.service_nat_forwards,
            &state.metrics.service_nat_forwards,
        ),
        ServiceForwardingModeOutcome::Dsr => increment_outcome(
            &state.service_dsr_forwards,
            &state.metrics.service_dsr_forwards,
        ),
        ServiceForwardingModeOutcome::Unknown => {
            unreachable!("validated forwarding mode")
        }
    }
}

fn record_last_service_witness(state: &AgentState, event: &ServiceEvent) {
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
    state
        .last_service_selection_tier
        .store(u64::from(event.reserved[1]), Ordering::Release);
    state.last_service_affinity_outcome.store(
        u64::from(event.reserved[2]).saturating_add(1),
        Ordering::Release,
    );
    state
        .last_service_selection_algorithm
        .store(u64::from(event.reserved[3]), Ordering::Release);
    state.last_service_forwarding_mode.store(
        u64::from(event.reserved[4]).saturating_add(1),
        Ordering::Release,
    );
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
            record_service_translation_selection(state, event);
            match service_event_frontend_kind(event) {
                ServiceFrontendKind::NodePortCluster => {
                    state
                        .node_port_cluster_translations
                        .fetch_add(1, Ordering::Relaxed);
                    state.metrics.node_port_cluster_translations.inc();
                }
                ServiceFrontendKind::NodePortLocal => {
                    state
                        .node_port_local_translations
                        .fetch_add(1, Ordering::Relaxed);
                    state.metrics.node_port_local_translations.inc();
                }
                ServiceFrontendKind::LoadBalancerCluster => {
                    state
                        .load_balancer_cluster_translations
                        .fetch_add(1, Ordering::Relaxed);
                    state.metrics.load_balancer_cluster_translations.inc();
                }
                ServiceFrontendKind::LoadBalancerLocal => {
                    state
                        .load_balancer_local_translations
                        .fetch_add(1, Ordering::Relaxed);
                    state.metrics.load_balancer_local_translations.inc();
                }
                ServiceFrontendKind::ClusterIp => {}
            }
        }
        SERVICE_EVENT_ACTION_DROP => {
            state.service_drops.fetch_add(1, Ordering::Relaxed);
            state.metrics.service_drops.inc();
            if event.reason == SERVICE_EVENT_REASON_NO_BACKEND
                && matches!(
                    service_event_frontend_kind(event),
                    ServiceFrontendKind::NodePortCluster | ServiceFrontendKind::NodePortLocal
                )
            {
                state
                    .node_port_no_backend_drops
                    .fetch_add(1, Ordering::Relaxed);
                state.metrics.node_port_no_backend_drops.inc();
            }
            if matches!(
                service_event_frontend_kind(event),
                ServiceFrontendKind::LoadBalancerCluster | ServiceFrontendKind::LoadBalancerLocal
            ) {
                if event.reason == SERVICE_EVENT_REASON_NO_BACKEND {
                    state
                        .load_balancer_no_backend_drops
                        .fetch_add(1, Ordering::Relaxed);
                    state.metrics.load_balancer_no_backend_drops.inc();
                } else if event.reason == SERVICE_EVENT_REASON_SOURCE_RANGE_DENIED {
                    state
                        .load_balancer_source_range_drops
                        .fetch_add(1, Ordering::Relaxed);
                    state.metrics.load_balancer_source_range_drops.inc();
                }
            }
        }
        SERVICE_EVENT_ACTION_EXPIRE => {
            state.service_expirations.fetch_add(1, Ordering::Relaxed);
            state.metrics.service_expirations.inc();
        }
        _ => return,
    }
    record_last_service_witness(state, event);
}

fn increment_outcome(counter: &AtomicU64, metric: &Counter) {
    counter.fetch_add(1, Ordering::Relaxed);
    metric.inc();
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

fn reported_selection_tier(value: u64) -> Option<ServiceSelectionTier> {
    match u8::try_from(value).ok()? {
        unf_ebpf_common::SERVICE_SELECTION_TIER_SAME_NODE => Some(ServiceSelectionTier::SameNode),
        unf_ebpf_common::SERVICE_SELECTION_TIER_SAME_ZONE => Some(ServiceSelectionTier::SameZone),
        unf_ebpf_common::SERVICE_SELECTION_TIER_CLUSTER => Some(ServiceSelectionTier::Cluster),
        _ => None,
    }
}

fn reported_affinity_outcome(value: u64) -> Option<ServiceAffinityOutcome> {
    match value
        .checked_sub(1)
        .and_then(|value| u8::try_from(value).ok())?
    {
        SERVICE_AFFINITY_OUTCOME_NONE => Some(ServiceAffinityOutcome::None),
        SERVICE_AFFINITY_OUTCOME_REUSED => Some(ServiceAffinityOutcome::Reused),
        SERVICE_AFFINITY_OUTCOME_CREATED => Some(ServiceAffinityOutcome::Created),
        SERVICE_AFFINITY_OUTCOME_RESELECTED => Some(ServiceAffinityOutcome::Reselected),
        _ => None,
    }
}

fn reported_selection_algorithm(value: u64) -> Option<ServiceSelectionAlgorithmOutcome> {
    match u8::try_from(value).ok()? {
        unf_ebpf_common::SERVICE_SELECTION_ALGORITHM_STABLE_HASH => {
            Some(ServiceSelectionAlgorithmOutcome::StableHash)
        }
        unf_ebpf_common::SERVICE_SELECTION_ALGORITHM_MAGLEV => {
            Some(ServiceSelectionAlgorithmOutcome::Maglev)
        }
        _ => None,
    }
}

fn reported_forwarding_mode(value: u64) -> Option<ServiceForwardingModeOutcome> {
    match value
        .checked_sub(1)
        .and_then(|value| u8::try_from(value).ok())?
    {
        unf_ebpf_common::SERVICE_EVENT_FORWARDING_NAT => Some(ServiceForwardingModeOutcome::Nat),
        unf_ebpf_common::SERVICE_EVENT_FORWARDING_DSR => Some(ServiceForwardingModeOutcome::Dsr),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
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
        service_snapshot_schema_version: SERVICE_SNAPSHOT_SCHEMA_VERSION,
        failed_service_epoch: state.failed_service_epoch.load(Ordering::Acquire),
        failed_service_revision: state.failed_service_revision.load(Ordering::Acquire),
        service_count: state.service_count.load(Ordering::Acquire),
        service_frontend_count: state.service_frontend_count.load(Ordering::Acquire),
        service_backend_count: state.service_backend_count.load(Ordering::Acquire),
        desired_selection_contract_revision: state
            .desired_selection_contract_revision
            .load(Ordering::Acquire),
        applied_selection_contract_revision: state
            .applied_selection_contract_revision
            .load(Ordering::Acquire),
        desired_selection_contract_digest: mutex_lock(&state.desired_selection_contract_digest)
            .clone(),
        applied_selection_contract_digest: mutex_lock(&state.applied_selection_contract_digest)
            .clone(),
        active_selection_bank: state.active_selection_bank.load(Ordering::Acquire),
        desired_node_port_frontend_count: state
            .desired_node_port_frontend_count
            .load(Ordering::Acquire),
        applied_node_port_frontend_count: state
            .applied_node_port_frontend_count
            .load(Ordering::Acquire),
        node_port_cluster_frontend_count: state
            .node_port_cluster_frontend_count
            .load(Ordering::Acquire),
        node_port_local_frontend_count: state
            .node_port_local_frontend_count
            .load(Ordering::Acquire),
        load_balancer_reachability_schema_version:
            unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION,
        selection_contract_schema_version: unf_service::SELECTION_CONTRACT_SCHEMA_VERSION,
        desired_load_balancer_epoch: state.desired_load_balancer_epoch.load(Ordering::Acquire),
        desired_load_balancer_revision: state
            .desired_load_balancer_revision
            .load(Ordering::Acquire),
        desired_load_balancer_allocation_revision: state
            .desired_load_balancer_allocation_revision
            .load(Ordering::Acquire),
        applied_load_balancer_epoch: state.applied_load_balancer_epoch.load(Ordering::Acquire),
        applied_load_balancer_revision: state
            .applied_load_balancer_revision
            .load(Ordering::Acquire),
        applied_load_balancer_allocation_revision: state
            .applied_load_balancer_allocation_revision
            .load(Ordering::Acquire),
        load_balancer_frontend_count: state.load_balancer_frontend_count.load(Ordering::Acquire),
        load_balancer_cluster_frontend_count: state
            .load_balancer_cluster_frontend_count
            .load(Ordering::Acquire),
        load_balancer_local_frontend_count: state
            .load_balancer_local_frontend_count
            .load(Ordering::Acquire),
        load_balancer_source_range_count: state
            .load_balancer_source_range_count
            .load(Ordering::Acquire),
        load_balancer_health_check_count: state
            .load_balancer_health_check_count
            .load(Ordering::Acquire),
        load_balancer_health_check_ready_count: state
            .load_balancer_health_check_ready_count
            .load(Ordering::Acquire),
        active_load_balancer_bank: state.active_load_balancer_bank.load(Ordering::Acquire),
        load_balancer_reconcile_errors: state
            .load_balancer_reconcile_errors
            .load(Ordering::Acquire),
        load_balancer_last_error: mutex_lock(&state.load_balancer_last_error).clone(),
        service_reconcile_errors: state.service_reconcile_errors.load(Ordering::Acquire),
        service_last_error: mutex_lock(&state.service_last_error).clone(),
        service_dataplane_events: state.service_dataplane_events.load(Ordering::Acquire),
        service_translations: state.service_translations.load(Ordering::Acquire),
        service_drops: state.service_drops.load(Ordering::Acquire),
        service_expirations: state.service_expirations.load(Ordering::Acquire),
        node_port_cluster_translations: state
            .node_port_cluster_translations
            .load(Ordering::Acquire),
        node_port_local_translations: state.node_port_local_translations.load(Ordering::Acquire),
        node_port_no_backend_drops: state.node_port_no_backend_drops.load(Ordering::Acquire),
        load_balancer_cluster_translations: state
            .load_balancer_cluster_translations
            .load(Ordering::Acquire),
        load_balancer_local_translations: state
            .load_balancer_local_translations
            .load(Ordering::Acquire),
        load_balancer_no_backend_drops: state
            .load_balancer_no_backend_drops
            .load(Ordering::Acquire),
        load_balancer_source_range_drops: state
            .load_balancer_source_range_drops
            .load(Ordering::Acquire),
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
        service_same_node_selections: state.service_same_node_selections.load(Ordering::Acquire),
        service_same_zone_selections: state.service_same_zone_selections.load(Ordering::Acquire),
        service_cluster_selections: state.service_cluster_selections.load(Ordering::Acquire),
        service_stable_hash_selections: state
            .service_stable_hash_selections
            .load(Ordering::Acquire),
        service_maglev_selections: state.service_maglev_selections.load(Ordering::Acquire),
        service_affinity_reuses: state.service_affinity_reuses.load(Ordering::Acquire),
        service_affinity_creations: state.service_affinity_creations.load(Ordering::Acquire),
        service_affinity_reselections: state.service_affinity_reselections.load(Ordering::Acquire),
        service_nat_forwards: state.service_nat_forwards.load(Ordering::Acquire),
        service_dsr_forwards: state.service_dsr_forwards.load(Ordering::Acquire),
        last_service_selection_tier: reported_selection_tier(
            state.last_service_selection_tier.load(Ordering::Acquire),
        ),
        last_service_affinity_outcome: reported_affinity_outcome(
            state.last_service_affinity_outcome.load(Ordering::Acquire),
        ),
        last_service_selection_algorithm: reported_selection_algorithm(
            state
                .last_service_selection_algorithm
                .load(Ordering::Acquire),
        ),
        last_service_forwarding_mode: reported_forwarding_mode(
            state.last_service_forwarding_mode.load(Ordering::Acquire),
        ),
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
    interface_index_at(Path::new("/sys/class/net"), interface)
}

fn interface_index_at(sys_class_net: &Path, interface: &str) -> Result<u32> {
    let value = fs::read_to_string(sys_class_net.join(interface).join("ifindex"))
        .with_context(|| format!("read interface index for {interface}"))?;
    value
        .trim()
        .parse()
        .with_context(|| format!("parse interface index for {interface}"))
}

fn native_egress_path_provider(args: &Args) -> Result<Option<NativeEgressPathProvider>> {
    let (Some(ipv4_interface), Some(ipv6_interface)) = (
        args.cni_native_ipv4_uplink.as_deref(),
        args.cni_native_ipv6_uplink.as_deref(),
    ) else {
        return Ok(None);
    };
    Ok(Some(NativeEgressPathProvider {
        ipv4_interface: ipv4_interface.to_owned(),
        ipv6_interface: ipv6_interface.to_owned(),
        ipv4_output_interface: interface_index(ipv4_interface)?,
        ipv6_output_interface: interface_index(ipv6_interface)?,
        ipv4_onlink: args.cni_native_ipv4_onlink,
        ipv6_onlink: args.cni_native_ipv6_onlink,
        sys_class_net: PathBuf::from("/sys/class/net"),
    }))
}

fn interface_mtu_at(sys_class_net: &Path, interface: &str, expected_index: u32) -> Result<u32> {
    let observed_index = interface_index_at(sys_class_net, interface)?;
    if observed_index != expected_index {
        bail!("interface {interface} index changed from {expected_index} to {observed_index}");
    }
    fs::read_to_string(sys_class_net.join(interface).join("mtu"))
        .with_context(|| format!("read MTU for interface {interface}"))?
        .trim()
        .parse()
        .with_context(|| format!("parse MTU for interface {interface}"))
}

fn service_dsr_transport_interfaces(
    ipv4_uplink: Option<&str>,
    ipv6_uplink: Option<&str>,
) -> Result<[u32; 4]> {
    service_dsr_transport_interfaces_at(
        Path::new("/sys/class/net"),
        Path::new("/proc/net/vlan"),
        ipv4_uplink,
        ipv6_uplink,
    )
}

fn service_dsr_transport_interfaces_at(
    sys_class_net: &Path,
    proc_net_vlan: &Path,
    ipv4_uplink: Option<&str>,
    ipv6_uplink: Option<&str>,
) -> Result<[u32; 4]> {
    let ipv4 = dsr_transport_interfaces(sys_class_net, proc_net_vlan, ipv4_uplink)?;
    let ipv6 = dsr_transport_interfaces(sys_class_net, proc_net_vlan, ipv6_uplink)?;
    Ok([ipv4.0, ipv4.1, ipv6.0, ipv6.1])
}

fn dsr_transport_interfaces(
    sys_class_net: &Path,
    proc_net_vlan: &Path,
    uplink: Option<&str>,
) -> Result<(u32, u32)> {
    let Some(uplink) = uplink else {
        return Ok((0, 0));
    };
    let route_ifindex = interface_index_at(sys_class_net, uplink)?;
    let iflink = fs::read_to_string(sys_class_net.join(uplink).join("iflink"))
        .with_context(|| format!("read interface link index for {uplink}"))?
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parse interface link index for {uplink}"))?;
    if iflink == route_ifindex || interface_vlan_id_at(proc_net_vlan, uplink)?.is_none() {
        return Ok((route_ifindex, route_ifindex));
    }
    let lower_exists = fs::read_dir(sys_class_net)
        .context("enumerate DSR transport interfaces")?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .any(|candidate| {
            interface_index_at(sys_class_net, &candidate)
                .is_ok_and(|candidate_ifindex| candidate_ifindex == iflink)
        });
    if !lower_exists {
        bail!(
            "VLAN route interface {uplink} references unavailable lower interface index {iflink}"
        );
    }
    Ok((route_ifindex, iflink))
}

fn interface_vlan_id_at(proc_net_vlan: &Path, interface: &str) -> Result<Option<u16>> {
    let path = proc_net_vlan.join(interface);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read VLAN state for {interface}"));
        }
    };
    let fields = contents.split_whitespace().collect::<Vec<_>>();
    let Some(position) = fields.iter().position(|field| *field == "VID:") else {
        bail!("VLAN state for {interface} omitted VID");
    };
    let vlan_id = fields
        .get(position + 1)
        .context("VLAN state omitted value after VID")?
        .parse::<u16>()
        .with_context(|| format!("parse VLAN ID for {interface}"))?;
    if !(1..=4094).contains(&vlan_id) {
        bail!("VLAN ID for {interface} is outside 1..=4094");
    }
    Ok(Some(vlan_id))
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
        || !service_event_frontend_kind_is_valid(bytes[86])
        || !service_selection_tier_is_valid(bytes[87])
        || !matches!(
            bytes[88],
            SERVICE_AFFINITY_OUTCOME_NONE
                | SERVICE_AFFINITY_OUTCOME_REUSED
                | SERVICE_AFFINITY_OUTCOME_CREATED
                | SERVICE_AFFINITY_OUTCOME_RESELECTED
        )
        || !service_selection_algorithm_is_valid(bytes[89])
        || !matches!(
            bytes[90],
            unf_ebpf_common::SERVICE_EVENT_FORWARDING_NAT
                | unf_ebpf_common::SERVICE_EVENT_FORWARDING_DSR
        )
        || bytes[91..96] != [0; 5]
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

fn decode_egress_event(bytes: &[u8]) -> Option<EgressEvent> {
    if bytes.len() != size_of::<EgressEvent>() {
        return None;
    }
    let version = u16::from_ne_bytes(copy_bytes(bytes, 130)?);
    let size = u16::from_ne_bytes(copy_bytes(bytes, 132)?);
    let protocol = bytes[140];
    let address_family = bytes[141];
    let action = bytes[142];
    let reason = bytes[143];
    let flags = u16::from_ne_bytes(copy_bytes(bytes, 144)?);
    let source_identity = IdentityId::new(u32::from_ne_bytes(copy_bytes(bytes, 120)?));
    let contract_revision = u64::from_ne_bytes(copy_bytes(bytes, 8)?);
    let lease_epoch = u64::from_ne_bytes(copy_bytes(bytes, 16)?);
    let egress_address: [u8; 16] = copy_bytes(bytes, 56)?;
    let gateway_digest: [u8; 16] = copy_bytes(bytes, 72)?;
    let proof_witness: [u8; 16] = copy_bytes(bytes, 104)?;
    if version != EGRESS_EVENT_ABI_VERSION
        || usize::from(size) != size_of::<EgressEvent>()
        || !matches!(protocol, 6 | 17)
        || !matches!(address_family, 4 | 6)
        || !egress_event_action_reason_is_valid(action, reason)
        || source_identity.get() == 0
        || contract_revision == 0
        || lease_epoch == 0
        || egress_address == [0; 16]
        || gateway_digest == [0; 16]
        || proof_witness == [0; 16]
        || flags
            & !(unf_ebpf_common::EGRESS_CONNECTION_FLAG_STANDBY_CERTIFIED
                | unf_ebpf_common::EGRESS_CONNECTION_FLAG_STANDBY_ACTIVE)
            != 0
        || bytes[146..152] != [0; 6]
        || (address_family == 4
            && (egress_address[..4] == [0; 4] || egress_address[4..] != [0; 12]))
    {
        return None;
    }
    Some(EgressEvent {
        timestamp_ns: u64::from_ne_bytes(copy_bytes(bytes, 0)?),
        contract_revision,
        lease_epoch,
        original_source_address: copy_bytes(bytes, 24)?,
        original_destination_address: copy_bytes(bytes, 40)?,
        egress_address,
        gateway_digest,
        standby_gateway_digest: copy_bytes(bytes, 88)?,
        proof_witness,
        source_identity,
        original_source_port: copy_bytes(bytes, 124)?,
        original_destination_port: copy_bytes(bytes, 126)?,
        translated_source_port: copy_bytes(bytes, 128)?,
        version,
        size,
        address_index: u16::from_ne_bytes(copy_bytes(bytes, 134)?),
        primary_gateway_index: u16::from_ne_bytes(copy_bytes(bytes, 136)?),
        standby_gateway_index: u16::from_ne_bytes(copy_bytes(bytes, 138)?),
        protocol,
        address_family,
        action,
        reason,
        flags,
        reserved: copy_bytes(bytes, 146)?,
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
        limitation: "service translation is bounded to IPv4/IPv6 TCP/UDP ClusterIP, NodePort Cluster/Local, and explicit-class LoadBalancer Cluster/Local on qualified primary-CNI tuples; session affinity, internalTrafficPolicy, topology-aware selection, Maglev, DSR, SCTP, fragments, and host-origin NodePort remain unqualified",
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
    use unf_ebpf_common::{
        SERVICE_CONNECTION_ROLE_FORWARD, ServiceConnectionKey, service_flow_hash,
    };
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
    fn dsr_transport_interfaces_include_only_a_confirmed_vlan_lower_link() {
        let directory = tempdir().unwrap();
        let sys_class_net = directory.path();
        let proc_net_vlan = directory.path().join("vlan");
        fs::create_dir(&proc_net_vlan).unwrap();
        for (name, ifindex, iflink) in [
            ("br-ex", 7_u32, 9_u32),
            ("ens18", 9, 9),
            ("mac0", 8, 9),
            ("eth0", 4, 55),
            ("veth-peer", 55, 4),
        ] {
            let interface = sys_class_net.join(name);
            fs::create_dir_all(&interface).unwrap();
            fs::write(interface.join("ifindex"), format!("{ifindex}\n")).unwrap();
            fs::write(interface.join("iflink"), format!("{iflink}\n")).unwrap();
        }
        fs::write(
            proc_net_vlan.join("br-ex"),
            "br-ex  VID: 600\t REORDER_HDR: 1  dev->priv_flags: 81021\n",
        )
        .unwrap();

        assert_eq!(
            service_dsr_transport_interfaces_at(
                sys_class_net,
                &proc_net_vlan,
                Some("br-ex"),
                Some("br-ex"),
            )
            .unwrap(),
            [7, 9, 7, 9],
            "a VLAN route preserves metadata across its route and lower links"
        );
        assert_eq!(
            service_dsr_transport_interfaces_at(
                sys_class_net,
                &proc_net_vlan,
                Some("eth0"),
                Some("eth0"),
            )
            .unwrap(),
            [4, 4, 4, 4],
            "a non-VLAN veth never contributes its peer as a transport link"
        );
        assert_eq!(
            service_dsr_transport_interfaces_at(
                sys_class_net,
                &proc_net_vlan,
                Some("mac0"),
                Some("mac0"),
            )
            .unwrap(),
            [8, 8, 8, 8],
            "a non-VLAN virtual uplink remains scoped to its route device"
        );
        assert_eq!(
            service_dsr_transport_interfaces_at(sys_class_net, &proc_net_vlan, None, None).unwrap(),
            [0; 4]
        );

        fs::write(proc_net_vlan.join("br-ex"), "br-ex VID: 4095\n").unwrap();
        assert!(
            service_dsr_transport_interfaces_at(
                sys_class_net,
                &proc_net_vlan,
                Some("br-ex"),
                Some("br-ex"),
            )
            .is_err(),
            "an out-of-range VLAN ID must fail closed"
        );
        fs::write(proc_net_vlan.join("br-ex"), "br-ex VID: 600\n").unwrap();
        fs::remove_dir_all(sys_class_net.join("ens18")).unwrap();
        assert!(
            service_dsr_transport_interfaces_at(
                sys_class_net,
                &proc_net_vlan,
                Some("br-ex"),
                Some("br-ex"),
            )
            .is_err(),
            "a VLAN lower link outside the namespace must fail closed"
        );
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

    #[allow(clippy::too_many_lines)]
    fn egress_path_test_source() -> unf_egress::AdmittedEgressProjection {
        let capabilities = BTreeSet::from([
            EgressCapability::IdentitySourceSteering,
            EgressCapability::LeaseEpochFencing,
            EgressCapability::OriginalTupleWitness,
            EgressCapability::Ipv4TcpUdpNat,
            EgressCapability::Ipv6TcpUdpNat,
        ]);
        let node = |name: &str| unf_egress::EgressNode {
            name: name.to_owned(),
            uid: format!("{name}-uid"),
            capabilities: capabilities.clone(),
        };
        let source_node = node("worker-a");
        let model = unf_egress::normalize_model(
            vec![unf_egress::EgressAddressPool {
                name: "public".to_owned(),
                uid: "public-uid".to_owned(),
                provider: unf_egress::EgressProviderRef {
                    name: "native".to_owned(),
                    instance: "test".to_owned(),
                },
                prefixes: vec![
                    unf_egress::IpPrefix {
                        address: "192.0.2.0".parse().unwrap(),
                        prefix_len: 24,
                    },
                    unf_egress::IpPrefix {
                        address: "2001:db8::".parse().unwrap(),
                        prefix_len: 64,
                    },
                ],
            }],
            vec![unf_egress::EgressIntent {
                owner: unf_egress::EgressIntentOwner {
                    scope: unf_egress::EgressIntentScope::Namespace("finance".to_owned()),
                    name: "payments".to_owned(),
                    uid: "payments-uid".to_owned(),
                },
                priority: unf_egress::DEFAULT_EGRESS_INTENT_PRIORITY,
                source: unf_egress::EgressSourceSelector::default(),
                destinations: unf_egress::EgressDestinations::Any,
                addresses: unf_egress::EgressAddressRequest::Pool {
                    name: "public".to_owned(),
                    families: vec![EgressAddressFamily::Ipv4, EgressAddressFamily::Ipv6],
                    addresses_per_family: 1,
                },
            }],
        )
        .unwrap();
        let facts = unf_egress::EgressContractFacts {
            revisions: unf_egress::EgressContractRevisions {
                intent: Revision::new(2),
                identity: Revision::new(3),
                policy: Revision::new(4),
                allocation: Revision::new(5),
                gateway: Revision::new(6),
                reachability: Revision::new(7),
            },
            sources: vec![unf_egress::EgressSourceFact {
                identity: IdentityId::new(42),
                namespace: "finance".to_owned(),
                workload: "ledger-0".to_owned(),
                workload_uid: "ledger-uid".to_owned(),
                service_account: "settlement".to_owned(),
                namespace_labels: BTreeMap::new(),
                workload_labels: BTreeMap::new(),
                node: source_node.clone(),
                intent_uid: "payments-uid".to_owned(),
            }],
            policies: vec![unf_egress::EgressPolicyFact {
                identity: IdentityId::new(42),
                intent_uid: "payments-uid".to_owned(),
                allowed: true,
                policy_ids: vec![PolicyId::new(9)],
            }],
            allocations: vec![unf_egress::EgressAllocationFact {
                intent_uid: "payments-uid".to_owned(),
                pool_name: Some("public".to_owned()),
                pool_uid: Some("public-uid".to_owned()),
                addresses: vec![
                    "192.0.2.20".parse().unwrap(),
                    "2001:db8::20".parse().unwrap(),
                ],
                lease_epoch: 11,
            }],
            gateways: vec![unf_egress::EgressGatewayFact {
                intent_uid: "payments-uid".to_owned(),
                rank: 0,
                node: node("worker-b"),
                lease_epoch: 11,
                ready: true,
                reachable: true,
            }],
        };
        let contract = unf_egress::EgressBehaviorContract::issue(
            &model,
            &facts,
            source_node,
            Revision::new(8),
        )
        .unwrap();
        let advertisement = egress_agent_advertisement();
        let principal = AuthenticatedEgressAgent {
            namespace: "unf-system".to_owned(),
            service_account: EGRESS_AGENT_SERVICE_ACCOUNT.to_owned(),
            pod_name: "unf-agent-a".to_owned(),
            pod_uid: "unf-agent-a-uid".to_owned(),
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
            audience: EGRESS_AGENT_TOKEN_AUDIENCE.to_owned(),
        };
        unf_egress::EgressNodeProjectionEnvelope::issue(
            &principal,
            &advertisement,
            9,
            Revision::new(10),
            model,
            facts,
            contract,
        )
        .unwrap()
        .admit(&principal, &advertisement)
        .unwrap()
    }

    #[test]
    fn dual_stack_egress_paths_bind_route_provenance_interface_and_mtu() {
        let source = egress_path_test_source();
        let (_, snapshot) = route_test_snapshots();
        let provider = NativeEgressPathProvider {
            ipv4_interface: "eth4".to_owned(),
            ipv6_interface: "eth6".to_owned(),
            ipv4_output_interface: 3,
            ipv6_output_interface: 4,
            ipv4_onlink: true,
            ipv6_onlink: false,
            sys_class_net: PathBuf::from("/unused"),
        };
        let paths = build_egress_path_certificates(&provider, &source, &snapshot, 1500, 9000)
            .expect("dual-stack paths derive from exact route ownership");
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().all(|path| {
            path.source.name == "worker-a"
                && path.gateway.name == "worker-b"
                && path.path_revision == Revision::new(7)
                && path.lease_epoch == 11
                && path.transport_address == path.next_hop_address
                && path.verify_integrity().is_ok()
        }));
        let ipv4 = paths
            .iter()
            .find(|path| path.address_family == EgressAddressFamily::Ipv4)
            .unwrap();
        assert_eq!(ipv4.output_interface, 3);
        assert_eq!(ipv4.mtu, 1500);
        let ipv6 = paths
            .iter()
            .find(|path| path.address_family == EgressAddressFamily::Ipv6)
            .unwrap();
        assert_eq!(ipv6.output_interface, 4);
        assert_eq!(ipv6.mtu, 9000);

        let mut missing = snapshot;
        missing.remote_nodes.clear();
        assert!(build_egress_path_certificates(&provider, &source, &missing, 1500, 9000).is_err());
    }

    #[test]
    fn egress_path_interface_readback_rejects_index_reuse() {
        let directory = tempdir().unwrap();
        let interface = directory.path().join("eth-test");
        fs::create_dir(&interface).unwrap();
        fs::write(interface.join("ifindex"), "17\n").unwrap();
        fs::write(interface.join("mtu"), "1500\n").unwrap();
        assert_eq!(
            interface_mtu_at(directory.path(), "eth-test", 17).unwrap(),
            1500
        );
        assert!(interface_mtu_at(directory.path(), "eth-test", 18).is_err());
        fs::write(interface.join("mtu"), "1279\n").unwrap();
        let mtu = interface_mtu_at(directory.path(), "eth-test", 17).unwrap();
        assert!(
            EgressPathCertificate::issue(
                unf_egress::EgressNode {
                    name: "worker-a".to_owned(),
                    uid: "worker-a-uid".to_owned(),
                    capabilities: BTreeSet::new(),
                },
                unf_egress::EgressNode {
                    name: "worker-b".to_owned(),
                    uid: "worker-b-uid".to_owned(),
                    capabilities: BTreeSet::new(),
                },
                EgressAddressFamily::Ipv4,
                "192.0.2.2".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                17,
                mtu,
                EgressPathMode::DirectNeighbor,
                Revision::new(1),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn active_egress_bank_compiles_to_destination_preserving_fences() {
        let source = egress_path_test_source();
        let (_, snapshot) = route_test_snapshots();
        let provider = NativeEgressPathProvider {
            ipv4_interface: "eth4".to_owned(),
            ipv6_interface: "eth6".to_owned(),
            ipv4_output_interface: 3,
            ipv6_output_interface: 4,
            ipv4_onlink: true,
            ipv6_onlink: false,
            sys_class_net: PathBuf::from("/unused"),
        };
        let paths =
            build_egress_path_certificates(&provider, &source, &snapshot, 1500, 1500).unwrap();
        let host = EgressGatewayHostBank::compile(&source).unwrap();
        let identity = host.contract.plans[0].source.identity;
        let mut guard = EgressAdmissionGuard::default();
        let behavior = &host.contract.plans[0];
        guard
            .fence(identity, behavior.intent.clone(), behavior.revisions.intent)
            .unwrap();
        guard.activate(identity, &source).unwrap();
        let active = compile_egress_dataplane(&host, &guard, &paths, 1).unwrap();
        let encoded = encode_egress_dataplane(&active).unwrap();
        let destination_count = encoded.ipv4_destinations.len() + encoded.ipv6_destinations.len();
        let fenced = compile_fenced_egress_bank(&encoded, 0)
            .unwrap()
            .expect("active bank requires fencing");
        assert!(fenced.sources.values().all(|value| {
            value[122] == unf_ebpf_common::EGRESS_ADMISSION_FENCED
                && value[123] & unf_ebpf_common::EGRESS_SOURCE_FLAG_PRECERTIFIED_STANDBY == 0
        }));
        assert_eq!(
            fenced.ipv4_destinations.len() + fenced.ipv6_destinations.len(),
            destination_count
        );
        assert!(fenced.addresses.is_empty());
        assert!(fenced.gateways.is_empty());
        assert!(fenced.selections.is_empty());
        assert_eq!(
            u64::from_ne_bytes(fenced.config[24..32].try_into().unwrap()),
            0
        );
        assert_eq!(fenced.config[50], 0);
        assert!(compile_fenced_egress_bank(&fenced, 1).unwrap().is_none());
    }

    #[allow(clippy::default_trait_access)]
    fn service_test_snapshot(epoch: u64, revision: u64) -> ServiceSnapshot {
        unf_service::compile_service_snapshot(
            epoch,
            Revision::new(revision),
            vec![unf_service::ServiceSource {
                namespace: "default".to_owned(),
                name: "api".to_owned(),
                cluster_ips: vec!["10.96.0.10".parse().unwrap()],
                external_traffic_policy: unf_service::ServiceTrafficPolicy::Cluster,
                internal_traffic_policy: Default::default(),
                session_affinity: Default::default(),
                traffic_distribution: Default::default(),
                selection_algorithm: Default::default(),
                forwarding_mode: Default::default(),
                load_balancer: None,
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

    #[allow(clippy::default_trait_access)]
    fn service_test_snapshot_with_backend(epoch: u64, revision: u64) -> ServiceSnapshot {
        unf_service::compile_service_snapshot(
            epoch,
            Revision::new(revision),
            vec![unf_service::ServiceSource {
                namespace: "default".to_owned(),
                name: "api".to_owned(),
                cluster_ips: vec!["10.96.0.10".parse().unwrap()],
                external_traffic_policy: unf_service::ServiceTrafficPolicy::Cluster,
                internal_traffic_policy: Default::default(),
                session_affinity: Default::default(),
                traffic_distribution: Default::default(),
                selection_algorithm: Default::default(),
                forwarding_mode: Default::default(),
                load_balancer: None,
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

    #[allow(clippy::default_trait_access)]
    fn load_balancer_service_test_snapshot(epoch: u64, revision: u64) -> ServiceSnapshot {
        let sources = [("api", "10.96.0.10"), ("web", "10.96.0.11")]
            .into_iter()
            .map(|(name, cluster_ip)| unf_service::ServiceSource {
                namespace: "default".to_owned(),
                name: name.to_owned(),
                cluster_ips: vec![cluster_ip.parse().unwrap()],
                external_traffic_policy: unf_service::ServiceTrafficPolicy::Cluster,
                internal_traffic_policy: Default::default(),
                session_affinity: Default::default(),
                traffic_distribution: Default::default(),
                selection_algorithm: Default::default(),
                forwarding_mode: Default::default(),
                load_balancer: Some(unf_service::ServiceLoadBalancerSource {
                    class: unf_service::UNF_LOAD_BALANCER_CLASS.to_owned(),
                    ip_families: vec![unf_service::AddressFamily::Ipv4],
                    ip_family_policy: unf_service::ServiceIpFamilyPolicy::SingleStack,
                    requested_ips: Vec::new(),
                    source_ranges: Vec::new(),
                    allocate_node_ports: false,
                    health_check_node_port: None,
                }),
                ports: vec![unf_service::ServiceSourcePort {
                    name: Some("http".to_owned()),
                    protocol: unf_common::Protocol::Tcp,
                    port: 80,
                    app_protocol: None,
                    node_port: None,
                }],
            })
            .collect();
        unf_service::compile_service_snapshot(epoch, Revision::new(revision), sources, Vec::new())
            .expect("LoadBalancer test service snapshot compiles")
    }

    fn load_balancer_node_snapshot(
        services: &ServiceSnapshot,
        revision: u64,
        addresses: &[&str],
    ) -> NodeReachabilitySnapshot {
        let targets = services
            .services
            .iter()
            .zip(addresses)
            .map(
                |(service, address)| unf_loadbalancer::NodeReachabilityTarget {
                    owner: unf_loadbalancer::LoadBalancerOwner {
                        service_id: service.id,
                        namespace: service.namespace.clone(),
                        name: service.name.clone(),
                        uid: format!("{}-uid", service.name),
                    },
                    address: address.parse().unwrap(),
                },
            )
            .collect();
        NodeReachabilitySnapshot {
            schema_version: unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION,
            source_epoch: services.source_epoch,
            revision: Revision::new(revision),
            allocation_revision: Revision::new(revision),
            provider: unf_loadbalancer::ReachabilityProviderRef {
                name: "direct-node".to_owned(),
                instance: "qualification-a".to_owned(),
                mode: unf_loadbalancer::ReachabilityMode::DirectNode,
            },
            node: unf_loadbalancer::ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            },
            targets,
        }
        .validate()
        .expect("LoadBalancer Node snapshot validates")
    }

    fn dual_stack_load_balancer_node_snapshot(
        services: &ServiceSnapshot,
        revision: u64,
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
    ) -> NodeReachabilitySnapshot {
        let service = services.services.first().expect("one test Service exists");
        let owner = unf_loadbalancer::LoadBalancerOwner {
            service_id: service.id,
            namespace: service.namespace.clone(),
            name: service.name.clone(),
            uid: format!("{}-uid", service.name),
        };
        NodeReachabilitySnapshot {
            schema_version: unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION,
            source_epoch: services.source_epoch,
            revision: Revision::new(revision),
            allocation_revision: Revision::new(revision),
            provider: unf_loadbalancer::ReachabilityProviderRef {
                name: "direct-node".to_owned(),
                instance: "qualification-a".to_owned(),
                mode: unf_loadbalancer::ReachabilityMode::DirectNode,
            },
            node: unf_loadbalancer::ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            },
            targets: vec![
                unf_loadbalancer::NodeReachabilityTarget {
                    owner: owner.clone(),
                    address: ipv4.into(),
                },
                unf_loadbalancer::NodeReachabilityTarget {
                    owner,
                    address: ipv6.into(),
                },
            ],
        }
        .validate()
        .expect("dual-stack LoadBalancer Node snapshot validates")
    }

    fn dual_stack_service_snapshot(
        revision: u64,
        ipv4_backend: Ipv4Addr,
        ipv6_backend: Ipv6Addr,
        include_backends: bool,
    ) -> ServiceSnapshot {
        dual_stack_service_snapshot_with_load_balancer(
            revision,
            ipv4_backend,
            ipv6_backend,
            include_backends,
            false,
        )
    }

    fn dual_stack_dsr_load_balancer_snapshot(
        revision: u64,
        ipv4_backend: Ipv4Addr,
        ipv6_backend: Ipv6Addr,
    ) -> ServiceSnapshot {
        let mut snapshot = dual_stack_service_snapshot_with_load_balancer(
            revision,
            ipv4_backend,
            ipv6_backend,
            true,
            true,
        );
        let service = snapshot.services.first_mut().expect("one test Service");
        service.forwarding_mode = unf_service::ServiceForwardingMode::Dsr;
        for backend in &mut service.backends {
            backend.port = if backend.protocol == unf_common::Protocol::Tcp {
                80
            } else {
                53
            };
        }
        service
            .load_balancer
            .as_mut()
            .expect("test Service has LoadBalancer intent")
            .source_ranges = vec![
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ];
        snapshot
            .validate_and_normalize()
            .expect("dual-stack DSR LoadBalancer snapshot validates")
    }

    fn dual_stack_affinity_snapshot(
        revision: u64,
        primary_v4: Ipv4Addr,
        secondary_v4: Ipv4Addr,
        primary_v6: Ipv6Addr,
        secondary_v6: Ipv6Addr,
        drain_secondary: bool,
    ) -> ServiceSnapshot {
        let mut snapshot = dual_stack_service_snapshot(revision, primary_v4, primary_v6, true);
        let service = snapshot
            .services
            .first_mut()
            .expect("one test Service exists");
        service.session_affinity = unf_service::ServiceSessionAffinity::ClientIp {
            timeout_seconds: 300,
        };
        let primary_backends = service.backends.clone();
        for primary in primary_backends {
            let secondary_address = match primary.address {
                IpAddr::V4(_) => IpAddr::V4(secondary_v4),
                IpAddr::V6(_) => IpAddr::V6(secondary_v6),
            };
            let mut secondary = primary.clone();
            secondary.id = unf_common::BackendId::new(
                primary
                    .id
                    .get()
                    .checked_add(10_000)
                    .expect("test BackendId remains bounded"),
            );
            secondary.address = secondary_address;
            secondary.target_workload = Some(match secondary_address {
                IpAddr::V4(_) => "default/api-v4-secondary".to_owned(),
                IpAddr::V6(_) => "default/api-v6-secondary".to_owned(),
            });
            secondary.terminating = drain_secondary;
            for frontend in &mut service.frontends {
                if frontend.protocol == primary.protocol
                    && frontend.address.is_ipv4() == primary.address.is_ipv4()
                    && frontend.backend_ids.contains(&primary.id)
                {
                    frontend.backend_ids.push(secondary.id);
                }
            }
            service.backends.push(secondary);
        }
        snapshot
            .validate_and_normalize()
            .expect("dual-stack ClientIP affinity snapshot validates")
    }

    #[allow(clippy::default_trait_access, clippy::too_many_lines)]
    fn dual_stack_service_snapshot_with_load_balancer(
        revision: u64,
        ipv4_backend: Ipv4Addr,
        ipv6_backend: Ipv6Addr,
        include_backends: bool,
        load_balancer: bool,
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
                internal_traffic_policy: Default::default(),
                session_affinity: Default::default(),
                traffic_distribution: Default::default(),
                selection_algorithm: Default::default(),
                forwarding_mode: Default::default(),
                load_balancer: load_balancer.then(|| unf_service::ServiceLoadBalancerSource {
                    class: unf_service::UNF_LOAD_BALANCER_CLASS.to_owned(),
                    ip_families: vec![
                        unf_service::AddressFamily::Ipv4,
                        unf_service::AddressFamily::Ipv6,
                    ],
                    ip_family_policy: unf_service::ServiceIpFamilyPolicy::RequireDualStack,
                    requested_ips: Vec::new(),
                    source_ranges: Vec::new(),
                    allocate_node_ports: false,
                    health_check_node_port: None,
                }),
                ports,
            }],
            slices,
        )
        .expect("dual-stack service snapshot compiles")
    }

    fn local_load_balancer_snapshot(mut snapshot: ServiceSnapshot) -> ServiceSnapshot {
        let load_balancer = snapshot.services[0]
            .load_balancer
            .as_mut()
            .expect("test snapshot has LoadBalancer intent");
        load_balancer.traffic_policy = unf_service::ServiceTrafficPolicy::Local;
        load_balancer.source_ranges = vec![
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ];
        snapshot
            .validate_and_normalize()
            .expect("Local LoadBalancer snapshot validates")
    }

    fn dual_stack_node_port_snapshot(revision: u64) -> ServiceSnapshot {
        dual_stack_node_port_snapshot_with_backend(
            revision,
            Ipv4Addr::new(10, 42, 0, 20),
            "fd00:42::20".parse().unwrap(),
            true,
            unf_service::ServiceTrafficPolicy::Cluster,
        )
    }

    fn dual_stack_node_port_snapshot_with_backend(
        revision: u64,
        ipv4_backend: Ipv4Addr,
        ipv6_backend: Ipv6Addr,
        include_backends: bool,
        traffic_policy: unf_service::ServiceTrafficPolicy,
    ) -> ServiceSnapshot {
        let mut snapshot =
            dual_stack_service_snapshot(revision, ipv4_backend, ipv6_backend, include_backends);
        let node_ports = snapshot.services[0]
            .frontends
            .iter()
            .map(|frontend| unf_service::ServiceNodePort {
                family: if frontend.address.is_ipv4() {
                    unf_service::AddressFamily::Ipv4
                } else {
                    unf_service::AddressFamily::Ipv6
                },
                port: if frontend.protocol == unf_common::Protocol::Tcp {
                    30_080
                } else {
                    30_053
                },
                service_port: frontend.port,
                protocol: frontend.protocol,
                name: frontend.name.clone(),
                app_protocol: frontend.app_protocol.clone(),
                backend_ids: frontend.backend_ids.clone(),
                traffic_policy,
            })
            .collect();
        snapshot.services[0].node_ports = node_ports;
        snapshot
            .validate_and_normalize()
            .expect("dual-stack NodePort snapshot validates")
    }

    fn node_port_node_snapshot(revision: u64) -> NodePortNodeSnapshot {
        NodePortNodeSnapshot {
            schema_version: unf_service::NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION,
            source_epoch: 7,
            revision: Revision::new(revision),
            node_name: "worker-a".to_owned(),
            node_uid: "worker-a-uid".to_owned(),
            addresses: vec![
                unf_service::ServiceNodeAddress {
                    address: "192.0.2.10".parse().unwrap(),
                    kind: unf_service::NodeAddressKind::Internal,
                },
                unf_service::ServiceNodeAddress {
                    address: "198.51.100.10".parse().unwrap(),
                    kind: unf_service::NodeAddressKind::External,
                },
                unf_service::ServiceNodeAddress {
                    address: "fdff::10".parse().unwrap(),
                    kind: unf_service::NodeAddressKind::Internal,
                },
            ],
        }
        .validate_and_normalize()
        .expect("local NodePort Node snapshot validates")
    }

    fn test_service_synchronizer(ebpf: &mut Ebpf, state_path: PathBuf) -> ServiceSynchronizer {
        let load_balancer_state_path = state_path.with_file_name("load-balancer.json");
        let (
            ipv4_frontends,
            ipv6_frontends,
            ipv4_backends,
            ipv6_backends,
            backend_slots,
            config,
            connections,
            affinity,
            node_port_ipv4_frontends,
            node_port_ipv6_frontends,
            node_port_config,
            load_balancer_ipv4_frontends,
            load_balancer_ipv6_frontends,
            load_balancer_ipv4_source_ranges,
            load_balancer_ipv6_source_ranges,
            load_balancer_config,
            load_balancer_node_source,
        ) = take_service_maps(ebpf).expect("take service and NodePort maps");
        ServiceSynchronizer {
            ipv4_frontends,
            ipv6_frontends,
            ipv4_backends,
            ipv6_backends,
            backend_slots,
            config,
            connections,
            affinity,
            node_port_ipv4_frontends,
            node_port_ipv6_frontends,
            node_port_config,
            load_balancer_ipv4_frontends,
            load_balancer_ipv6_frontends,
            load_balancer_ipv4_source_ranges,
            load_balancer_ipv6_source_ranges,
            load_balancer_config,
            load_balancer_node_source,
            health_checks: HealthCheckManager::default(),
            banks: [None, None],
            node_port_banks: [None, None],
            load_balancer_banks: [None, None],
            selection_banks: [None, None],
            active_bank: 0,
            active_node_port_bank: 0,
            active_load_balancer_bank: 0,
            applied: None,
            applied_node_port_node: None,
            applied_load_balancer_reachability: None,
            applied_selection_contract: None,
            active_selection_bank: 0,
            node_name: "worker-a".to_owned(),
            controller_url: None,
            client: ReloadingControllerClient::without_custom_trust(
                Counter::default(),
                Counter::default(),
            ),
            agent_token_path: PathBuf::new(),
            state_path,
            load_balancer_state_path,
            interval: Duration::from_secs(1),
        }
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

    fn expected_service_backend(
        snapshot: &ServiceSnapshot,
        source_address: [u8; 16],
        destination_address: [u8; 16],
        address_family: u8,
        source_port: u16,
    ) -> IpAddr {
        let service = snapshot.services.first().expect("one test Service exists");
        let frontend = service
            .frontends
            .iter()
            .find(|frontend| {
                frontend.address.is_ipv4() == (address_family == 4)
                    && frontend.protocol == unf_common::Protocol::Tcp
                    && frontend.port == 80
            })
            .expect("test TCP frontend exists");
        let key = ServiceConnectionKey {
            source_address,
            destination_address,
            source_port: source_port.to_be_bytes(),
            destination_port: 80_u16.to_be_bytes(),
            protocol: 6,
            address_family,
            role: SERVICE_CONNECTION_ROLE_FORWARD,
            reserved: 0,
        };
        let slot = usize::try_from(
            service_flow_hash(&key, service.id)
                % u32::try_from(frontend.backend_ids.len()).expect("test backend count fits u32"),
        )
        .expect("test slot fits usize");
        let backend_id = frontend.backend_ids[slot];
        service
            .backends
            .iter()
            .find(|backend| backend.id == backend_id)
            .expect("selected test backend exists")
            .address
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
    fn load_balancer_service_checkpoint_preserves_current_intent() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("service-snapshot.json");
        let snapshot = load_balancer_service_test_snapshot(7, 4);
        let node = node_port_node_snapshot(7);

        persist_service_checkpoint(&path, &snapshot, Some(&node), "LoadBalancer service")
            .expect("current LoadBalancer service checkpoint persists");
        assert_eq!(
            load_optional_service_checkpoint(&path).unwrap(),
            Some((snapshot.clone(), Some(node)))
        );
        assert!(
            snapshot
                .services
                .iter()
                .all(|service| service.load_balancer.is_some())
        );
        assert!(persist_service_checkpoint(&path, &snapshot, None, "missing Node").is_err());
    }

    #[test]
    fn load_balancer_node_source_prefers_internal_dual_stack_addresses() {
        let node = node_port_node_snapshot(7);
        let encoded = encode_load_balancer_node_source(Some(&node));
        assert_eq!(u64::from_ne_bytes(encoded[0..8].try_into().unwrap()), 7);
        assert_eq!(&encoded[8..12], &Ipv4Addr::new(192, 0, 2, 10).octets());
        assert_eq!(
            &encoded[12..28],
            &"fdff::10".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            u16::from_ne_bytes(encoded[28..30].try_into().unwrap()),
            unf_ebpf_common::LOAD_BALANCER_NODE_SOURCE_SCHEMA_VERSION
        );
        assert_eq!(
            encoded[30],
            unf_ebpf_common::LOAD_BALANCER_NODE_SOURCE_FLAG_IPV4
                | unf_ebpf_common::LOAD_BALANCER_NODE_SOURCE_FLAG_IPV6
        );
        assert_eq!(&encoded[31..40], &[0; 9]);
        assert_eq!(encode_load_balancer_node_source(None), [0; 40]);
    }

    #[test]
    fn load_balancer_reachability_checkpoint_is_private_strict_and_transition_fenced() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("load-balancer-reachability.json");
        let snapshot = NodeReachabilitySnapshot {
            schema_version: unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION,
            source_epoch: 7,
            revision: Revision::new(4),
            allocation_revision: Revision::new(3),
            provider: unf_loadbalancer::ReachabilityProviderRef {
                name: "direct-node".to_owned(),
                instance: "qualification-a".to_owned(),
                mode: unf_loadbalancer::ReachabilityMode::DirectNode,
            },
            node: unf_loadbalancer::ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            },
            targets: vec![unf_loadbalancer::NodeReachabilityTarget {
                owner: unf_loadbalancer::LoadBalancerOwner {
                    service_id: unf_common::ServiceId::new(44),
                    namespace: "apps".to_owned(),
                    name: "api".to_owned(),
                    uid: "api-uid".to_owned(),
                },
                address: "192.0.2.4".parse().unwrap(),
            }],
        };
        let checkpoint = NodeReachabilityCheckpoint {
            schema_version: NODE_REACHABILITY_CHECKPOINT_SCHEMA_VERSION,
            applied: snapshot.clone(),
        };
        persist_secure_json(&path, &checkpoint, "LoadBalancer reachability").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_optional_load_balancer_reachability(&path).unwrap(),
            Some(snapshot.clone())
        );
        assert!(!snapshot.validate_transition(Some(&snapshot)).unwrap());

        let mut malformed = checkpoint;
        malformed.schema_version += 1;
        persist_secure_json(&path, &malformed, "LoadBalancer reachability").unwrap();
        assert!(load_optional_load_balancer_reachability(&path).is_err());
    }

    #[test]
    fn node_port_service_checkpoint_is_composite_private_and_transition_fenced() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("service.json");
        let service = dual_stack_node_port_snapshot(4);
        let node = node_port_node_snapshot(7);
        persist_service_checkpoint(&path, &service, Some(&node), "test NodePort service")
            .expect("composite checkpoint persists");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            load_optional_service_checkpoint(&path).unwrap(),
            Some((service.clone(), Some(node.clone())))
        );
        let state = test_agent_state();
        publish_desired_service_snapshot(&state, &service);
        publish_applied_service_snapshot(&state, &service);
        let report = agent_state_report(&state);
        assert_eq!(report.desired_node_port_frontend_count, 4);
        assert_eq!(report.applied_node_port_frontend_count, 4);
        assert_eq!(report.node_port_cluster_frontend_count, 4);
        assert_eq!(report.node_port_local_frontend_count, 0);
        assert!(persist_service_checkpoint(&path, &service, None, "missing Node").is_err());

        let mut mutated = node.clone();
        mutated.addresses[0].address = "192.0.2.11".parse().unwrap();
        assert!(validate_node_port_node_transition(Some(&mutated), Some(&node)).is_err());
        mutated.revision = node.revision.next();
        assert!(validate_node_port_node_transition(Some(&mutated), Some(&node)).unwrap());
        assert!(validate_node_port_node_transition(None, Some(&node)).unwrap());
    }

    #[test]
    fn selection_checkpoint_is_digest_bound_private_and_crash_repairable() {
        let directory = tempdir().unwrap();
        let service_path = directory.path().join("service.json");
        let service = service_test_snapshot_with_backend(7, 4);
        persist_service_checkpoint(&service_path, &service, None, "test service").unwrap();
        let node = node_port_node_snapshot(3);
        let selection_node = local_selection_node(&node, Some("zone-a".to_owned()));
        let contract = NetworkBehaviorContract::compile(
            &service,
            Revision::new(8),
            Revision::new(8),
            selection_node,
        )
        .expect("test selection contract compiles");
        let pending = prepare_selection_checkpoint(&service_path, &contract, &node, 1)
            .expect("selection contract is durably prepared");
        assert_eq!(
            fs::metadata(&pending).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let prepared = load_optional_selection_checkpoint(&pending)
            .expect("prepared selection contract validates")
            .expect("prepared selection contract exists");
        assert_eq!(prepared.contract, contract);
        assert_eq!(prepared.active_bank, 1);

        commit_prepared_selection_checkpoint(&service_path, &pending)
            .expect("prepared selection contract commits atomically");
        let current = selection_contract_state_path(&service_path).unwrap();
        assert!(!pending.exists());
        assert_eq!(
            load_optional_selection_checkpoint(&current)
                .unwrap()
                .unwrap()
                .contract,
            contract
        );

        let mut malformed = serde_json::to_value(SelectionContractCheckpoint {
            schema_version: SELECTION_CONTRACT_CHECKPOINT_SCHEMA_VERSION,
            active_bank: 1,
            node,
            contract,
        })
        .unwrap();
        malformed["contract"]["contractDigest"] = serde_json::json!("00".repeat(32));
        persist_secure_json(&current, &malformed, "mutated selection contract").unwrap();
        assert!(load_optional_selection_checkpoint(&current).is_err());

        malformed["unexpected"] = serde_json::json!(true);
        persist_secure_json(&current, &malformed, "unknown selection state").unwrap();
        assert!(load_optional_selection_checkpoint(&current).is_err());
    }

    #[test]
    fn selection_recovery_chooses_pending_contract_for_committed_service_revision() {
        let directory = tempdir().unwrap();
        let service_path = directory.path().join("service.json");
        let node = node_port_node_snapshot(3);
        let old_service = service_test_snapshot_with_backend(7, 4);
        persist_service_checkpoint(&service_path, &old_service, None, "old service").unwrap();
        let old_contract = NetworkBehaviorContract::compile(
            &old_service,
            Revision::new(8),
            Revision::new(8),
            local_selection_node(&node, Some("zone-a".to_owned())),
        )
        .unwrap();
        let old_pending =
            prepare_selection_checkpoint(&service_path, &old_contract, &node, 1).unwrap();
        commit_prepared_selection_checkpoint(&service_path, &old_pending).unwrap();

        let new_service = service_test_snapshot_with_backend(7, 5);
        persist_service_checkpoint(&service_path, &new_service, None, "committed new service")
            .unwrap();
        let new_contract = NetworkBehaviorContract::compile(
            &new_service,
            Revision::new(9),
            Revision::new(9),
            local_selection_node(&node, Some("zone-a".to_owned())),
        )
        .unwrap();
        let pending = prepare_selection_checkpoint(&service_path, &new_contract, &node, 0).unwrap();
        let current_path = selection_contract_state_path(&service_path).unwrap();
        assert!(load_optional_selection_checkpoint(&current_path).is_err());
        let current = decode_optional_selection_checkpoint(&current_path).unwrap();
        let prepared = decode_optional_selection_checkpoint(&pending).unwrap();
        let (selected_pending, selected) =
            select_recovered_selection_checkpoint(&new_service, current, prepared)
                .expect("the prepared contract matches the service revision that won");
        assert!(selected_pending);
        assert_eq!(selected.contract, new_contract);
        verify_selection_checkpoint(&selected, &new_service).unwrap();
        commit_prepared_selection_checkpoint(&service_path, &pending).unwrap();
        assert_eq!(
            load_optional_selection_checkpoint(&current_path)
                .unwrap()
                .unwrap()
                .contract,
            new_contract
        );
    }

    #[test]
    fn recovered_selection_contract_is_published_as_converged() {
        let service = service_test_snapshot_with_backend(7, 4);
        let node = node_port_node_snapshot(3);
        let contract = NetworkBehaviorContract::compile(
            &service,
            Revision::new(8),
            Revision::new(8),
            local_selection_node(&node, Some("zone-a".to_owned())),
        )
        .unwrap();
        let state = test_agent_state();

        publish_recovered_selection_contract(&state, Some(&contract), 1);

        assert_eq!(
            state
                .desired_selection_contract_revision
                .load(Ordering::Acquire),
            contract.contract_revision.get()
        );
        assert_eq!(
            state
                .applied_selection_contract_revision
                .load(Ordering::Acquire),
            contract.contract_revision.get()
        );
        assert_eq!(
            *mutex_lock(&state.desired_selection_contract_digest),
            Some(contract.contract_digest.to_string())
        );
        assert_eq!(
            *mutex_lock(&state.applied_selection_contract_digest),
            Some(contract.contract_digest.to_string())
        );
        assert_eq!(state.active_selection_bank.load(Ordering::Acquire), 1);
    }

    #[test]
    fn selection_inactive_stage_reads_back_and_restores_previous_content_on_rejection() {
        let service = service_test_snapshot_with_backend(7, 4);
        let node = node_port_node_snapshot(3);
        let contract = NetworkBehaviorContract::compile(
            &service,
            Revision::new(8),
            Revision::new(8),
            local_selection_node(&node, Some("zone-a".to_owned())),
        )
        .unwrap();
        let mut banks = [Some(contract.clone()), None];
        let mut mutated = contract.clone();
        mutated.contract_revision = mutated.contract_revision.next();
        assert!(
            stage_selection_contract(&mut banks, 0, &mutated, &service, &node).is_err(),
            "readback rejects a staged contract whose digest no longer matches"
        );
        assert_eq!(banks, [Some(contract.clone()), None]);

        let previous = stage_selection_contract(&mut banks, 1, &contract, &service, &node)
            .expect("a verified contract stages in the inactive bank");
        assert!(previous.is_none());
        assert_eq!(banks[1], Some(contract));
    }

    #[test]
    fn service_schema_transition_reads_v1_without_breaking_rollback() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("service-snapshot.json");
        let mut legacy = service_test_snapshot(7, 4);
        legacy.schema_version = LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        persist_secure_json(&path, &legacy, "legacy service").unwrap();

        let migrated = load_optional_service_snapshot(&path)
            .expect("legacy checkpoint migration succeeds")
            .expect("legacy checkpoint exists");
        assert_eq!(migrated.schema_version, SERVICE_SNAPSHOT_SCHEMA_VERSION);
        let persisted: ServiceSnapshot = load_secure_json(&path, "service").unwrap();
        assert_eq!(
            persisted.schema_version,
            LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION
        );

        let node_port_path = directory.path().join("node-port-snapshot.json");
        let mut node_port = service_test_snapshot(7, 5);
        node_port.services[0]
            .node_ports
            .push(unf_service::ServiceNodePort {
                family: unf_service::AddressFamily::Ipv4,
                port: 30_080,
                service_port: 80,
                protocol: unf_common::Protocol::Tcp,
                name: Some("http".to_owned()),
                app_protocol: Some("kubernetes.io/h2c".to_owned()),
                traffic_policy: unf_service::ServiceTrafficPolicy::Cluster,
                backend_ids: Vec::new(),
            });
        let state = test_agent_state();
        let mut applied = None;
        let error = adopt_service_snapshot(node_port, &mut applied, &node_port_path, &state)
            .expect_err("userspace reconciliation rejects NodePort intent");
        assert!(error.to_string().contains("host-facing lowering"));
        assert!(!node_port_path.exists());
        assert_eq!(agent_state_report(&state).desired_service_revision, 5);
        assert_eq!(agent_state_report(&state).applied_service_revision, 0);
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
        corrupt_value[24] = 0;
        assert!(validate_service_frontend_entry(key, &corrupt_value, 7).is_err());
        let mut corrupt_key = *key;
        corrupt_key[7] = SERVICE_BANK_COUNT;
        assert!(validate_service_frontend_entry(&corrupt_key, value, 7).is_err());

        let node_port = compile_node_port_fabric_dataplane(
            &dual_stack_node_port_snapshot(4),
            &node_port_node_snapshot(7),
            1,
            0,
        )
        .unwrap()
        .node_port;
        assert_eq!(
            decode_recovered_node_port_config(node_port.config).unwrap(),
            Some((7, 4, 7, 4, 2, 0))
        );
        let (key, value) = node_port.ipv4_frontends.first_key_value().unwrap();
        validate_node_port_frontend_entry(key, value, 7).unwrap();
        let mut corrupt_value = *value;
        corrupt_value[24] = SERVICE_BANK_COUNT;
        assert!(validate_node_port_frontend_entry(key, &corrupt_value, 7).is_err());
        let mut corrupt_value = *value;
        corrupt_value[25] = 0;
        assert!(validate_node_port_frontend_entry(key, &corrupt_value, 7).is_err());
        let mut corrupt_config = node_port.config;
        corrupt_config[35] = 1;
        assert!(decode_recovered_node_port_config(corrupt_config).is_err());
    }

    #[test]
    fn service_map_checkpoint_recovers_each_two_phase_crash_boundary() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("service.json");
        let first = service_test_snapshot(7, 1);
        let second = service_test_snapshot(7, 2);
        persist_secure_json(&path, &first, "service").unwrap();

        let pending = prepare_service_checkpoint(&path, &second, None).unwrap();
        assert!(pending.exists());
        let recovered = load_service_snapshot_for_active(&path, 7, 1).unwrap();
        assert_eq!(recovered, first);
        assert!(!pending.exists());

        let pending = prepare_service_checkpoint(&path, &second, None).unwrap();
        let recovered = load_service_snapshot_for_active(&path, 7, 2).unwrap();
        assert_eq!(recovered, second);
        assert!(!pending.exists());
        assert_eq!(load_optional_service_snapshot(&path).unwrap(), Some(second));
    }

    #[test]
    #[ignore = "requires root bpffs access and UNF_EBPF_OBJECT"]
    fn privileged_pinned_tail_call_map_survives_agent_owner_exit() {
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let root = PathBuf::from(format!(
            "/sys/fs/bpf/unf-tail-map-test-{}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("isolated bpffs test directory is created");
        let pin = root.join(DATAPLANE_TAIL_CALL_MAP_NAME);

        let mut loader = EbpfLoader::new();
        loader.map_pin_path(DATAPLANE_TAIL_CALL_MAP_NAME, &pin);
        let mut ebpf = loader
            .load_file(object)
            .expect("load eBPF object with a pinned tail-call map");
        load_dataplane_tail_programs(&mut ebpf).expect("populate all tail-call targets");
        drop(ebpf);

        let map = MapData::from_pin(&pin).expect("reopen tail-call map after owner exit");
        let tail_calls = AyaProgramArray::try_from(aya::maps::Map::ProgramArray(map))
            .expect("pinned map remains a program array");
        let indices = tail_calls
            .indices()
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("read retained tail-call indices");
        assert_eq!(indices, vec![0, 1, 2, 3, 4, 5]);
        drop(tail_calls);

        fs::remove_file(&pin).expect("remove isolated tail-call map pin");
        fs::remove_dir(&root).expect("remove isolated bpffs test directory");
    }

    #[test]
    #[ignore = "requires root BPF map creation and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_egress_bank_activation_rollback_and_recovery_are_exact() {
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut loader = EbpfLoader::new();
        loader.map_max_entries("EGRESS_SOURCES", 2);
        let mut ebpf = loader
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        let (
            sources,
            ipv4_destinations,
            ipv6_destinations,
            addresses,
            gateways,
            selections,
            config,
            gateway_nat_sources,
            gateway_nat_ipv4_destinations,
            gateway_nat_ipv6_destinations,
            gateway_nat_addresses,
            gateway_nat_gateways,
            gateway_nat_selections,
            gateway_nat_config,
            connections,
        ) = take_egress_maps(&mut ebpf).expect("take egress maps");
        let mut synchronizer = EgressSynchronizer {
            sources,
            ipv4_destinations,
            ipv6_destinations,
            addresses,
            gateways,
            selections,
            config,
            gateway_nat_sources,
            gateway_nat_ipv4_destinations,
            gateway_nat_ipv6_destinations,
            gateway_nat_addresses,
            gateway_nat_gateways,
            gateway_nat_selections,
            gateway_nat_config,
            connections,
            banks: [EncodedEgressBank::default(), EncodedEgressBank::default()],
            gateway_nat_banks: [EncodedEgressBank::default(), EncodedEgressBank::default()],
            active_bank: 0,
            gateway_nat_active_bank: 0,
            ledger: EgressProjectionLedger::default(),
            gateway_ledger: EgressGatewayProjectionLedger::default(),
            applied_authority: None,
            path_provider: None,
            node_name: "worker-a".to_owned(),
            controller_url: None,
            client: ReloadingControllerClient::without_custom_trust(
                Counter::default(),
                Counter::default(),
            ),
            agent_token_path: PathBuf::new(),
            interval: Duration::from_secs(1),
        };
        let make_state = |bank: u8, identities: &[u32]| EgressDataplaneState {
            config: unf_ebpf_common::EgressMapConfig {
                controller_epoch: 7,
                projection_revision: 11 + u64::from(bank),
                contract_revision: 13 + u64::from(bank),
                path_revision: 0,
                source_count: u32::try_from(identities.len()).unwrap(),
                address_count: 0,
                gateway_count: 0,
                selection_count: 0,
                schema_version: EGRESS_MAP_ABI_VERSION,
                active_bank: bank,
                flags: 0,
                destination_count: 1,
            },
            sources: identities
                .iter()
                .map(|identity| {
                    (
                        unf_ebpf_common::EgressSourceKey {
                            source_identity: IdentityId::new(*identity),
                            bank,
                            reserved: [0; 3],
                        },
                        unf_ebpf_common::EgressSourceValue {
                            lease_epoch: 17,
                            contract_revision: 13 + u64::from(bank),
                            intent_revision: 2,
                            identity_revision: 3,
                            policy_revision: 5,
                            allocation_revision: 7,
                            gateway_revision: 11,
                            reachability_revision: 12,
                            contract_digest: [0xA5; 32],
                            intent_digest: [0x5A; 16],
                            intent_index: 0,
                            address_count: 0,
                            gateway_count: 0,
                            schema_version: EGRESS_MAP_ABI_VERSION,
                            admission: unf_ebpf_common::EGRESS_ADMISSION_FENCED,
                            flags: unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV4,
                            reserved: [0; 4],
                        },
                    )
                })
                .collect(),
            ipv4_destinations: vec![(
                0,
                unf_ebpf_common::EgressIpv4DestinationData {
                    intent_index: 0,
                    bank,
                    reserved: [0; 3],
                    destination_address: [0; 4],
                },
                unf_ebpf_common::EgressDestinationValue {
                    contract_revision: 13 + u64::from(bank),
                    intent_digest: [0x5A; 16],
                    schema_version: EGRESS_MAP_ABI_VERSION,
                    flags: 0,
                    reserved: [0; 4],
                },
            )],
            ipv6_destinations: Vec::new(),
            addresses: Vec::new(),
            gateways: Vec::new(),
            selections: Vec::new(),
        };

        let first = make_state(1, &[42]);
        apply_egress_dataplane(&mut synchronizer, &first)
            .expect("first egress bank activates atomically");
        let active_config = synchronizer.config.get(&0, 0).unwrap();
        assert_eq!(active_config[50], 1);

        let error = apply_egress_dataplane(&mut synchronizer, &make_state(0, &[43, 44]))
            .expect_err("capacity failure rolls the inactive bank back");
        assert!(error.to_string().contains("staging bank was rolled back"));
        assert_eq!(synchronizer.config.get(&0, 0).unwrap(), active_config);
        assert_eq!(synchronizer.sources.keys().count(), 1);

        synchronizer.banks = [EncodedEgressBank::default(), EncodedEgressBank::default()];
        synchronizer.active_bank = 0;
        recover_egress_state(&mut synchronizer).expect("active egress bank recovers exactly");
        assert_eq!(synchronizer.active_bank, 1);
        assert_eq!(synchronizer.banks[1].sources.len(), 1);
        assert!(synchronizer.banks[0].sources.is_empty());
    }

    #[test]
    #[ignore = "requires root BPF program execution and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_egress_source_steering_is_policy_first_destination_exact_and_dual_stack() {
        const TC_ACT_SHOT: u32 = 2;
        const TC_ACT_PIPE: u32 = 3;
        const TC_ACT_REDIRECT: u32 = 7;
        const POLICY_REVISION: u64 = 5;
        const CONTRACT_REVISION: u64 = 13;
        const PATH_REVISION: u64 = 19;
        const BANK: u8 = 1;

        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut loader = EbpfLoader::new();
        loader.map_max_entries("EGRESS_EVENTS", 4_096);
        let mut ebpf = loader
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts source-steering tail programs");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("UNF TC program exists")
                .try_into()
                .expect("UNF program is a TC classifier");
            program
                .load()
                .expect("kernel verifier accepts UNF TC program");
        }
        let mut egress_events = RingBuf::try_from(
            ebpf.take_map("EGRESS_EVENTS")
                .expect("egress event ring exists"),
        )
        .expect("egress event ring opens");
        let egress_event_counters = AyaPerCpuArray::<_, u64>::try_from(
            ebpf.take_map("EGRESS_EVENT_COUNTERS")
                .expect("egress event counters exist"),
        )
        .expect("egress event counters open");

        let source_v4 = Ipv4Addr::new(10, 244, 0, 20);
        let destination_v4 = Ipv4Addr::new(203, 0, 113, 9);
        let source_v6: Ipv6Addr = "fd00::20".parse().unwrap();
        let destination_v6: Ipv6Addr = "2001:db8:1::9".parse().unwrap();
        let identity_v4 = IdentityId::new(42);
        let identity_v6 = IdentityId::new(43);

        let (mut identity_v4_maps, mut identity_v6_maps, mut identity_config) =
            take_identity_maps(&mut ebpf).expect("take identity maps");
        identity_v4_maps[0]
            .insert(
                source_v4.octets(),
                encode_identity_value(IdentityMapValue::new(identity_v4, 3)),
                0,
            )
            .unwrap();
        identity_v6_maps[0]
            .insert(
                source_v6.octets(),
                encode_identity_value(IdentityMapValue::new(identity_v6, 3)),
                0,
            )
            .unwrap();
        identity_config
            .set(0, encode_identity_config(7, 3, 2, 0).unwrap(), 0)
            .unwrap();

        let (
            _identity_policy,
            _ipv4_policy,
            _ipv6_policy,
            mut egress_ipv4_policy,
            _egress_ipv6_policy,
            mut policy_config,
        ) = take_policy_maps(&mut ebpf).expect("take policy maps");
        policy_config
            .set(
                0,
                encode_policy_config(7, POLICY_REVISION, 0, 0).unwrap(),
                0,
            )
            .unwrap();

        let (
            sources,
            ipv4_destinations,
            ipv6_destinations,
            addresses,
            gateways,
            selections,
            config,
            gateway_nat_sources,
            gateway_nat_ipv4_destinations,
            gateway_nat_ipv6_destinations,
            gateway_nat_addresses,
            gateway_nat_gateways,
            gateway_nat_selections,
            gateway_nat_config,
            connections,
        ) = take_egress_maps(&mut ebpf).expect("take egress maps");
        let mut synchronizer = EgressSynchronizer {
            sources,
            ipv4_destinations,
            ipv6_destinations,
            addresses,
            gateways,
            selections,
            config,
            gateway_nat_sources,
            gateway_nat_ipv4_destinations,
            gateway_nat_ipv6_destinations,
            gateway_nat_addresses,
            gateway_nat_gateways,
            gateway_nat_selections,
            gateway_nat_config,
            connections,
            banks: [EncodedEgressBank::default(), EncodedEgressBank::default()],
            gateway_nat_banks: [EncodedEgressBank::default(), EncodedEgressBank::default()],
            active_bank: 0,
            gateway_nat_active_bank: 0,
            ledger: EgressProjectionLedger::default(),
            gateway_ledger: EgressGatewayProjectionLedger::default(),
            applied_authority: None,
            path_provider: None,
            node_name: "worker-a".to_owned(),
            controller_url: None,
            client: ReloadingControllerClient::without_custom_trust(
                Counter::default(),
                Counter::default(),
            ),
            agent_token_path: PathBuf::new(),
            interval: Duration::from_secs(1),
        };

        let source_value = |flags: u8| unf_ebpf_common::EgressSourceValue {
            lease_epoch: 17,
            contract_revision: CONTRACT_REVISION,
            intent_revision: 2,
            identity_revision: 3,
            policy_revision: POLICY_REVISION,
            allocation_revision: 7,
            gateway_revision: 11,
            reachability_revision: 12,
            contract_digest: [0xA5; 32],
            intent_digest: [0x5A; 16],
            intent_index: flags.into(),
            address_count: 1,
            gateway_count: 1,
            schema_version: EGRESS_MAP_ABI_VERSION,
            admission: unf_ebpf_common::EGRESS_ADMISSION_ACTIVE,
            flags,
            reserved: [0; 4],
        };
        let source_v4_value = source_value(unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV4);
        let source_v6_value = source_value(unf_ebpf_common::EGRESS_SOURCE_FLAG_IPV6);
        let intent_v4 = source_v4_value.intent_index;
        let intent_v6 = source_v6_value.intent_index;
        let destination_value = unf_ebpf_common::EgressDestinationValue {
            contract_revision: CONTRACT_REVISION,
            intent_digest: [0x5A; 16],
            schema_version: EGRESS_MAP_ABI_VERSION,
            flags: 0,
            reserved: [0; 4],
        };
        let address_bytes = |address: IpAddr| match address {
            IpAddr::V4(address) => {
                let mut value = [0; 16];
                value[..4].copy_from_slice(&address.octets());
                value
            }
            IpAddr::V6(address) => address.octets(),
        };
        let address_value = |address: IpAddr| unf_ebpf_common::EgressAddressValue {
            lease_epoch: 17,
            contract_revision: CONTRACT_REVISION,
            address: address_bytes(address),
            candidate_witness: [0x11; 16],
            schema_version: EGRESS_MAP_ABI_VERSION,
            flags: 0,
            reserved: [0; 4],
        };
        let gateway_value = |transport: IpAddr| unf_ebpf_common::EgressGatewayValue {
            lease_epoch: 17,
            contract_revision: CONTRACT_REVISION,
            path_revision: PATH_REVISION,
            transport_address: address_bytes(transport),
            next_hop_address: address_bytes(transport),
            gateway_digest: [0x22; 16],
            output_interface: 1,
            mtu: 1_500,
            schema_version: EGRESS_MAP_ABI_VERSION,
            path_mode: unf_ebpf_common::EGRESS_PATH_DIRECT_NEIGHBOR,
            flags: 0,
            reserved: [0; 4],
        };
        let packet_v4 = ipv4_packet(6, source_v4, destination_v4, 40_000, 443);
        let packet_v6 = ipv6_packet(6, source_v6, destination_v6, 40_001, 443);
        let selection = |identity: IdentityId,
                         source: [u8; 16],
                         destination: [u8; 16],
                         source_port: u16,
                         family: u8,
                         intent_index: u32| {
            let flow = unf_ebpf_common::EgressConnectionKey {
                source_address: source,
                destination_address: destination,
                source_port: source_port.to_be_bytes(),
                destination_port: 443_u16.to_be_bytes(),
                source_identity: identity,
                protocol: 6,
                address_family: family,
                role: unf_ebpf_common::EGRESS_CONNECTION_ROLE_FORWARD,
                reserved: 0,
            };
            (
                unf_ebpf_common::EgressSelectionKey {
                    intent_index,
                    bucket: unf_ebpf_common::egress_selection_bucket(&flow),
                    address_family: family,
                    bank: BANK,
                },
                unf_ebpf_common::EgressSelectionValue {
                    selection_witness: [0x33; 16],
                    address_index: 0,
                    primary_gateway_index: 0,
                    standby_gateway_index: 0,
                    schema_version: EGRESS_MAP_ABI_VERSION,
                    flags: 0,
                    reserved: [0; 6],
                },
            )
        };
        let expanded_v4 = {
            let mut value = [0; 16];
            value[..4].copy_from_slice(&source_v4.octets());
            value
        };
        let expanded_destination_v4 = {
            let mut value = [0; 16];
            value[..4].copy_from_slice(&destination_v4.octets());
            value
        };
        let state = EgressDataplaneState {
            config: unf_ebpf_common::EgressMapConfig {
                controller_epoch: 7,
                projection_revision: 11,
                contract_revision: CONTRACT_REVISION,
                path_revision: PATH_REVISION,
                source_count: 2,
                address_count: 2,
                gateway_count: 2,
                selection_count: 2,
                schema_version: EGRESS_MAP_ABI_VERSION,
                active_bank: BANK,
                flags: 0,
                destination_count: 2,
            },
            sources: vec![
                (
                    unf_ebpf_common::EgressSourceKey {
                        source_identity: identity_v4,
                        bank: BANK,
                        reserved: [0; 3],
                    },
                    source_v4_value,
                ),
                (
                    unf_ebpf_common::EgressSourceKey {
                        source_identity: identity_v6,
                        bank: BANK,
                        reserved: [0; 3],
                    },
                    source_v6_value,
                ),
            ],
            ipv4_destinations: vec![(
                24,
                unf_ebpf_common::EgressIpv4DestinationData {
                    intent_index: intent_v4,
                    bank: BANK,
                    reserved: [0; 3],
                    destination_address: [203, 0, 113, 0],
                },
                destination_value,
            )],
            ipv6_destinations: vec![(
                64,
                unf_ebpf_common::EgressIpv6DestinationData {
                    intent_index: intent_v6,
                    bank: BANK,
                    reserved: [0; 3],
                    destination_address: "2001:db8:1::".parse::<Ipv6Addr>().unwrap().octets(),
                },
                destination_value,
            )],
            addresses: vec![
                (
                    unf_ebpf_common::EgressCandidateKey {
                        intent_index: intent_v4,
                        candidate_index: 0,
                        address_family: 4,
                        bank: BANK,
                    },
                    address_value("198.51.100.10".parse().unwrap()),
                ),
                (
                    unf_ebpf_common::EgressCandidateKey {
                        intent_index: intent_v6,
                        candidate_index: 0,
                        address_family: 6,
                        bank: BANK,
                    },
                    address_value("2001:db8:ffff::10".parse().unwrap()),
                ),
            ],
            gateways: vec![
                (
                    unf_ebpf_common::EgressCandidateKey {
                        intent_index: intent_v4,
                        candidate_index: 0,
                        address_family: 4,
                        bank: BANK,
                    },
                    gateway_value("192.0.2.2".parse().unwrap()),
                ),
                (
                    unf_ebpf_common::EgressCandidateKey {
                        intent_index: intent_v6,
                        candidate_index: 0,
                        address_family: 6,
                        bank: BANK,
                    },
                    gateway_value("2001:db8:ffff::2".parse().unwrap()),
                ),
            ],
            selections: vec![
                selection(
                    identity_v4,
                    expanded_v4,
                    expanded_destination_v4,
                    40_000,
                    4,
                    intent_v4,
                ),
                selection(
                    identity_v6,
                    source_v6.octets(),
                    destination_v6.octets(),
                    40_001,
                    6,
                    intent_v6,
                ),
            ],
        };
        apply_egress_dataplane(&mut synchronizer, &state)
            .expect("activate exact destination-aware egress state");

        for packet in [&packet_v4, &packet_v6] {
            let (action, output) = run_tc(&mut ebpf, "unf_observe_ingress", packet);
            assert_eq!(action, TC_ACT_REDIRECT);
            assert_eq!(
                &output, packet,
                "source steering must preserve the original tuple"
            );
        }
        let outside_v4 = ipv4_packet(6, source_v4, Ipv4Addr::new(198, 51, 100, 9), 40_002, 443);
        let outside_v6 = ipv6_packet(6, source_v6, "2001:db9::9".parse().unwrap(), 40_003, 443);
        assert_eq!(
            run_tc(&mut ebpf, "unf_observe_ingress", &outside_v4).0,
            TC_ACT_PIPE
        );
        assert_eq!(
            run_tc(&mut ebpf, "unf_observe_ingress", &outside_v6).0,
            TC_ACT_PIPE
        );

        let mut fenced = state.sources[0].1;
        fenced.admission = unf_ebpf_common::EGRESS_ADMISSION_FENCED;
        fenced.address_count = 0;
        fenced.gateway_count = 0;
        synchronizer
            .sources
            .insert(
                encode_egress_source_key(state.sources[0].0),
                encode_egress_source_value(&fenced),
                0,
            )
            .unwrap();
        assert_eq!(
            run_tc(&mut ebpf, "unf_observe_ingress", &packet_v4).0,
            TC_ACT_SHOT
        );
        assert_eq!(
            run_tc(&mut ebpf, "unf_observe_ingress", &outside_v4).0,
            TC_ACT_PIPE,
            "a fenced target must not capture an unrelated destination"
        );
        synchronizer
            .sources
            .insert(
                encode_egress_source_key(state.sources[0].0),
                encode_egress_source_value(&state.sources[0].1),
                0,
            )
            .unwrap();

        let mut gateway_state = state.clone();
        gateway_state.config.contract_revision = 0;
        gateway_state.config.path_revision = 0;
        gateway_state.config.flags = unf_ebpf_common::EGRESS_CONFIG_FLAG_GATEWAY_NAT;
        for (key, value) in &mut gateway_state.sources {
            value.intent_index = key.source_identity.get();
            value.flags |= unf_ebpf_common::EGRESS_SOURCE_FLAG_GATEWAY_NAT;
            value.reserved = [0; 4];
        }
        gateway_state.ipv4_destinations[0].1.intent_index = identity_v4.get();
        gateway_state.ipv6_destinations[0].1.intent_index = identity_v6.get();
        gateway_state.addresses[0].0.intent_index = identity_v4.get();
        gateway_state.addresses[1].0.intent_index = identity_v6.get();
        gateway_state.gateways[0].0.intent_index = identity_v4.get();
        gateway_state.gateways[1].0.intent_index = identity_v6.get();
        for (_, gateway) in &mut gateway_state.gateways {
            gateway.transport_address = [0; 16];
            gateway.next_hop_address = [0; 16];
            gateway.output_interface = 0;
            gateway.mtu = 0;
            gateway.path_mode = 0;
        }
        gateway_state.selections.clear();
        for (identity, family) in [(identity_v4, 4_u8), (identity_v6, 6_u8)] {
            for bucket in 0..unf_ebpf_common::EGRESS_SELECTION_TABLE_SIZE {
                gateway_state.selections.push((
                    unf_ebpf_common::EgressSelectionKey {
                        intent_index: identity.get(),
                        bucket,
                        address_family: family,
                        bank: BANK,
                    },
                    unf_ebpf_common::EgressSelectionValue {
                        selection_witness: [0x33; 16],
                        address_index: 0,
                        primary_gateway_index: 0,
                        standby_gateway_index: 0,
                        schema_version: EGRESS_MAP_ABI_VERSION,
                        flags: 0,
                        reserved: [0; 6],
                    },
                ));
            }
        }
        gateway_state.config.selection_count =
            u32::try_from(gateway_state.selections.len()).unwrap();
        apply_egress_gateway_dataplane(&mut synchronizer, &gateway_state)
            .expect("activate heterogeneous gateway NAT bank");
        synchronizer.gateway_nat_banks =
            [EncodedEgressBank::default(), EncodedEgressBank::default()];
        synchronizer.gateway_nat_active_bank = 0;
        recover_egress_gateway_nat_state(&mut synchronizer)
            .expect("recover exact gateway NAT bank after agent restart");
        assert_eq!(synchronizer.gateway_nat_active_bank, BANK);
        let recovered_gateway =
            &synchronizer.gateway_nat_banks[usize::from(synchronizer.gateway_nat_active_bank)];
        assert_eq!(recovered_gateway.sources.len(), 2);
        assert_eq!(recovered_gateway.ipv4_destinations.len(), 1);
        assert_eq!(recovered_gateway.ipv6_destinations.len(), 1);
        assert_eq!(
            recovered_gateway.selections.len(),
            usize::from(unf_ebpf_common::EGRESS_SELECTION_TABLE_SIZE) * 2
        );

        let egress_v4 = Ipv4Addr::new(198, 51, 100, 10);
        let egress_v6: Ipv6Addr = "2001:db8:ffff::10".parse().unwrap();
        let (action, translated_v4) = run_tc(&mut ebpf, "unf_observe_ingress", &packet_v4);
        assert_eq!(action, TC_ACT_PIPE);
        let translated_port_v4 = u16::from_be_bytes([translated_v4[34], translated_v4[35]]);
        assert!((unf_ebpf_common::EGRESS_SNAT_PORT_BASE..=u16::MAX).contains(&translated_port_v4));
        assert_ipv4_packet(
            &translated_v4,
            6,
            egress_v4,
            destination_v4,
            translated_port_v4,
            443,
        );
        let reverse_v4 = ipv4_packet(6, destination_v4, egress_v4, 443, translated_port_v4);
        let (action, restored_v4) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse_v4);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&restored_v4, 6, destination_v4, source_v4, 443, 40_000);

        let (action, translated_v6) = run_tc(&mut ebpf, "unf_observe_ingress", &packet_v6);
        assert_eq!(action, TC_ACT_PIPE);
        let translated_port_v6 = u16::from_be_bytes([translated_v6[54], translated_v6[55]]);
        assert_ipv6_packet(
            &translated_v6,
            6,
            egress_v6,
            destination_v6,
            translated_port_v6,
            443,
        );
        let reverse_v6 = ipv6_packet(6, destination_v6, egress_v6, 443, translated_port_v6);
        let (action, restored_v6) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse_v6);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&restored_v6, 6, destination_v6, source_v6, 443, 40_001);

        let first_flow = unf_ebpf_common::EgressConnectionKey {
            source_address: expanded_v4,
            destination_address: expanded_destination_v4,
            source_port: 40_000_u16.to_be_bytes(),
            destination_port: 443_u16.to_be_bytes(),
            source_identity: identity_v4,
            protocol: 6,
            address_family: 4,
            role: unf_ebpf_common::EGRESS_CONNECTION_ROLE_FORWARD,
            reserved: 0,
        };
        let proof_salt = u32::from_ne_bytes([0x33; 4]);
        let first_candidate = unf_ebpf_common::egress_snat_candidate(
            unf_ebpf_common::egress_flow_hash(&first_flow),
            proof_salt,
            0,
        );
        assert_eq!(first_candidate, translated_port_v4);
        let colliding_source_port = (1_u16..=u16::MAX)
            .filter(|port| *port != 40_000)
            .find(|port| {
                let mut candidate = first_flow;
                candidate.source_port = port.to_be_bytes();
                unf_ebpf_common::egress_snat_candidate(
                    unf_ebpf_common::egress_flow_hash(&candidate),
                    proof_salt,
                    0,
                ) == first_candidate
            })
            .expect("another original tuple shares the first candidate");
        let collision_packet =
            ipv4_packet(6, source_v4, destination_v4, colliding_source_port, 443);
        let (action, collision_output) =
            run_tc(&mut ebpf, "unf_observe_ingress", &collision_packet);
        assert_eq!(action, TC_ACT_PIPE);
        let collision_port = u16::from_be_bytes([collision_output[34], collision_output[35]]);
        assert_ne!(collision_port, translated_port_v4);
        let (action, restored_v4_again) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse_v4);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(
            &restored_v4_again,
            6,
            destination_v4,
            source_v4,
            443,
            40_000,
        );

        let mut nat_events = Vec::new();
        while let Some(item) = egress_events.next() {
            nat_events.push(decode_egress_event(&item).expect("kernel egress event is valid"));
        }
        assert_eq!(nat_events.len(), 3, "only new NAT flows emit witnesses");
        assert!(nat_events.iter().all(|event| {
            event.action == EGRESS_EVENT_ACTION_CREATE
                && event.reason == unf_ebpf_common::EGRESS_EVENT_REASON_TRANSLATION_CREATED
                && event.contract_revision == CONTRACT_REVISION
                && event.lease_epoch == 17
                && event.gateway_digest == [0x22; 16]
                && event.proof_witness == [0x33; 16]
                && event.translated_source_port != [0; 2]
        }));
        assert_eq!(
            nat_events
                .iter()
                .filter(|event| event.address_family == 4)
                .count(),
            2
        );
        assert_eq!(
            nat_events
                .iter()
                .filter(|event| event.address_family == 6)
                .count(),
            1
        );
        let counter_total = |index| {
            egress_event_counters
                .get(&index, 0)
                .expect("egress event counter reads")
                .iter()
                .copied()
                .sum::<u64>()
        };
        assert_eq!(counter_total(EGRESS_EVENT_COUNTER_ATTEMPTED), 3);
        assert_eq!(counter_total(EGRESS_EVENT_COUNTER_DROPPED), 0);

        for source_port in 41_000_u16..41_064 {
            let packet = ipv4_packet(6, source_v4, destination_v4, source_port, 443);
            assert_eq!(
                run_tc(&mut ebpf, "unf_observe_ingress", &packet).0,
                TC_ACT_PIPE,
                "full telemetry ring must never stop NAT forwarding"
            );
        }
        let attempts_after_pressure = counter_total(EGRESS_EVENT_COUNTER_ATTEMPTED);
        let drops_after_pressure = counter_total(EGRESS_EVENT_COUNTER_DROPPED);
        assert_eq!(attempts_after_pressure, 67);
        assert!(
            drops_after_pressure > 0,
            "small ring must expose event loss"
        );
        let mut retained_after_pressure = 0_u64;
        while let Some(item) = egress_events.next() {
            decode_egress_event(&item).expect("retained pressure event remains valid");
            retained_after_pressure += 1;
        }
        assert_eq!(retained_after_pressure + drops_after_pressure, 64);

        let mut deny_key = [0_u8; 12];
        deny_key[0..4].copy_from_slice(&destination_v4.octets());
        deny_key[4..8].copy_from_slice(&identity_v4.get().to_ne_bytes());
        deny_key[8..10].copy_from_slice(&443_u16.to_be_bytes());
        deny_key[10] = 6;
        let mut deny_value = [0_u8; 32];
        deny_value[0..4].copy_from_slice(&1_u32.to_ne_bytes());
        deny_value[4..8].copy_from_slice(&1_u32.to_ne_bytes());
        deny_value[16..24].copy_from_slice(&POLICY_REVISION.to_ne_bytes());
        deny_value[24..26].copy_from_slice(&POLICY_MAP_ABI_VERSION.to_ne_bytes());
        deny_value[26..28]
            .copy_from_slice(&(POLICY_FLAG_HAS_POLICY | POLICY_FLAG_HAS_RULE).to_ne_bytes());
        deny_value[28] = Verdict::Deny as u8;
        deny_value[29] = PolicyReason::ExplicitRule as u8;
        egress_ipv4_policy.insert(deny_key, deny_value, 0).unwrap();
        policy_config
            .set(
                0,
                encode_policy_config(7, POLICY_REVISION, 1, 0).unwrap(),
                0,
            )
            .unwrap();
        assert_eq!(
            run_tc(&mut ebpf, "unf_observe_ingress", &packet_v4).0,
            TC_ACT_SHOT,
            "policy denial must win before a valid source-steering contract"
        );
    }

    #[test]
    #[ignore = "requires root BPF map creation and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
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
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts dataplane tail programs");
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
            affinity,
            node_port_ipv4_frontends,
            node_port_ipv6_frontends,
            node_port_config,
            load_balancer_ipv4_frontends,
            load_balancer_ipv6_frontends,
            load_balancer_ipv4_source_ranges,
            load_balancer_ipv6_source_ranges,
            load_balancer_config,
            load_balancer_node_source,
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
            affinity,
            node_port_ipv4_frontends,
            node_port_ipv6_frontends,
            node_port_config,
            load_balancer_ipv4_frontends,
            load_balancer_ipv6_frontends,
            load_balancer_ipv4_source_ranges,
            load_balancer_ipv6_source_ranges,
            load_balancer_config,
            load_balancer_node_source,
            health_checks: HealthCheckManager::default(),
            banks: [None, None],
            node_port_banks: [None, None],
            load_balancer_banks: [None, None],
            selection_banks: [None, None],
            active_bank: 0,
            active_node_port_bank: 0,
            active_load_balancer_bank: 0,
            applied: None,
            applied_node_port_node: None,
            applied_load_balancer_reachability: None,
            applied_selection_contract: None,
            active_selection_bank: 0,
            node_name: "worker-a".to_owned(),
            controller_url: None,
            client: ReloadingControllerClient::without_custom_trust(
                Counter::default(),
                Counter::default(),
            ),
            agent_token_path: PathBuf::new(),
            state_path: directory.path().join("service.json"),
            load_balancer_state_path: directory.path().join("load-balancer.json"),
            interval: Duration::from_secs(1),
        };
        let state = test_agent_state();
        let first = service_test_snapshot_with_backend(7, 1);
        activate_service_snapshot(&mut synchronizer, &first, None, false, &state)
            .expect("first service bank activates");
        let active_config = synchronizer.config.get(&0, 0).unwrap();
        assert_eq!(active_config[30], 1);

        let second = service_test_snapshot_with_backend(7, 2);
        let error = activate_service_snapshot(&mut synchronizer, &second, None, false, &state)
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
    #[ignore = "requires root BPF map creation and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_load_balancer_bank_activation_rollback_and_recovery_are_exact() {
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut loader = EbpfLoader::new();
        loader.map_max_entries("LOAD_BALANCER_FRONTENDS_V4", 1);
        let mut ebpf = loader
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        let directory = tempdir().unwrap();
        let service_path = directory.path().join("service.json");
        let mut synchronizer = test_service_synchronizer(&mut ebpf, service_path);
        let state = test_agent_state();
        let services = load_balancer_service_test_snapshot(7, 5);
        let node = node_port_node_snapshot(1);
        activate_service_snapshot(&mut synchronizer, &services, Some(&node), true, &state)
            .expect("LoadBalancer Service keeps existing service maps exact");

        let first = load_balancer_node_snapshot(&services, 3, &["192.0.2.4"]);
        publish_desired_load_balancer(&state, &first);
        activate_load_balancer_snapshot(&mut synchronizer, &first, &state)
            .expect("first VIP bank activates");
        let active_config = synchronizer.load_balancer_config.get(&0, 0).unwrap();
        assert_eq!(active_config[42], 1);
        assert_eq!(active_config[43], synchronizer.active_bank);
        assert_eq!(agent_state_report(&state).applied_load_balancer_revision, 3);
        assert_eq!(
            load_optional_load_balancer_reachability(&synchronizer.load_balancer_state_path)
                .unwrap(),
            Some(first.clone())
        );

        let second = load_balancer_node_snapshot(&services, 4, &["192.0.2.4", "192.0.2.5"]);
        publish_desired_load_balancer(&state, &second);
        let error = activate_load_balancer_snapshot(&mut synchronizer, &second, &state)
            .expect_err("undersized VIP map rejects partial inactive staging");
        assert!(error.to_string().contains("staging bank rolled back"));
        assert_eq!(
            synchronizer.load_balancer_config.get(&0, 0).unwrap(),
            active_config
        );
        assert_eq!(
            synchronizer.applied_load_balancer_reachability,
            Some(first.clone())
        );
        assert_eq!(
            load_optional_load_balancer_reachability(&synchronizer.load_balancer_state_path)
                .unwrap(),
            Some(first.clone())
        );

        synchronizer.load_balancer_banks = [None, None];
        synchronizer.active_load_balancer_bank = 0;
        synchronizer.applied_load_balancer_reachability = None;
        recover_load_balancer_state(&mut synchronizer)
            .expect("exact active VIP bank and checkpoint recover");
        assert_eq!(synchronizer.active_load_balancer_bank, 1);
        assert_eq!(
            synchronizer.applied_load_balancer_reachability,
            Some(first.clone())
        );

        let advanced_services = load_balancer_service_test_snapshot(7, 6);
        activate_service_snapshot(
            &mut synchronizer,
            &advanced_services,
            Some(&node),
            true,
            &state,
        )
        .expect("service domain can advance before LoadBalancer reconciliation");
        assert_eq!(
            synchronizer.load_balancer_config.get(&0, 0).unwrap(),
            active_config
        );

        synchronizer.banks = [None, None];
        synchronizer.applied = None;
        recover_service_state(&mut synchronizer)
            .expect("new active service tuple recovers after interrupted reconciliation");
        assert_eq!(
            synchronizer.load_balancer_node_source.get(&0, 0).unwrap(),
            encode_load_balancer_node_source(Some(&node))
        );
        synchronizer.load_balancer_banks = [None, None];
        synchronizer.active_load_balancer_bank = 0;
        synchronizer.applied_load_balancer_reachability = None;
        recover_load_balancer_state(&mut synchronizer)
            .expect("unlinked derived VIP state resets for authoritative replay");
        assert_eq!(
            synchronizer.load_balancer_config.get(&0, 0).unwrap(),
            [0; 48]
        );
        assert!(
            synchronizer
                .load_balancer_banks
                .iter()
                .flatten()
                .all(|bank| bank.ipv4_frontends.is_empty() && bank.ipv6_frontends.is_empty())
        );
        assert_eq!(
            load_optional_load_balancer_reachability(&synchronizer.load_balancer_state_path)
                .unwrap(),
            None
        );

        // A controller can retain a non-initial allocation revision after the
        // last LoadBalancer Service is deleted. Recovery must therefore fetch
        // and activate its empty Node projection even though the authoritative
        // Service snapshot no longer contains a LoadBalancer. Otherwise this
        // node remains at 0/0 while already-converged peers retain the current
        // allocation/reachability fence.
        let services_without_load_balancer = service_test_snapshot_with_backend(7, 7);
        activate_service_snapshot(
            &mut synchronizer,
            &services_without_load_balancer,
            None,
            true,
            &state,
        )
        .expect("post-deletion Service state activates");
        let empty_reachability = NodeReachabilitySnapshot {
            schema_version: unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION,
            source_epoch: services_without_load_balancer.source_epoch,
            revision: Revision::new(5),
            allocation_revision: Revision::new(9),
            provider: unf_loadbalancer::ReachabilityProviderRef {
                name: "direct-node".to_owned(),
                instance: "qualification-a".to_owned(),
                mode: unf_loadbalancer::ReachabilityMode::DirectNode,
            },
            node: unf_loadbalancer::ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            },
            targets: Vec::new(),
        }
        .validate()
        .expect("empty non-initial reachability projection validates");
        publish_desired_load_balancer(&state, &empty_reachability);
        activate_load_balancer_snapshot(&mut synchronizer, &empty_reachability, &state)
            .expect("empty post-deletion reachability fence replays after reset");
        let report = agent_state_report(&state);
        assert_eq!(report.desired_load_balancer_revision, 5);
        assert_eq!(report.applied_load_balancer_revision, 5);
        assert_eq!(report.desired_load_balancer_allocation_revision, 9);
        assert_eq!(report.applied_load_balancer_allocation_revision, 9);
        assert_eq!(report.load_balancer_frontend_count, 0);
        assert_eq!(
            synchronizer
                .applied_load_balancer_reachability
                .as_ref()
                .map(|snapshot| snapshot.revision.get()),
            Some(5)
        );
    }

    #[test]
    #[ignore = "requires root BPF map creation and UNF_EBPF_OBJECT"]
    fn privileged_load_balancer_relink_frees_the_next_service_bank() {
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        let directory = tempdir().unwrap();
        let service_path = directory.path().join("service.json");
        let mut synchronizer = test_service_synchronizer(&mut ebpf, service_path);
        let state = test_agent_state();
        let node = node_port_node_snapshot(1);

        let first_services = load_balancer_service_test_snapshot(7, 5);
        activate_service_snapshot(
            &mut synchronizer,
            &first_services,
            Some(&node),
            true,
            &state,
        )
        .expect("initial Service state activates");
        let old_reachability = load_balancer_node_snapshot(&first_services, 3, &["192.0.2.4"]);
        activate_load_balancer_snapshot(&mut synchronizer, &old_reachability, &state)
            .expect("initial LoadBalancer state activates");

        let mut current_node = node.clone();
        current_node.source_epoch = 8;
        let current_services = load_balancer_service_test_snapshot(8, 6);
        activate_service_snapshot(
            &mut synchronizer,
            &current_services,
            Some(&current_node),
            true,
            &state,
        )
        .expect("new controller epoch activates while old LoadBalancer state is retained");
        let next_services = load_balancer_service_test_snapshot(8, 7);
        let error = activate_service_snapshot(
            &mut synchronizer,
            &next_services,
            Some(&current_node),
            true,
            &state,
        )
        .expect_err("the old LoadBalancer link initially protects its referenced Service bank");
        assert!(error.to_string().contains("still referenced"));

        let current_reachability =
            load_balancer_node_snapshot(&current_services, 4, &["192.0.2.4"]);
        activate_load_balancer_snapshot(&mut synchronizer, &current_reachability, &state)
            .expect("LoadBalancer retry relinks to the currently active Service bank");
        activate_service_snapshot(
            &mut synchronizer,
            &next_services,
            Some(&current_node),
            true,
            &state,
        )
        .expect("next Service revision activates after derived-state relink");
        assert_eq!(synchronizer.applied.as_ref(), Some(&next_services));
    }

    #[test]
    #[ignore = "requires root BPF program execution and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_load_balancer_cluster_packets_translate_dual_stack_and_survive_churn() {
        const TC_ACT_SHOT: u32 = 2;
        const TC_ACT_PIPE: u32 = 3;
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts dataplane tail programs");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("service TC program exists")
                .try_into()
                .expect("service program is a TC classifier");
            program
                .load()
                .expect("kernel verifier accepts LoadBalancer TC program");
        }
        let mut service_events = RingBuf::try_from(
            ebpf.take_map("SERVICE_EVENTS")
                .expect("service event ring exists"),
        )
        .expect("service event ring opens");
        let (mut identity_v4_maps, _identity_v6_maps, mut identity_config) =
            take_identity_maps(&mut ebpf).expect("take identity maps");
        let (
            _identity_policy,
            mut ipv4_policy,
            _ipv6_policy,
            _egress_ipv4_policy,
            _egress_ipv6_policy,
            mut policy_config,
        ) = take_policy_maps(&mut ebpf).expect("take policy maps");
        let directory = tempdir().unwrap();
        let mut synchronizer =
            test_service_synchronizer(&mut ebpf, directory.path().join("service.json"));
        let state = test_agent_state();
        let client_v4 = Ipv4Addr::new(203, 0, 113, 5);
        let client_v6 = "2001:db8::5".parse::<Ipv6Addr>().unwrap();
        let vip_v4 = Ipv4Addr::new(192, 0, 2, 60);
        let vip_v6 = "2001:db8:ffff::60".parse::<Ipv6Addr>().unwrap();
        let backend_v4 = Ipv4Addr::new(10, 42, 0, 20);
        let backend_v6 = "fd00:42::20".parse::<Ipv6Addr>().unwrap();
        let node_v4 = Ipv4Addr::new(192, 0, 2, 10);
        let node_v6 = "fdff::10".parse::<Ipv6Addr>().unwrap();
        let node = node_port_node_snapshot(1);
        let first =
            dual_stack_service_snapshot_with_load_balancer(1, backend_v4, backend_v6, true, true);
        activate_service_snapshot(&mut synchronizer, &first, Some(&node), true, &state)
            .expect("dual-stack LoadBalancer Service activates");
        let first_reachability = dual_stack_load_balancer_node_snapshot(&first, 1, vip_v4, vip_v6);
        activate_load_balancer_snapshot(&mut synchronizer, &first_reachability, &state)
            .expect("dual-stack VIP bank activates");

        let ipv4_tcp = ipv4_packet(6, client_v4, vip_v4, 40_000, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        let ipv4_tcp_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert!((32_768..=u16::MAX).contains(&ipv4_tcp_snat));
        assert_ipv4_packet(&translated, 6, node_v4, backend_v4, ipv4_tcp_snat, 8080);
        let reverse = ipv4_packet(6, backend_v4, node_v4, 8080, ipv4_tcp_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, vip_v4, client_v4, 80, 40_000);

        // The source-port high bit does not change the low 15-bit initial NAT
        // candidate. A second flow proves collision-safe bounded probing for
        // LoadBalancer Cluster traffic rather than reverse-tuple replacement.
        let colliding_client_port = 0x9c40_u16 ^ 0x8000;
        let colliding = ipv4_packet(6, client_v4, vip_v4, colliding_client_port, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &colliding);
        assert_eq!(action, TC_ACT_PIPE);
        let colliding_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert!((32_768..=u16::MAX).contains(&colliding_snat));
        assert_ne!(colliding_snat, ipv4_tcp_snat);
        assert_ipv4_packet(&translated, 6, node_v4, backend_v4, colliding_snat, 8080);
        let reverse = ipv4_packet(6, backend_v4, node_v4, 8080, colliding_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, vip_v4, client_v4, 80, colliding_client_port);

        let ipv4_udp = ipv4_packet(17, client_v4, vip_v4, 40_001, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_udp);
        assert_eq!(action, TC_ACT_PIPE);
        let ipv4_udp_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert_ipv4_packet(&translated, 17, node_v4, backend_v4, ipv4_udp_snat, 5353);
        let reverse = ipv4_packet(17, backend_v4, node_v4, 5353, ipv4_udp_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, vip_v4, client_v4, 53, 40_001);

        let ipv6_tcp = ipv6_packet(6, client_v6, vip_v6, 40_002, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        let ipv6_tcp_snat = u16::from_be_bytes([translated[54], translated[55]]);
        assert_ipv6_packet(&translated, 6, node_v6, backend_v6, ipv6_tcp_snat, 8080);
        let reverse = ipv6_packet(6, backend_v6, node_v6, 8080, ipv6_tcp_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, vip_v6, client_v6, 80, 40_002);

        let ipv6_udp = ipv6_packet(17, client_v6, vip_v6, 40_003, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6_udp);
        assert_eq!(action, TC_ACT_PIPE);
        let ipv6_udp_snat = u16::from_be_bytes([translated[54], translated[55]]);
        assert_ipv6_packet(&translated, 17, node_v6, backend_v6, ipv6_udp_snat, 5353);
        let reverse = ipv6_packet(17, backend_v6, node_v6, 5353, ipv6_udp_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, vip_v6, client_v6, 53, 40_003);

        // Service translation precedes ingress policy evaluation: policy sees
        // the external source and selected backend identity/port, not the VIP.
        let backend_identity = IdentityId::new(22);
        identity_v4_maps[0]
            .insert(
                backend_v4.octets(),
                encode_identity_value(IdentityMapValue::new(backend_identity, 9)),
                0,
            )
            .expect("backend identity is staged");
        identity_config
            .set(0, encode_identity_config(7, 9, 1, 0).unwrap(), 0)
            .expect("backend identity is activated");
        let deny = Ipv4PolicyMapEntry {
            key: unf_state::Ipv4PolicyMapKey {
                source_address: Ipv4Addr::UNSPECIFIED,
                destination_identity: backend_identity,
                protocol: 6,
                destination_port: 8080,
            },
            decision: PolicyDecisionRecord {
                verdict: Verdict::Deny,
                reason: PolicyReason::DefaultAction,
                policy_id: Some(PolicyId::new(7)),
                rule_id: None,
            },
            shadow: None,
        };
        ipv4_policy
            .insert(
                encode_ipv4_policy_key(&deny, 0),
                encode_policy_decisions(&deny.decision, None, 9),
                0,
            )
            .expect("external-source deny is staged");
        policy_config
            .set(0, encode_policy_config(7, 9, 1, 0).unwrap(), 0)
            .expect("external-source deny is activated");
        let denied = ipv4_packet(6, client_v4, vip_v4, 40_100, 80);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &denied);
        assert_eq!(action, TC_ACT_SHOT);
        identity_config
            .set(0, [0; 24], 0)
            .expect("test identity state is disabled");
        policy_config
            .set(0, [0; 24], 0)
            .expect("test policy state is disabled");

        let replacement_v4 = Ipv4Addr::new(10, 42, 0, 21);
        let replacement_v6 = "fd00:42::21".parse::<Ipv6Addr>().unwrap();
        let second = dual_stack_service_snapshot_with_load_balancer(
            2,
            replacement_v4,
            replacement_v6,
            true,
            true,
        );
        activate_service_snapshot(&mut synchronizer, &second, Some(&node), true, &state)
            .expect("replacement LoadBalancer backend activates");
        let active_load_balancer = synchronizer.load_balancer_banks
            [usize::from(synchronizer.active_load_balancer_bank)]
        .as_ref()
        .expect("active LoadBalancer bank remains materialized");
        assert_eq!(active_load_balancer.service_bank, synchronizer.active_bank);
        let eagerly_relinked = ipv4_packet(6, client_v4, vip_v4, 40_900, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &eagerly_relinked);
        assert_eq!(action, TC_ACT_PIPE);
        let eager_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert_ipv4_packet(&translated, 6, node_v4, replacement_v4, eager_snat, 8080);
        let second_reachability =
            dual_stack_load_balancer_node_snapshot(&second, 2, vip_v4, vip_v6);
        activate_load_balancer_snapshot(&mut synchronizer, &second_reachability, &state)
            .expect("replacement VIP linkage activates");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, node_v4, backend_v4, ipv4_tcp_snat, 8080);
        let new_flow = ipv4_packet(6, client_v4, vip_v4, 41_000, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &new_flow);
        assert_eq!(action, TC_ACT_PIPE);
        let new_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert_ipv4_packet(&translated, 6, node_v4, replacement_v4, new_snat, 8080);

        let backendless = dual_stack_service_snapshot_with_load_balancer(
            3,
            replacement_v4,
            replacement_v6,
            false,
            true,
        );
        activate_service_snapshot(&mut synchronizer, &backendless, Some(&node), true, &state)
            .expect("backendless LoadBalancer Service activates");
        let backendless_reachability =
            dual_stack_load_balancer_node_snapshot(&backendless, 3, vip_v4, vip_v6);
        activate_load_balancer_snapshot(&mut synchronizer, &backendless_reachability, &state)
            .expect("backendless VIP linkage activates");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &new_flow);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, node_v4, replacement_v4, new_snat, 8080);
        let no_backend = ipv4_packet(6, client_v4, vip_v4, 42_000, 80);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &no_backend);
        assert_eq!(action, TC_ACT_SHOT);

        let unrelated = ipv4_packet(6, client_v4, Ipv4Addr::new(192, 0, 2, 99), 42_001, 80);
        let (action, output) = run_tc(&mut ebpf, "unf_observe_ingress", &unrelated);
        assert_eq!(action, TC_ACT_PIPE);
        assert_eq!(output, unrelated);

        // Withdrawal activates an empty VIP bank before publication can be
        // removed. Fresh packets are no longer intercepted by this host.
        let mut withdrawn = backendless_reachability.clone();
        withdrawn.revision = Revision::new(4);
        withdrawn.allocation_revision = Revision::new(4);
        withdrawn.targets.clear();
        let withdrawn = withdrawn
            .validate()
            .expect("empty LoadBalancer reachability validates");
        activate_load_balancer_snapshot(&mut synchronizer, &withdrawn, &state)
            .expect("empty VIP bank activates before route/status withdrawal");
        let after_withdrawal = ipv4_packet(6, client_v4, vip_v4, 42_002, 80);
        let (action, output) = run_tc(&mut ebpf, "unf_observe_ingress", &after_withdrawal);
        assert_eq!(action, TC_ACT_PIPE);
        assert_eq!(output, after_withdrawal);

        let mut events = Vec::new();
        while let Some(item) = service_events.next() {
            events.push(decode_service_event(&item).expect("kernel service event is valid"));
        }
        for event in &events {
            record_service_event(&state, event);
        }
        assert!(events.iter().any(|event| {
            event.action == SERVICE_EVENT_ACTION_TRANSLATE
                && service_event_frontend_kind(event) == ServiceFrontendKind::LoadBalancerCluster
        }));
        assert!(events.iter().any(|event| {
            event.reason == SERVICE_EVENT_REASON_NO_BACKEND
                && service_event_frontend_kind(event) == ServiceFrontendKind::LoadBalancerCluster
        }));
    }

    #[test]
    #[ignore = "requires root BPF program execution and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_load_balancer_dsr_preserves_dual_stack_vips_and_direct_return() {
        const TC_ACT_SHOT: u32 = 2;
        const TC_ACT_PIPE: u32 = 3;
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts dataplane tail programs");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("DSR TC program exists")
                .try_into()
                .expect("DSR program is a TC classifier");
            program.load().expect("kernel verifier accepts DSR helpers");
        }
        let mut service_events = RingBuf::try_from(
            ebpf.take_map("SERVICE_EVENTS")
                .expect("service event ring exists"),
        )
        .expect("service event ring opens");
        let directory = tempdir().unwrap();
        let mut synchronizer =
            test_service_synchronizer(&mut ebpf, directory.path().join("service.json"));
        let state = test_agent_state();
        let client_v4 = Ipv4Addr::new(203, 0, 113, 5);
        let denied_v4 = Ipv4Addr::new(198, 51, 100, 5);
        let client_v6 = "2001:db8::5".parse::<Ipv6Addr>().unwrap();
        let vip_v4 = Ipv4Addr::new(192, 0, 2, 60);
        let vip_v6 = "2001:db8:ffff::60".parse::<Ipv6Addr>().unwrap();
        let backend_v4 = Ipv4Addr::new(10, 42, 0, 20);
        let backend_v6 = "fd00:42::20".parse::<Ipv6Addr>().unwrap();
        let service = dual_stack_dsr_load_balancer_snapshot(1, backend_v4, backend_v6);
        let node = node_port_node_snapshot(1);
        let contract = NetworkBehaviorContract::compile(
            &service,
            Revision::new(1),
            Revision::new(1),
            local_selection_node(&node, Some("zone-a".to_owned())),
        )
        .expect("dual-stack DSR selection contract compiles");
        activate_service_snapshot_with_contract(
            &mut synchronizer,
            &service,
            Some(&node),
            Some(&contract),
            true,
            &state,
        )
        .expect("DSR selection contract and Service banks activate");
        let reachability = dual_stack_load_balancer_node_snapshot(&service, 1, vip_v4, vip_v6);
        activate_load_balancer_snapshot(&mut synchronizer, &reachability, &state)
            .expect("DSR VIP bank activates");

        let ipv4 = ipv4_packet(6, client_v4, vip_v4, 40_000, 80);
        let (action, output) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4);
        assert_eq!(action, TC_ACT_PIPE);
        assert_eq!(output, ipv4, "DSR must preserve the complete VIP tuple");
        let ipv6 = ipv6_packet(17, client_v6, vip_v6, 40_001, 53);
        let (action, output) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6);
        assert_eq!(action, TC_ACT_PIPE);
        assert_eq!(
            output, ipv6,
            "IPv6 DSR must preserve the complete VIP tuple"
        );

        let denied = ipv4_packet(6, denied_v4, vip_v4, 40_002, 80);
        assert_eq!(
            run_tc(&mut ebpf, "unf_observe_ingress", &denied).0,
            TC_ACT_SHOT,
            "source-range admission remains before DSR selection"
        );
        let direct_reply = ipv4_packet(6, vip_v4, client_v4, 80, 40_000);
        let (action, output) = run_tc(&mut ebpf, "unf_observe_egress", &direct_reply);
        assert_eq!(action, TC_ACT_PIPE);
        assert_eq!(output, direct_reply, "direct return bypasses reverse NAT");

        let connections = synchronizer
            .connections
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(connections.len(), 2, "DSR stores forward state only");
        assert!(connections.iter().all(|(key, value)| {
            key[38] == unf_ebpf_common::SERVICE_CONNECTION_ROLE_FORWARD
                && u16::from_ne_bytes(value[98..100].try_into().unwrap())
                    & unf_ebpf_common::SERVICE_CONNECTION_FLAG_DSR
                    != 0
                && value[90..92] == value[92..94]
        }));

        let mut events = Vec::new();
        while let Some(item) = service_events.next() {
            events.push(decode_service_event(&item).expect("DSR event is ABI-valid"));
        }
        let dsr = events
            .iter()
            .filter(|event| event.reason == unf_ebpf_common::SERVICE_EVENT_REASON_FORWARD_DSR)
            .collect::<Vec<_>>();
        assert_eq!(dsr.len(), 2);
        assert!(dsr.iter().all(|event| {
            event.reserved[0] == unf_ebpf_common::SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER
                && event.reserved[4] == unf_ebpf_common::SERVICE_EVENT_FORWARDING_DSR
                && event.backend_id.get() != 0
                && event.frontend_port == event.backend_port
        }));
        assert!(events.iter().any(|event| {
            event.reason == unf_ebpf_common::SERVICE_EVENT_REASON_SOURCE_RANGE_DENIED
        }));

        // A redirected DSR packet can land on a node whose persistent LRU map
        // still owns the same tuple for a previously allocated VIP. The exact
        // current frontend owner must fence that state before translation.
        let (stale_key, mut stale_value) = synchronizer
            .connections
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .find(|(key, _)| {
                key[32..34] == 40_000_u16.to_be_bytes()
                    && key[37] == 4
                    && key[38] == unf_ebpf_common::SERVICE_CONNECTION_ROLE_FORWARD
            })
            .expect("one DSR forward connection exists");
        stale_value[80..84].copy_from_slice(&u32::MAX.to_ne_bytes());
        synchronizer
            .connections
            .insert(stale_key, stale_value, 0)
            .expect("stale VIP owner is injected");
        let (action, output) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4);
        assert_eq!(action, TC_ACT_PIPE);
        assert_eq!(output, ipv4, "current DSR owner replaces stale state");
        let repaired = synchronizer
            .connections
            .get(&stale_key, 0)
            .expect("current DSR connection is restored");
        assert_eq!(
            u32::from_ne_bytes(repaired[80..84].try_into().unwrap()),
            service.services[0].id.get()
        );

        let mut withdrawn = reachability.clone();
        withdrawn.revision = Revision::new(2);
        withdrawn.allocation_revision = Revision::new(2);
        withdrawn.targets.clear();
        let withdrawn = withdrawn
            .validate()
            .expect("empty DSR reachability validates");
        activate_load_balancer_snapshot(&mut synchronizer, &withdrawn, &state)
            .expect("DSR withdrawal activates");
        assert_eq!(
            synchronizer.connections.iter().count(),
            0,
            "VIP withdrawal purges all forward ownership state"
        );
    }

    #[test]
    #[ignore = "requires root BPF program execution and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_load_balancer_local_packets_preserve_source_and_follow_placement() {
        const TC_ACT_SHOT: u32 = 2;
        const TC_ACT_PIPE: u32 = 3;
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts dataplane tail programs");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("service TC program exists")
                .try_into()
                .expect("service program is a TC classifier");
            program
                .load()
                .expect("kernel verifier accepts Local LoadBalancer TC program");
        }
        let mut service_events = RingBuf::try_from(
            ebpf.take_map("SERVICE_EVENTS")
                .expect("service event ring exists"),
        )
        .expect("service event ring opens");
        let (mut identity_v4_maps, _identity_v6_maps, mut identity_config) =
            take_identity_maps(&mut ebpf).expect("take identity maps");
        let (
            _identity_policy,
            mut ipv4_policy,
            _ipv6_policy,
            _egress_ipv4_policy,
            _egress_ipv6_policy,
            mut policy_config,
        ) = take_policy_maps(&mut ebpf).expect("take policy maps");
        let directory = tempdir().unwrap();
        let mut synchronizer =
            test_service_synchronizer(&mut ebpf, directory.path().join("service.json"));
        let state = test_agent_state();
        let client_v4 = Ipv4Addr::new(203, 0, 113, 5);
        let client_v6 = "2001:db8::5".parse::<Ipv6Addr>().unwrap();
        let vip_v4 = Ipv4Addr::new(192, 0, 2, 60);
        let vip_v6 = "2001:db8:ffff::60".parse::<Ipv6Addr>().unwrap();
        let backend_v4 = Ipv4Addr::new(10, 42, 0, 20);
        let backend_v6 = "fd00:42::20".parse::<Ipv6Addr>().unwrap();
        let node = node_port_node_snapshot(1);
        let first = local_load_balancer_snapshot(dual_stack_service_snapshot_with_load_balancer(
            1, backend_v4, backend_v6, true, true,
        ));
        activate_service_snapshot(&mut synchronizer, &first, Some(&node), true, &state)
            .expect("dual-stack Local LoadBalancer Service activates");
        let first_reachability = dual_stack_load_balancer_node_snapshot(&first, 1, vip_v4, vip_v6);
        activate_load_balancer_snapshot(&mut synchronizer, &first_reachability, &state)
            .expect("dual-stack Local VIP bank activates");

        let ipv4_tcp = ipv4_packet(6, client_v4, vip_v4, 43_000, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 43_000, 8080);
        let reverse = ipv4_packet(6, backend_v4, client_v4, 8080, 43_000);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, vip_v4, client_v4, 80, 43_000);

        let ipv4_udp = ipv4_packet(17, client_v4, vip_v4, 43_001, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, client_v4, backend_v4, 43_001, 5353);
        let reverse = ipv4_packet(17, backend_v4, client_v4, 5353, 43_001);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, vip_v4, client_v4, 53, 43_001);

        let ipv6_tcp = ipv6_packet(6, client_v6, vip_v6, 43_002, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, client_v6, backend_v6, 43_002, 8080);
        let reverse = ipv6_packet(6, backend_v6, client_v6, 8080, 43_002);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, vip_v6, client_v6, 80, 43_002);

        let ipv6_udp = ipv6_packet(17, client_v6, vip_v6, 43_003, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, client_v6, backend_v6, 43_003, 5353);
        let reverse = ipv6_packet(17, backend_v6, client_v6, 5353, 43_003);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, vip_v6, client_v6, 53, 43_003);

        let backend_identity = IdentityId::new(22);
        identity_v4_maps[0]
            .insert(
                backend_v4.octets(),
                encode_identity_value(IdentityMapValue::new(backend_identity, 9)),
                0,
            )
            .expect("Local backend identity is staged");
        identity_config
            .set(0, encode_identity_config(7, 9, 1, 0).unwrap(), 0)
            .expect("Local backend identity is activated");
        let deny = Ipv4PolicyMapEntry {
            key: unf_state::Ipv4PolicyMapKey {
                source_address: Ipv4Addr::UNSPECIFIED,
                destination_identity: backend_identity,
                protocol: 6,
                destination_port: 8080,
            },
            decision: PolicyDecisionRecord {
                verdict: Verdict::Deny,
                reason: PolicyReason::DefaultAction,
                policy_id: Some(PolicyId::new(7)),
                rule_id: None,
            },
            shadow: None,
        };
        ipv4_policy
            .insert(
                encode_ipv4_policy_key(&deny, 0),
                encode_policy_decisions(&deny.decision, None, 9),
                0,
            )
            .expect("Local external-source deny is staged");
        policy_config
            .set(0, encode_policy_config(7, 9, 1, 0).unwrap(), 0)
            .expect("Local external-source deny is activated");
        let denied = ipv4_packet(6, client_v4, vip_v4, 43_050, 80);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &denied);
        assert_eq!(action, TC_ACT_SHOT);
        identity_config.set(0, [0; 24], 0).unwrap();
        policy_config.set(0, [0; 24], 0).unwrap();

        let denied_source_v4 = ipv4_packet(6, Ipv4Addr::new(198, 51, 100, 5), vip_v4, 43_051, 80);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &denied_source_v4);
        assert_eq!(action, TC_ACT_SHOT);
        let denied_source_v6 = ipv6_packet(17, "2001:db9::5".parse().unwrap(), vip_v6, 43_052, 53);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &denied_source_v6);
        assert_eq!(action, TC_ACT_SHOT);

        let mut remote_only = first.clone();
        remote_only.revision = Revision::new(2);
        for backend in &mut remote_only.services[0].backends {
            backend.node_name = Some("worker-b".to_owned());
        }
        let remote_only = remote_only.validate_and_normalize().unwrap();
        activate_service_snapshot(&mut synchronizer, &remote_only, Some(&node), true, &state)
            .expect("remote-only Local Service bank activates");
        let remote_reachability =
            dual_stack_load_balancer_node_snapshot(&remote_only, 2, vip_v4, vip_v6);
        activate_load_balancer_snapshot(&mut synchronizer, &remote_reachability, &state)
            .expect("remote-only Local VIP bank activates");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 43_000, 8080);
        let no_local = ipv4_packet(6, client_v4, vip_v4, 43_100, 80);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &no_local);
        assert_eq!(action, TC_ACT_SHOT);

        let mut unready = first.clone();
        unready.revision = Revision::new(3);
        for backend in &mut unready.services[0].backends {
            backend.ready = false;
        }
        let unready = unready.validate_and_normalize().unwrap();
        activate_service_snapshot(&mut synchronizer, &unready, Some(&node), true, &state)
            .expect("unready Local Service bank activates");
        let unready_reachability =
            dual_stack_load_balancer_node_snapshot(&unready, 3, vip_v4, vip_v6);
        activate_load_balancer_snapshot(&mut synchronizer, &unready_reachability, &state)
            .expect("unready Local VIP bank activates");
        let unready_flow = ipv4_packet(6, client_v4, vip_v4, 43_101, 80);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &unready_flow);
        assert_eq!(action, TC_ACT_SHOT);

        let recovered = local_load_balancer_snapshot(
            dual_stack_service_snapshot_with_load_balancer(4, backend_v4, backend_v6, true, true),
        );
        activate_service_snapshot(&mut synchronizer, &recovered, Some(&node), true, &state)
            .expect("recovered Local Service bank activates");
        let recovered_reachability =
            dual_stack_load_balancer_node_snapshot(&recovered, 4, vip_v4, vip_v6);
        activate_load_balancer_snapshot(&mut synchronizer, &recovered_reachability, &state)
            .expect("recovered Local VIP bank activates");
        let recovered_flow = ipv4_packet(6, client_v4, vip_v4, 43_102, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &recovered_flow);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 43_102, 8080);

        let active_load_balancer_bank = synchronizer.active_load_balancer_bank;
        restore_lpm_bank(
            &mut synchronizer.load_balancer_ipv4_source_ranges,
            &BTreeMap::new(),
            active_load_balancer_bank,
        )
        .unwrap();
        restore_lpm_bank(
            &mut synchronizer.load_balancer_ipv6_source_ranges,
            &BTreeMap::new(),
            active_load_balancer_bank,
        )
        .unwrap();
        synchronizer.banks = [None, None];
        synchronizer.applied = None;
        assert_eq!(
            recover_service_state(&mut synchronizer)
                .expect("Local LoadBalancer service bank recovers before VIP state"),
            (Some(recovered.source_epoch), Some(recovered.revision.get()))
        );
        assert_eq!(synchronizer.applied.as_ref(), Some(&recovered));

        synchronizer.load_balancer_banks = [None, None];
        synchronizer.active_load_balancer_bank = 0;
        synchronizer.applied_load_balancer_reachability = None;
        recover_load_balancer_state(&mut synchronizer)
            .expect("VIP state and runtime source-range tries rebuild after service recovery");
        let after_restart = ipv4_packet(6, client_v4, vip_v4, 43_103, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &after_restart);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 43_103, 8080);
        let denied_after_restart =
            ipv4_packet(6, Ipv4Addr::new(198, 51, 100, 6), vip_v4, 43_104, 80);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &denied_after_restart);
        assert_eq!(action, TC_ACT_SHOT);

        let mut events = Vec::new();
        while let Some(item) = service_events.next() {
            events.push(decode_service_event(&item).expect("kernel service event is valid"));
        }
        for event in &events {
            record_service_event(&state, event);
        }
        assert!(events.iter().any(|event| {
            event.action == SERVICE_EVENT_ACTION_TRANSLATE
                && service_event_frontend_kind(event) == ServiceFrontendKind::LoadBalancerLocal
        }));
        assert!(events.iter().any(|event| {
            event.reason == SERVICE_EVENT_REASON_NO_BACKEND
                && service_event_frontend_kind(event) == ServiceFrontendKind::LoadBalancerLocal
        }));
        assert!(events.iter().any(|event| {
            event.reason == SERVICE_EVENT_REASON_SOURCE_RANGE_DENIED
                && service_event_frontend_kind(event) == ServiceFrontendKind::LoadBalancerLocal
        }));
        let report = agent_state_report(&state);
        assert_eq!(report.load_balancer_cluster_frontend_count, 0);
        assert_eq!(report.load_balancer_local_frontend_count, 4);
        assert_eq!(report.load_balancer_source_range_count, 2);
        assert!(report.load_balancer_local_translations > 0);
        assert!(report.load_balancer_no_backend_drops > 0);
        assert!(report.load_balancer_source_range_drops > 0);
    }

    #[tokio::test]
    async fn load_balancer_health_check_is_dual_stack_local_and_lifecycle_exact() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn response(port: u16, address: &str) -> String {
            let mut stream = tokio::net::TcpStream::connect((address, port))
                .await
                .expect("health listener accepts the requested family");
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: node\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            String::from_utf8(bytes).unwrap()
        }

        let reservation = std::net::TcpListener::bind("[::]:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let mut snapshot =
            local_load_balancer_snapshot(dual_stack_service_snapshot_with_load_balancer(
                1,
                Ipv4Addr::new(10, 42, 0, 20),
                "fd00:42::20".parse().unwrap(),
                true,
                true,
            ));
        snapshot.services[0]
            .load_balancer
            .as_mut()
            .unwrap()
            .health_check_node_port = Some(port);
        let snapshot = snapshot.validate_and_normalize().unwrap();
        let ready = load_balancer_health_check_plan(&snapshot, "worker-a").unwrap();
        assert!(ready[&port].local_endpoints > 0);
        let state = test_agent_state();
        publish_load_balancer_health(&state, &ready);
        let report = agent_state_report(&state);
        assert_eq!(report.load_balancer_health_check_count, 1);
        assert_eq!(report.load_balancer_health_check_ready_count, 1);
        let mut collision = snapshot.clone();
        let mut second = collision.services[0].clone();
        second.id = unf_common::ServiceId::new(second.id.get().saturating_add(1));
        second.name = "collision".to_owned();
        collision.services.push(second);
        assert!(
            load_balancer_health_check_plan(&collision, "worker-a")
                .unwrap_err()
                .to_string()
                .contains("is claimed by services")
        );

        let mut manager = HealthCheckManager::default();
        manager.reconcile(&ready).unwrap();
        tokio::task::yield_now().await;
        let ipv4 = response(port, "127.0.0.1").await;
        assert!(ipv4.starts_with("HTTP/1.1 200 OK"));
        assert!(ipv4.contains(&format!(
            "\"localEndpoints\":{}",
            ready[&port].local_endpoints
        )));
        let ipv6 = response(port, "::1").await;
        assert!(ipv6.starts_with("HTTP/1.1 200 OK"));

        let mut remote = snapshot.clone();
        for backend in &mut remote.services[0].backends {
            backend.node_name = Some("worker-b".to_owned());
        }
        let remote = remote.validate_and_normalize().unwrap();
        let unavailable = load_balancer_health_check_plan(&remote, "worker-a").unwrap();
        assert_eq!(unavailable[&port].local_endpoints, 0);
        publish_load_balancer_health(&state, &unavailable);
        assert_eq!(
            agent_state_report(&state).load_balancer_health_check_ready_count,
            0
        );
        manager.reconcile(&unavailable).unwrap();
        let response = response(port, "127.0.0.1").await;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("\"localEndpoints\":0"));

        manager.reconcile(&BTreeMap::new()).unwrap();
        assert!(manager.listeners.is_empty());

        let conflict = std::net::TcpListener::bind("[::]:0").unwrap();
        let conflict_port = conflict.local_addr().unwrap().port();
        let rejected = BTreeMap::from([(
            conflict_port,
            HealthCheckPlan {
                port: conflict_port,
                service_id: snapshot.services[0].id,
                local_endpoints: 1,
            },
        )]);
        assert!(manager.prepare(&rejected).is_err());
        assert!(manager.listeners.is_empty());
    }

    #[test]
    #[ignore = "requires root BPF map creation and UNF_EBPF_OBJECT"]
    fn privileged_node_port_partial_stage_rolls_back_service_and_host_banks() {
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut loader = EbpfLoader::new();
        loader
            .map_max_entries("NODE_PORT_FRONTENDS_V4", 1)
            .map_max_entries("NODE_PORT_FRONTENDS_V6", 1);
        let mut ebpf = loader
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        let directory = tempdir().unwrap();
        let state_path = directory.path().join("service.json");
        let mut synchronizer = test_service_synchronizer(&mut ebpf, state_path.clone());
        let state = test_agent_state();
        let first = dual_stack_service_snapshot(
            1,
            Ipv4Addr::new(10, 42, 0, 20),
            "fd00:42::20".parse().unwrap(),
            true,
        );
        activate_service_snapshot(&mut synchronizer, &first, None, true, &state)
            .expect("ClusterIP baseline activates");
        let service_config = synchronizer.config.get(&0, 0).unwrap();
        let node_port_config = synchronizer.node_port_config.get(&0, 0).unwrap();
        assert_eq!(node_port_config, [0; 40]);

        let node_port = dual_stack_node_port_snapshot(2);
        let node = node_port_node_snapshot(1);
        let error =
            activate_service_snapshot(&mut synchronizer, &node_port, Some(&node), true, &state)
                .expect_err("undersized NodePort map rejects the inactive transaction");
        assert!(error.to_string().contains("NodePort staging"));
        assert_eq!(synchronizer.config.get(&0, 0).unwrap(), service_config);
        assert_eq!(
            synchronizer.node_port_config.get(&0, 0).unwrap(),
            node_port_config
        );
        assert_eq!(synchronizer.applied.as_ref(), Some(&first));
        assert!(synchronizer.applied_node_port_node.is_none());
        assert!(!service_pending_state_path(&state_path).unwrap().exists());
    }

    #[test]
    #[ignore = "requires root BPF map creation and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_node_port_activation_address_only_switch_and_recovery_are_exact() {
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        let directory = tempdir().unwrap();
        let state_path = directory.path().join("service.json");
        let mut synchronizer = test_service_synchronizer(&mut ebpf, state_path.clone());
        let state = test_agent_state();
        let service = dual_stack_node_port_snapshot(2);
        let first_node = node_port_node_snapshot(1);
        activate_service_snapshot(&mut synchronizer, &service, Some(&first_node), true, &state)
            .expect("complete NodePort transaction activates");
        let service_config = synchronizer.config.get(&0, 0).unwrap();
        let first_node_port_config = synchronizer.node_port_config.get(&0, 0).unwrap();
        let service_bank = synchronizer.active_bank;
        let first_node_port_bank = synchronizer.active_node_port_bank;

        let mut second_node = first_node.clone();
        second_node.revision = first_node.revision.next();
        second_node.addresses[0].address = "192.0.2.11".parse().unwrap();
        second_node = second_node.validate_and_normalize().unwrap();
        activate_service_snapshot(
            &mut synchronizer,
            &service,
            Some(&second_node),
            true,
            &state,
        )
        .expect("Node-address-only transaction activates");
        assert_eq!(synchronizer.config.get(&0, 0).unwrap(), service_config);
        assert_eq!(synchronizer.active_bank, service_bank);
        assert_ne!(synchronizer.active_node_port_bank, first_node_port_bank);
        assert_ne!(
            synchronizer.node_port_config.get(&0, 0).unwrap(),
            first_node_port_config
        );
        assert_eq!(
            load_optional_service_checkpoint(&state_path).unwrap(),
            Some((service.clone(), Some(second_node.clone())))
        );

        synchronizer.banks = [None, None];
        synchronizer.node_port_banks = [None, None];
        synchronizer.active_bank = 0;
        synchronizer.active_node_port_bank = 0;
        synchronizer.applied = None;
        synchronizer.applied_node_port_node = None;
        assert_eq!(
            recover_service_state(&mut synchronizer).unwrap(),
            (Some(7), Some(2))
        );
        assert_eq!(synchronizer.active_bank, service_bank);
        assert_eq!(
            synchronizer.applied_node_port_node.as_ref(),
            Some(&second_node)
        );

        let next_service = dual_stack_node_port_snapshot(3);
        let next_service_bank = (synchronizer.active_bank + 1) % SERVICE_BANK_COUNT;
        let next_node_port_bank =
            (synchronizer.active_node_port_bank + 1) % unf_ebpf_common::NODE_PORT_BANK_COUNT;
        let next = compile_node_port_fabric_dataplane(
            &next_service,
            &second_node,
            next_service_bank,
            next_node_port_bank,
        )
        .unwrap();
        let previous_service_stage = synchronizer.banks[usize::from(next_service_bank)]
            .clone()
            .unwrap_or_else(|| empty_service_bank(next_service_bank));
        let previous_node_port_stage = synchronizer.node_port_banks
            [usize::from(next_node_port_bank)]
        .clone()
        .unwrap_or_else(|| empty_node_port_bank(next_node_port_bank));
        stage_service_bank(&mut synchronizer, &previous_service_stage, &next.service).unwrap();
        stage_node_port_bank(
            &mut synchronizer,
            &previous_node_port_stage,
            &next.node_port,
        )
        .unwrap();
        prepare_service_checkpoint(&state_path, &next_service, Some(&second_node)).unwrap();
        synchronizer.config.set(0, next.service.config, 0).unwrap();
        synchronizer.banks = [None, None];
        synchronizer.node_port_banks = [None, None];
        synchronizer.applied = None;
        synchronizer.applied_node_port_node = None;
        recover_service_state(&mut synchronizer)
            .expect("crash between activation pointers rolls back to the durable tuple");
        assert_eq!(synchronizer.applied.as_ref(), Some(&service));
        assert_eq!(synchronizer.config.get(&0, 0).unwrap(), service_config);
        assert!(!service_pending_state_path(&state_path).unwrap().exists());

        let next = compile_node_port_fabric_dataplane(
            &next_service,
            &second_node,
            next_service_bank,
            next_node_port_bank,
        )
        .unwrap();
        let previous_service_stage = synchronizer.banks[usize::from(next_service_bank)]
            .clone()
            .unwrap_or_else(|| empty_service_bank(next_service_bank));
        let previous_node_port_stage = synchronizer.node_port_banks
            [usize::from(next_node_port_bank)]
        .clone()
        .unwrap_or_else(|| empty_node_port_bank(next_node_port_bank));
        stage_service_bank(&mut synchronizer, &previous_service_stage, &next.service).unwrap();
        stage_node_port_bank(
            &mut synchronizer,
            &previous_node_port_stage,
            &next.node_port,
        )
        .unwrap();
        prepare_service_checkpoint(&state_path, &next_service, Some(&second_node)).unwrap();
        synchronizer.config.set(0, next.service.config, 0).unwrap();
        synchronizer
            .node_port_config
            .set(0, next.node_port.config, 0)
            .unwrap();
        synchronizer.banks = [None, None];
        synchronizer.node_port_banks = [None, None];
        synchronizer.applied = None;
        synchronizer.applied_node_port_node = None;
        assert_eq!(
            recover_service_state(&mut synchronizer).unwrap(),
            (Some(7), Some(3))
        );
        assert_eq!(synchronizer.applied.as_ref(), Some(&next_service));
        assert!(!service_pending_state_path(&state_path).unwrap().exists());
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
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts dataplane tail programs");
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
            affinity,
            node_port_ipv4_frontends,
            node_port_ipv6_frontends,
            node_port_config,
            load_balancer_ipv4_frontends,
            load_balancer_ipv6_frontends,
            load_balancer_ipv4_source_ranges,
            load_balancer_ipv6_source_ranges,
            load_balancer_config,
            load_balancer_node_source,
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
            affinity,
            node_port_ipv4_frontends,
            node_port_ipv6_frontends,
            node_port_config,
            load_balancer_ipv4_frontends,
            load_balancer_ipv6_frontends,
            load_balancer_ipv4_source_ranges,
            load_balancer_ipv6_source_ranges,
            load_balancer_config,
            load_balancer_node_source,
            health_checks: HealthCheckManager::default(),
            banks: [None, None],
            node_port_banks: [None, None],
            load_balancer_banks: [None, None],
            selection_banks: [None, None],
            active_bank: 0,
            active_node_port_bank: 0,
            active_load_balancer_bank: 0,
            applied: None,
            applied_node_port_node: None,
            applied_load_balancer_reachability: None,
            applied_selection_contract: None,
            active_selection_bank: 0,
            node_name: "worker-a".to_owned(),
            controller_url: None,
            client: ReloadingControllerClient::without_custom_trust(
                Counter::default(),
                Counter::default(),
            ),
            agent_token_path: PathBuf::new(),
            state_path: directory.path().join("service.json"),
            load_balancer_state_path: directory.path().join("load-balancer.json"),
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
        activate_service_snapshot(&mut synchronizer, &first, None, false, &state)
            .expect("dual-stack service activates");

        let ipv4_tcp = ipv4_packet(6, client_v4, service_v4, 40_000, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 40_000, 8080);
        let reverse = ipv4_packet(6, backend_v4, client_v4, 8080, 40_000);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, service_v4, client_v4, 80, 40_000);

        let ipv4_udp = ipv4_packet(17, client_v4, service_v4, 40_001, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, client_v4, backend_v4, 40_001, 5353);
        let reverse = ipv4_packet(17, backend_v4, client_v4, 5353, 40_001);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
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

        // Host-network and Node-origin flows encounter only an uplink egress
        // hook before leaving the Node. They must receive the same exact
        // frontend translation and ingress-side reply restoration.
        let host_v4 = Ipv4Addr::new(192, 0, 2, 20);
        let host_v6 = "2001:db8::20".parse::<Ipv6Addr>().unwrap();
        let host_ipv4_tcp = ipv4_packet(6, host_v4, service_v4, 40_010, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &host_ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, host_v4, backend_v4, 40_010, 8080);
        let reverse = ipv4_packet(6, backend_v4, host_v4, 8080, 40_010);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, service_v4, host_v4, 80, 40_010);

        let host_ipv4_udp = ipv4_packet(17, host_v4, service_v4, 40_011, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &host_ipv4_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, host_v4, backend_v4, 40_011, 5353);
        let reverse = ipv4_packet(17, backend_v4, host_v4, 5353, 40_011);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, service_v4, host_v4, 53, 40_011);

        let host_ipv6_tcp = ipv6_packet(6, host_v6, service_v6, 40_012, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &host_ipv6_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, host_v6, backend_v6, 40_012, 8080);
        let reverse = ipv6_packet(6, backend_v6, host_v6, 8080, 40_012);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, service_v6, host_v6, 80, 40_012);

        let host_ipv6_udp = ipv6_packet(17, host_v6, service_v6, 40_013, 53);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &host_ipv6_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, host_v6, backend_v6, 40_013, 5353);
        let reverse = ipv6_packet(17, backend_v6, host_v6, 5353, 40_013);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, service_v6, host_v6, 53, 40_013);
        assert_eq!(
            synchronizer
                .connections
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            16
        );

        let replacement_v4 = Ipv4Addr::new(10, 42, 0, 21);
        let replacement_v6 = "fd00:42::21".parse::<Ipv6Addr>().unwrap();
        let second = dual_stack_service_snapshot(2, replacement_v4, replacement_v6, true);
        activate_service_snapshot(&mut synchronizer, &second, None, false, &state)
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
            if value[88..90] == 40_000_u16.to_be_bytes() {
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
            .filter(|(_, value)| value[88..90] == 40_000_u16.to_be_bytes())
            .collect::<Vec<_>>();
        assert_eq!(refreshed_pair.len(), 2);
        assert!(refreshed_pair.iter().all(|(_, value)| {
            u64::from_ne_bytes(value[8..16].try_into().unwrap()) == 2
                && u32::from_ne_bytes(value[80..84].try_into().unwrap()) != 0
                && u32::from_ne_bytes(value[84..88].try_into().unwrap()) != 0
                && value[48..52] == replacement_v4.octets()
                && value[52..64] == [0; 12]
        }));

        let backendless = dual_stack_service_snapshot(3, replacement_v4, replacement_v6, false);
        activate_service_snapshot(&mut synchronizer, &backendless, None, false, &state)
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
        assert_eq!(events.len(), 22);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.action == SERVICE_EVENT_ACTION_TRANSLATE)
                .count(),
            20
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
    #[ignore = "requires root BPF program execution and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_client_ip_affinity_expires_and_drains_dual_stack() {
        const TC_ACT_PIPE: u32 = 3;
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts dataplane tail programs");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("service TC program exists")
                .try_into()
                .expect("service program is a TC classifier");
            program
                .load()
                .expect("kernel verifier accepts ClientIP affinity TC program");
        }
        let mut service_events = RingBuf::try_from(
            ebpf.take_map("SERVICE_EVENTS")
                .expect("service event ring exists"),
        )
        .expect("service event ring opens");
        let directory = tempdir().unwrap();
        let mut synchronizer =
            test_service_synchronizer(&mut ebpf, directory.path().join("service.json"));
        let state = test_agent_state();
        let service_v4 = Ipv4Addr::new(10, 96, 0, 10);
        let primary_v4 = Ipv4Addr::new(10, 42, 0, 20);
        let secondary_v4 = Ipv4Addr::new(10, 42, 0, 21);
        let client_v4 = Ipv4Addr::new(10, 42, 0, 5);
        let service_v6 = "fd00:96::10".parse::<Ipv6Addr>().unwrap();
        let primary_v6 = "fd00:42::20".parse::<Ipv6Addr>().unwrap();
        let secondary_v6 = "fd00:42::21".parse::<Ipv6Addr>().unwrap();
        let client_v6 = "fd00:42::5".parse::<Ipv6Addr>().unwrap();
        let initial = dual_stack_affinity_snapshot(
            1,
            primary_v4,
            secondary_v4,
            primary_v6,
            secondary_v6,
            false,
        );
        let node = node_port_node_snapshot(1);
        let selection_node = local_selection_node(&node, Some("zone-a".to_owned()));
        let initial_contract = NetworkBehaviorContract::compile(
            &initial,
            Revision::new(1),
            Revision::new(1),
            selection_node.clone(),
        )
        .expect("ClientIP affinity contract verifies");
        activate_service_snapshot_with_contract(
            &mut synchronizer,
            &initial,
            Some(&node),
            Some(&initial_contract),
            true,
            &state,
        )
        .expect("ClientIP affinity Service activates");

        let mut client_v4_key = [0; 16];
        client_v4_key[..4].copy_from_slice(&client_v4.octets());
        let mut service_v4_key = [0; 16];
        service_v4_key[..4].copy_from_slice(&service_v4.octets());
        let v4_primary_port = 45_000;
        let v4_affinity_port = 45_001;
        let v4_expired_port = 45_002;
        let selected_v4 = match expected_service_backend(
            &initial,
            client_v4_key,
            service_v4_key,
            4,
            v4_primary_port,
        ) {
            IpAddr::V4(address) => address,
            IpAddr::V6(_) => panic!("IPv4 frontend selected an IPv6 backend"),
        };
        let v6_primary_port = 46_000;
        let v6_affinity_port = 46_001;
        let v6_expired_port = 46_002;
        let selected_v6 = match expected_service_backend(
            &initial,
            client_v6.octets(),
            service_v6.octets(),
            6,
            v6_primary_port,
        ) {
            IpAddr::V6(address) => address,
            IpAddr::V4(_) => panic!("IPv6 frontend selected an IPv4 backend"),
        };

        for (port, expected) in [
            (v4_primary_port, selected_v4),
            (v4_affinity_port, selected_v4),
        ] {
            let packet = ipv4_packet(6, client_v4, service_v4, port, 80);
            let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &packet);
            assert_eq!(action, TC_ACT_PIPE);
            assert_ipv4_packet(&translated, 6, client_v4, expected, port, 8080);
        }
        for (port, expected) in [
            (v6_primary_port, selected_v6),
            (v6_affinity_port, selected_v6),
        ] {
            let packet = ipv6_packet(6, client_v6, service_v6, port, 80);
            let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &packet);
            assert_eq!(action, TC_ACT_PIPE);
            assert_ipv6_packet(&translated, 6, client_v6, expected, port, 8080);
        }
        let affinity_keys = synchronizer
            .affinity
            .keys()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(affinity_keys.len(), 2);
        for key in affinity_keys {
            let mut value = synchronizer.affinity.get(&key, 0).unwrap();
            value[0..8].copy_from_slice(&0_u64.to_ne_bytes());
            synchronizer.affinity.insert(key, value, 0).unwrap();
        }

        let v4_expired = ipv4_packet(6, client_v4, service_v4, v4_expired_port, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &v4_expired);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(
            &translated,
            6,
            client_v4,
            selected_v4,
            v4_expired_port,
            8080,
        );
        let v6_expired = ipv6_packet(6, client_v6, service_v6, v6_expired_port, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &v6_expired);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(
            &translated,
            6,
            client_v6,
            selected_v6,
            v6_expired_port,
            8080,
        );

        let mut draining = dual_stack_affinity_snapshot(
            2,
            primary_v4,
            secondary_v4,
            primary_v6,
            secondary_v6,
            false,
        );
        for backend in &mut draining.services[0].backends {
            if backend.address == IpAddr::V4(selected_v4)
                || backend.address == IpAddr::V6(selected_v6)
            {
                backend.terminating = true;
            }
        }
        draining = draining
            .validate_and_normalize()
            .expect("selected backends can enter graceful draining");
        let replacement_v4 = if selected_v4 == primary_v4 {
            secondary_v4
        } else {
            primary_v4
        };
        let replacement_v6 = if selected_v6 == primary_v6 {
            secondary_v6
        } else {
            primary_v6
        };
        let draining_contract = NetworkBehaviorContract::compile(
            &draining,
            Revision::new(2),
            Revision::new(2),
            selection_node,
        )
        .expect("draining affinity contract verifies");
        activate_service_snapshot_with_contract(
            &mut synchronizer,
            &draining,
            Some(&node),
            Some(&draining_contract),
            true,
            &state,
        )
        .expect("terminating backends are withdrawn from new-flow slots");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &v4_expired);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(
            &translated,
            6,
            client_v4,
            selected_v4,
            v4_expired_port,
            8080,
        );
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &v6_expired);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(
            &translated,
            6,
            client_v6,
            selected_v6,
            v6_expired_port,
            8080,
        );

        let v4_new_port = v4_expired_port + 1;
        let v4_new = ipv4_packet(6, client_v4, service_v4, v4_new_port, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &v4_new);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, replacement_v4, v4_new_port, 8080);
        let v6_new_port = v6_expired_port + 1;
        let v6_new = ipv6_packet(6, client_v6, service_v6, v6_new_port, 80);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &v6_new);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, client_v6, replacement_v6, v6_new_port, 8080);

        let mut outcomes = Vec::new();
        while let Some(item) = service_events.next() {
            let event = decode_service_event(&item).expect("kernel service event is valid");
            assert_eq!(event.action, SERVICE_EVENT_ACTION_TRANSLATE);
            outcomes.push(event.reserved[2]);
        }
        assert_eq!(outcomes.len(), 10);
        let outcome_counts = outcomes.iter().fold([0_usize; 4], |mut counts, outcome| {
            counts[usize::from(*outcome)] += 1;
            counts
        });
        assert_eq!(outcome_counts, [0, 2, 2, 6]);
        assert_eq!(
            synchronizer
                .affinity
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    #[ignore = "requires root BPF program execution and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_selection_packets_enforce_local_and_topology_fallback_dual_stack() {
        const TC_ACT_SHOT: u32 = 2;
        const TC_ACT_PIPE: u32 = 3;
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts dataplane tail programs");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("service TC program exists")
                .try_into()
                .expect("service program is a TC classifier");
            program
                .load()
                .expect("kernel verifier accepts selection TC program");
        }
        let mut service_events = RingBuf::try_from(
            ebpf.take_map("SERVICE_EVENTS")
                .expect("service event ring exists"),
        )
        .expect("service event ring opens");
        let mut flow_events = RingBuf::try_from(
            ebpf.take_map("FLOW_EVENTS")
                .expect("flow event ring exists"),
        )
        .expect("flow event ring opens");
        let (mut identity_v4_maps, _identity_v6_maps, mut identity_config) =
            take_identity_maps(&mut ebpf).expect("take identity maps");
        let (
            _identity_policy,
            mut ipv4_policy,
            _ipv6_policy,
            _egress_ipv4_policy,
            _egress_ipv6_policy,
            mut policy_config,
        ) = take_policy_maps(&mut ebpf).expect("take policy maps");
        let directory = tempdir().unwrap();
        let mut synchronizer =
            test_service_synchronizer(&mut ebpf, directory.path().join("service.json"));
        // Service and selection banks are independent activation domains. A
        // Phase 6 -> 7 migration can enter the first selection transaction
        // with an already-active service bank, so exercise opposite parity
        // instead of relying on a fresh-cluster coincidence.
        synchronizer.active_bank = 1;
        let state = test_agent_state();
        let node = node_port_node_snapshot(1);
        let selection_node = local_selection_node(&node, Some("zone-a".to_owned()));
        let service_v4 = Ipv4Addr::new(10, 96, 0, 10);
        let backend_v4 = Ipv4Addr::new(10, 42, 0, 20);
        let client_v4 = Ipv4Addr::new(10, 42, 0, 5);
        let service_v6 = "fd00:96::10".parse::<Ipv6Addr>().unwrap();
        let backend_v6 = "fd00:42::20".parse::<Ipv6Addr>().unwrap();
        let client_v6 = "fd00:42::5".parse::<Ipv6Addr>().unwrap();

        let mut local = dual_stack_service_snapshot(1, backend_v4, backend_v6, true);
        local.services[0].internal_traffic_policy = ServiceTrafficPolicy::Local;
        for backend in &mut local.services[0].backends {
            backend.node_name = Some("worker-a".to_owned());
            backend.zone = Some("zone-a".to_owned());
        }
        local = local.validate_and_normalize().unwrap();
        let local_contract = NetworkBehaviorContract::compile(
            &local,
            Revision::new(1),
            Revision::new(1),
            selection_node.clone(),
        )
        .unwrap();
        activate_service_snapshot_with_contract(
            &mut synchronizer,
            &local,
            Some(&node),
            Some(&local_contract),
            true,
            &state,
        )
        .expect("strict-local selection activates");
        let (action, translated) = run_tc(
            &mut ebpf,
            "unf_observe_ingress",
            &ipv4_packet(6, client_v4, service_v4, 45_000, 80),
        );
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 45_000, 8080);
        let (action, translated) = run_tc(
            &mut ebpf,
            "unf_observe_ingress",
            &ipv6_packet(17, client_v6, service_v6, 45_001, 53),
        );
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, client_v6, backend_v6, 45_001, 5353);

        let mut remote = dual_stack_service_snapshot(2, backend_v4, backend_v6, true);
        remote.services[0].internal_traffic_policy = ServiceTrafficPolicy::Local;
        for backend in &mut remote.services[0].backends {
            backend.node_name = Some("worker-b".to_owned());
            backend.zone = Some("zone-b".to_owned());
        }
        remote = remote.validate_and_normalize().unwrap();
        let remote_contract = NetworkBehaviorContract::compile(
            &remote,
            Revision::new(2),
            Revision::new(2),
            selection_node.clone(),
        )
        .unwrap();
        activate_service_snapshot_with_contract(
            &mut synchronizer,
            &remote,
            Some(&node),
            Some(&remote_contract),
            true,
            &state,
        )
        .expect("remote-only strict-local selection activates");
        let (action, _) = run_tc(
            &mut ebpf,
            "unf_observe_ingress",
            &ipv4_packet(6, client_v4, service_v4, 45_010, 80),
        );
        assert_eq!(action, TC_ACT_SHOT);
        let (action, _) = run_tc(
            &mut ebpf,
            "unf_observe_ingress",
            &ipv6_packet(17, client_v6, service_v6, 45_011, 53),
        );
        assert_eq!(action, TC_ACT_SHOT);

        let mut preferred = dual_stack_service_snapshot(3, backend_v4, backend_v6, true);
        preferred.services[0].traffic_distribution =
            unf_service::ServiceTrafficDistribution::PreferSameNode;
        for backend in &mut preferred.services[0].backends {
            backend.node_name = Some("worker-b".to_owned());
            backend.zone = Some("zone-b".to_owned());
        }
        preferred = preferred.validate_and_normalize().unwrap();
        let preferred_contract = NetworkBehaviorContract::compile(
            &preferred,
            Revision::new(3),
            Revision::new(3),
            selection_node.clone(),
        )
        .unwrap();
        activate_service_snapshot_with_contract(
            &mut synchronizer,
            &preferred,
            Some(&node),
            Some(&preferred_contract),
            true,
            &state,
        )
        .expect("topology fallback selection activates");
        let (action, translated) = run_tc(
            &mut ebpf,
            "unf_observe_ingress",
            &ipv4_packet(6, client_v4, service_v4, 45_020, 80),
        );
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, backend_v4, 45_020, 8080);

        let prior_service_bank = synchronizer.active_bank;
        let mut zone_b_node = selection_node;
        zone_b_node.zone = Some("zone-b".to_owned());
        let zone_b_contract = NetworkBehaviorContract::compile(
            &preferred,
            Revision::new(4),
            Revision::new(4),
            zone_b_node,
        )
        .unwrap();
        activate_service_snapshot_with_contract(
            &mut synchronizer,
            &preferred,
            Some(&node),
            Some(&zone_b_contract),
            true,
            &state,
        )
        .expect("topology-only contract change activates");
        assert_ne!(synchronizer.active_bank, prior_service_bank);
        assert_eq!(synchronizer.applied.as_ref().unwrap().revision.get(), 3);
        let (action, translated) = run_tc(
            &mut ebpf,
            "unf_observe_ingress",
            &ipv6_packet(17, client_v6, service_v6, 45_022, 53),
        );
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, client_v6, backend_v6, 45_022, 5353);

        let backend_identity = IdentityId::new(22);
        identity_v4_maps[0]
            .insert(
                backend_v4.octets(),
                encode_identity_value(IdentityMapValue::new(backend_identity, 9)),
                0,
            )
            .unwrap();
        identity_config
            .set(0, encode_identity_config(7, 9, 1, 0).unwrap(), 0)
            .unwrap();
        let deny = Ipv4PolicyMapEntry {
            key: unf_state::Ipv4PolicyMapKey {
                source_address: Ipv4Addr::UNSPECIFIED,
                destination_identity: backend_identity,
                protocol: 6,
                destination_port: 8080,
            },
            decision: PolicyDecisionRecord {
                verdict: Verdict::Deny,
                reason: PolicyReason::DefaultAction,
                policy_id: Some(PolicyId::new(7)),
                rule_id: None,
            },
            shadow: None,
        };
        ipv4_policy
            .insert(
                encode_ipv4_policy_key(&deny, 0),
                encode_policy_decisions(&deny.decision, None, 9),
                0,
            )
            .unwrap();
        policy_config
            .set(0, encode_policy_config(7, 9, 1, 0).unwrap(), 0)
            .unwrap();
        let (action, _) = run_tc(
            &mut ebpf,
            "unf_observe_ingress",
            &ipv4_packet(6, client_v4, service_v4, 45_030, 80),
        );
        assert_eq!(action, TC_ACT_SHOT);
        let mut denied = None;
        while let Some(item) = flow_events.next() {
            let event = decode_event(&item).expect("policy event ABI is valid");
            if event.verdict == Verdict::Deny {
                denied = Some(event);
            }
        }
        let denied = denied.expect("translated-backend policy denial is emitted");
        assert_eq!(&denied.flow.destination_address[..4], &backend_v4.octets());
        assert_eq!(denied.flow.destination_port, 8080_u16.to_be_bytes());
        identity_config.set(0, [0; 24], 0).unwrap();
        policy_config.set(0, [0; 24], 0).unwrap();

        let expected_service_bank = synchronizer.active_bank;
        let expected_selection_bank = synchronizer.active_selection_bank;
        assert_ne!(expected_service_bank, expected_selection_bank);
        let expected_digest = zone_b_contract.contract_digest;
        synchronizer.banks = [None, None];
        synchronizer.node_port_banks = [None, None];
        synchronizer.selection_banks = [None, None];
        synchronizer.active_bank = 0;
        synchronizer.active_node_port_bank = 0;
        synchronizer.active_selection_bank = 0;
        synchronizer.applied = None;
        synchronizer.applied_node_port_node = None;
        synchronizer.applied_selection_contract = None;
        assert_eq!(
            recover_service_state(&mut synchronizer).unwrap(),
            (Some(7), Some(3))
        );
        recover_selection_contract_state(&mut synchronizer).unwrap();
        assert_eq!(synchronizer.active_bank, expected_service_bank);
        assert_eq!(synchronizer.active_selection_bank, expected_selection_bank);
        assert_eq!(
            synchronizer
                .applied_selection_contract
                .as_ref()
                .unwrap()
                .contract_digest,
            expected_digest
        );
        let (action, translated) = run_tc(
            &mut ebpf,
            "unf_observe_ingress",
            &ipv6_packet(17, client_v6, service_v6, 45_021, 53),
        );
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, client_v6, backend_v6, 45_021, 5353);

        let mut events = Vec::new();
        while let Some(item) = service_events.next() {
            events.push(decode_service_event(&item).expect("selection event ABI is valid"));
        }
        assert!(events.iter().any(|event| {
            event.action == SERVICE_EVENT_ACTION_TRANSLATE
                && event.reserved[1] == unf_ebpf_common::SERVICE_SELECTION_TIER_SAME_NODE
        }));
        assert_eq!(
            events
                .iter()
                .filter(|event| {
                    event.reason == SERVICE_EVENT_REASON_NO_BACKEND
                        && event.reserved[1] == unf_ebpf_common::SERVICE_SELECTION_TIER_SAME_NODE
                })
                .count(),
            2
        );
        assert!(events.iter().any(|event| {
            event.action == SERVICE_EVENT_ACTION_TRANSLATE
                && event.reserved[1] == unf_ebpf_common::SERVICE_SELECTION_TIER_CLUSTER
        }));
        assert!(events.iter().any(|event| {
            event.action == SERVICE_EVENT_ACTION_TRANSLATE
                && event.reserved[1] == unf_ebpf_common::SERVICE_SELECTION_TIER_SAME_ZONE
        }));
    }

    #[test]
    #[ignore = "requires root BPF program execution and UNF_EBPF_OBJECT"]
    #[allow(clippy::too_many_lines)]
    fn privileged_node_port_cluster_and_local_packets_translate_dual_stack_and_survive_churn() {
        const TC_ACT_SHOT: u32 = 2;
        const TC_ACT_PIPE: u32 = 3;
        let object = std::env::var_os("UNF_EBPF_OBJECT").expect("UNF_EBPF_OBJECT is set");
        let mut ebpf = EbpfLoader::new()
            .load_file(object)
            .expect("load verifier-approved eBPF object");
        load_dataplane_tail_programs(&mut ebpf)
            .expect("kernel verifier accepts dataplane tail programs");
        for program_name in ["unf_observe_ingress", "unf_observe_egress"] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(program_name)
                .expect("service TC program exists")
                .try_into()
                .expect("service program is a TC classifier");
            program
                .load()
                .expect("kernel verifier accepts NodePort TC program");
        }
        let mut service_events = RingBuf::try_from(
            ebpf.take_map("SERVICE_EVENTS")
                .expect("service event ring exists"),
        )
        .expect("service event ring opens");
        let mut flow_events = RingBuf::try_from(
            ebpf.take_map("FLOW_EVENTS")
                .expect("flow event ring exists"),
        )
        .expect("flow event ring opens");
        let (mut identity_v4_maps, _identity_v6_maps, mut identity_config) =
            take_identity_maps(&mut ebpf).expect("take identity maps");
        let (
            _identity_policy,
            mut ipv4_policy,
            _ipv6_policy,
            _egress_ipv4_policy,
            _egress_ipv6_policy,
            mut policy_config,
        ) = take_policy_maps(&mut ebpf).expect("take policy maps");
        let directory = tempdir().unwrap();
        let mut synchronizer =
            test_service_synchronizer(&mut ebpf, directory.path().join("service.json"));
        let state = test_agent_state();
        let node = node_port_node_snapshot(1);
        let node_v4 = Ipv4Addr::new(192, 0, 2, 10);
        let node_v6 = "fdff::10".parse::<Ipv6Addr>().unwrap();
        let backend_v4 = Ipv4Addr::new(10, 42, 0, 20);
        let backend_v6 = "fd00:42::20".parse::<Ipv6Addr>().unwrap();
        let client_v4 = Ipv4Addr::new(203, 0, 113, 5);
        let client_v6 = "2001:db8::5".parse::<Ipv6Addr>().unwrap();
        let first = dual_stack_node_port_snapshot_with_backend(
            1,
            backend_v4,
            backend_v6,
            true,
            unf_service::ServiceTrafficPolicy::Cluster,
        );
        activate_service_snapshot(&mut synchronizer, &first, Some(&node), true, &state)
            .expect("dual-stack Cluster NodePort activates");

        let ipv4_tcp = ipv4_packet(6, client_v4, node_v4, 40_000, 30_080);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        let ipv4_tcp_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert!((32_768..=u16::MAX).contains(&ipv4_tcp_snat));
        assert_ipv4_packet(&translated, 6, node_v4, backend_v4, ipv4_tcp_snat, 8080);
        let reverse = ipv4_packet(6, backend_v4, node_v4, 8080, ipv4_tcp_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, node_v4, client_v4, 30_080, 40_000);

        let ipv4_udp = ipv4_packet(17, client_v4, node_v4, 40_001, 30_053);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_udp);
        assert_eq!(action, TC_ACT_PIPE);
        let ipv4_udp_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert_ipv4_packet(&translated, 17, node_v4, backend_v4, ipv4_udp_snat, 5353);
        let reverse = ipv4_packet(17, backend_v4, node_v4, 5353, ipv4_udp_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, node_v4, client_v4, 30_053, 40_001);

        let ipv6_tcp = ipv6_packet(6, client_v6, node_v6, 40_002, 30_080);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        let ipv6_tcp_snat = u16::from_be_bytes([translated[54], translated[55]]);
        assert_ipv6_packet(&translated, 6, node_v6, backend_v6, ipv6_tcp_snat, 8080);
        let reverse = ipv6_packet(6, backend_v6, node_v6, 8080, ipv6_tcp_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, node_v6, client_v6, 30_080, 40_002);

        let ipv6_udp = ipv6_packet(17, client_v6, node_v6, 40_003, 30_053);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv6_udp);
        assert_eq!(action, TC_ACT_PIPE);
        let ipv6_udp_snat = u16::from_be_bytes([translated[54], translated[55]]);
        assert_ipv6_packet(&translated, 17, node_v6, backend_v6, ipv6_udp_snat, 5353);
        let reverse = ipv6_packet(17, backend_v6, node_v6, 5353, ipv6_udp_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, node_v6, client_v6, 30_053, 40_003);
        assert_eq!(
            synchronizer
                .connections
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            8
        );

        // The source-port high bit does not change the low 15-bit initial NAT
        // candidate. The second flow therefore proves bounded, dispersed collision
        // probing instead of overwriting the first reverse tuple.
        let colliding_client_port = 0x9c40_u16 ^ 0x8000;
        let colliding = ipv4_packet(6, client_v4, node_v4, colliding_client_port, 30_080);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &colliding);
        assert_eq!(action, TC_ACT_PIPE);
        let colliding_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert!((32_768..=u16::MAX).contains(&colliding_snat));
        assert_ne!(colliding_snat, ipv4_tcp_snat);
        assert_ipv4_packet(&translated, 6, node_v4, backend_v4, colliding_snat, 8080);
        let reverse = ipv4_packet(6, backend_v4, node_v4, 8080, colliding_snat);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(
            &translated,
            6,
            node_v4,
            client_v4,
            30_080,
            colliding_client_port,
        );
        assert_eq!(
            synchronizer
                .connections
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
            10
        );

        let backend_identity = IdentityId::new(22);
        identity_v4_maps[0]
            .insert(
                backend_v4.octets(),
                encode_identity_value(IdentityMapValue::new(backend_identity, 9)),
                0,
            )
            .expect("backend identity is staged");
        identity_config
            .set(0, encode_identity_config(7, 9, 1, 0).unwrap(), 0)
            .expect("backend identity is activated");
        let deny = Ipv4PolicyMapEntry {
            key: unf_state::Ipv4PolicyMapKey {
                source_address: Ipv4Addr::UNSPECIFIED,
                destination_identity: backend_identity,
                protocol: 6,
                destination_port: 8080,
            },
            decision: PolicyDecisionRecord {
                verdict: Verdict::Deny,
                reason: PolicyReason::DefaultAction,
                policy_id: Some(PolicyId::new(7)),
                rule_id: None,
            },
            shadow: None,
        };
        let deny_key = encode_ipv4_policy_key(&deny, 0);
        let deny_value = encode_policy_decisions(&deny.decision, None, 9);
        ipv4_policy
            .insert(deny_key, deny_value, 0)
            .expect("external-source deny is staged");
        policy_config
            .set(0, encode_policy_config(7, 9, 1, 0).unwrap(), 0)
            .expect("external-source deny is activated");
        let denied = ipv4_packet(6, client_v4, node_v4, 40_100, 30_080);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &denied);
        assert_eq!(action, TC_ACT_SHOT);
        identity_config
            .set(0, [0; 24], 0)
            .expect("test identity state is disabled");
        policy_config
            .set(0, [0; 24], 0)
            .expect("test policy state is disabled");

        let replacement_v4 = Ipv4Addr::new(10, 42, 0, 21);
        let replacement_v6 = "fd00:42::21".parse::<Ipv6Addr>().unwrap();
        let second = dual_stack_node_port_snapshot_with_backend(
            2,
            replacement_v4,
            replacement_v6,
            true,
            unf_service::ServiceTrafficPolicy::Cluster,
        );
        activate_service_snapshot(&mut synchronizer, &second, Some(&node), true, &state)
            .expect("replacement NodePort backend activates");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &ipv4_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, node_v4, backend_v4, ipv4_tcp_snat, 8080);
        let new_flow = ipv4_packet(6, client_v4, node_v4, 41_000, 30_080);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &new_flow);
        assert_eq!(action, TC_ACT_PIPE);
        let new_flow_snat = u16::from_be_bytes([translated[34], translated[35]]);
        assert_ipv4_packet(&translated, 6, node_v4, replacement_v4, new_flow_snat, 8080);

        let backendless = dual_stack_node_port_snapshot_with_backend(
            3,
            replacement_v4,
            replacement_v6,
            false,
            unf_service::ServiceTrafficPolicy::Cluster,
        );
        activate_service_snapshot(&mut synchronizer, &backendless, Some(&node), true, &state)
            .expect("backendless NodePort frontend activates");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &new_flow);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, node_v4, replacement_v4, new_flow_snat, 8080);
        let no_backend = ipv4_packet(6, client_v4, node_v4, 42_000, 30_080);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &no_backend);
        assert_eq!(action, TC_ACT_SHOT);

        let local = dual_stack_node_port_snapshot_with_backend(
            4,
            replacement_v4,
            replacement_v6,
            true,
            unf_service::ServiceTrafficPolicy::Local,
        );
        activate_service_snapshot(&mut synchronizer, &local, Some(&node), true, &state)
            .expect("Local NodePort intent activates with node-local slots");
        let local_flow = ipv4_packet(6, client_v4, node_v4, 42_001, 30_080);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &local_flow);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, replacement_v4, 42_001, 8080);
        let reverse = ipv4_packet(6, replacement_v4, client_v4, 8080, 42_001);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, node_v4, client_v4, 30_080, 42_001);

        let local_udp = ipv4_packet(17, client_v4, node_v4, 42_002, 30_053);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &local_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, client_v4, replacement_v4, 42_002, 5353);
        let reverse = ipv4_packet(17, replacement_v4, client_v4, 5353, 42_002);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 17, node_v4, client_v4, 30_053, 42_002);

        let local_v6_tcp = ipv6_packet(6, client_v6, node_v6, 42_003, 30_080);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &local_v6_tcp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, client_v6, replacement_v6, 42_003, 8080);
        let reverse = ipv6_packet(6, replacement_v6, client_v6, 8080, 42_003);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 6, node_v6, client_v6, 30_080, 42_003);

        let local_v6_udp = ipv6_packet(17, client_v6, node_v6, 42_004, 30_053);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &local_v6_udp);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, client_v6, replacement_v6, 42_004, 5353);
        let reverse = ipv6_packet(17, replacement_v6, client_v6, 5353, 42_004);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv6_packet(&translated, 17, node_v6, client_v6, 30_053, 42_004);

        identity_v4_maps[0]
            .insert(
                replacement_v4.octets(),
                encode_identity_value(IdentityMapValue::new(backend_identity, 10)),
                0,
            )
            .expect("local backend identity is staged");
        identity_config
            .set(0, encode_identity_config(7, 10, 1, 0).unwrap(), 0)
            .expect("local backend identity is activated");
        let local_deny_value = encode_policy_decisions(&deny.decision, None, 10);
        ipv4_policy
            .insert(deny_key, local_deny_value, 0)
            .expect("local external-source deny is staged");
        policy_config
            .set(0, encode_policy_config(7, 10, 1, 0).unwrap(), 0)
            .expect("local external-source deny is activated");
        let denied_local = ipv4_packet(6, client_v4, node_v4, 42_100, 30_080);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &denied_local);
        assert_eq!(action, TC_ACT_SHOT);
        identity_config.set(0, [0; 24], 0).unwrap();
        policy_config.set(0, [0; 24], 0).unwrap();

        let mut remote_only = dual_stack_node_port_snapshot_with_backend(
            5,
            replacement_v4,
            replacement_v6,
            true,
            unf_service::ServiceTrafficPolicy::Local,
        );
        for backend in &mut remote_only.services[0].backends {
            backend.node_name = Some("worker-b".to_owned());
        }
        remote_only = remote_only.validate_and_normalize().unwrap();
        activate_service_snapshot(&mut synchronizer, &remote_only, Some(&node), true, &state)
            .expect("remote-only Local intent activates with no local slots");
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &local_flow);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, replacement_v4, 42_001, 8080);
        let no_local = ipv4_packet(6, client_v4, node_v4, 42_101, 30_080);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &no_local);
        assert_eq!(action, TC_ACT_SHOT);

        let mut unready_local = dual_stack_node_port_snapshot_with_backend(
            6,
            replacement_v4,
            replacement_v6,
            true,
            unf_service::ServiceTrafficPolicy::Local,
        );
        for backend in &mut unready_local.services[0].backends {
            backend.ready = false;
        }
        unready_local = unready_local.validate_and_normalize().unwrap();
        activate_service_snapshot(&mut synchronizer, &unready_local, Some(&node), true, &state)
            .expect("unready Local intent activates with no eligible slots");
        let unready = ipv4_packet(6, client_v4, node_v4, 42_102, 30_080);
        let (action, _) = run_tc(&mut ebpf, "unf_observe_ingress", &unready);
        assert_eq!(action, TC_ACT_SHOT);

        let recovered = dual_stack_node_port_snapshot_with_backend(
            7,
            replacement_v4,
            replacement_v6,
            true,
            unf_service::ServiceTrafficPolicy::Local,
        );
        activate_service_snapshot(&mut synchronizer, &recovered, Some(&node), true, &state)
            .expect("ready local backend recovers");
        let recovered_flow = ipv4_packet(6, client_v4, node_v4, 42_103, 30_080);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_ingress", &recovered_flow);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, client_v4, replacement_v4, 42_103, 8080);
        let reverse = ipv4_packet(6, replacement_v4, client_v4, 8080, 42_103);
        let (action, translated) = run_tc(&mut ebpf, "unf_observe_egress", &reverse);
        assert_eq!(action, TC_ACT_PIPE);
        assert_ipv4_packet(&translated, 6, node_v4, client_v4, 30_080, 42_103);

        let unrelated = ipv4_packet(6, client_v4, node_v4, 42_200, 30_081);
        let (action, output) = run_tc(&mut ebpf, "unf_observe_ingress", &unrelated);
        assert_eq!(action, TC_ACT_PIPE);
        assert_eq!(output, unrelated);

        let mut events = Vec::new();
        while let Some(item) = service_events.next() {
            events.push(decode_service_event(&item).expect("kernel service event is valid"));
        }
        assert_eq!(events.len(), 29);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.action == SERVICE_EVENT_ACTION_TRANSLATE)
                .count(),
            26
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.action == SERVICE_EVENT_ACTION_DROP)
                .count(),
            3
        );
        let first_forward = events
            .iter()
            .find(|event| {
                event.client_port == 40_000_u16.to_be_bytes()
                    && event.action == SERVICE_EVENT_ACTION_TRANSLATE
            })
            .expect("NodePort forward translation has provenance");
        assert_eq!(&first_forward.frontend_address[..4], &node_v4.octets());
        assert_eq!(first_forward.frontend_address[4..], [0; 12]);
        assert_eq!(first_forward.frontend_port, 30_080_u16.to_be_bytes());
        assert_ne!(first_forward.service_id.get(), 0);
        assert_ne!(first_forward.backend_id.get(), 0);
        assert_eq!(first_forward.service_revision, 1);
        assert_eq!(
            service_event_frontend_kind(first_forward),
            ServiceFrontendKind::NodePortCluster
        );
        let local_forward = events
            .iter()
            .find(|event| {
                event.client_port == 42_001_u16.to_be_bytes()
                    && event.reason == unf_ebpf_common::SERVICE_EVENT_REASON_FORWARD_TRANSLATED
            })
            .expect("Local forward translation has provenance");
        assert_eq!(&local_forward.client_address[..4], &client_v4.octets());
        assert_eq!(&local_forward.frontend_address[..4], &node_v4.octets());
        assert_eq!(
            &local_forward.backend_address[..4],
            &replacement_v4.octets()
        );
        assert_eq!(local_forward.service_revision, 4);
        assert_eq!(
            service_event_frontend_kind(local_forward),
            ServiceFrontendKind::NodePortLocal
        );
        assert!(
            events
                .iter()
                .filter(|event| {
                    event.reason == SERVICE_EVENT_REASON_NO_BACKEND
                        && service_event_frontend_kind(event) == ServiceFrontendKind::NodePortLocal
                })
                .count()
                >= 2
        );

        let mut policy_events = Vec::new();
        while let Some(item) = flow_events.next() {
            policy_events.push(decode_event(&item).expect("kernel policy event is valid"));
        }
        let denied = policy_events
            .iter()
            .find(|event| event.verdict == Verdict::Deny)
            .expect("NodePort policy denial is emitted");
        assert_eq!(denied.flow.destination_identity, backend_identity);
        assert_eq!(&denied.flow.destination_address[..4], &backend_v4.octets());
        assert_eq!(denied.flow.destination_address[4..], [0; 12]);
        assert_eq!(denied.flow.destination_port, 8080_u16.to_be_bytes());
        assert_eq!(denied.policy_revision, 9);
        assert_eq!(denied.policy_id, PolicyId::new(7));
        let denied_local = policy_events
            .iter()
            .find(|event| event.verdict == Verdict::Deny && event.policy_revision == 10)
            .expect("Local NodePort policy denial is emitted");
        assert_eq!(&denied_local.flow.source_address[..4], &client_v4.octets());
        assert_eq!(denied_local.flow.source_port, 42_100_u16.to_be_bytes());
        assert_eq!(
            &denied_local.flow.destination_address[..4],
            &replacement_v4.octets()
        );
        assert_eq!(denied_local.flow.destination_port, 8080_u16.to_be_bytes());
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
    fn cleanup_recognizes_only_owned_tail_program_pin_names() {
        assert!(recognized_tail_program_pin_name(
            DATAPLANE_TAIL_CALL_MAP_NAME
        ));
        assert!(recognized_tail_program_pin_name("unf_policy_v4"));
        assert!(recognized_tail_program_pin_name("unf_policy_v6-123-456789"));
        assert!(!recognized_tail_program_pin_name("unf_policy_v6-next"));
        assert!(!recognized_tail_program_pin_name(
            "unf_policy_v6-123-not-a-timestamp"
        ));
        assert!(!recognized_tail_program_pin_name(
            "unf_policy_v6-123-456-extra"
        ));
        assert!(!recognized_tail_program_pin_name("unf_policy_v7-123-456"));
    }

    #[test]
    fn tail_runtime_pin_directory_refuses_unknown_content_without_mutation() {
        let temporary = tempdir().expect("temporary directory is created");
        let programs = temporary.path().join("programs");
        fs::create_dir(&programs).expect("program directory is created");
        let dispatch = programs.join(DATAPLANE_TAIL_CALL_MAP_NAME);
        let legacy_program = programs.join("unf_policy_v4-123-456");
        let unknown = programs.join("operator-owned-program");
        fs::write(&dispatch, []).expect("dispatch pin fixture is created");
        fs::write(&legacy_program, []).expect("legacy program pin fixture is created");
        assert_eq!(
            validate_tail_program_pin_directory(&programs)
                .expect("owned runtime pins are accepted")
                .len(),
            2
        );
        fs::write(&unknown, []).expect("unknown fixture is created");

        assert!(
            validate_tail_program_pin_directory(&programs)
                .expect_err("unknown content is refused")
                .to_string()
                .contains("unrecognized tail program pin content")
        );
        assert!(dispatch.exists());
        assert!(legacy_program.exists());
        assert!(unknown.exists());
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
        let programs = abi.join("programs");
        fs::create_dir_all(&links).expect("fixture directories are created");
        fs::create_dir_all(&programs).expect("program fixture directory is created");
        fs::write(abi.join("IDENTITY_V4"), []).expect("map fixture is created");
        fs::write(abi.join("POLICY_CONFIG"), []).expect("map fixture is created");
        fs::write(links.join("tcx-ingress-7"), []).expect("link fixture is created");
        fs::write(programs.join(DATAPLANE_TAIL_CALL_MAP_NAME), [])
            .expect("dispatch map fixture is created");
        fs::write(programs.join("unf_policy_v4"), []).expect("program fixture is created");
        fs::write(programs.join("unf_policy_v6-123-456789"), [])
            .expect("generation program fixture is created");
        fs::write(root.join("operator-note"), []).expect("sibling fixture is created");

        let plan = plan_abi_cleanup(&root, 1, false).expect("known fixture has a safe plan");
        assert_eq!(plan.map_pins.len(), 2);
        assert_eq!(plan.link_pins.len(), 1);
        assert_eq!(plan.program_pins.len(), 3);
        execute_abi_cleanup(&plan).expect("known fixture is removed");

        assert!(!abi.exists());
        assert!(root.join("operator-note").exists());
    }

    #[test]
    fn cleanup_distinguishes_historical_and_current_map_ownership() {
        let temporary = tempdir().unwrap();
        let root = temporary.path().join("unf");
        for (version, names) in [
            (4_u16, ABI_V4_MAP_NAMES.as_slice()),
            (5_u16, ABI_V5_MAP_NAMES.as_slice()),
            (6_u16, ABI_V8_MAP_NAMES.as_slice()),
            (7_u16, ABI_V8_MAP_NAMES.as_slice()),
            (8_u16, ABI_V8_MAP_NAMES.as_slice()),
            (9_u16, ABI_V11_MAP_NAMES.as_slice()),
            (10_u16, ABI_V11_MAP_NAMES.as_slice()),
            (11_u16, ABI_V11_MAP_NAMES.as_slice()),
            (12_u16, ABI_V12_MAP_NAMES.as_slice()),
            (13_u16, ABI_V13_MAP_NAMES.as_slice()),
            (CURRENT_BPF_ABI_VERSION, PERSISTENT_MAP_NAMES.as_slice()),
        ] {
            let abi = root.join(format!("v{version}"));
            fs::create_dir_all(&abi).unwrap();
            for name in names {
                fs::write(abi.join(name), []).unwrap();
            }
            let plan = plan_abi_cleanup(&root, version, version == CURRENT_BPF_ABI_VERSION)
                .expect("complete known ABI map set is recognized");
            assert_eq!(plan.map_pins.len(), names.len());
        }
        assert_eq!(ABI_V4_MAP_NAMES.len(), 18);
        assert_eq!(ABI_V5_MAP_NAMES.len(), 21);
        assert_eq!(ABI_V8_MAP_NAMES.len(), 24);
        assert_eq!(ABI_V11_MAP_NAMES.len(), 25);
        assert_eq!(ABI_V12_MAP_NAMES.len(), 31);
        assert_eq!(ABI_V13_MAP_NAMES.len(), 33);
        assert_eq!(PERSISTENT_MAP_NAMES.len(), 40);
    }

    #[test]
    fn recovered_egress_connections_require_exact_bidirectional_tuples_and_proofs() {
        let source = [10, 0, 0, 8];
        let destination = [203, 0, 113, 9];
        let translated = [198, 51, 100, 10];
        let mut value = [0_u8; 208];
        value[8..16].copy_from_slice(&13_u64.to_ne_bytes());
        value[16..24].copy_from_slice(&7_u64.to_ne_bytes());
        value[24..28].copy_from_slice(&source);
        value[40..44].copy_from_slice(&destination);
        value[56..60].copy_from_slice(&translated);
        value[104..120].fill(0x11);
        value[120..152].fill(0x22);
        value[152..168].fill(0x33);
        value[168..184].fill(0x44);
        value[184..188].copy_from_slice(&42_u32.to_ne_bytes());
        value[188..190].copy_from_slice(&40_000_u16.to_be_bytes());
        value[190..192].copy_from_slice(&443_u16.to_be_bytes());
        value[192..194].copy_from_slice(&50_000_u16.to_be_bytes());
        value[200..202].copy_from_slice(&EGRESS_MAP_ABI_VERSION.to_ne_bytes());
        value[202] = 6;
        value[203] = 4;

        let mut forward = [0_u8; 44];
        forward[0..4].copy_from_slice(&source);
        forward[16..20].copy_from_slice(&destination);
        forward[32..34].copy_from_slice(&40_000_u16.to_be_bytes());
        forward[34..36].copy_from_slice(&443_u16.to_be_bytes());
        forward[36..40].copy_from_slice(&42_u32.to_ne_bytes());
        forward[40] = 6;
        forward[41] = 4;
        forward[42] = unf_ebpf_common::EGRESS_CONNECTION_ROLE_FORWARD;
        validate_recovered_egress_connection(&forward, &value).unwrap();

        let mut reverse = [0_u8; 44];
        reverse[0..4].copy_from_slice(&destination);
        reverse[16..20].copy_from_slice(&translated);
        reverse[32..34].copy_from_slice(&443_u16.to_be_bytes());
        reverse[34..36].copy_from_slice(&50_000_u16.to_be_bytes());
        reverse[40] = 6;
        reverse[41] = 4;
        reverse[42] = unf_ebpf_common::EGRESS_CONNECTION_ROLE_REVERSE;
        validate_recovered_egress_connection(&reverse, &value).unwrap();

        reverse[16] ^= 1;
        assert!(validate_recovered_egress_connection(&reverse, &value).is_err());
        value[120] = 0;
        value[121..152].fill(0);
        assert!(validate_recovered_egress_connection(&forward, &value).is_err());
    }

    #[test]
    fn gateway_retirement_preserves_active_pairs_and_collects_only_one_expired_lease() {
        fn pair(lease_epoch: u64, last_seen_ns: u64, identity: u32) -> Vec<([u8; 44], [u8; 208])> {
            let source = [10, 0, 0, u8::try_from(identity).unwrap_or(8)];
            let destination = [203, 0, 113, 9];
            let translated = [198, 51, 100, u8::try_from(identity).unwrap_or(10)];
            let mut value = [0_u8; 208];
            value[0..8].copy_from_slice(&last_seen_ns.to_ne_bytes());
            value[8..16].copy_from_slice(&13_u64.to_ne_bytes());
            value[16..24].copy_from_slice(&lease_epoch.to_ne_bytes());
            value[24..28].copy_from_slice(&source);
            value[40..44].copy_from_slice(&destination);
            value[56..60].copy_from_slice(&translated);
            value[104..120].fill(0x11);
            value[120..152].fill(0x22);
            value[152..168].fill(0x33);
            value[168..184].fill(0x44);
            value[184..188].copy_from_slice(&identity.to_ne_bytes());
            value[188..190].copy_from_slice(&40_000_u16.to_be_bytes());
            value[190..192].copy_from_slice(&443_u16.to_be_bytes());
            value[192..194].copy_from_slice(&50_000_u16.to_be_bytes());
            value[200..202].copy_from_slice(&EGRESS_MAP_ABI_VERSION.to_ne_bytes());
            value[202] = 6;
            value[203] = 4;

            let mut forward = [0_u8; 44];
            forward[0..4].copy_from_slice(&source);
            forward[16..20].copy_from_slice(&destination);
            forward[32..34].copy_from_slice(&40_000_u16.to_be_bytes());
            forward[34..36].copy_from_slice(&443_u16.to_be_bytes());
            forward[36..40].copy_from_slice(&identity.to_ne_bytes());
            forward[40] = 6;
            forward[41] = 4;
            forward[42] = unf_ebpf_common::EGRESS_CONNECTION_ROLE_FORWARD;

            let mut reverse = [0_u8; 44];
            reverse[0..4].copy_from_slice(&destination);
            reverse[16..20].copy_from_slice(&translated);
            reverse[32..34].copy_from_slice(&443_u16.to_be_bytes());
            reverse[34..36].copy_from_slice(&50_000_u16.to_be_bytes());
            reverse[40] = 6;
            reverse[41] = 4;
            reverse[42] = unf_ebpf_common::EGRESS_CONNECTION_ROLE_REVERSE;
            vec![(forward, value), (reverse, value)]
        }

        let now_ns = unf_ebpf_common::CONNECTION_TCP_TIMEOUT_NS + 100;
        let mut connections = BTreeMap::new();
        connections.extend(pair(7, now_ns, 42));
        connections.extend(pair(8, 0, 43));
        assert_eq!(
            plan_egress_gateway_lease_drain(&connections, 7, now_ns).unwrap(),
            EgressGatewayDrainPlan::Active(2)
        );
        let EgressGatewayDrainPlan::Remove(expired) =
            plan_egress_gateway_lease_drain(&connections, 8, now_ns).unwrap()
        else {
            panic!("expired lease must be removable");
        };
        assert_eq!(expired.len(), 2);
        assert!(
            expired
                .iter()
                .all(|key| connections[key][16..24] == 8_u64.to_ne_bytes())
        );

        let mut corrupt = connections;
        corrupt.values_mut().next().expect("connection exists")[206] = 1;
        assert!(plan_egress_gateway_lease_drain(&corrupt, 8, now_ns).is_err());
    }

    #[test]
    fn egress_agent_advertisement_is_exact_and_current() {
        let advertisement = egress_agent_advertisement();
        assert_eq!(
            advertisement.distribution_schemas,
            BTreeSet::from([EGRESS_DISTRIBUTION_SCHEMA_VERSION])
        );
        assert_eq!(
            advertisement.host_state_schemas,
            BTreeSet::from([EGRESS_HOST_STATE_SCHEMA_VERSION])
        );
        assert_eq!(advertisement.capabilities.len(), 5);
        assert!(
            advertisement
                .capabilities
                .contains(&EgressCapability::LeaseEpochFencing)
        );
        assert!(
            advertisement
                .capabilities
                .contains(&EgressCapability::Ipv6TcpUdpNat)
        );
    }

    #[test]
    fn egress_persistent_authority_rejects_regression_and_same_revision_mutation() {
        let applied = EgressAppliedAuthority {
            controller_epoch: 7,
            projection_revision: 11,
            contract_revision: 13,
            contract_digest: Some([0xA5; 32]),
        };
        assert!(egress_authority_is_current(Some(applied), applied).unwrap());

        let regression = EgressAppliedAuthority {
            projection_revision: 10,
            ..applied
        };
        assert!(egress_authority_is_current(Some(applied), regression).is_err());
        let mutation = EgressAppliedAuthority {
            contract_digest: Some([0x5A; 32]),
            ..applied
        };
        assert!(egress_authority_is_current(Some(applied), mutation).is_err());
        let advance = EgressAppliedAuthority {
            projection_revision: 12,
            ..applied
        };
        assert!(!egress_authority_is_current(Some(applied), advance).unwrap());
    }

    #[test]
    fn egress_dataplane_encoding_is_exact_and_rejects_foreign_bank_entries() {
        let source = unf_ebpf_common::EgressSourceKey {
            source_identity: IdentityId::new(42),
            bank: 1,
            reserved: [0; 3],
        };
        let value = unf_ebpf_common::EgressSourceValue {
            lease_epoch: 7,
            contract_revision: 13,
            intent_revision: 2,
            identity_revision: 3,
            policy_revision: 5,
            allocation_revision: 8,
            gateway_revision: 11,
            reachability_revision: 12,
            contract_digest: [0xA5; 32],
            intent_digest: [0x5A; 16],
            intent_index: 9,
            address_count: 2,
            gateway_count: 2,
            schema_version: EGRESS_MAP_ABI_VERSION,
            admission: unf_ebpf_common::EGRESS_ADMISSION_ACTIVE,
            flags: 0,
            reserved: [0; 4],
        };
        let mut state = EgressDataplaneState {
            config: unf_ebpf_common::EgressMapConfig {
                controller_epoch: 7,
                projection_revision: 17,
                contract_revision: 13,
                path_revision: 19,
                source_count: 1,
                address_count: 0,
                gateway_count: 0,
                selection_count: 0,
                schema_version: EGRESS_MAP_ABI_VERSION,
                active_bank: 1,
                flags: 0,
                destination_count: 1,
            },
            sources: vec![(source, value)],
            ipv4_destinations: vec![(
                0,
                unf_ebpf_common::EgressIpv4DestinationData {
                    intent_index: 9,
                    bank: 1,
                    reserved: [0; 3],
                    destination_address: [0; 4],
                },
                unf_ebpf_common::EgressDestinationValue {
                    contract_revision: 13,
                    intent_digest: [0x5A; 16],
                    schema_version: EGRESS_MAP_ABI_VERSION,
                    flags: 0,
                    reserved: [0; 4],
                },
            )],
            ipv6_destinations: Vec::new(),
            addresses: Vec::new(),
            gateways: Vec::new(),
            selections: Vec::new(),
        };

        let encoded = encode_egress_dataplane(&state).expect("valid state encodes");
        let key = encode_egress_source_key(source);
        let encoded_value = encoded.sources.get(&key).expect("source is retained");
        assert_eq!(u32::from_ne_bytes(key[0..4].try_into().unwrap()), 42);
        assert_eq!(key[4], 1);
        assert_eq!(
            u64::from_ne_bytes(encoded_value[40..48].try_into().unwrap()),
            8
        );
        assert_eq!(&encoded_value[64..96], &[0xA5; 32]);
        assert_eq!(encoded_value[122], unf_ebpf_common::EGRESS_ADMISSION_ACTIVE);
        assert_eq!(encoded.config[50], 1);

        state.sources[0].0.bank = 0;
        assert!(encode_egress_dataplane(&state).is_err());
        state.sources[0].0.bank = 1;
        state.ipv4_destinations[0].2.intent_digest = [0x11; 16];
        assert!(encode_egress_dataplane(&state).is_err());
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
    fn egress_event_decoder_requires_exact_proof_bound_nat_evidence() {
        let mut bytes = [0_u8; size_of::<EgressEvent>()];
        bytes[0..8].copy_from_slice(&19_u64.to_ne_bytes());
        bytes[8..16].copy_from_slice(&23_u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&29_u64.to_ne_bytes());
        bytes[24..28].copy_from_slice(&[10, 42, 0, 7]);
        bytes[40..44].copy_from_slice(&[198, 51, 100, 9]);
        bytes[56..60].copy_from_slice(&[192, 0, 2, 10]);
        bytes[72..88].fill(0x11);
        bytes[88..104].fill(0x22);
        bytes[104..120].fill(0x33);
        bytes[120..124].copy_from_slice(&37_u32.to_ne_bytes());
        bytes[124..126].copy_from_slice(&40_000_u16.to_be_bytes());
        bytes[126..128].copy_from_slice(&443_u16.to_be_bytes());
        bytes[128..130].copy_from_slice(&50_000_u16.to_be_bytes());
        bytes[130..132].copy_from_slice(&EGRESS_EVENT_ABI_VERSION.to_ne_bytes());
        bytes[132..134].copy_from_slice(
            &u16::try_from(size_of::<EgressEvent>())
                .expect("egress event size fits u16")
                .to_ne_bytes(),
        );
        bytes[134..136].copy_from_slice(&2_u16.to_ne_bytes());
        bytes[136..138].copy_from_slice(&3_u16.to_ne_bytes());
        bytes[138..140].copy_from_slice(&4_u16.to_ne_bytes());
        bytes[140] = 6;
        bytes[141] = 4;
        bytes[142] = EGRESS_EVENT_ACTION_CREATE;
        bytes[143] = unf_ebpf_common::EGRESS_EVENT_REASON_TRANSLATION_CREATED;

        let event = decode_egress_event(&bytes).expect("egress event ABI is valid");
        assert_eq!(event.contract_revision, 23);
        assert_eq!(event.lease_epoch, 29);
        assert_eq!(event.source_identity.get(), 37);
        assert_eq!(event.egress_address[..4], [192, 0, 2, 10]);
        assert_eq!(u16::from_be_bytes(event.translated_source_port), 50_000);

        let mut invalid = bytes;
        invalid[143] = unf_ebpf_common::EGRESS_EVENT_REASON_REWRITE_FAILED;
        assert!(decode_egress_event(&invalid).is_none());
        let mut invalid = bytes;
        invalid[104..120].fill(0);
        assert!(decode_egress_event(&invalid).is_none());
        let mut invalid = bytes;
        invalid[60] = 1;
        assert!(decode_egress_event(&invalid).is_none());
        let mut invalid = bytes;
        invalid[151] = 1;
        assert!(decode_egress_event(&invalid).is_none());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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
        bytes[86] = SERVICE_EVENT_FRONTEND_NODE_PORT_CLUSTER;
        bytes[87] = unf_ebpf_common::SERVICE_SELECTION_TIER_CLUSTER;
        bytes[89] = unf_ebpf_common::SERVICE_SELECTION_ALGORITHM_MAGLEV;
        let event = decode_service_event(&bytes).expect("service event ABI is valid");
        assert_eq!(
            event.reserved[1],
            unf_ebpf_common::SERVICE_SELECTION_TIER_CLUSTER
        );
        assert_eq!(
            event.reserved[3],
            unf_ebpf_common::SERVICE_SELECTION_ALGORITHM_MAGLEV
        );
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
        assert_eq!(outcome.frontend_kind, ServiceFrontendKind::NodePortCluster);
        assert_eq!(outcome.selection_tier, ServiceSelectionTier::Cluster);
        assert_eq!(outcome.affinity_outcome, ServiceAffinityOutcome::None);
        assert_eq!(
            outcome.selection_algorithm,
            ServiceSelectionAlgorithmOutcome::Maglev
        );
        assert_eq!(outcome.forwarding_mode, ServiceForwardingModeOutcome::Nat);
        let state = test_agent_state();
        record_service_event(&state, &event);
        let report = agent_state_report(&state);
        assert_eq!(report.service_dataplane_events, 1);
        assert_eq!(report.service_translations, 1);
        assert_eq!(report.node_port_cluster_translations, 1);
        assert_eq!(report.node_port_local_translations, 0);
        assert_eq!(report.service_drops, 0);
        assert_eq!(report.last_service_id, 11);
        assert_eq!(report.last_backend_id, 13);
        assert_eq!(report.last_service_revision, 7);
        assert_eq!(report.last_service_action, SERVICE_EVENT_ACTION_TRANSLATE);
        assert_eq!(report.service_cluster_selections, 1);
        assert_eq!(report.service_maglev_selections, 1);
        assert_eq!(report.service_nat_forwards, 1);
        assert_eq!(
            report.last_service_selection_tier,
            Some(ServiceSelectionTier::Cluster)
        );
        assert_eq!(
            report.last_service_selection_algorithm,
            Some(ServiceSelectionAlgorithmOutcome::Maglev)
        );
        assert_eq!(
            report.last_service_forwarding_mode,
            Some(ServiceForwardingModeOutcome::Nat)
        );
        assert_eq!(
            report.last_service_reason,
            unf_ebpf_common::SERVICE_EVENT_REASON_FORWARD_TRANSLATED
        );

        bytes[86] = SERVICE_EVENT_FRONTEND_LOAD_BALANCER_CLUSTER;
        let load_balancer = decode_service_event(&bytes)
            .expect("LoadBalancer Cluster event classification is valid");
        assert_eq!(
            service_event_frontend_kind(&load_balancer),
            ServiceFrontendKind::LoadBalancerCluster
        );
        record_service_event(&state, &load_balancer);
        assert_eq!(
            agent_state_report(&state).load_balancer_cluster_translations,
            1
        );
        bytes[48..64].fill(0);
        bytes[68..72].fill(0);
        bytes[76..78].fill(0);
        bytes[84] = SERVICE_EVENT_ACTION_DROP;
        bytes[85] = unf_ebpf_common::SERVICE_EVENT_REASON_NO_BACKEND;
        bytes[86] = SERVICE_EVENT_FRONTEND_NODE_PORT_LOCAL;
        let no_backend = decode_service_event(&bytes).expect("Local no-backend event is valid");
        record_service_event(&state, &no_backend);
        let report = agent_state_report(&state);
        assert_eq!(report.service_drops, 1);
        assert_eq!(report.node_port_no_backend_drops, 1);

        bytes[86] = SERVICE_EVENT_FRONTEND_LOAD_BALANCER_LOCAL;
        let no_backend = decode_service_event(&bytes).expect("LoadBalancer no-backend is valid");
        record_service_event(&state, &no_backend);
        assert_eq!(agent_state_report(&state).load_balancer_no_backend_drops, 1);
        bytes[85] = SERVICE_EVENT_REASON_SOURCE_RANGE_DENIED;
        let denied = decode_service_event(&bytes).expect("source-range denial is valid");
        record_service_event(&state, &denied);
        let report = agent_state_report(&state);
        assert_eq!(report.load_balancer_source_range_drops, 1);
        assert_eq!(state.metrics.load_balancer_source_range_drops.get(), 1);
        let mut exposition = String::new();
        encode(&mut exposition, &mutex_lock(&state.registry)).unwrap();
        for metric in [
            "unf_loadbalancer_revision_desired",
            "unf_loadbalancer_frontend_count",
            "unf_loadbalancer_health_check_ready_count",
            "unf_loadbalancer_cluster_translations_total",
            "unf_loadbalancer_local_translations_total",
            "unf_loadbalancer_no_backend_drops_total",
            "unf_loadbalancer_source_range_drops_total",
            "unf_service_selection_cluster_total",
            "unf_service_selection_maglev_total",
            "unf_service_forwarding_nat_total",
        ] {
            assert!(exposition.contains(metric), "missing metric {metric}");
        }

        bytes[84] = SERVICE_EVENT_ACTION_TRANSLATE;
        assert!(decode_service_event(&bytes).is_none());
        bytes[86] = 0;
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
                Path::new("/sys/fs/bpf/unf/v14/links"),
                Direction::Ingress,
                17
            ),
            Path::new("/sys/fs/bpf/unf/v14/links/tcx-ingress-17")
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
        assert_eq!(
            version.selection_contract_schema_version,
            SELECTION_CONTRACT_SCHEMA_VERSION
        );
    }

    #[test]
    fn controller_preflight_accepts_the_bounded_service_schema_transition() {
        let mut controller = ComponentCompatibility::current(
            "unf-controller",
            env!("CARGO_PKG_VERSION"),
            "controller-revision",
        );
        assert!(ensure_controller_compatibility(&controller).is_ok());

        controller.service_snapshot_schema_version = LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        assert!(ensure_controller_compatibility(&controller).is_ok());
        controller.service_snapshot_schema_version = NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        assert!(ensure_controller_compatibility(&controller).is_ok());
        controller.service_snapshot_schema_version = LOAD_BALANCER_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        assert!(ensure_controller_compatibility(&controller).is_ok());
        controller.service_snapshot_schema_version = SERVICE_SNAPSHOT_SCHEMA_VERSION;
        controller.selection_contract_schema_version = 0;
        controller.agent_status_schema_version = PRE_SELECTION_AGENT_STATUS_SCHEMA_VERSION;
        assert!(ensure_controller_compatibility(&controller).is_ok());
        controller.agent_status_schema_version = AGENT_STATUS_SCHEMA_VERSION;
        controller.selection_contract_schema_version = SELECTION_CONTRACT_SCHEMA_VERSION;

        controller.load_balancer_reachability_schema_version = 0;
        assert!(ensure_controller_compatibility(&controller).is_ok());
        controller.load_balancer_reachability_schema_version =
            unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION;

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
        assert!(error.to_string().contains(&format!(
            "persistent BPF-state ABI controller={} agent={}",
            PERSISTENT_BPF_STATE_ABI_VERSION + 1,
            PERSISTENT_BPF_STATE_ABI_VERSION
        )));

        controller.persistent_bpf_state_abi_version -= 1;
        controller.service_snapshot_schema_version += 1;
        let error = ensure_controller_compatibility(&controller)
            .expect_err("a service-schema mismatch is rejected");
        assert!(error.to_string().contains(&format!(
            "service snapshot schema controller={} agent={}",
            unf_service::SERVICE_SNAPSHOT_SCHEMA_VERSION + 1,
            unf_service::SERVICE_SNAPSHOT_SCHEMA_VERSION
        )));

        controller.service_snapshot_schema_version = SERVICE_SNAPSHOT_SCHEMA_VERSION;
        controller.selection_contract_schema_version = SELECTION_CONTRACT_SCHEMA_VERSION + 1;
        let error = ensure_controller_compatibility(&controller)
            .expect_err("a newer selection contract schema is rejected");
        assert!(
            error
                .to_string()
                .contains("selection contract schema controller=2 agent=1")
        );
        controller.selection_contract_schema_version = SELECTION_CONTRACT_SCHEMA_VERSION;
        controller.load_balancer_reachability_schema_version =
            unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION + 1;
        let error = ensure_controller_compatibility(&controller)
            .expect_err("a newer LoadBalancer reachability schema is rejected");
        assert!(
            error
                .to_string()
                .contains("LoadBalancer reachability schema controller=2 agent=1")
        );
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
        assert!(ensure_bpf_pin_path_abi(Path::new("/sys/fs/bpf/unf/v14")).is_ok());
        assert_eq!(
            configured_abi_version(Path::new("/sys/fs/bpf/unf/v14")),
            Some(14)
        );
        let error = ensure_bpf_pin_path_abi(Path::new("/sys/fs/bpf/unf/v2"))
            .expect_err("a stale ABI directory is rejected before access");
        assert!(
            error.to_string().contains(
                "incompatible with persistent BPF-state ABI v14; expected a /v14 directory"
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
        assert_eq!(
            report.service_snapshot_schema_version,
            SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
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
