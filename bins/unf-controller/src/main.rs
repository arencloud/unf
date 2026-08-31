use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use clap::{Parser, ValueEnum};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Node, Pod, Service, ServiceSpec};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Patch, PatchParams, PostParams};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, ResourceExt};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use unf_api::SecurityPolicy;
use unf_common::{
    BackendId, IdentityId, PolicyAction, PolicyDirection, PolicyId, PolicyReason, Protocol,
    Revision, ServiceId, Verdict,
};
use unf_ipam::{
    Ipv4NodeBlock, Ipv6NodeBlock, NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION, NodeBlockProvider,
    NodeBlockSnapshot,
};
use unf_loadbalancer::{
    AllocationCheckpoint, LoadBalancerAllocator, LoadBalancerLease, LoadBalancerOwner,
    LoadBalancerPool, NodeReachabilitySnapshot, ReachabilityMode, ReachabilityNode,
    ReachabilityProviderRef, ReachabilitySnapshot, allocation_request_for_service,
    compile_direct_node_reachability, reconcile_finalizers,
};
use unf_policy::{
    DestinationAddresses, DestinationPort, Endpoint, Flow, Ipv4Endpoint, Ipv6Endpoint, NamedPort,
    NetworkPolicyCompiler, PolicyCompiler, PolicyIr, compile_dataplane_entries,
    compile_egress_ipv4_dataplane_entries, compile_egress_ipv6_dataplane_entries,
    compile_ipv4_dataplane_entries, compile_ipv6_dataplane_entries,
    evaluate_for_direction_with_addresses,
};
use unf_route::{
    MAX_REMOTE_NODES, REMOTE_ROUTE_SNAPSHOT_SCHEMA_VERSION, RemoteNodeIntent, RemoteRouteSnapshot,
    RemoteRouteSnapshotNode,
};
use unf_service::{
    AddressFamily, EndpointPortSource, EndpointSliceSource, EndpointSource,
    LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION, NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION,
    NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION, NodeAddressKind, NodePortNodeSnapshot,
    SERVICE_SNAPSHOT_SCHEMA_VERSION, ServiceBackend, ServiceIpFamilyPolicy, ServiceIpPrefix,
    ServiceIr, ServiceLoadBalancerSource, ServiceNodeAddress, ServiceNodePort, ServiceSnapshot,
    ServiceSource, ServiceSourcePort, ServiceTrafficPolicy, UNF_LOAD_BALANCER_CLASS,
    compile_service_snapshot,
};
use unf_state::{
    AGENT_STATUS_SCHEMA_VERSION, AgentConvergenceEntry, AgentConvergenceSnapshot, AgentStateReport,
    ComponentCompatibility, EgressIpv4PolicyMapEntry, EgressIpv4PolicyMapKey,
    EgressIpv6PolicyMapEntry, EgressIpv6PolicyMapKey, FLOW_EXPORT_BATCH_LIMIT,
    FLOW_EXPORT_SCHEMA_VERSION, FLOW_HISTORY_CAPACITY, FlowExportBatch, FlowExportRecord,
    FlowHistoryCheckpoint, FlowHistoryEntry, FlowHistoryQuerySummary, FlowHistorySnapshot,
    FlowHistoryStore, IdentityRegistry, IdentityStateSnapshot, Ipv4PolicyMapEntry,
    Ipv4PolicyMapKey, Ipv6PolicyMapEntry, Ipv6PolicyMapKey, NetworkIdentity,
    POLICY_SNAPSHOT_SCHEMA_VERSION, PolicyDecisionRecord, PolicyStateSnapshot, RevisionSet,
    ServiceFrontendKind, TOPOLOGY_HISTORY_CAPACITY, TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
    TopologyHistoryCheckpoint, TopologyHistorySnapshot, TopologyHistoryStore, TopologyNode,
    TopologyService, TopologyServiceBackend, TopologyServiceBackendPort, TopologyServicePort,
    TopologyStateSnapshot, TopologyWorkload, provisional_identity_id,
};

mod external_flow_export;

const BUILD_REVISION: &str = match option_env!("UNF_BUILD_REVISION") {
    Some(revision) => revision,
    None => "unknown",
};

use external_flow_export::{
    ExternalFlowExportConfig, ExternalFlowExportEnvelope, ExternalFlowExportMetrics,
    ExternalFlowExporter, build_external_flow_export,
};

const AGENT_STATUS_FRESHNESS_MILLIS: u64 = 10_000;
const AGENT_TOKEN_AUDIENCE: &str = "unf-controller.unf-system.svc";
const AGENT_SERVICE_ACCOUNT_USERNAME: &str = "system:serviceaccount:unf-system:unf-agent";
const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";
const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";
const AGENT_AUTHENTICATION_CACHE_TTL: Duration = Duration::from_secs(30);
const AGENT_AUTHENTICATION_CACHE_CAPACITY: usize = 64;
const AGENT_REPORT_STORE_NAME: &str = "unf-agent-acknowledgements";
const AGENT_REPORT_STORE_KEY: &str = "reports.json";
const AGENT_REPORT_STORE_SCHEMA_VERSION: u16 = 1;
const AGENT_REPORT_STORE_CAPACITY: usize = 1_024;
const AGENT_REPORT_PERSISTENCE_INTERVAL: Duration = Duration::from_secs(2);
const AGENT_REPORT_MAX_FUTURE_SKEW_MILLIS: u64 = 60_000;
const FLOW_HISTORY_STORE_NAME: &str = "unf-flow-history";
const FLOW_HISTORY_STORE_KEY: &str = "flows.json";
const FLOW_HISTORY_DURABLE_ENTRY_LIMIT: usize = 1_024;
const FLOW_HISTORY_CONFIG_MAP_DATA_LIMIT: usize = 900_000;
const FLOW_HISTORY_PERSISTENCE_INTERVAL: Duration = Duration::from_secs(2);
const FLOW_HISTORY_MAX_FUTURE_SKEW_MILLIS: u64 = 60_000;
const TOPOLOGY_HISTORY_STORE_NAME: &str = "unf-topology-history";
const TOPOLOGY_HISTORY_STORE_KEY: &str = "history.json";
const TOPOLOGY_HISTORY_CONFIG_MAP_DATA_LIMIT: usize = 900_000;
const TOPOLOGY_HISTORY_PERSISTENCE_INTERVAL: Duration = Duration::from_secs(2);
const TOPOLOGY_HISTORY_MAX_FUTURE_SKEW_MILLIS: u64 = 60_000;
const LOAD_BALANCER_STORE_NAME: &str = "unf-load-balancer-control-plane";
const LOAD_BALANCER_STORE_KEY: &str = "state.json";
const LOAD_BALANCER_STORE_SCHEMA_VERSION: u16 = 1;
const LOAD_BALANCER_STORE_DATA_LIMIT: usize = 900_000;
const LOAD_BALANCER_RECONCILE_INTERVAL: Duration = Duration::from_millis(500);
const PRIMARY_CNI_NODE_LABEL: &str = "network.unf.io/primary-cni";
const PRIMARY_CNI_NODE_LABEL_VALUE: &str = "enabled";

#[derive(Debug, Parser)]
#[command(about = "UNF Kubernetes desired-state controller")]
struct Args {
    #[arg(long, env = "UNF_CONTROLLER_LISTEN", default_value = "0.0.0.0:9962")]
    listen: SocketAddr,
    #[arg(
        long,
        env = "UNF_CONTROLLER_INTERNAL_LISTEN",
        default_value = "0.0.0.0:9964"
    )]
    internal_listen: SocketAddr,
    #[arg(
        long,
        env = "UNF_CONTROLLER_TLS_CERT",
        default_value = "/var/run/secrets/unf-internal-tls/tls.crt"
    )]
    tls_cert: PathBuf,
    #[arg(
        long,
        env = "UNF_CONTROLLER_TLS_KEY",
        default_value = "/var/run/secrets/unf-internal-tls/tls.key"
    )]
    tls_key: PathBuf,
    #[arg(long, env = "UNF_CONTROLLER_TLS_RELOAD_SECONDS", default_value_t = 5)]
    tls_reload_seconds: u64,
    /// Count agents only on Nodes matching this exact label key or key=value pair.
    #[arg(
        long,
        env = "UNF_CONTROLLER_AGENT_NODE_SELECTOR",
        value_parser = validate_agent_node_selector
    )]
    agent_node_selector: Option<String>,
    /// Optional HTTP endpoint that receives validated, schema-versioned flow batches.
    #[arg(long, env = "UNF_CONTROLLER_FLOW_EXPORT_HTTP_URL")]
    flow_export_http_url: Option<String>,
    /// Permit a plaintext HTTP flow-export endpoint (development only).
    #[arg(
        long,
        env = "UNF_CONTROLLER_FLOW_EXPORT_HTTP_ALLOW_PLAINTEXT",
        default_value_t = false
    )]
    flow_export_http_allow_plaintext: bool,
    /// Additional PEM CA bundle used with the platform trust roots.
    #[arg(long, env = "UNF_CONTROLLER_FLOW_EXPORT_HTTP_CA")]
    flow_export_http_ca: Option<PathBuf>,
    /// File containing a bearer token, reread for every delivery attempt.
    #[arg(long, env = "UNF_CONTROLLER_FLOW_EXPORT_HTTP_BEARER_TOKEN_FILE")]
    flow_export_http_bearer_token_file: Option<PathBuf>,
    #[arg(
        long,
        env = "UNF_CONTROLLER_FLOW_EXPORT_HTTP_QUEUE_CAPACITY",
        default_value_t = 256,
        value_parser = parse_flow_export_queue_capacity
    )]
    flow_export_http_queue_capacity: usize,
    #[arg(
        long,
        env = "UNF_CONTROLLER_FLOW_EXPORT_HTTP_MAX_ATTEMPTS",
        default_value_t = 3,
        value_parser = parse_flow_export_max_attempts
    )]
    flow_export_http_max_attempts: u8,
    #[arg(
        long,
        env = "UNF_CONTROLLER_FLOW_EXPORT_HTTP_TIMEOUT_SECONDS",
        default_value_t = 10,
        value_parser = parse_flow_export_timeout_seconds
    )]
    flow_export_http_timeout_seconds: u64,
    /// Stable UID of the explicitly configured `LoadBalancer` address pool.
    #[arg(long, env = "UNF_CONTROLLER_LOAD_BALANCER_POOL_UID")]
    load_balancer_pool_uid: Option<String>,
    #[arg(
        long,
        env = "UNF_CONTROLLER_LOAD_BALANCER_POOL_NAME",
        default_value = "public"
    )]
    load_balancer_pool_name: String,
    #[arg(long, env = "UNF_CONTROLLER_LOAD_BALANCER_IPV4_POOL")]
    load_balancer_ipv4_pool: Option<ServiceIpPrefix>,
    #[arg(long, env = "UNF_CONTROLLER_LOAD_BALANCER_IPV6_POOL")]
    load_balancer_ipv6_pool: Option<ServiceIpPrefix>,
    #[arg(
        long,
        env = "UNF_CONTROLLER_LOAD_BALANCER_PROVIDER_INSTANCE",
        default_value = "unf-system"
    )]
    load_balancer_provider_instance: String,
    /// Run the API server without connecting to Kubernetes (development only).
    #[arg(long)]
    offline: bool,
}

#[derive(Default)]
struct ControllerMetrics {
    reconciles: Counter,
    errors: Counter,
    telemetry_batches: Counter,
    telemetry_observations: Counter,
    agent_status_reports: Counter,
    agent_authentication_failures: Counter,
    tls_reloads: Counter,
    tls_reload_errors: Counter,
    agent_report_persistence_writes: Counter,
    agent_report_persistence_errors: Counter,
    agent_reports_restored: Counter,
    flow_history_persistence_writes: Counter,
    flow_history_persistence_errors: Counter,
    flow_history_entries_restored: Counter,
    topology_history_persistence_writes: Counter,
    topology_history_persistence_errors: Counter,
    topology_history_entries_restored: Counter,
    external_flow_export: ExternalFlowExportMetrics,
}

#[derive(Clone, PartialEq, Eq)]
struct TlsMaterial {
    certificate: Vec<u8>,
    private_key: Vec<u8>,
}

struct ControllerState {
    ready: AtomicBool,
    identity_epoch: u64,
    offline: bool,
    agent_node_selector: Option<String>,
    pods: RwLock<BTreeMap<String, PodRecord>>,
    nodes: RwLock<BTreeMap<String, TopologyNode>>,
    node_port_nodes: RwLock<BTreeMap<String, NodePortNodeRecord>>,
    rejected_node_port_nodes: RwLock<BTreeMap<String, String>>,
    node_port_node_initialization: Mutex<Option<BTreeSet<String>>>,
    node_block_inputs: RwLock<BTreeMap<String, NodeBlockInput>>,
    node_block_initialization: Mutex<Option<BTreeMap<String, NodeBlockInput>>>,
    node_blocks: RwLock<BTreeMap<String, AssignedNodeBlock>>,
    rejected_node_blocks: RwLock<BTreeMap<String, String>>,
    host_network_gateways: RwLock<BTreeMap<String, HostNetworkGateways>>,
    services: RwLock<BTreeMap<String, ServiceRecord>>,
    endpoint_slices: RwLock<BTreeMap<String, EndpointSliceRecord>>,
    rejected_service_sources: RwLock<BTreeMap<String, String>>,
    rejected_endpoint_slice_sources: RwLock<BTreeMap<String, String>>,
    compiled_service_snapshot: RwLock<Option<ServiceSnapshot>>,
    compiled_load_balancer_reachability: RwLock<Option<ReachabilitySnapshot>>,
    load_balancer_runtime: Mutex<Option<LoadBalancerRuntime>>,
    load_balancer_store: Option<Api<ConfigMap>>,
    service_compilation_error: RwLock<Option<String>>,
    namespaces: RwLock<BTreeMap<String, BTreeMap<String, String>>>,
    security_policies: RwLock<BTreeMap<String, SecurityPolicy>>,
    compiled_security_policies: RwLock<BTreeMap<String, PolicyIr>>,
    network_policies: RwLock<BTreeMap<String, NetworkPolicy>>,
    compiled_network_policies: RwLock<BTreeMap<String, Vec<PolicyIr>>>,
    rejected_network_policies: RwLock<BTreeMap<String, String>>,
    policy_state_guard: RwLock<()>,
    dataplane_policy_cache: Mutex<Option<DataplanePolicyState>>,
    identities: Mutex<IdentityRegistry>,
    flow_history: Mutex<FlowHistoryStore>,
    flow_history_dirty: AtomicBool,
    flow_history_store: Option<Api<ConfigMap>>,
    flow_history_checkpointed_flows: AtomicU64,
    flow_history_checkpoint_omitted_flows: AtomicU64,
    flow_history_checkpoint_omitted_observations: AtomicU64,
    external_flow_export: RwLock<Option<ExternalFlowExporter>>,
    topology_history: Mutex<TopologyHistoryStore>,
    topology_history_dirty: AtomicBool,
    topology_history_store: Option<Api<ConfigMap>>,
    topology_history_checkpointed_snapshots: AtomicU64,
    topology_history_checkpoint_omitted_snapshots: AtomicU64,
    topology_initializations: AtomicU64,
    agent_reports: RwLock<BTreeMap<String, StoredAgentReport>>,
    agent_reports_dirty: AtomicBool,
    agent_report_store: Option<Api<ConfigMap>>,
    agent_authentication_cache: Mutex<BTreeMap<String, CachedAgentAuthentication>>,
    token_review_client: Option<Client>,
    revisions: Mutex<RevisionSet>,
    registry: Mutex<Registry>,
    metrics: ControllerMetrics,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HostNetworkGateways {
    ipv4: BTreeSet<std::net::Ipv4Addr>,
    ipv6: BTreeSet<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeBlockInput {
    node_uid: String,
    provider: Result<NodeBlockProvider, String>,
    transport: Result<NodeTransport, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignedNodeBlock {
    node_uid: String,
    provider: NodeBlockProvider,
    revision: Revision,
    transport: Result<NodeTransport, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NodeTransport {
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodePortNodeRecord {
    node_uid: String,
    revision: Revision,
    addresses: Vec<ServiceNodeAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct StoredAgentReport {
    report: AgentStateReport,
    last_received_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct DurableAgentReportStore {
    schema_version: u16,
    reports: BTreeMap<String, StoredAgentReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedAgent {
    node_name: String,
    pod_name: String,
    pod_uid: String,
}

#[derive(Debug, Clone)]
struct CachedAgentAuthentication {
    agent: AuthenticatedAgent,
    validated_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PodRecord {
    namespace: String,
    name: String,
    uid: String,
    node_name: Option<String>,
    host_network: bool,
    endpoint: Endpoint,
    ipv4_addresses: BTreeSet<std::net::Ipv4Addr>,
    ipv6_addresses: BTreeSet<Ipv6Addr>,
}

type DataplanePolicyState = (
    Revision,
    Vec<unf_state::PolicyMapEntry>,
    Vec<unf_state::Ipv4PolicyMapEntry>,
    Vec<unf_state::Ipv6PolicyMapEntry>,
    Vec<unf_state::EgressIpv4PolicyMapEntry>,
    Vec<unf_state::EgressIpv6PolicyMapEntry>,
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceRecord {
    namespace: String,
    name: String,
    uid: String,
    resource_version: String,
    finalizers: Vec<String>,
    deleting: bool,
    service_type: String,
    cluster_ips: BTreeSet<IpAddr>,
    selector: BTreeMap<String, String>,
    ports: Vec<TopologyServicePort>,
    compiler_source: ServiceSource,
}

#[derive(Debug, Clone)]
struct LoadBalancerRuntime {
    pool_name: String,
    provider: ReachabilityProviderRef,
    allocator: LoadBalancerAllocator,
    reachability_revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DurableLoadBalancerState {
    schema_version: u16,
    reachability_revision: Revision,
    allocation: AllocationCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointSliceRecord {
    service_reference: String,
    backends: Vec<TopologyServiceBackend>,
    compiler_source: EndpointSliceSource,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    component: &'static str,
    healthy: bool,
    ready: bool,
    mode: &'static str,
    pods: usize,
    nodes: usize,
    assigned_node_blocks: usize,
    rejected_node_blocks: usize,
    unroutable_node_transports: usize,
    services: usize,
    endpoint_slices: usize,
    rejected_service_sources: usize,
    rejected_endpoint_slice_sources: usize,
    compiled_services: usize,
    compiled_service_frontends: usize,
    compiled_service_backends: usize,
    compiled_service_revision: u64,
    service_compilation_error: Option<String>,
    namespaces: usize,
    security_policies: usize,
    network_policies: usize,
    rejected_network_policies: usize,
    compiled_policies: usize,
    resolved_policy_entries: usize,
    resolved_ingress_policy_entries: usize,
    resolved_egress_policy_entries: usize,
    identities: usize,
    indexed_pod_ips: usize,
    retained_flows: usize,
    retained_flow_observations: u64,
    telemetry_dropped_events: u64,
    identity_epoch: u64,
    revisions: RevisionSet,
    agents: AgentConvergenceSnapshot,
    limitations: [&'static str; 3],
}

#[derive(Debug, Deserialize)]
struct ExplainRequest {
    from: String,
    to: String,
    #[serde(default)]
    direction: RequestPolicyDirection,
    #[serde(default)]
    ip_family: Option<RequestIpFamily>,
    protocol: RequestProtocol,
    port: u16,
}

#[derive(Debug, Clone, Copy, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum RequestProtocol {
    Tcp,
    Udp,
    Sctp,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RequestPolicyDirection {
    #[default]
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum RequestIpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Serialize)]
struct ExplainResponse {
    source: ResolvedEndpoint,
    destination: ResolvedEndpoint,
    direction: PolicyDirection,
    ip_family: RequestIpFamily,
    source_address: IpAddr,
    destination_address: IpAddr,
    decision: unf_policy::PolicyDecision,
    policy_revision: Revision,
    dataplane_enforcement: bool,
    note: &'static str,
}

const POLICY_SIMULATION_SCHEMA_VERSION: u16 = 4;
const POLICY_SIMULATION_FLOW_LIMIT: usize = 10_000;

#[derive(Debug, Deserialize)]
struct PolicySimulationRequest {
    policy: serde_json::Value,
    #[serde(default)]
    flow_history: Option<FlowHistoryQuery>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum PolicySimulationOperation {
    Add,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum PolicySimulationResourceKind {
    SecurityPolicy,
    NetworkPolicy,
}

#[derive(Debug, Serialize)]
struct PolicySimulationSnapshot {
    identity_epoch: u64,
    identity_revision: Revision,
    policy_revision: Revision,
    topology_revision: Revision,
    flow_history_revision: Revision,
    pods: usize,
    flow_source: &'static str,
}

#[derive(Debug, Default, Serialize)]
struct PolicySimulationSummary {
    evaluated_flows: usize,
    remain_allowed: usize,
    remain_denied: usize,
    would_be_allowed: usize,
    would_be_denied: usize,
    verdict_changes: usize,
    decision_changes: usize,
    affected_workloads: usize,
}

#[derive(Debug, Serialize)]
struct PolicySimulationChange {
    source: ResolvedEndpoint,
    destination: ResolvedEndpoint,
    direction: PolicyDirection,
    ip_family: Option<RequestIpFamily>,
    source_address: Option<IpAddr>,
    destination_address: Option<IpAddr>,
    protocol: &'static str,
    destination_port: u16,
    current: unf_policy::PolicyDecision,
    proposed: unf_policy::PolicyDecision,
}

#[derive(Debug, Default, Serialize)]
struct PolicySimulationHistoricalSummary {
    retained_flows: usize,
    retained_observations: u64,
    evaluated_flows: usize,
    evaluated_observations: u64,
    skipped_unresolved_flows: usize,
    remain_allowed_observations: u64,
    remain_denied_observations: u64,
    would_be_allowed_observations: u64,
    would_be_denied_observations: u64,
    verdict_change_flows: usize,
    decision_change_flows: usize,
    affected_observations: u64,
    affected_workloads: usize,
}

#[derive(Debug, Serialize)]
struct PolicySimulationHistoricalChange {
    source: ResolvedEndpoint,
    destination: ResolvedEndpoint,
    direction: PolicyDirection,
    protocol: &'static str,
    destination_port: u16,
    observed_events: u64,
    first_received_unix_ms: u64,
    last_received_unix_ms: u64,
    reporting_nodes: Vec<String>,
    current: unf_policy::PolicyDecision,
    proposed: unf_policy::PolicyDecision,
}

#[derive(Debug, Serialize)]
struct PolicySimulationResponse {
    schema_version: u16,
    resource_kind: PolicySimulationResourceKind,
    policy: String,
    policy_id: PolicyId,
    operation: PolicySimulationOperation,
    snapshot: PolicySimulationSnapshot,
    affected_sources: usize,
    affected_destinations: usize,
    affected_services: Vec<String>,
    summary: PolicySimulationSummary,
    changes: Vec<PolicySimulationChange>,
    historical_query: FlowHistoryQuerySummary,
    historical_summary: PolicySimulationHistoricalSummary,
    historical_changes: Vec<PolicySimulationHistoricalChange>,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct ResolvedEndpoint {
    reference: String,
    identity: u32,
    namespace: String,
    service_account: String,
    application: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FlowHistoryQuery {
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
struct ServiceExplainQuery {
    service_id: u32,
    backend_id: Option<u32>,
    frontend_kind: Option<ServiceFrontendKind>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ServiceExplanation {
    schema_version: u16,
    service_id: ServiceId,
    backend_id: Option<BackendId>,
    frontend_kind: Option<ServiceFrontendKind>,
    current_service_revision: Option<Revision>,
    current_service: Option<ServiceIr>,
    current_backend: Option<ServiceBackend>,
    load_balancer: Option<LoadBalancerExplanation>,
    matched_outcomes: usize,
    matched_observations: u64,
    outcomes: Vec<FlowHistoryEntry>,
    note: &'static str,
}

#[derive(Debug, Serialize)]
struct LoadBalancerExplanation {
    allocation: Option<LoadBalancerLease>,
    provider: Option<ReachabilityProviderRef>,
    reachability_revision: Option<Revision>,
    allocation_revision: Option<Revision>,
    reachable_nodes: Vec<String>,
    converged_nodes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NodePortSimulationQuery {
    node_name: String,
    address: IpAddr,
    port: u16,
    protocol: String,
}

#[derive(Debug, Serialize)]
struct NodePortSimulation {
    schema_version: u16,
    node_name: String,
    address: IpAddr,
    port: u16,
    protocol: Protocol,
    service_revision: Revision,
    service_id: ServiceId,
    namespace: String,
    name: String,
    frontend_kind: ServiceFrontendKind,
    traffic_policy: ServiceTrafficPolicy,
    source_preserved: bool,
    eligible_backend_ids: Vec<BackendId>,
    eligible_backends: Vec<ServiceBackend>,
    decision: &'static str,
    note: &'static str,
}

#[derive(Debug, Deserialize)]
struct LoadBalancerSimulationQuery {
    node_name: String,
    address: IpAddr,
    source_address: IpAddr,
    port: u16,
    protocol: String,
}

#[derive(Debug, Serialize)]
struct LoadBalancerSimulation {
    schema_version: u16,
    node_name: String,
    address: IpAddr,
    source_address: IpAddr,
    port: u16,
    protocol: Protocol,
    service_revision: Revision,
    reachability_revision: Revision,
    allocation_revision: Revision,
    provider: ReachabilityProviderRef,
    allocation: Option<LoadBalancerLease>,
    service_id: ServiceId,
    namespace: String,
    name: String,
    frontend_kind: ServiceFrontendKind,
    traffic_policy: ServiceTrafficPolicy,
    source_preserved: bool,
    source_allowed: bool,
    eligible_backend_ids: Vec<BackendId>,
    eligible_backends: Vec<ServiceBackend>,
    decision: &'static str,
    note: &'static str,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ServiceSchemaQuery {
    service_snapshot_schema_version: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
struct TopologyHistoryQuery {
    since_revision: Option<u64>,
    until_revision: Option<u64>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug)]
struct CompiledSimulationCandidate {
    resource_kind: PolicySimulationResourceKind,
    key: String,
    policy_id: PolicyId,
    policies: Vec<PolicyIr>,
}

#[derive(Debug, Clone, Copy)]
struct SimulationAddresses {
    ip_family: Option<RequestIpFamily>,
    source_ipv4: Option<std::net::Ipv4Addr>,
    source_ipv6: Option<Ipv6Addr>,
    destination: DestinationAddresses,
}

#[derive(Debug)]
struct SimulationMatrixFlow {
    direction: PolicyDirection,
    source_index: usize,
    destination_index: usize,
    protocol: Protocol,
    destination_port: u16,
    addresses: SimulationAddresses,
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    install_crypto_provider()?;
    init_tracing();
    let args = Args::parse();
    let client = if args.offline {
        None
    } else {
        Some(
            Client::try_default()
                .await
                .context("create Kubernetes client from in-cluster or kubeconfig settings")?,
        )
    };
    let state = Arc::new(new_state_with_client_and_selector(
        args.offline,
        client.clone(),
        args.agent_node_selector.clone(),
    ));
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();

    if let Some(endpoint) = args.flow_export_http_url.as_deref() {
        let config = ExternalFlowExportConfig::new(
            endpoint,
            args.flow_export_http_allow_plaintext,
            args.flow_export_http_ca.clone(),
            args.flow_export_http_bearer_token_file.clone(),
            args.flow_export_http_queue_capacity,
            args.flow_export_http_max_attempts,
            Duration::from_secs(args.flow_export_http_timeout_seconds),
        )?;
        let (exporter, worker) =
            build_external_flow_export(config, state.metrics.external_flow_export.clone())?;
        *write_lock(&state.external_flow_export) = Some(exporter);
        let worker_cancellation = cancellation.clone();
        tasks.spawn(worker.run(worker_cancellation));
    }

    if args.offline {
        configure_load_balancer_runtime(&state, &args)
            .await
            .context("configure offline LoadBalancer control plane")?;
        warn!("running without Kubernetes watchers");
    } else {
        configure_load_balancer_runtime(&state, &args)
            .await
            .context("configure durable LoadBalancer control plane")?;
        restore_agent_reports(&state)
            .await
            .context("restore durable agent acknowledgements")?;
        restore_flow_history(&state)
            .await
            .context("restore durable flow history")?;
        restore_topology_history(&state)
            .await
            .context("restore durable topology history")?;
        spawn_agent_report_persistence(Arc::clone(&state), cancellation.clone(), &mut tasks);
        spawn_flow_history_persistence(Arc::clone(&state), cancellation.clone(), &mut tasks);
        spawn_topology_history_persistence(Arc::clone(&state), cancellation.clone(), &mut tasks);
        let client = client.context("Kubernetes client is required in connected mode")?;
        spawn_load_balancer_reconciler(
            &mut tasks,
            client.clone(),
            Arc::clone(&state),
            cancellation.clone(),
        );
        spawn_watchers(&mut tasks, client, Arc::clone(&state), cancellation.clone());
        state.ready.store(true, Ordering::Release);
    }

    let public_app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/version", get(version))
        .route("/v1/status", get(status))
        .route("/v1/state/agents", get(agent_state))
        .route("/v1/topology", get(topology))
        .route("/v1/topology/history", get(topology_history))
        .route("/v1/flows", get(flow_history))
        .route("/v1/services/explain", get(explain_service))
        .route("/v1/services/nodeport/simulate", get(simulate_node_port))
        .route(
            "/v1/services/loadbalancer/simulate",
            get(simulate_load_balancer),
        )
        .route("/v1/explain", post(explain))
        .route("/v1/policy/simulate", post(simulate_policy))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind controller API to {}", args.listen))?;
    info!(address = %args.listen, "controller public API listening");

    let shutdown = cancellation.clone();
    tasks.spawn(async move {
        if let Err(error) = axum::serve(listener, public_app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
        {
            error!(%error, "controller public API server failed");
        }
    });

    if !args.offline {
        spawn_internal_api(&args, Arc::clone(&state), cancellation.clone(), &mut tasks).await?;
    }

    tokio::signal::ctrl_c()
        .await
        .context("listen for shutdown signal")?;
    cancellation.cancel();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            error!(%error, "controller task failed");
        }
    }
    Ok(())
}

async fn spawn_internal_api(
    args: &Args,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
    tasks: &mut JoinSet<()>,
) -> Result<()> {
    let tls_material = read_tls_material(&args.tls_cert, &args.tls_key)?;
    let tls_config = RustlsConfig::from_pem(
        tls_material.certificate.clone(),
        tls_material.private_key.clone(),
    )
    .await
    .with_context(|| {
        format!(
            "load controller internal TLS certificate {} and key {}",
            args.tls_cert.display(),
            args.tls_key.display()
        )
    })?;
    spawn_tls_reloader(
        tls_config.clone(),
        args.tls_cert.clone(),
        args.tls_key.clone(),
        Duration::from_secs(args.tls_reload_seconds.max(1)),
        tls_material,
        Arc::clone(&state),
        cancellation.clone(),
        tasks,
    );
    let internal_app = Router::new()
        .route("/v1/version", get(version))
        .route("/v1/state/identities", get(identity_snapshot))
        .route("/v1/state/policies", get(policy_snapshot))
        .route("/v1/state/services", get(service_snapshot))
        .route(
            "/v1/state/load-balancer-reachability",
            get(load_balancer_reachability_snapshot),
        )
        .route("/v1/state/node-port-node", get(node_port_node_snapshot))
        .route("/v1/state/node-block", get(node_block_snapshot))
        .route("/v1/state/remote-routes", get(remote_route_snapshot))
        .route("/v1/state/agents", post(ingest_agent_status))
        .route("/v1/telemetry/flows", post(ingest_flows))
        .with_state(state);
    let internal_listener =
        std::net::TcpListener::bind(args.internal_listen).with_context(|| {
            format!(
                "bind controller internal TLS API to {}",
                args.internal_listen
            )
        })?;
    internal_listener
        .set_nonblocking(true)
        .context("configure controller internal TLS listener as nonblocking")?;
    let internal_server = axum_server::from_tcp_rustls(internal_listener, tls_config)
        .context("create controller internal TLS server")?;
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tasks.spawn(async move {
        cancellation.cancelled().await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    info!(address = %args.internal_listen, "controller authenticated internal TLS API listening");
    tasks.spawn(async move {
        if let Err(error) = internal_server
            .handle(handle)
            .serve(internal_app.into_make_service())
            .await
        {
            error!(%error, "controller internal TLS API server failed");
        }
    });
    Ok(())
}

fn read_tls_material(
    certificate_path: &PathBuf,
    private_key_path: &PathBuf,
) -> Result<TlsMaterial> {
    Ok(TlsMaterial {
        certificate: std::fs::read(certificate_path).with_context(|| {
            format!(
                "read controller internal TLS certificate {}",
                certificate_path.display()
            )
        })?,
        private_key: std::fs::read(private_key_path).with_context(|| {
            format!(
                "read controller internal TLS private key {}",
                private_key_path.display()
            )
        })?,
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_tls_reloader(
    tls_config: RustlsConfig,
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    reload_interval: Duration,
    mut observed_material: TlsMaterial,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
    tasks: &mut JoinSet<()>,
) {
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(reload_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => break,
                _ = interval.tick() => {
                    let candidate = match read_tls_material(&certificate_path, &private_key_path) {
                        Ok(candidate) => candidate,
                        Err(error) => {
                            state.metrics.tls_reload_errors.inc();
                            warn!(%error, "could not read updated internal TLS material; retaining last-known-good certificate");
                            continue;
                        }
                    };
                    if candidate == observed_material {
                        continue;
                    }
                    observed_material = candidate.clone();
                    match tls_config
                        .reload_from_pem(candidate.certificate, candidate.private_key)
                        .await
                    {
                        Ok(()) => {
                            state.metrics.tls_reloads.inc();
                            info!("reloaded controller internal TLS certificate");
                        }
                        Err(error) => {
                            state.metrics.tls_reload_errors.inc();
                            warn!(%error, "rejected updated internal TLS material; retaining last-known-good certificate");
                        }
                    }
                }
            }
        }
    });
}

fn install_crypto_provider() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("install process-wide Rustls crypto provider"))
}

#[cfg(test)]
fn new_state(offline: bool) -> ControllerState {
    new_state_with_client_and_selector(offline, None, None)
}

fn register_flow_history_metrics(registry: &mut Registry, metrics: &ControllerMetrics) {
    registry.register(
        "unf_flow_history_persistence_writes",
        "Durable flow-history checkpoints written by the controller",
        metrics.flow_history_persistence_writes.clone(),
    );
    registry.register(
        "unf_flow_history_persistence_errors",
        "Durable flow-history checkpoint reads or writes that failed",
        metrics.flow_history_persistence_errors.clone(),
    );
    registry.register(
        "unf_flow_history_entries_restored",
        "Flow-history entries restored from the durable checkpoint at controller startup",
        metrics.flow_history_entries_restored.clone(),
    );
}

fn register_external_flow_export_metrics(registry: &mut Registry, metrics: &ControllerMetrics) {
    let external = &metrics.external_flow_export;
    registry.register(
        "unf_external_flow_export_queue_capacity",
        "Configured capacity of the bounded external flow-export queue",
        external.queue_capacity.clone(),
    );
    registry.register(
        "unf_external_flow_export_queue_depth",
        "Current number of batches reserved in the external flow-export queue",
        external.queue_depth.clone(),
    );
    registry.register(
        "unf_external_flow_export_queue_high_watermark",
        "Highest external flow-export queue depth observed in this controller process",
        external.queue_high_watermark.clone(),
    );
    registry.register(
        "unf_external_flow_export_enqueued_batches",
        "Validated flow batches accepted by the bounded external-export queue",
        external.enqueued_batches.clone(),
    );
    registry.register(
        "unf_external_flow_export_delivery_attempts",
        "HTTP delivery attempts made by the external flow-export worker",
        external.delivery_attempts.clone(),
    );
    registry.register(
        "unf_external_flow_export_delivered_batches",
        "Flow batches successfully delivered to the external HTTP receiver",
        external.delivered_batches.clone(),
    );
    registry.register(
        "unf_external_flow_export_delivered_observations",
        "Flow observations successfully delivered to the external HTTP receiver",
        external.delivered_observations.clone(),
    );
    registry.register(
        "unf_external_flow_export_delivery_errors",
        "Failed external HTTP flow-export attempts, including receiver rejections",
        external.delivery_errors.clone(),
    );
    registry.register(
        "unf_external_flow_export_dropped_batches",
        "External flow-export batches dropped after queue pressure or delivery exhaustion",
        external.dropped_batches.clone(),
    );
    registry.register(
        "unf_external_flow_export_dropped_observations",
        "External flow observations dropped after queue pressure or delivery exhaustion",
        external.dropped_observations.clone(),
    );
}

fn register_topology_history_metrics(registry: &mut Registry, metrics: &ControllerMetrics) {
    registry.register(
        "unf_topology_history_persistence_writes",
        "Durable topology-history checkpoints written by the controller",
        metrics.topology_history_persistence_writes.clone(),
    );
    registry.register(
        "unf_topology_history_persistence_errors",
        "Durable topology-history checkpoint reads or writes that failed",
        metrics.topology_history_persistence_errors.clone(),
    );
    registry.register(
        "unf_topology_history_entries_restored",
        "Topology-history snapshots restored at controller startup",
        metrics.topology_history_entries_restored.clone(),
    );
}

#[allow(clippy::too_many_lines)]
fn new_state_with_client_and_selector(
    offline: bool,
    token_review_client: Option<Client>,
    agent_node_selector: Option<String>,
) -> ControllerState {
    let metrics = ControllerMetrics::default();
    let mut registry = Registry::default();
    registry.register(
        "unf_controller_reconcile",
        "Kubernetes objects processed by controller watchers",
        metrics.reconciles.clone(),
    );
    registry.register(
        "unf_controller_reconcile_errors",
        "Kubernetes object reconciliation errors",
        metrics.errors.clone(),
    );
    registry.register(
        "unf_telemetry_batches",
        "Flow telemetry batches accepted from node agents",
        metrics.telemetry_batches.clone(),
    );
    registry.register(
        "unf_telemetry_observations",
        "Aggregated flow-event observations accepted from node agents",
        metrics.telemetry_observations.clone(),
    );
    registry.register(
        "unf_agent_status_reports",
        "Authenticated node-agent status acknowledgements accepted by the controller",
        metrics.agent_status_reports.clone(),
    );
    registry.register(
        "unf_agent_authentication_failures",
        "Node-agent internal API requests rejected by authentication or identity binding",
        metrics.agent_authentication_failures.clone(),
    );
    registry.register(
        "unf_controller_tls_reloads",
        "Internal TLS certificate reloads accepted without a process restart",
        metrics.tls_reloads.clone(),
    );
    registry.register(
        "unf_controller_tls_reload_errors",
        "Internal TLS certificate updates rejected while retaining last-known-good material",
        metrics.tls_reload_errors.clone(),
    );
    registry.register(
        "unf_agent_report_persistence_writes",
        "Durable agent-report checkpoints written by the controller",
        metrics.agent_report_persistence_writes.clone(),
    );
    registry.register(
        "unf_agent_report_persistence_errors",
        "Durable agent-report checkpoint reads or writes that failed",
        metrics.agent_report_persistence_errors.clone(),
    );
    registry.register(
        "unf_agent_reports_restored",
        "Agent reports restored from the durable checkpoint at controller startup",
        metrics.agent_reports_restored.clone(),
    );
    register_flow_history_metrics(&mut registry, &metrics);
    register_external_flow_export_metrics(&mut registry, &metrics);
    register_topology_history_metrics(&mut registry, &metrics);
    let config_map_store = token_review_client
        .clone()
        .map(|client| Api::<ConfigMap>::namespaced(client, "unf-system"));
    ControllerState {
        ready: AtomicBool::new(offline),
        identity_epoch: controller_epoch(),
        offline,
        agent_node_selector,
        pods: RwLock::new(BTreeMap::new()),
        nodes: RwLock::new(BTreeMap::new()),
        node_port_nodes: RwLock::new(BTreeMap::new()),
        rejected_node_port_nodes: RwLock::new(BTreeMap::new()),
        node_port_node_initialization: Mutex::new(None),
        node_block_inputs: RwLock::new(BTreeMap::new()),
        node_block_initialization: Mutex::new(None),
        node_blocks: RwLock::new(BTreeMap::new()),
        rejected_node_blocks: RwLock::new(BTreeMap::new()),
        host_network_gateways: RwLock::new(BTreeMap::new()),
        services: RwLock::new(BTreeMap::new()),
        endpoint_slices: RwLock::new(BTreeMap::new()),
        rejected_service_sources: RwLock::new(BTreeMap::new()),
        rejected_endpoint_slice_sources: RwLock::new(BTreeMap::new()),
        compiled_service_snapshot: RwLock::new(None),
        compiled_load_balancer_reachability: RwLock::new(None),
        load_balancer_runtime: Mutex::new(None),
        load_balancer_store: config_map_store.clone(),
        service_compilation_error: RwLock::new(None),
        namespaces: RwLock::new(BTreeMap::new()),
        security_policies: RwLock::new(BTreeMap::new()),
        compiled_security_policies: RwLock::new(BTreeMap::new()),
        network_policies: RwLock::new(BTreeMap::new()),
        compiled_network_policies: RwLock::new(BTreeMap::new()),
        rejected_network_policies: RwLock::new(BTreeMap::new()),
        policy_state_guard: RwLock::new(()),
        dataplane_policy_cache: Mutex::new(None),
        identities: Mutex::new(IdentityRegistry::default()),
        flow_history: Mutex::new(FlowHistoryStore::default()),
        flow_history_dirty: AtomicBool::new(false),
        flow_history_store: config_map_store.clone(),
        flow_history_checkpointed_flows: AtomicU64::new(0),
        flow_history_checkpoint_omitted_flows: AtomicU64::new(0),
        flow_history_checkpoint_omitted_observations: AtomicU64::new(0),
        external_flow_export: RwLock::new(None),
        topology_history: Mutex::new(TopologyHistoryStore::default()),
        topology_history_dirty: AtomicBool::new(false),
        topology_history_store: config_map_store.clone(),
        topology_history_checkpointed_snapshots: AtomicU64::new(0),
        topology_history_checkpoint_omitted_snapshots: AtomicU64::new(0),
        topology_initializations: AtomicU64::new(0),
        agent_reports: RwLock::new(BTreeMap::new()),
        agent_reports_dirty: AtomicBool::new(false),
        agent_report_store: config_map_store,
        agent_authentication_cache: Mutex::new(BTreeMap::new()),
        token_review_client,
        revisions: Mutex::new(RevisionSet::default()),
        registry: Mutex::new(registry),
        metrics,
    }
}

async fn configure_load_balancer_runtime(state: &ControllerState, args: &Args) -> Result<()> {
    let configured = args.load_balancer_ipv4_pool.is_some()
        || args.load_balancer_ipv6_pool.is_some()
        || args.load_balancer_pool_uid.is_some();
    if !configured {
        info!("LoadBalancer control plane is disabled because no address pool is configured");
        return Ok(());
    }
    if args.load_balancer_ipv4_pool.is_none() && args.load_balancer_ipv6_pool.is_none() {
        return Err(anyhow!(
            "a LoadBalancer pool UID requires at least one IPv4 or IPv6 pool"
        ));
    }
    let pool_uid = args
        .load_balancer_pool_uid
        .clone()
        .context("configured LoadBalancer address pools require --load-balancer-pool-uid")?;
    let provider = ReachabilityProviderRef {
        name: "direct-node".to_owned(),
        instance: args.load_balancer_provider_instance.clone(),
        mode: ReachabilityMode::DirectNode,
    };
    let pool = LoadBalancerPool {
        name: args.load_balancer_pool_name.clone(),
        uid: pool_uid,
        provider: provider.clone(),
        ipv4: args.load_balancer_ipv4_pool,
        ipv6: args.load_balancer_ipv6_pool,
    };
    let (allocator, reachability_revision) = if state.offline {
        (
            LoadBalancerAllocator::new(vec![pool.clone()])?,
            Revision::INITIAL,
        )
    } else {
        restore_load_balancer_runtime(state, &pool).await?
    };
    *mutex_lock(&state.load_balancer_runtime) = Some(LoadBalancerRuntime {
        pool_name: pool.name,
        provider,
        allocator,
        reachability_revision,
    });
    info!("configured durable direct-Node LoadBalancer control plane");
    Ok(())
}

async fn restore_load_balancer_runtime(
    state: &ControllerState,
    configured_pool: &LoadBalancerPool,
) -> Result<(LoadBalancerAllocator, Revision)> {
    let api = state
        .load_balancer_store
        .as_ref()
        .context("durable LoadBalancer API is unavailable")?;
    let config_map = api
        .get(LOAD_BALANCER_STORE_NAME)
        .await
        .with_context(|| format!("read ConfigMap unf-system/{LOAD_BALANCER_STORE_NAME}"))?;
    let Some(encoded) = config_map
        .data
        .as_ref()
        .and_then(|data| data.get(LOAD_BALANCER_STORE_KEY))
    else {
        info!("durable LoadBalancer control-plane store is empty");
        return Ok((
            LoadBalancerAllocator::new(vec![configured_pool.clone()])?,
            Revision::INITIAL,
        ));
    };
    let durable: DurableLoadBalancerState =
        serde_json::from_str(encoded).context("decode durable LoadBalancer control-plane state")?;
    if durable.schema_version != LOAD_BALANCER_STORE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported durable LoadBalancer schema {}; expected {}",
            durable.schema_version,
            LOAD_BALANCER_STORE_SCHEMA_VERSION
        ));
    }
    let allocator = LoadBalancerAllocator::restore(durable.allocation)?;
    if allocator.checkpoint().pools != [configured_pool.clone()] {
        return Err(anyhow!(
            "configured LoadBalancer pool does not exactly match durable ownership"
        ));
    }
    info!(
        leases = allocator.checkpoint().leases.len(),
        allocation_revision = allocator.checkpoint().revision.get(),
        reachability_revision = durable.reachability_revision.get(),
        "restored durable LoadBalancer control-plane state"
    );
    Ok((allocator, durable.reachability_revision))
}

fn spawn_load_balancer_reconciler(
    tasks: &mut JoinSet<()>,
    client: Client,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
) {
    if mutex_lock(&state.load_balancer_runtime).is_none() {
        return;
    }
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(LOAD_BALANCER_RECONCILE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(error) = reconcile_load_balancer_control_plane(&state, &client).await {
                        state.metrics.errors.inc();
                        warn!(%error, "LoadBalancer control-plane reconcile failed; retaining last-valid state");
                    }
                }
            }
        }
    });
}

#[allow(clippy::too_many_lines)]
async fn reconcile_load_balancer_control_plane(
    state: &ControllerState,
    client: &Client,
) -> Result<()> {
    let Some(mut runtime) = mutex_lock(&state.load_balancer_runtime).clone() else {
        return Ok(());
    };
    let Some(service_snapshot) = read_lock(&state.compiled_service_snapshot).clone() else {
        return Ok(());
    };
    let records = read_lock(&state.services).clone();
    let current_reachability = read_lock(&state.compiled_load_balancer_reachability).clone();
    let current_converged = current_reachability
        .as_ref()
        .is_some_and(|desired| load_balancer_agents_converged(state, desired));
    let original_checkpoint = runtime.allocator.checkpoint();
    let original_reachability_revision = runtime.reachability_revision;

    let active_services = service_snapshot
        .services
        .iter()
        .filter(|service| {
            service
                .load_balancer
                .as_ref()
                .is_some_and(|intent| intent.class == UNF_LOAD_BALANCER_CLASS)
        })
        .map(|service| {
            (
                format!("{}/{}", service.namespace, service.name),
                service.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut finalizer_updates = Vec::new();
    for (key, record) in &records {
        let admitted = active_services.contains_key(key);
        let has_finalizer = record
            .finalizers
            .iter()
            .any(|entry| entry == unf_loadbalancer::UNF_LOAD_BALANCER_FINALIZER);
        if admitted && !record.deleting && !has_finalizer {
            finalizer_updates.push((record.clone(), true));
        }
    }

    let retained_owners = active_services
        .iter()
        .filter_map(|(key, service)| {
            let record = records.get(key)?;
            let has_finalizer = record
                .finalizers
                .iter()
                .any(|entry| entry == unf_loadbalancer::UNF_LOAD_BALANCER_FINALIZER);
            (!record.deleting && has_finalizer).then(|| LoadBalancerOwner {
                service_id: service.id,
                namespace: service.namespace.clone(),
                name: service.name.clone(),
                uid: record.uid.clone(),
            })
        })
        .collect::<BTreeSet<_>>();

    let withdrawable = runtime
        .allocator
        .checkpoint()
        .leases
        .into_iter()
        .filter(|lease| !retained_owners.contains(&lease.owner))
        .filter(|lease| {
            current_reachability.as_ref().is_some_and(|desired| {
                current_converged
                    && desired
                        .targets
                        .iter()
                        .all(|target| target.owner != lease.owner)
            })
        })
        .map(|lease| lease.owner)
        .collect::<Vec<_>>();
    for owner in withdrawable {
        runtime.allocator.release(&owner)?;
    }

    for (key, service) in &active_services {
        let Some(record) = records.get(key) else {
            continue;
        };
        let has_finalizer = record
            .finalizers
            .iter()
            .any(|entry| entry == unf_loadbalancer::UNF_LOAD_BALANCER_FINALIZER);
        if record.deleting || !has_finalizer {
            continue;
        }
        let request = allocation_request_for_service(
            service,
            &record.uid,
            &runtime.pool_name,
            state.identity_epoch,
            service_snapshot.revision,
        )?
        .context("admitted LoadBalancer Service produced no allocation request")?;
        runtime.allocator.allocate(request)?;
    }

    let nodes = read_lock(&state.node_port_nodes)
        .iter()
        .map(|(name, node)| ReachabilityNode {
            name: name.clone(),
            uid: node.node_uid.clone(),
        })
        .collect::<Vec<_>>();
    let leases = runtime
        .allocator
        .checkpoint()
        .leases
        .into_iter()
        .filter(|lease| retained_owners.contains(&lease.owner))
        .collect::<Vec<_>>();
    let allocation_revision = runtime.allocator.checkpoint().revision;
    let candidate_revision = if runtime.reachability_revision == Revision::INITIAL {
        Revision::new(1)
    } else {
        runtime.reachability_revision
    };
    let mut desired = compile_direct_node_reachability(
        state.identity_epoch,
        candidate_revision,
        allocation_revision,
        runtime.provider.clone(),
        &leases,
        nodes,
    )?;
    let content_changed = current_reachability.as_ref().is_some_and(|current| {
        current.provider != desired.provider
            || current.allocation_revision != desired.allocation_revision
            || current.targets != desired.targets
    });
    if content_changed {
        runtime.reachability_revision = candidate_revision.next();
        desired.revision = runtime.reachability_revision;
    } else {
        runtime.reachability_revision = candidate_revision;
    }

    let durable_changed = runtime.allocator.checkpoint() != original_checkpoint
        || runtime.reachability_revision != original_reachability_revision;
    if durable_changed {
        persist_load_balancer_runtime(state, &runtime).await?;
    }
    *mutex_lock(&state.load_balancer_runtime) = Some(runtime.clone());
    *write_lock(&state.compiled_load_balancer_reachability) = Some(desired.clone());

    for record in records.values() {
        let owner_is_retained = retained_owners.iter().any(|owner| {
            owner.namespace == record.namespace
                && owner.name == record.name
                && owner.uid == record.uid
        });
        if owner_is_retained
            || !record
                .finalizers
                .iter()
                .any(|entry| entry == unf_loadbalancer::UNF_LOAD_BALANCER_FINALIZER)
        {
            continue;
        }
        let owner_has_lease = runtime.allocator.checkpoint().leases.iter().any(|lease| {
            lease.owner.namespace == record.namespace
                && lease.owner.name == record.name
                && lease.owner.uid == record.uid
        });
        let can_remove = !owner_has_lease
            && load_balancer_agents_converged(state, &desired)
            && desired.allocation_revision == runtime.allocator.checkpoint().revision;
        if can_remove {
            finalizer_updates.push((record.clone(), false));
        }
    }
    for (record, retain) in finalizer_updates {
        patch_load_balancer_finalizer(client, &record, retain).await?;
    }
    Ok(())
}

fn load_balancer_agents_converged(state: &ControllerState, desired: &ReachabilitySnapshot) -> bool {
    let now = unix_time_millis();
    let reports = read_lock(&state.agent_reports);
    read_lock(&state.node_port_nodes).keys().all(|node_name| {
        reports.get(node_name).is_some_and(|stored| {
            now.saturating_sub(stored.last_received_unix_ms) <= AGENT_STATUS_FRESHNESS_MILLIS
                && stored.report.ready
                && stored.report.bpf_loaded
                && stored.report.load_balancer_reachability_schema_version
                    >= unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION
                && stored.report.applied_load_balancer_epoch == desired.source_epoch
                && stored.report.applied_load_balancer_revision == desired.revision.get()
                && stored.report.applied_load_balancer_allocation_revision
                    == desired.allocation_revision.get()
                && stored.report.load_balancer_last_error.is_none()
        })
    })
}

async fn persist_load_balancer_runtime(
    state: &ControllerState,
    runtime: &LoadBalancerRuntime,
) -> Result<()> {
    let api = state
        .load_balancer_store
        .as_ref()
        .context("durable LoadBalancer API is unavailable")?;
    let durable = DurableLoadBalancerState {
        schema_version: LOAD_BALANCER_STORE_SCHEMA_VERSION,
        reachability_revision: runtime.reachability_revision,
        allocation: runtime.allocator.checkpoint(),
    };
    let encoded = serde_json::to_string(&durable)
        .context("encode durable LoadBalancer control-plane state")?;
    if encoded.len() > LOAD_BALANCER_STORE_DATA_LIMIT {
        return Err(anyhow!(
            "durable LoadBalancer state requires {} bytes; ConfigMap limit is {}",
            encoded.len(),
            LOAD_BALANCER_STORE_DATA_LIMIT
        ));
    }
    let data = BTreeMap::from([(LOAD_BALANCER_STORE_KEY.to_owned(), encoded)]);
    let patch = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": LOAD_BALANCER_STORE_NAME,
            "namespace": "unf-system",
        },
        "data": data,
    });
    api.patch(
        LOAD_BALANCER_STORE_NAME,
        &PatchParams::apply("unf-controller-load-balancer").force(),
        &Patch::Apply(&patch),
    )
    .await
    .with_context(|| format!("patch ConfigMap unf-system/{LOAD_BALANCER_STORE_NAME}"))?;
    Ok(())
}

async fn patch_load_balancer_finalizer(
    client: &Client,
    record: &ServiceRecord,
    retain: bool,
) -> Result<()> {
    let finalizers = reconcile_finalizers(&record.finalizers, retain);
    let patch = serde_json::json!({
        "metadata": {
            "resourceVersion": record.resource_version,
            "finalizers": finalizers,
        }
    });
    Api::<Service>::namespaced(client.clone(), &record.namespace)
        .patch(&record.name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .with_context(|| {
            format!(
                "{} UNF finalizer on Service {}/{}",
                if retain { "add" } else { "remove" },
                record.namespace,
                record.name
            )
        })?;
    Ok(())
}

async fn restore_agent_reports(state: &ControllerState) -> Result<()> {
    let api = state
        .agent_report_store
        .as_ref()
        .context("durable agent-report API is unavailable")?;
    let config_map = api
        .get(AGENT_REPORT_STORE_NAME)
        .await
        .with_context(|| format!("read ConfigMap unf-system/{AGENT_REPORT_STORE_NAME}"))?;
    let Some(encoded) = config_map
        .data
        .as_ref()
        .and_then(|data| data.get(AGENT_REPORT_STORE_KEY))
    else {
        info!("durable agent acknowledgement store is empty");
        return Ok(());
    };
    let (reports, ignored_older_reports) = decode_agent_report_store(encoded, unix_time_millis())?;
    let restored = reports.len() as u64;
    *write_lock(&state.agent_reports) = reports;
    state.metrics.agent_reports_restored.inc_by(restored);
    if ignored_older_reports > 0 {
        warn!(
            ignored_older_reports,
            expected_schema = AGENT_STATUS_SCHEMA_VERSION,
            "ignored durable agent acknowledgements from an older status schema"
        );
    }
    info!(restored, "restored durable agent acknowledgements");
    Ok(())
}

fn decode_agent_report_store(
    encoded: &str,
    now_unix_ms: u64,
) -> Result<(BTreeMap<String, StoredAgentReport>, usize)> {
    let store: DurableAgentReportStore =
        serde_json::from_str(encoded).context("decode durable agent-report checkpoint")?;
    if store.schema_version != AGENT_REPORT_STORE_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported durable agent-report schema {}; expected {}",
            store.schema_version,
            AGENT_REPORT_STORE_SCHEMA_VERSION
        ));
    }
    if store.reports.len() > AGENT_REPORT_STORE_CAPACITY {
        return Err(anyhow!(
            "durable agent-report checkpoint contains {} entries; limit is {}",
            store.reports.len(),
            AGENT_REPORT_STORE_CAPACITY
        ));
    }
    let mut reports = BTreeMap::new();
    let mut ignored_older_reports = 0usize;
    for (node_name, stored) in store.reports {
        if node_name.as_str() != stored.report.node_name {
            return Err(anyhow!(
                "durable agent-report key {node_name:?} does not match report node {:?}",
                stored.report.node_name
            ));
        }
        if stored.last_received_unix_ms == 0 {
            return Err(anyhow!(
                "durable agent report for {node_name} has no receive timestamp"
            ));
        }
        if stored.last_received_unix_ms
            > now_unix_ms.saturating_add(AGENT_REPORT_MAX_FUTURE_SKEW_MILLIS)
        {
            return Err(anyhow!(
                "durable agent report for {node_name} is unreasonably far in the future"
            ));
        }
        if stored.report.schema_version < AGENT_STATUS_SCHEMA_VERSION {
            ignored_older_reports = ignored_older_reports.saturating_add(1);
            continue;
        }
        validate_agent_status(&stored.report).map_err(|error| {
            anyhow!("invalid durable report for {node_name}: {}", error.message)
        })?;
        reports.insert(node_name, stored);
    }
    Ok((reports, ignored_older_reports))
}

fn spawn_agent_report_persistence(
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
    tasks: &mut JoinSet<()>,
) {
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(AGENT_REPORT_PERSISTENCE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => {
                    persist_agent_reports_if_dirty(&state).await;
                    break;
                }
                _ = interval.tick() => persist_agent_reports_if_dirty(&state).await,
            }
        }
    });
}

async fn persist_agent_reports_if_dirty(state: &ControllerState) {
    if !state.agent_reports_dirty.swap(false, Ordering::AcqRel) {
        return;
    }
    if let Err(error) = persist_agent_reports(state).await {
        state.agent_reports_dirty.store(true, Ordering::Release);
        state.metrics.agent_report_persistence_errors.inc();
        warn!(%error, "could not persist agent acknowledgements; retrying");
    }
}

async fn persist_agent_reports(state: &ControllerState) -> Result<()> {
    let api = state
        .agent_report_store
        .as_ref()
        .context("durable agent-report API is unavailable")?;
    let store = DurableAgentReportStore {
        schema_version: AGENT_REPORT_STORE_SCHEMA_VERSION,
        reports: read_lock(&state.agent_reports).clone(),
    };
    let encoded =
        serde_json::to_string(&store).context("encode durable agent-report checkpoint")?;
    let data = BTreeMap::from([(AGENT_REPORT_STORE_KEY.to_owned(), encoded)]);
    let patch = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": AGENT_REPORT_STORE_NAME,
            "namespace": "unf-system",
        },
        "data": data,
    });
    api.patch(
        AGENT_REPORT_STORE_NAME,
        &PatchParams::apply("unf-controller-agent-reports").force(),
        &Patch::Apply(&patch),
    )
    .await
    .with_context(|| format!("patch ConfigMap unf-system/{AGENT_REPORT_STORE_NAME}"))?;
    state.metrics.agent_report_persistence_writes.inc();
    Ok(())
}

async fn restore_flow_history(state: &ControllerState) -> Result<()> {
    let api = state
        .flow_history_store
        .as_ref()
        .context("durable flow-history API is unavailable")?;
    let config_map = api
        .get(FLOW_HISTORY_STORE_NAME)
        .await
        .with_context(|| format!("read ConfigMap unf-system/{FLOW_HISTORY_STORE_NAME}"))?;
    let Some(encoded) = config_map
        .data
        .as_ref()
        .and_then(|data| data.get(FLOW_HISTORY_STORE_KEY))
    else {
        info!("durable flow-history store is empty");
        return Ok(());
    };
    let checkpoint: FlowHistoryCheckpoint =
        serde_json::from_str(encoded).context("decode durable flow-history checkpoint")?;
    validate_flow_history_checkpoint(&checkpoint, unix_time_millis())?;
    let restored = checkpoint.entries.len();
    let omitted_flows = checkpoint.omitted_flows;
    let omitted_observations = checkpoint.omitted_observations;
    let history = FlowHistoryStore::from_checkpoint(checkpoint, FLOW_HISTORY_CAPACITY)
        .context("validate durable flow-history checkpoint")?;
    let revision = history.revision();
    *mutex_lock(&state.flow_history) = history;
    mutex_lock(&state.revisions).telemetry = revision;
    state
        .flow_history_checkpointed_flows
        .store(restored as u64, Ordering::Release);
    state
        .flow_history_checkpoint_omitted_flows
        .store(omitted_flows as u64, Ordering::Release);
    state
        .flow_history_checkpoint_omitted_observations
        .store(omitted_observations, Ordering::Release);
    state
        .metrics
        .flow_history_entries_restored
        .inc_by(restored as u64);
    info!(restored, omitted_flows, "restored durable flow history");
    Ok(())
}

fn validate_flow_history_checkpoint(
    checkpoint: &FlowHistoryCheckpoint,
    now_unix_ms: u64,
) -> Result<()> {
    for entry in &checkpoint.entries {
        if entry.last_received_unix_ms
            > now_unix_ms.saturating_add(FLOW_HISTORY_MAX_FUTURE_SKEW_MILLIS)
        {
            return Err(anyhow!(
                "durable flow-history entry for port {} is unreasonably far in the future",
                entry.key.destination_port
            ));
        }
        let node_name = entry.reporting_nodes.first().cloned().unwrap_or_default();
        let batch = FlowExportBatch {
            schema_version: FLOW_EXPORT_SCHEMA_VERSION,
            node_name,
            dropped_events: 0,
            entries: vec![FlowExportRecord {
                key: entry.key.clone(),
                policy_revision: entry.policy_revision,
                decision: entry.decision,
                shadow: entry.shadow,
                service: entry.service,
                observed_events: entry.observed_events,
            }],
        };
        validate_flow_export_batch(&batch)
            .map_err(|error| anyhow!("invalid durable flow-history entry: {}", error.message))?;
    }
    Ok(())
}

fn spawn_flow_history_persistence(
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
    tasks: &mut JoinSet<()>,
) {
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(FLOW_HISTORY_PERSISTENCE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => {
                    persist_flow_history_if_dirty(&state).await;
                    break;
                }
                _ = interval.tick() => persist_flow_history_if_dirty(&state).await,
            }
        }
    });
}

async fn persist_flow_history_if_dirty(state: &ControllerState) {
    if !state.flow_history_dirty.swap(false, Ordering::AcqRel) {
        return;
    }
    if let Err(error) = persist_flow_history(state).await {
        state.flow_history_dirty.store(true, Ordering::Release);
        state.metrics.flow_history_persistence_errors.inc();
        warn!(%error, "could not persist flow history; retrying");
    }
}

async fn persist_flow_history(state: &ControllerState) -> Result<()> {
    let api = state
        .flow_history_store
        .as_ref()
        .context("durable flow-history API is unavailable")?;
    let mut entry_limit = FLOW_HISTORY_DURABLE_ENTRY_LIMIT;
    let (checkpoint, encoded) = loop {
        let checkpoint = mutex_lock(&state.flow_history).checkpoint(entry_limit);
        let encoded =
            serde_json::to_string(&checkpoint).context("encode durable flow-history checkpoint")?;
        if encoded.len() <= FLOW_HISTORY_CONFIG_MAP_DATA_LIMIT {
            break (checkpoint, encoded);
        }
        if entry_limit == 0 {
            return Err(anyhow!(
                "empty durable flow-history checkpoint exceeds ConfigMap data limit"
            ));
        }
        entry_limit /= 2;
    };
    let data = BTreeMap::from([(FLOW_HISTORY_STORE_KEY.to_owned(), encoded)]);
    let patch = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": FLOW_HISTORY_STORE_NAME,
            "namespace": "unf-system",
        },
        "data": data,
    });
    api.patch(
        FLOW_HISTORY_STORE_NAME,
        &PatchParams::apply("unf-controller-flow-history").force(),
        &Patch::Apply(&patch),
    )
    .await
    .with_context(|| format!("patch ConfigMap unf-system/{FLOW_HISTORY_STORE_NAME}"))?;
    state
        .flow_history_checkpointed_flows
        .store(checkpoint.entries.len() as u64, Ordering::Release);
    state
        .flow_history_checkpoint_omitted_flows
        .store(checkpoint.omitted_flows as u64, Ordering::Release);
    state
        .flow_history_checkpoint_omitted_observations
        .store(checkpoint.omitted_observations, Ordering::Release);
    state.metrics.flow_history_persistence_writes.inc();
    if checkpoint.omitted_flows != 0 {
        warn!(
            checkpointed_flows = checkpoint.entries.len(),
            omitted_flows = checkpoint.omitted_flows,
            "durable flow-history checkpoint retained only the newest bounded entries"
        );
    }
    Ok(())
}

async fn restore_topology_history(state: &ControllerState) -> Result<()> {
    let api = state
        .topology_history_store
        .as_ref()
        .context("durable topology-history API is unavailable")?;
    let config_map = api
        .get(TOPOLOGY_HISTORY_STORE_NAME)
        .await
        .with_context(|| format!("read ConfigMap unf-system/{TOPOLOGY_HISTORY_STORE_NAME}"))?;
    let Some(encoded) = config_map
        .data
        .as_ref()
        .and_then(|data| data.get(TOPOLOGY_HISTORY_STORE_KEY))
    else {
        info!("durable topology-history store is empty");
        return Ok(());
    };
    let checkpoint: TopologyHistoryCheckpoint =
        serde_json::from_str(encoded).context("decode durable topology-history checkpoint")?;
    let now_unix_ms = unix_time_millis();
    for entry in &checkpoint.entries {
        if entry.captured_at_unix_ms
            > now_unix_ms.saturating_add(TOPOLOGY_HISTORY_MAX_FUTURE_SKEW_MILLIS)
        {
            return Err(anyhow!(
                "durable topology-history revision {} is unreasonably far in the future",
                entry.snapshot.revision.get()
            ));
        }
    }
    let restored = checkpoint.entries.len();
    let omitted = checkpoint.omitted_snapshots;
    let history = TopologyHistoryStore::from_checkpoint(checkpoint, TOPOLOGY_HISTORY_CAPACITY)
        .context("validate durable topology-history checkpoint")?;
    let latest_revision = history.latest_revision();
    *mutex_lock(&state.topology_history) = history;
    mutex_lock(&state.revisions).topology = latest_revision;
    state
        .topology_history_checkpointed_snapshots
        .store(restored as u64, Ordering::Release);
    state
        .topology_history_checkpoint_omitted_snapshots
        .store(omitted, Ordering::Release);
    state
        .metrics
        .topology_history_entries_restored
        .inc_by(restored as u64);
    info!(restored, "restored durable topology history");
    Ok(())
}

fn spawn_topology_history_persistence(
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
    tasks: &mut JoinSet<()>,
) {
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(TOPOLOGY_HISTORY_PERSISTENCE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => {
                    persist_topology_history_if_dirty(&state).await;
                    break;
                }
                _ = interval.tick() => persist_topology_history_if_dirty(&state).await,
            }
        }
    });
}

async fn persist_topology_history_if_dirty(state: &ControllerState) {
    if !state.topology_history_dirty.swap(false, Ordering::AcqRel) {
        return;
    }
    if let Err(error) = persist_topology_history(state).await {
        state.topology_history_dirty.store(true, Ordering::Release);
        state.metrics.topology_history_persistence_errors.inc();
        warn!(%error, "could not persist topology history; retrying");
    }
}

async fn persist_topology_history(state: &ControllerState) -> Result<()> {
    let api = state
        .topology_history_store
        .as_ref()
        .context("durable topology-history API is unavailable")?;
    let mut entry_limit = TOPOLOGY_HISTORY_CAPACITY;
    let (checkpoint, encoded) = loop {
        let checkpoint = mutex_lock(&state.topology_history).checkpoint(entry_limit);
        let encoded = serde_json::to_string(&checkpoint)
            .context("encode durable topology-history checkpoint")?;
        if encoded.len() <= TOPOLOGY_HISTORY_CONFIG_MAP_DATA_LIMIT {
            break (checkpoint, encoded);
        }
        if entry_limit == 0 {
            return Err(anyhow!(
                "empty durable topology-history checkpoint exceeds ConfigMap data limit"
            ));
        }
        entry_limit /= 2;
    };
    let data = BTreeMap::from([(TOPOLOGY_HISTORY_STORE_KEY.to_owned(), encoded)]);
    let patch = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": TOPOLOGY_HISTORY_STORE_NAME,
            "namespace": "unf-system",
        },
        "data": data,
    });
    api.patch(
        TOPOLOGY_HISTORY_STORE_NAME,
        &PatchParams::apply("unf-controller-topology-history").force(),
        &Patch::Apply(&patch),
    )
    .await
    .with_context(|| format!("patch ConfigMap unf-system/{TOPOLOGY_HISTORY_STORE_NAME}"))?;
    state
        .topology_history_checkpointed_snapshots
        .store(checkpoint.entries.len() as u64, Ordering::Release);
    state
        .topology_history_checkpoint_omitted_snapshots
        .store(checkpoint.omitted_snapshots, Ordering::Release);
    state.metrics.topology_history_persistence_writes.inc();
    if checkpoint.omitted_snapshots != 0 {
        warn!(
            checkpointed_snapshots = checkpoint.entries.len(),
            omitted_snapshots = checkpoint.omitted_snapshots,
            "durable topology-history checkpoint retained only the newest bounded snapshots"
        );
    }
    Ok(())
}

fn spawn_watchers(
    tasks: &mut JoinSet<()>,
    client: Client,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
) {
    let pod_state = Arc::clone(&state);
    let pod_cancel = cancellation.clone();
    let pod_api = Api::<Pod>::all(client.clone());
    tasks.spawn(async move {
        watch_pods(pod_api, pod_state, pod_cancel).await;
    });

    let namespace_state = Arc::clone(&state);
    let namespace_cancel = cancellation.clone();
    let namespace_api = Api::<Namespace>::all(client.clone());
    tasks.spawn(async move {
        watch_namespaces(namespace_api, namespace_state, namespace_cancel).await;
    });

    let node_state = Arc::clone(&state);
    let node_cancel = cancellation.clone();
    let node_api = Api::<Node>::all(client.clone());
    tasks.spawn(async move {
        watch_nodes(node_api, node_state, node_cancel).await;
    });

    let service_state = Arc::clone(&state);
    let service_cancel = cancellation.clone();
    let service_api = Api::<Service>::all(client.clone());
    tasks.spawn(async move {
        watch_services(service_api, service_state, service_cancel).await;
    });

    let endpoint_slice_state = Arc::clone(&state);
    let endpoint_slice_cancel = cancellation.clone();
    let endpoint_slice_api = Api::<EndpointSlice>::all(client.clone());
    tasks.spawn(async move {
        watch_endpoint_slices(
            endpoint_slice_api,
            endpoint_slice_state,
            endpoint_slice_cancel,
        )
        .await;
    });

    let policy_api = Api::<SecurityPolicy>::all(client.clone());
    let network_policy_state = Arc::clone(&state);
    let network_policy_cancel = cancellation.clone();
    tasks.spawn(async move {
        watch_policies(policy_api, state, cancellation).await;
    });

    let network_policy_api = Api::<NetworkPolicy>::all(client);
    tasks.spawn(async move {
        watch_network_policies(
            network_policy_api,
            network_policy_state,
            network_policy_cancel,
        )
        .await;
    });
}

async fn watch_pods(api: Api<Pod>, state: Arc<ControllerState>, cancellation: CancellationToken) {
    let stream = watcher::watcher(api, watcher::Config::default()).boxed();
    tokio::pin!(stream);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            item = stream.try_next() => match item {
                Ok(Some(event)) => apply_pod_event(&state, event),
                Ok(None) => break,
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, "pod watch error");
                }
            }
        }
    }
}

fn apply_pod_event(state: &ControllerState, event: Event<Pod>) {
    let _policy_state_guard = write_lock(&state.policy_state_guard);
    match event {
        Event::Apply(pod) | Event::InitApply(pod) => {
            if pod_is_terminal(&pod) {
                remove_pod(state, &object_key(&pod));
            } else {
                upsert_pod(state, &pod);
            }
        }
        Event::Delete(pod) => remove_pod(state, &object_key(&pod)),
        Event::Init => {
            begin_topology_initialization(state);
            let had_pods = !read_lock(&state.pods).is_empty();
            write_lock(&state.pods).clear();
            mutex_lock(&state.identities).clear();
            if had_pods {
                bump_policy_revision(state);
                bump_topology_revision(state);
            }
        }
        Event::InitDone => finish_topology_initialization(state),
    }
}

fn pod_is_terminal(pod: &Pod) -> bool {
    matches!(
        pod.status
            .as_ref()
            .and_then(|status| status.phase.as_deref()),
        Some("Succeeded" | "Failed")
    )
}

fn remove_pod(state: &ControllerState, key: &str) {
    let removed = write_lock(&state.pods).remove(key);
    mutex_lock(&state.identities).remove_pod(key);
    if let Some(removed) = removed {
        bump_topology_revision(state);
        if !removed.ipv4_addresses.is_empty()
            || !removed.ipv6_addresses.is_empty()
            || !read_lock(&state.pods)
                .values()
                .any(|pod| pod.endpoint.identity == removed.endpoint.identity)
        {
            bump_policy_revision(state);
        }
    }
}

fn upsert_pod(state: &ControllerState, pod: &Pod) {
    let namespace = pod.namespace().unwrap_or_default();
    let name = pod.name_any();
    let labels: BTreeMap<String, String> = pod
        .metadata
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let service_account = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.service_account_name.clone())
        .unwrap_or_else(|| "default".to_owned());
    let application = labels
        .get("app.kubernetes.io/name")
        .or_else(|| labels.get("app"))
        .cloned();
    let workload = application.clone().unwrap_or_else(|| name.clone());
    let named_ports = match pod_named_ports(pod) {
        Ok(named_ports) => named_ports,
        Err(error) => {
            state.metrics.errors.inc();
            warn!(%error, namespace, name, "Pod named-port admission failed");
            return;
        }
    };
    let identity_key = canonical_identity_key(
        "local",
        &namespace,
        &service_account,
        &workload,
        &labels,
        &named_ports,
    );
    let identity_id = provisional_identity_id(&identity_key);
    let identity = NetworkIdentity {
        id: identity_id,
        cluster: "local".to_owned(),
        namespace: namespace.clone(),
        workload,
        service_account: service_account.clone(),
        application: application.clone(),
        labels: labels.clone(),
    };
    let key = format!("{namespace}/{name}");
    let host_network = pod_uses_host_network(pod);
    let addresses = pod_addresses(pod);
    if let Err(error) = mutex_lock(&state.identities).admit_pod(
        key.clone(),
        identity_key,
        &identity,
        addresses.iter().copied(),
    ) {
        state.metrics.errors.inc();
        warn!(%error, %key, "Pod identity admission failed");
        return;
    }
    let endpoint = Endpoint {
        identity: identity_id,
        namespace: namespace.clone(),
        namespace_labels: BTreeMap::new(),
        service_account,
        application,
        labels,
        named_ports,
    };
    let (ipv4_addresses, ipv6_addresses) = pod_address_families(pod);
    let record = PodRecord {
        namespace,
        name,
        uid: pod.metadata.uid.clone().unwrap_or_default(),
        node_name: pod.spec.as_ref().and_then(|spec| spec.node_name.clone()),
        host_network,
        endpoint,
        ipv4_addresses,
        ipv6_addresses,
    };
    let previous = write_lock(&state.pods).insert(key, record.clone());
    if previous.as_ref().is_none_or(|previous| {
        previous.endpoint != record.endpoint
            || previous.host_network != record.host_network
            || previous.ipv4_addresses != record.ipv4_addresses
            || previous.ipv6_addresses != record.ipv6_addresses
    }) {
        bump_policy_revision(state);
    }
    if previous.as_ref() != Some(&record) {
        bump_topology_revision(state);
    }
    state.metrics.reconciles.inc();
}

fn pod_named_ports(pod: &Pod) -> Result<BTreeMap<NamedPort, u16>> {
    let mut named_ports = BTreeMap::new();
    for container in pod.spec.iter().flat_map(|spec| &spec.containers) {
        for port in container.ports.iter().flatten() {
            let Some(name) = &port.name else {
                continue;
            };
            let protocol = match port.protocol.as_deref().unwrap_or("TCP") {
                "TCP" => Protocol::Tcp,
                "UDP" => Protocol::Udp,
                "SCTP" => Protocol::Sctp,
                _ => continue,
            };
            let number = u16::try_from(port.container_port)
                .with_context(|| format!("named port {name:?} is outside the u16 range"))?;
            if number == 0 {
                return Err(anyhow!("named port {name:?} cannot map to port zero"));
            }
            let key = NamedPort {
                name: name.clone(),
                protocol,
            };
            if let Some(existing) = named_ports.insert(key, number)
                && existing != number
            {
                return Err(anyhow!(
                    "named port {name:?} has conflicting mappings {existing} and {number}"
                ));
            }
        }
    }
    Ok(named_ports)
}

fn pod_addresses(pod: &Pod) -> BTreeSet<IpAddr> {
    if pod_uses_host_network(pod) {
        return BTreeSet::new();
    }
    pod_status_addresses(pod)
}

fn pod_uses_host_network(pod: &Pod) -> bool {
    pod.spec
        .as_ref()
        .and_then(|spec| spec.host_network)
        .unwrap_or(false)
}

fn pod_address_families(pod: &Pod) -> (BTreeSet<Ipv4Addr>, BTreeSet<Ipv6Addr>) {
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    for address in pod_status_addresses(pod) {
        match address {
            IpAddr::V4(address) => {
                ipv4.insert(address);
            }
            IpAddr::V6(address) => {
                ipv6.insert(address);
            }
        }
    }
    (ipv4, ipv6)
}

fn pod_status_addresses(pod: &Pod) -> BTreeSet<IpAddr> {
    let mut addresses = BTreeSet::new();
    if let Some(status) = &pod.status {
        if let Some(pod_ips) = &status.pod_ips {
            for pod_ip in pod_ips {
                if let Ok(address) = pod_ip.ip.parse() {
                    addresses.insert(address);
                }
            }
        }
        if let Some(pod_ip) = &status.pod_ip
            && let Ok(address) = pod_ip.parse()
        {
            addresses.insert(address);
        }
    }
    addresses
}

async fn watch_namespaces(
    api: Api<Namespace>,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
) {
    let stream = watcher::watcher(api, watcher::Config::default()).boxed();
    tokio::pin!(stream);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            item = stream.try_next() => match item {
                Ok(Some(event)) => apply_namespace_event(&state, event),
                Ok(None) => break,
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, "namespace watch error");
                }
            }
        }
    }
}

fn apply_namespace_event(state: &ControllerState, event: Event<Namespace>) {
    let _policy_state_guard = write_lock(&state.policy_state_guard);
    match event {
        Event::Apply(namespace) | Event::InitApply(namespace) => {
            let name = namespace.name_any();
            let labels = normalized_namespace_labels(&name, &namespace);
            let previous = write_lock(&state.namespaces).insert(name, labels.clone());
            state.metrics.reconciles.inc();
            if previous.as_ref() != Some(&labels) {
                bump_policy_revision(state);
            }
        }
        Event::Delete(namespace) => {
            if write_lock(&state.namespaces)
                .remove(&namespace.name_any())
                .is_some()
            {
                bump_policy_revision(state);
            }
        }
        Event::Init => {
            let had_namespaces = !read_lock(&state.namespaces).is_empty();
            write_lock(&state.namespaces).clear();
            if had_namespaces {
                bump_policy_revision(state);
            }
        }
        Event::InitDone => {}
    }
}

fn normalized_namespace_labels(name: &str, namespace: &Namespace) -> BTreeMap<String, String> {
    let mut labels: BTreeMap<_, _> = namespace
        .metadata
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    labels.insert("kubernetes.io/metadata.name".to_owned(), name.to_owned());
    labels
}

async fn watch_nodes(api: Api<Node>, state: Arc<ControllerState>, cancellation: CancellationToken) {
    let stream = watcher::watcher(api, watcher::Config::default()).boxed();
    tokio::pin!(stream);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            item = stream.try_next() => match item {
                Ok(Some(event)) => apply_node_event(&state, event),
                Ok(None) => break,
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, "Node watch error");
                }
            }
        }
    }
}

fn apply_node_event(state: &ControllerState, event: Event<Node>) {
    let _policy_state_guard = write_lock(&state.policy_state_guard);
    match event {
        Event::Apply(node) => reconcile_node(state, &node, false),
        Event::InitApply(node) => reconcile_node(state, &node, true),
        Event::Delete(node) => {
            let node_name = node.name_any();
            write_lock(&state.node_port_nodes).remove(&node_name);
            write_lock(&state.rejected_node_port_nodes).remove(&node_name);
            if write_lock(&state.node_block_inputs)
                .remove(&node_name)
                .is_some()
            {
                recompute_node_blocks(state);
            }
            if write_lock(&state.nodes).remove(&node_name).is_some() {
                bump_topology_revision(state);
            }
            if write_lock(&state.host_network_gateways)
                .remove(&node_name)
                .is_some()
            {
                bump_policy_revision(state);
            }
            if write_lock(&state.agent_reports)
                .remove(&node_name)
                .is_some()
            {
                state.agent_reports_dirty.store(true, Ordering::Release);
            }
        }
        Event::Init => {
            begin_topology_initialization(state);
            *mutex_lock(&state.node_port_node_initialization) = Some(BTreeSet::new());
            *mutex_lock(&state.node_block_initialization) = Some(BTreeMap::new());
            let had_nodes = !read_lock(&state.nodes).is_empty();
            write_lock(&state.nodes).clear();
            let had_gateways = !read_lock(&state.host_network_gateways).is_empty();
            write_lock(&state.host_network_gateways).clear();
            if had_nodes {
                bump_topology_revision(state);
            }
            if had_gateways {
                bump_policy_revision(state);
            }
        }
        Event::InitDone => {
            if let Some(initialized) = mutex_lock(&state.node_port_node_initialization).take() {
                write_lock(&state.node_port_nodes)
                    .retain(|node_name, _| initialized.contains(node_name));
                write_lock(&state.rejected_node_port_nodes)
                    .retain(|node_name, _| initialized.contains(node_name));
            }
            if let Some(initialized) = mutex_lock(&state.node_block_initialization).take() {
                let changed = *read_lock(&state.node_block_inputs) != initialized;
                if changed {
                    *write_lock(&state.node_block_inputs) = initialized;
                    recompute_node_blocks(state);
                }
            }
            let nodes = read_lock(&state.nodes);
            let mut reports = write_lock(&state.agent_reports);
            let previous_len = reports.len();
            reports.retain(|node_name, _| nodes.contains_key(node_name));
            if reports.len() != previous_len {
                state.agent_reports_dirty.store(true, Ordering::Release);
            }
            drop(reports);
            drop(nodes);
            finish_topology_initialization(state);
        }
    }
}

fn reconcile_node(state: &ControllerState, node: &Node, initializing: bool) {
    let normalized = topology_node(node);
    let gateways = ovn_host_network_gateways(node);
    if initializing
        && let Some(initialized) = mutex_lock(&state.node_port_node_initialization).as_mut()
    {
        initialized.insert(normalized.name.clone());
    }
    reconcile_node_port_node(state, node);
    if initializing {
        stage_node_block_input(state, node);
    } else {
        update_node_block_input(state, node);
    }
    let previous = write_lock(&state.nodes).insert(normalized.name.clone(), normalized.clone());
    let previous_gateways = if gateways == HostNetworkGateways::default() {
        write_lock(&state.host_network_gateways).remove(&normalized.name)
    } else {
        write_lock(&state.host_network_gateways).insert(normalized.name.clone(), gateways.clone())
    };
    state.metrics.reconciles.inc();
    if previous.as_ref() != Some(&normalized) {
        bump_topology_revision(state);
    }
    let gateways_changed = previous_gateways.as_ref().map_or(
        !gateways.ipv4.is_empty() || !gateways.ipv6.is_empty(),
        |previous| previous != &gateways,
    );
    if gateways_changed {
        bump_policy_revision(state);
    }
}

fn reconcile_node_port_node(state: &ControllerState, node: &Node) {
    let node_name = node.name_any();
    let previous = read_lock(&state.node_port_nodes).get(&node_name).cloned();
    let next_revision = previous
        .as_ref()
        .map_or(Revision::new(1), |record| record.revision.next());
    match node_port_node_record(node, state.identity_epoch, next_revision) {
        Ok(candidate) => {
            write_lock(&state.rejected_node_port_nodes).remove(&node_name);
            if previous.as_ref().is_some_and(|record| {
                record.node_uid == candidate.node_uid && record.addresses == candidate.addresses
            }) {
                return;
            }
            write_lock(&state.node_port_nodes).insert(node_name, candidate);
        }
        Err(error) => {
            state.metrics.errors.inc();
            write_lock(&state.rejected_node_port_nodes)
                .insert(node_name.clone(), error.to_string());
            warn!(%error, %node_name, "NodePort Node-address admission failed; retaining last-valid state");
        }
    }
}

fn node_port_node_record(
    node: &Node,
    source_epoch: u64,
    revision: Revision,
) -> Result<NodePortNodeRecord> {
    let node_name = node.name_any();
    let node_uid = node
        .metadata
        .uid
        .clone()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| anyhow!("Node {node_name} has no authoritative UID"))?;
    let mut addresses = Vec::new();
    for address in node
        .status
        .as_ref()
        .and_then(|status| status.addresses.as_ref())
        .into_iter()
        .flatten()
    {
        let kind = match address.type_.as_str() {
            "InternalIP" => NodeAddressKind::Internal,
            "ExternalIP" => NodeAddressKind::External,
            _ => continue,
        };
        addresses.push(ServiceNodeAddress {
            address: address.address.parse().with_context(|| {
                format!(
                    "Node {node_name} {} {:?} is not an IP address",
                    address.type_, address.address
                )
            })?,
            kind,
        });
    }
    let snapshot = NodePortNodeSnapshot {
        schema_version: NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION,
        source_epoch,
        revision,
        node_name,
        node_uid,
        addresses,
    }
    .validate_and_normalize()?;
    Ok(NodePortNodeRecord {
        node_uid: snapshot.node_uid,
        revision: snapshot.revision,
        addresses: snapshot.addresses,
    })
}

fn update_node_block_input(state: &ControllerState, node: &Node) {
    let node_name = node.name_any();
    let input = node_block_input(node);
    let changed = if let Some(input) = input {
        write_lock(&state.node_block_inputs)
            .insert(node_name, input.clone())
            .as_ref()
            != Some(&input)
    } else {
        write_lock(&state.node_block_inputs)
            .remove(&node_name)
            .is_some()
    };
    if changed {
        recompute_node_blocks(state);
    }
}

fn stage_node_block_input(state: &ControllerState, node: &Node) {
    let Some(input) = node_block_input(node) else {
        return;
    };
    let mut initialization = mutex_lock(&state.node_block_initialization);
    if let Some(inputs) = initialization.as_mut() {
        inputs.insert(node.name_any(), input);
    } else {
        drop(initialization);
        update_node_block_input(state, node);
    }
}

fn node_block_input(node: &Node) -> Option<NodeBlockInput> {
    let enabled = node
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(PRIMARY_CNI_NODE_LABEL))
        .is_some_and(|value| value == PRIMARY_CNI_NODE_LABEL_VALUE);
    if !enabled {
        return None;
    }
    Some(NodeBlockInput {
        node_uid: node.metadata.uid.clone().unwrap_or_default(),
        provider: node_block_provider(node),
        transport: node_transport(node),
    })
}

fn node_transport(node: &Node) -> Result<NodeTransport, String> {
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    for entry in node
        .status
        .as_ref()
        .and_then(|status| status.addresses.as_ref())
        .into_iter()
        .flatten()
        .filter(|entry| entry.type_ == "InternalIP")
    {
        match entry.address.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) if usable_ipv4_transport(address) => {
                ipv4.insert(address);
            }
            Ok(IpAddr::V6(address)) if usable_ipv6_transport(address) => {
                ipv6.insert(address);
            }
            Ok(_) => {}
            Err(error) => {
                return Err(format!(
                    "Node InternalIP {:?} is not an IP address: {error}",
                    entry.address
                ));
            }
        }
    }
    if ipv4.len() != 1 || ipv6.len() != 1 {
        return Err(format!(
            "Node status must contain exactly one usable IPv4 and one IPv6 InternalIP; found {} and {}",
            ipv4.len(),
            ipv6.len()
        ));
    }
    Ok(NodeTransport {
        ipv4: *ipv4.first().expect("one IPv4 transport exists"),
        ipv6: *ipv6.first().expect("one IPv6 transport exists"),
    })
}

const fn usable_ipv4_transport(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_link_local()
}

const fn usable_ipv6_transport(address: Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_unicast_link_local()
}

fn node_block_provider(node: &Node) -> Result<NodeBlockProvider, String> {
    let cidrs = node
        .spec
        .as_ref()
        .and_then(|spec| {
            spec.pod_cidrs
                .clone()
                .filter(|cidrs| !cidrs.is_empty())
                .or_else(|| spec.pod_cidr.clone().map(|cidr| vec![cidr]))
        })
        .ok_or_else(|| "Node spec has no Pod CIDRs".to_owned())?;
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for cidr in cidrs {
        if cidr.contains(':') {
            ipv6.push(
                cidr.parse::<Ipv6NodeBlock>()
                    .map_err(|error| error.to_string())?,
            );
        } else {
            ipv4.push(
                cidr.parse::<Ipv4NodeBlock>()
                    .map_err(|error| error.to_string())?,
            );
        }
    }
    if ipv4.len() != 1 || ipv6.len() != 1 {
        return Err(format!(
            "Node spec must contain exactly one IPv4 and one IPv6 Pod CIDR; found {} and {}",
            ipv4.len(),
            ipv6.len()
        ));
    }
    Ok(NodeBlockProvider::new(ipv4[0], ipv6[0]))
}

fn recompute_node_blocks(state: &ControllerState) {
    let inputs = read_lock(&state.node_block_inputs).clone();
    let previous_assignments = read_lock(&state.node_blocks).clone();
    let mut candidates = BTreeMap::new();
    let mut rejected = BTreeMap::new();
    for (node_name, input) in &inputs {
        match input.provider {
            Ok(provider) if !input.node_uid.is_empty() => {
                candidates.insert(
                    node_name.clone(),
                    (input.node_uid.clone(), provider, input.transport.clone()),
                );
            }
            Ok(_) => {
                rejected.insert(node_name.clone(), "Node UID is missing".to_owned());
            }
            Err(ref error) => {
                rejected.insert(node_name.clone(), error.clone());
            }
        }
    }

    let overlap_candidates: Vec<_> = candidates
        .iter()
        .map(|(name, (_, provider, _))| (name.clone(), *provider))
        .collect();
    for (index, (left_name, left)) in overlap_candidates.iter().enumerate() {
        for (right_name, right) in overlap_candidates.iter().skip(index + 1) {
            if left.ipv4_block.overlaps(right.ipv4_block)
                || left.ipv6_block.overlaps(right.ipv6_block)
            {
                let message = format!("node blocks overlap assignment for {right_name}");
                rejected.insert(left_name.clone(), message);
                let message = format!("node blocks overlap assignment for {left_name}");
                rejected.insert(right_name.clone(), message);
            }
        }
    }
    for node_name in rejected.keys() {
        candidates.remove(node_name);
    }

    let assignments_changed = previous_assignments.len() != candidates.len()
        || candidates
            .iter()
            .any(|(node_name, (node_uid, provider, transport))| {
                previous_assignments.get(node_name).is_none_or(|previous| {
                    previous.node_uid != *node_uid
                        || previous.provider != *provider
                        || previous.transport != *transport
                })
            });
    let changed = assignments_changed || *read_lock(&state.rejected_node_blocks) != rejected;
    if changed {
        bump_routing_revision(state);
        if assignments_changed {
            bump_policy_revision(state);
        }
        let routing_revision = mutex_lock(&state.revisions).routing;
        let assignments = candidates
            .into_iter()
            .map(|(node_name, (node_uid, provider, transport))| {
                let revision = previous_assignments
                    .get(&node_name)
                    .filter(|previous| {
                        previous.node_uid == node_uid && previous.provider == provider
                    })
                    .map_or(routing_revision, |previous| previous.revision);
                (
                    node_name,
                    AssignedNodeBlock {
                        node_uid,
                        provider,
                        revision,
                        transport,
                    },
                )
            })
            .collect();
        *write_lock(&state.node_blocks) = assignments;
        *write_lock(&state.rejected_node_blocks) = rejected;
    }
}

fn ovn_host_network_gateways(node: &Node) -> HostNetworkGateways {
    const NODE_SUBNETS_ANNOTATION: &str = "k8s.ovn.org/node-subnets";
    let Some(encoded) = node
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(NODE_SUBNETS_ANNOTATION))
    else {
        return HostNetworkGateways::default();
    };
    let Ok(networks) = serde_json::from_str::<BTreeMap<String, Vec<String>>>(encoded) else {
        warn!(node = %node.name_any(), "ignored malformed OVN node-subnets annotation");
        return HostNetworkGateways::default();
    };
    let mut gateways = HostNetworkGateways::default();
    for network in networks.into_values().flatten() {
        match ovn_gateway_address(&network) {
            Some(IpAddr::V4(address)) => {
                gateways.ipv4.insert(address);
            }
            Some(IpAddr::V6(address)) => {
                gateways.ipv6.insert(address);
            }
            None => warn!(node = %node.name_any(), network, "ignored invalid OVN node subnet"),
        }
    }
    gateways
}

fn ovn_gateway_address(network: &str) -> Option<IpAddr> {
    let (address, prefix_len) = network.split_once('/')?;
    let prefix_len: u8 = prefix_len.parse().ok()?;
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) if prefix_len <= 30 => {
            let mask = u32::MAX << (32 - prefix_len);
            Some(IpAddr::V4(Ipv4Addr::from(
                (u32::from(address) & mask).checked_add(2)?,
            )))
        }
        IpAddr::V6(address) if prefix_len <= 126 => {
            let mask = u128::MAX << (128 - prefix_len);
            Some(IpAddr::V6(Ipv6Addr::from(
                (u128::from(address) & mask).checked_add(2)?,
            )))
        }
        _ => None,
    }
}

fn topology_node(node: &Node) -> TopologyNode {
    let ready = node.status.as_ref().is_some_and(|status| {
        status.conditions.iter().flatten().any(|condition| {
            condition.type_ == "Ready" && condition.status.eq_ignore_ascii_case("true")
        })
    });
    TopologyNode {
        name: node.name_any(),
        ready,
        labels: node
            .metadata
            .labels
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
    }
}

async fn watch_services(
    api: Api<Service>,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
) {
    let stream = watcher::watcher(api, watcher::Config::default()).boxed();
    tokio::pin!(stream);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            item = stream.try_next() => match item {
                Ok(Some(event)) => apply_service_event(&state, event),
                Ok(None) => break,
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, "Service watch error");
                }
            }
        }
    }
}

fn apply_service_event(state: &ControllerState, event: Event<Service>) {
    let _policy_state_guard = write_lock(&state.policy_state_guard);
    match event {
        Event::Apply(service) | Event::InitApply(service) => {
            let key = object_key(&service);
            match service_record(&service) {
                Ok(record) => {
                    write_lock(&state.rejected_service_sources).remove(&key);
                    let previous = write_lock(&state.services).insert(key, record.clone());
                    state.metrics.reconciles.inc();
                    if previous
                        .as_ref()
                        .is_none_or(|previous| !service_record_semantics_equal(previous, &record))
                    {
                        bump_service_and_topology_revision(state);
                    }
                }
                Err(error) => {
                    state.metrics.errors.inc();
                    write_lock(&state.rejected_service_sources)
                        .insert(key.clone(), error.to_string());
                    warn!(%error, %key, "Service topology admission failed");
                }
            }
        }
        Event::Delete(service) => {
            let key = object_key(&service);
            write_lock(&state.rejected_service_sources).remove(&key);
            if write_lock(&state.services).remove(&key).is_some() {
                bump_service_and_topology_revision(state);
            }
        }
        Event::Init => {
            begin_topology_initialization(state);
            let had_services = !read_lock(&state.services).is_empty();
            write_lock(&state.services).clear();
            write_lock(&state.rejected_service_sources).clear();
            if had_services {
                bump_service_and_topology_revision(state);
            }
        }
        Event::InitDone => finish_topology_initialization(state),
    }
}

fn service_record_semantics_equal(left: &ServiceRecord, right: &ServiceRecord) -> bool {
    left.namespace == right.namespace
        && left.name == right.name
        && left.service_type == right.service_type
        && left.cluster_ips == right.cluster_ips
        && left.selector == right.selector
        && left.ports == right.ports
        && left.compiler_source == right.compiler_source
}

fn service_record(service: &Service) -> Result<ServiceRecord> {
    let namespace = service.namespace().unwrap_or_default();
    let name = service.name_any();
    let uid = service.metadata.uid.clone().unwrap_or_default();
    let resource_version = service
        .metadata
        .resource_version
        .clone()
        .unwrap_or_default();
    let spec = service
        .spec
        .as_ref()
        .ok_or_else(|| anyhow!("Service {namespace}/{name} is missing spec"))?;
    let mut cluster_ips = BTreeSet::new();
    let configured_ips = spec
        .cluster_ips
        .clone()
        .or_else(|| spec.cluster_ip.clone().map(|address| vec![address]))
        .unwrap_or_default();
    for address in configured_ips {
        if address == "None" {
            continue;
        }
        cluster_ips.insert(address.parse().with_context(|| {
            format!("Service {namespace}/{name} has invalid cluster IP {address:?}")
        })?);
    }
    let mut ports = Vec::new();
    let mut compiler_ports = Vec::new();
    let service_type = spec.type_.clone().unwrap_or_else(|| "ClusterIP".to_owned());
    let external_traffic_policy = service_external_traffic_policy(
        &namespace,
        &name,
        spec.external_traffic_policy.as_deref(),
    )?;
    for port in spec.ports.iter().flatten() {
        let number = u16::try_from(port.port).with_context(|| {
            format!(
                "Service {namespace}/{name} port {} is outside the u16 range",
                port.port
            )
        })?;
        if number == 0 {
            return Err(anyhow!(
                "Service {namespace}/{name} cannot expose port zero"
            ));
        }
        let node_port = service_node_port(&namespace, &name, port.node_port)?;
        let protocol = port.protocol.clone().unwrap_or_else(|| "TCP".to_owned());
        let target_port = Some(port.target_port.as_ref().map_or_else(
            || number.to_string(),
            |target| match target {
                IntOrString::Int(number) => number.to_string(),
                IntOrString::String(name) => name.clone(),
            },
        ));
        ports.push(TopologyServicePort {
            name: port.name.clone(),
            protocol: protocol.clone(),
            port: number,
            target_port,
        });
        compiler_ports.push(ServiceSourcePort {
            name: port.name.clone(),
            protocol: service_protocol(&protocol)?,
            port: number,
            app_protocol: port.app_protocol.clone(),
            node_port,
        });
    }
    ports.sort();
    compiler_ports.sort();
    let load_balancer =
        service_load_balancer_source(&namespace, &name, &service_type, spec, &cluster_ips)?;
    let compiler_source = ServiceSource {
        namespace: namespace.clone(),
        name: name.clone(),
        cluster_ips: cluster_ips.iter().copied().collect(),
        external_traffic_policy,
        load_balancer,
        ports: compiler_ports,
    };
    Ok(ServiceRecord {
        namespace,
        name,
        uid,
        resource_version,
        finalizers: service.metadata.finalizers.clone().unwrap_or_default(),
        deleting: service.metadata.deletion_timestamp.is_some(),
        service_type,
        cluster_ips,
        selector: spec
            .selector
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        ports,
        compiler_source,
    })
}

fn service_load_balancer_source(
    namespace: &str,
    name: &str,
    service_type: &str,
    spec: &ServiceSpec,
    cluster_ips: &BTreeSet<IpAddr>,
) -> Result<Option<ServiceLoadBalancerSource>> {
    if service_type != "LoadBalancer" {
        if spec.load_balancer_class.is_some() {
            return Err(anyhow!(
                "Service {namespace}/{name} sets loadBalancerClass without type LoadBalancer"
            ));
        }
        return Ok(None);
    }
    let Some(class) = spec.load_balancer_class.as_deref() else {
        return Ok(None);
    };
    if class != UNF_LOAD_BALANCER_CLASS {
        return Ok(None);
    }
    if spec
        .internal_traffic_policy
        .as_deref()
        .is_some_and(|policy| policy != "Cluster")
    {
        return Err(anyhow!(
            "Service {namespace}/{name} uses unsupported internalTrafficPolicy"
        ));
    }
    if spec
        .session_affinity
        .as_deref()
        .is_some_and(|affinity| affinity != "None")
    {
        return Err(anyhow!(
            "Service {namespace}/{name} uses unsupported sessionAffinity"
        ));
    }
    if spec.traffic_distribution.is_some() {
        return Err(anyhow!(
            "Service {namespace}/{name} uses unsupported trafficDistribution"
        ));
    }

    let ip_families = if let Some(families) = &spec.ip_families {
        families
            .iter()
            .map(|family| service_ip_family(namespace, name, family))
            .collect::<Result<Vec<_>>>()?
    } else {
        cluster_ips
            .iter()
            .map(|address| {
                if address.is_ipv4() {
                    AddressFamily::Ipv4
                } else {
                    AddressFamily::Ipv6
                }
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let ip_family_policy = match spec.ip_family_policy.as_deref() {
        Some("PreferDualStack") => ServiceIpFamilyPolicy::PreferDualStack,
        Some("RequireDualStack") => ServiceIpFamilyPolicy::RequireDualStack,
        None if ip_families.len() == 2 => ServiceIpFamilyPolicy::PreferDualStack,
        Some("SingleStack") | None => ServiceIpFamilyPolicy::SingleStack,
        Some(policy) => {
            return Err(anyhow!(
                "Service {namespace}/{name} has unsupported ipFamilyPolicy {policy:?}"
            ));
        }
    };
    let requested_ips = spec
        .load_balancer_ip
        .iter()
        .map(|address| {
            address.parse().with_context(|| {
                format!("Service {namespace}/{name} has invalid loadBalancerIP {address:?}")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let source_ranges = spec
        .load_balancer_source_ranges
        .iter()
        .flatten()
        .map(|prefix| {
            prefix.parse::<ServiceIpPrefix>().with_context(|| {
                format!("Service {namespace}/{name} has invalid loadBalancerSourceRange {prefix:?}")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let health_check_node_port = service_node_port(namespace, name, spec.health_check_node_port)?;

    Ok(Some(ServiceLoadBalancerSource {
        class: class.to_owned(),
        ip_families,
        ip_family_policy,
        requested_ips,
        source_ranges,
        allocate_node_ports: spec.allocate_load_balancer_node_ports.unwrap_or(true),
        health_check_node_port,
    }))
}

fn service_ip_family(namespace: &str, name: &str, family: &str) -> Result<AddressFamily> {
    match family {
        "IPv4" => Ok(AddressFamily::Ipv4),
        "IPv6" => Ok(AddressFamily::Ipv6),
        family => Err(anyhow!(
            "Service {namespace}/{name} has unsupported IP family {family:?}"
        )),
    }
}

fn service_external_traffic_policy(
    namespace: &str,
    name: &str,
    policy: Option<&str>,
) -> Result<ServiceTrafficPolicy> {
    match policy.unwrap_or("Cluster") {
        "Cluster" => Ok(ServiceTrafficPolicy::Cluster),
        "Local" => Ok(ServiceTrafficPolicy::Local),
        policy => Err(anyhow!(
            "Service {namespace}/{name} has unsupported externalTrafficPolicy {policy:?}"
        )),
    }
}

fn service_node_port(namespace: &str, name: &str, node_port: Option<i32>) -> Result<Option<u16>> {
    let node_port = node_port.map(u16::try_from).transpose().with_context(|| {
        format!("Service {namespace}/{name} nodePort {node_port:?} is outside the u16 range")
    })?;
    if node_port == Some(0) {
        return Err(anyhow!(
            "Service {namespace}/{name} cannot expose NodePort zero"
        ));
    }
    Ok(node_port)
}

fn service_protocol(protocol: &str) -> Result<Protocol> {
    match protocol {
        "TCP" => Ok(Protocol::Tcp),
        "UDP" => Ok(Protocol::Udp),
        "SCTP" => Ok(Protocol::Sctp),
        _ => Err(anyhow!(
            "unsupported Service or EndpointSlice protocol {protocol:?}"
        )),
    }
}

async fn watch_endpoint_slices(
    api: Api<EndpointSlice>,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
) {
    let stream = watcher::watcher(api, watcher::Config::default()).boxed();
    tokio::pin!(stream);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            item = stream.try_next() => match item {
                Ok(Some(event)) => apply_endpoint_slice_event(&state, event),
                Ok(None) => break,
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, "EndpointSlice watch error");
                }
            }
        }
    }
}

fn apply_endpoint_slice_event(state: &ControllerState, event: Event<EndpointSlice>) {
    let _policy_state_guard = write_lock(&state.policy_state_guard);
    match event {
        Event::Apply(endpoint_slice) | Event::InitApply(endpoint_slice) => {
            let key = object_key(&endpoint_slice);
            match endpoint_slice_record(&endpoint_slice) {
                Ok(record) => {
                    write_lock(&state.rejected_endpoint_slice_sources).remove(&key);
                    let previous = write_lock(&state.endpoint_slices).insert(key, record.clone());
                    state.metrics.reconciles.inc();
                    if previous.as_ref() != Some(&record) {
                        bump_service_and_topology_revision(state);
                    }
                }
                Err(error) => {
                    state.metrics.errors.inc();
                    write_lock(&state.rejected_endpoint_slice_sources)
                        .insert(key.clone(), error.to_string());
                    warn!(%error, %key, "EndpointSlice topology admission failed");
                }
            }
        }
        Event::Delete(endpoint_slice) => {
            let key = object_key(&endpoint_slice);
            write_lock(&state.rejected_endpoint_slice_sources).remove(&key);
            if write_lock(&state.endpoint_slices).remove(&key).is_some() {
                bump_service_and_topology_revision(state);
            }
        }
        Event::Init => {
            begin_topology_initialization(state);
            let had_endpoint_slices = !read_lock(&state.endpoint_slices).is_empty();
            write_lock(&state.endpoint_slices).clear();
            write_lock(&state.rejected_endpoint_slice_sources).clear();
            if had_endpoint_slices {
                bump_service_and_topology_revision(state);
            }
        }
        Event::InitDone => finish_topology_initialization(state),
    }
}

#[allow(clippy::too_many_lines)]
fn endpoint_slice_record(endpoint_slice: &EndpointSlice) -> Result<EndpointSliceRecord> {
    let namespace = endpoint_slice.namespace().ok_or_else(|| {
        anyhow!(
            "EndpointSlice {} is missing namespace",
            endpoint_slice.name_any()
        )
    })?;
    let name = endpoint_slice.name_any();
    let service_name = endpoint_slice
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get("kubernetes.io/service-name"))
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            anyhow!("EndpointSlice {namespace}/{name} is missing kubernetes.io/service-name")
        })?;
    let slice_reference = format!("{namespace}/{name}");
    let address_family = match endpoint_slice.address_type.as_str() {
        "IPv4" => AddressFamily::Ipv4,
        "IPv6" => AddressFamily::Ipv6,
        other => {
            return Err(anyhow!(
                "EndpointSlice {slice_reference} has unsupported address type {other:?}"
            ));
        }
    };
    let ports = endpoint_slice
        .ports
        .iter()
        .flatten()
        .map(|port| {
            let number = port.port.map(u16::try_from).transpose().with_context(|| {
                format!("EndpointSlice {slice_reference} contains a port outside the u16 range")
            })?;
            if number == Some(0) {
                return Err(anyhow!(
                    "EndpointSlice {slice_reference} cannot contain port zero"
                ));
            }
            Ok(TopologyServiceBackendPort {
                name: port.name.clone(),
                protocol: port.protocol.clone().unwrap_or_else(|| "TCP".to_owned()),
                port: number,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut ports = ports;
    ports.sort();
    let mut compiler_ports = endpoint_slice
        .ports
        .iter()
        .flatten()
        .map(|port| {
            let protocol = port.protocol.as_deref().unwrap_or("TCP");
            Ok(EndpointPortSource {
                name: port.name.clone(),
                protocol: service_protocol(protocol)?,
                port: port.port.map(u16::try_from).transpose().with_context(|| {
                    format!("EndpointSlice {slice_reference} contains a port outside the u16 range")
                })?,
                app_protocol: port.app_protocol.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    compiler_ports.sort();

    let mut backends = Vec::with_capacity(endpoint_slice.endpoints.len());
    let mut compiler_endpoints = Vec::with_capacity(endpoint_slice.endpoints.len());
    for endpoint in &endpoint_slice.endpoints {
        let mut addresses = endpoint.addresses.clone();
        addresses.sort();
        addresses.dedup();
        let compiler_addresses = addresses
            .iter()
            .map(|address| {
                address.parse().with_context(|| {
                    format!("EndpointSlice {slice_reference} contains invalid address {address:?}")
                })
            })
            .collect::<Result<Vec<IpAddr>>>()?;
        let conditions = endpoint.conditions.as_ref();
        let ready = conditions.and_then(|value| value.ready).unwrap_or(true);
        let serving = conditions.and_then(|value| value.serving).unwrap_or(ready);
        let terminating = conditions
            .and_then(|value| value.terminating)
            .unwrap_or(false);
        let target_workload = endpoint.target_ref.as_ref().and_then(|target| {
            if target.kind.as_deref() != Some("Pod") {
                return None;
            }
            target.name.as_ref().map(|name| {
                format!(
                    "{}/{}",
                    target.namespace.as_deref().unwrap_or(&namespace),
                    name
                )
            })
        });
        backends.push(TopologyServiceBackend {
            endpoint_slice: slice_reference.clone(),
            address_type: endpoint_slice.address_type.clone(),
            addresses,
            target_workload: target_workload.clone(),
            node_name: endpoint.node_name.clone(),
            zone: endpoint.zone.clone(),
            ready,
            serving,
            terminating,
            ports: ports.clone(),
        });
        compiler_endpoints.push(EndpointSource {
            addresses: compiler_addresses,
            target_workload,
            node_name: endpoint.node_name.clone(),
            zone: endpoint.zone.clone(),
            ready,
            serving,
            terminating,
            ports: compiler_ports.clone(),
        });
    }
    backends.sort();
    compiler_endpoints.sort();
    Ok(EndpointSliceRecord {
        service_reference: format!("{namespace}/{service_name}"),
        backends,
        compiler_source: EndpointSliceSource {
            namespace,
            name,
            service_name: service_name.clone(),
            address_family,
            endpoints: compiler_endpoints,
        },
    })
}

async fn watch_policies(
    api: Api<SecurityPolicy>,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
) {
    let stream = watcher::watcher(api, watcher::Config::default()).boxed();
    tokio::pin!(stream);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            item = stream.try_next() => match item {
                Ok(Some(event)) => apply_policy_event(&state, event),
                Ok(None) => break,
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, "SecurityPolicy watch error");
                }
            }
        }
    }
}

fn apply_policy_event(state: &ControllerState, event: Event<SecurityPolicy>) {
    let _policy_state_guard = write_lock(&state.policy_state_guard);
    match event {
        Event::Apply(policy) | Event::InitApply(policy) => {
            let key = object_key(&policy);
            let id = stable_policy_id(&key);
            match PolicyCompiler::compile(id, policy.clone()) {
                Ok(ir) => {
                    let previous = write_lock(&state.compiled_security_policies)
                        .insert(key.clone(), ir.clone());
                    write_lock(&state.security_policies).insert(key, policy);
                    state.metrics.reconciles.inc();
                    if previous.as_ref() != Some(&ir) {
                        bump_policy_revision(state);
                    }
                }
                Err(error) => {
                    state.metrics.errors.inc();
                    let removed = write_lock(&state.compiled_security_policies)
                        .remove(&key)
                        .is_some();
                    write_lock(&state.security_policies).remove(&key);
                    if removed {
                        bump_policy_revision(state);
                    }
                    warn!(%error, %key, "policy compilation failed");
                }
            }
        }
        Event::Delete(policy) => {
            let key = object_key(&policy);
            write_lock(&state.security_policies).remove(&key);
            if write_lock(&state.compiled_security_policies)
                .remove(&key)
                .is_some()
            {
                bump_policy_revision(state);
            }
        }
        Event::Init => {
            write_lock(&state.security_policies).clear();
            let had_policies = !read_lock(&state.compiled_security_policies).is_empty();
            write_lock(&state.compiled_security_policies).clear();
            if had_policies {
                bump_policy_revision(state);
            }
        }
        Event::InitDone => {}
    }
}

async fn watch_network_policies(
    api: Api<NetworkPolicy>,
    state: Arc<ControllerState>,
    cancellation: CancellationToken,
) {
    let stream = watcher::watcher(api, watcher::Config::default()).boxed();
    tokio::pin!(stream);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            item = stream.try_next() => match item {
                Ok(Some(event)) => apply_network_policy_event(&state, event),
                Ok(None) => break,
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, "NetworkPolicy watch error");
                }
            }
        }
    }
}

fn apply_network_policy_event(state: &ControllerState, event: Event<NetworkPolicy>) {
    let _policy_state_guard = write_lock(&state.policy_state_guard);
    match event {
        Event::Apply(policy) | Event::InitApply(policy) => {
            let key = object_key(&policy);
            let id = stable_policy_id(&format!("networkpolicy:{key}"));
            match NetworkPolicyCompiler::compile_directions(id, policy.clone()) {
                Ok(policies) => {
                    let previous = write_lock(&state.compiled_network_policies)
                        .insert(key.clone(), policies.clone());
                    write_lock(&state.network_policies).insert(key.clone(), policy);
                    write_lock(&state.rejected_network_policies).remove(&key);
                    state.metrics.reconciles.inc();
                    if previous.as_ref() != Some(&policies) {
                        bump_policy_revision(state);
                    }
                }
                Err(error) => {
                    state.metrics.errors.inc();
                    let removed = write_lock(&state.compiled_network_policies)
                        .remove(&key)
                        .is_some();
                    write_lock(&state.network_policies).remove(&key);
                    write_lock(&state.rejected_network_policies)
                        .insert(key.clone(), error.to_string());
                    if removed {
                        bump_policy_revision(state);
                    }
                    warn!(%error, %key, "NetworkPolicy compilation failed");
                }
            }
        }
        Event::Delete(policy) => {
            let key = object_key(&policy);
            write_lock(&state.network_policies).remove(&key);
            write_lock(&state.rejected_network_policies).remove(&key);
            if write_lock(&state.compiled_network_policies)
                .remove(&key)
                .is_some()
            {
                bump_policy_revision(state);
            }
        }
        Event::Init => {
            write_lock(&state.network_policies).clear();
            write_lock(&state.rejected_network_policies).clear();
            let had_policies = !read_lock(&state.compiled_network_policies).is_empty();
            write_lock(&state.compiled_network_policies).clear();
            if had_policies {
                bump_policy_revision(state);
            }
        }
        Event::InitDone => {}
    }
}

async fn health() -> &'static str {
    "ok\n"
}

async fn ready(State(state): State<Arc<ControllerState>>) -> Response {
    if state.ready.load(Ordering::Acquire) {
        (StatusCode::OK, "ready\n").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n").into_response()
    }
}

async fn metrics(State(state): State<Arc<ControllerState>>) -> Response {
    let mut body = String::new();
    match encode(&mut body, &mutex_lock(&state.registry)) {
        Ok(()) => (StatusCode::OK, body).into_response(),
        Err(error) => {
            error!(%error, "encode controller metrics");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn version(
    Query(query): Query<ServiceSchemaQuery>,
) -> Result<Json<ComponentCompatibility>, ApiError> {
    compatibility_for_service_schema(requested_service_schema(&query)?).map(Json)
}

fn component_compatibility() -> ComponentCompatibility {
    ComponentCompatibility::current("unf-controller", env!("CARGO_PKG_VERSION"), BUILD_REVISION)
}

fn requested_service_schema(query: &ServiceSchemaQuery) -> Result<u16, ApiError> {
    let requested = query
        .service_snapshot_schema_version
        .unwrap_or(LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION);
    if matches!(
        requested,
        LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION
            | NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION
            | SERVICE_SNAPSHOT_SCHEMA_VERSION
    ) {
        Ok(requested)
    } else {
        Err(ApiError::bad_request(format!(
            "unsupported requested service snapshot schema {requested}; supported schemas are 1, 2, and {SERVICE_SNAPSHOT_SCHEMA_VERSION}"
        )))
    }
}

fn compatibility_for_service_schema(
    requested_schema: u16,
) -> Result<ComponentCompatibility, ApiError> {
    requested_service_schema(&ServiceSchemaQuery {
        service_snapshot_schema_version: Some(requested_schema),
    })?;
    let mut compatibility = component_compatibility();
    compatibility.service_snapshot_schema_version = requested_schema;
    Ok(compatibility)
}

async fn status(State(state): State<Arc<ControllerState>>) -> Result<Json<StatusBody>, ApiError> {
    let (
        _,
        policy_entries,
        ipv4_policy_entries,
        ipv6_policy_entries,
        egress_ipv4_policy_entries,
        egress_ipv6_policy_entries,
    ) = dataplane_policy_state(&state)?;
    let resolved_ingress_policy_entries =
        policy_entries.len() + ipv4_policy_entries.len() + ipv6_policy_entries.len();
    let resolved_egress_policy_entries =
        egress_ipv4_policy_entries.len() + egress_ipv6_policy_entries.len();
    let resolved_policy_entries = resolved_ingress_policy_entries + resolved_egress_policy_entries;
    let (identity_revision, identity_count, indexed_pod_ips) = {
        let identities = mutex_lock(&state.identities);
        (
            identities.revision(),
            identities.identity_count(),
            identities.address_count(),
        )
    };
    let history = mutex_lock(&state.flow_history).snapshot(state.identity_epoch);
    let mut revisions = mutex_lock(&state.revisions).clone();
    revisions.identity = identity_revision;
    revisions.telemetry = history.revision;
    let agents = agent_convergence_snapshot(
        &state,
        identity_revision,
        revisions.policy,
        unix_time_millis(),
    );
    let (
        compiled_services,
        compiled_service_frontends,
        compiled_service_backends,
        compiled_service_revision,
    ) = compiled_service_counts(&state);
    Ok(Json(StatusBody {
        component: "unf-controller",
        healthy: true,
        ready: state.ready.load(Ordering::Acquire),
        mode: if state.offline {
            "offline"
        } else {
            "kubernetes"
        },
        pods: read_lock(&state.pods).len(),
        nodes: read_lock(&state.nodes).len(),
        assigned_node_blocks: read_lock(&state.node_blocks).len(),
        rejected_node_blocks: read_lock(&state.rejected_node_blocks).len(),
        unroutable_node_transports: read_lock(&state.node_blocks)
            .values()
            .filter(|assignment| assignment.transport.is_err())
            .count(),
        services: read_lock(&state.services).len(),
        endpoint_slices: read_lock(&state.endpoint_slices).len(),
        rejected_service_sources: read_lock(&state.rejected_service_sources).len(),
        rejected_endpoint_slice_sources: read_lock(&state.rejected_endpoint_slice_sources).len(),
        compiled_services,
        compiled_service_frontends,
        compiled_service_backends,
        compiled_service_revision,
        service_compilation_error: read_lock(&state.service_compilation_error).clone(),
        namespaces: read_lock(&state.namespaces).len(),
        security_policies: read_lock(&state.security_policies).len(),
        network_policies: read_lock(&state.network_policies).len(),
        rejected_network_policies: read_lock(&state.rejected_network_policies).len(),
        compiled_policies: read_lock(&state.compiled_security_policies).len()
            + read_lock(&state.compiled_network_policies)
                .values()
                .map(Vec::len)
                .sum::<usize>(),
        resolved_policy_entries,
        resolved_ingress_policy_entries,
        resolved_egress_policy_entries,
        identities: identity_count,
        indexed_pod_ips,
        retained_flows: history.retained_flows,
        retained_flow_observations: history.retained_observations,
        telemetry_dropped_events: history
            .agent_dropped_events
            .saturating_add(history.evicted_observations),
        identity_epoch: state.identity_epoch,
        revisions,
        agents,
        limitations: [
            "desired state and identity allocations are currently in-memory only",
            "agent acknowledgements and the newest bounded flow history use separate single-controller ConfigMap checkpoints",
            "service translation is bounded to primary-CNI Pod clients plus host-origin ClusterIP, IPv4/IPv6 TCP/UDP, and NodePort Cluster/Local traffic; LoadBalancer allocation/reachability/host state/packet translation, session affinity, DSR, SCTP, fragments, and host-origin NodePort clients remain unqualified",
        ],
    }))
}

fn compiled_service_counts(state: &ControllerState) -> (usize, usize, usize, u64) {
    read_lock(&state.compiled_service_snapshot)
        .as_ref()
        .map_or((0, 0, 0, 0), |snapshot| {
            (
                snapshot.services.len(),
                snapshot
                    .services
                    .iter()
                    .map(|service| service.frontends.len())
                    .sum(),
                snapshot
                    .services
                    .iter()
                    .map(|service| service.backends.len())
                    .sum(),
                snapshot.revision.get(),
            )
        })
}

async fn agent_state(State(state): State<Arc<ControllerState>>) -> Json<AgentConvergenceSnapshot> {
    let identity_revision = mutex_lock(&state.identities).revision();
    let policy_revision = mutex_lock(&state.revisions).policy;
    Json(agent_convergence_snapshot(
        &state,
        identity_revision,
        policy_revision,
        unix_time_millis(),
    ))
}

async fn ingest_agent_status(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
    Json(report): Json<AgentStateReport>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate_internal_agent(&state, &headers).await?;
    if let Err(error) =
        validate_agent_claims(&agent, &report.node_name, &report.pod_name, &report.pod_uid)
    {
        state.metrics.agent_authentication_failures.inc();
        return Err(error);
    }
    validate_agent_status(&report)?;
    let mut reports = write_lock(&state.agent_reports);
    if !reports.contains_key(&report.node_name) && reports.len() >= AGENT_REPORT_STORE_CAPACITY {
        return Err(ApiError::service_unavailable(
            "durable agent-report capacity is exhausted",
        ));
    }
    reports.insert(
        report.node_name.clone(),
        StoredAgentReport {
            report,
            last_received_unix_ms: unix_time_millis(),
        },
    );
    drop(reports);
    state.agent_reports_dirty.store(true, Ordering::Release);
    state.metrics.agent_status_reports.inc();
    Ok(StatusCode::NO_CONTENT)
}

async fn authenticate_internal_agent(
    state: &ControllerState,
    headers: &HeaderMap,
) -> Result<AuthenticatedAgent, ApiError> {
    let result = authenticate_internal_agent_inner(state, headers).await;
    if result.is_err() {
        state.metrics.agent_authentication_failures.inc();
    }
    result
}

async fn authenticate_internal_agent_inner(
    state: &ControllerState,
    headers: &HeaderMap,
) -> Result<AuthenticatedAgent, ApiError> {
    let token = bearer_token(headers)?;
    if let Some(agent) = cached_agent_authentication(state, token)? {
        return Ok(agent);
    }
    let client = state.token_review_client.as_ref().ok_or_else(|| {
        ApiError::service_unavailable("agent authentication requires Kubernetes TokenReview")
    })?;
    let review = TokenReview {
        spec: TokenReviewSpec {
            audiences: Some(vec![AGENT_TOKEN_AUDIENCE.to_owned()]),
            token: Some(token.to_owned()),
        },
        ..TokenReview::default()
    };
    let reviewed = Api::<TokenReview>::all(client.clone())
        .create(&PostParams::default(), &review)
        .await
        .map_err(|_| ApiError::service_unavailable("Kubernetes TokenReview failed"))?;
    let status = reviewed
        .status
        .as_ref()
        .ok_or_else(|| ApiError::unauthorized("agent token was not authenticated"))?;
    let agent = validate_agent_token_identity(status, &read_lock(&state.pods))?;
    cache_agent_authentication(state, token, agent.clone());
    Ok(agent)
}

fn cached_agent_authentication(
    state: &ControllerState,
    token: &str,
) -> Result<Option<AuthenticatedAgent>, ApiError> {
    let now = Instant::now();
    let cached = {
        let mut cache = mutex_lock(&state.agent_authentication_cache);
        cache.retain(|_, entry| {
            now.duration_since(entry.validated_at) < AGENT_AUTHENTICATION_CACHE_TTL
        });
        cache.get(token).cloned()
    };
    let Some(cached) = cached else {
        return Ok(None);
    };
    validate_authoritative_agent(&cached.agent, &read_lock(&state.pods))?;
    Ok(Some(cached.agent))
}

fn cache_agent_authentication(state: &ControllerState, token: &str, agent: AuthenticatedAgent) {
    let mut cache = mutex_lock(&state.agent_authentication_cache);
    if cache.len() >= AGENT_AUTHENTICATION_CACHE_CAPACITY
        && let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.validated_at)
            .map(|(token, _)| token.clone())
    {
        cache.remove(&oldest);
    }
    cache.insert(
        token.to_owned(),
        CachedAgentAuthentication {
            agent,
            validated_at: Instant::now(),
        },
    );
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let authorization = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("invalid authorization header"))?;
    let token = authorization
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
        .ok_or_else(|| ApiError::unauthorized("invalid bearer token"))?;
    Ok(token)
}

fn validate_agent_token_identity(
    status: &TokenReviewStatus,
    pods: &BTreeMap<String, PodRecord>,
) -> Result<AuthenticatedAgent, ApiError> {
    if status.authenticated != Some(true) || status.error.is_some() {
        return Err(ApiError::unauthorized("agent token was not authenticated"));
    }
    if !status
        .audiences
        .as_ref()
        .is_some_and(|audiences| audiences.iter().any(|value| value == AGENT_TOKEN_AUDIENCE))
    {
        return Err(ApiError::unauthorized(
            "agent token has an incompatible audience",
        ));
    }
    let user = status
        .user
        .as_ref()
        .ok_or_else(|| ApiError::unauthorized("agent token has no user identity"))?;
    if user.username.as_deref() != Some(AGENT_SERVICE_ACCOUNT_USERNAME) {
        return Err(ApiError::forbidden(
            "agent token does not identify the UNF agent service account",
        ));
    }
    let extra = user
        .extra
        .as_ref()
        .ok_or_else(|| ApiError::forbidden("agent token is not bound to a Pod"))?;
    let pod_name = exact_extra_value(extra, POD_NAME_EXTRA)
        .ok_or_else(|| ApiError::forbidden("agent token has no unique Pod name"))?;
    let pod_uid = exact_extra_value(extra, POD_UID_EXTRA)
        .ok_or_else(|| ApiError::forbidden("agent token has no unique Pod UID"))?;
    let pod_key = format!("unf-system/{pod_name}");
    let pod = pods
        .get(&pod_key)
        .ok_or_else(|| ApiError::forbidden("agent Pod is not present in watched state"))?;
    if pod.uid != pod_uid || pod.endpoint.service_account != "unf-agent" {
        return Err(ApiError::forbidden(
            "agent token does not match its authoritative Pod identity",
        ));
    }
    let node_name = pod
        .node_name
        .clone()
        .ok_or_else(|| ApiError::forbidden("agent Pod has no authoritative Node placement"))?;
    Ok(AuthenticatedAgent {
        node_name,
        pod_name: pod_name.to_owned(),
        pod_uid: pod_uid.to_owned(),
    })
}

fn validate_agent_claims(
    agent: &AuthenticatedAgent,
    node_name: &str,
    pod_name: &str,
    pod_uid: &str,
) -> Result<(), ApiError> {
    if agent.node_name != node_name || agent.pod_name != pod_name || agent.pod_uid != pod_uid {
        return Err(ApiError::forbidden(
            "agent request does not match its authoritative Pod placement",
        ));
    }
    Ok(())
}

fn validate_authoritative_agent(
    agent: &AuthenticatedAgent,
    pods: &BTreeMap<String, PodRecord>,
) -> Result<(), ApiError> {
    let pod_key = format!("unf-system/{}", agent.pod_name);
    let pod = pods
        .get(&pod_key)
        .ok_or_else(|| ApiError::forbidden("agent Pod is not present in watched state"))?;
    if pod.uid != agent.pod_uid
        || pod.endpoint.service_account != "unf-agent"
        || pod.node_name.as_deref() != Some(agent.node_name.as_str())
    {
        return Err(ApiError::forbidden(
            "cached agent identity no longer matches authoritative Pod placement",
        ));
    }
    Ok(())
}

fn exact_extra_value<'value>(
    extra: &'value BTreeMap<String, Vec<String>>,
    key: &str,
) -> Option<&'value str> {
    let values = extra.get(key)?;
    (values.len() == 1).then(|| values[0].as_str())
}

fn validate_agent_status(report: &AgentStateReport) -> Result<(), ApiError> {
    if report.schema_version != AGENT_STATUS_SCHEMA_VERSION {
        return Err(ApiError::bad_request(format!(
            "unsupported agent status schema {}; expected {}",
            report.schema_version, AGENT_STATUS_SCHEMA_VERSION
        )));
    }
    let valid_node_name = !report.node_name.is_empty()
        && report.node_name.len() <= 253
        && report
            .node_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && report
            .node_name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && report
            .node_name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !valid_node_name {
        return Err(ApiError::bad_request(
            "node_name must be a valid 1 to 253 character Kubernetes node name",
        ));
    }
    if report.pod_name.is_empty() || report.pod_name.len() > 253 {
        return Err(ApiError::bad_request(
            "pod_name must be a valid 1 to 253 character Kubernetes Pod name",
        ));
    }
    if report.pod_uid.is_empty() || report.pod_uid.len() > 128 {
        return Err(ApiError::bad_request(
            "pod_uid must identify the reporting Kubernetes Pod",
        ));
    }
    if report.active_policy_bank > 1 {
        return Err(ApiError::bad_request(
            "active_policy_bank must identify transactional bank 0 or 1",
        ));
    }
    if report.service_snapshot_schema_version > SERVICE_SNAPSHOT_SCHEMA_VERSION {
        return Err(ApiError::bad_request(format!(
            "unsupported reported service snapshot schema {}; controller supports at most {}",
            report.service_snapshot_schema_version, SERVICE_SNAPSHOT_SCHEMA_VERSION
        )));
    }
    if report
        .service_last_error
        .as_ref()
        .is_some_and(|error| error.is_empty() || error.len() > 1_024)
    {
        return Err(ApiError::bad_request(
            "service_last_error must be nonempty and at most 1024 bytes when present",
        ));
    }
    validate_service_dataplane_status(report)?;
    let service_revision_pairs = [
        (
            report.desired_service_epoch,
            report.desired_service_revision,
        ),
        (
            report.applied_service_epoch,
            report.applied_service_revision,
        ),
        (report.failed_service_epoch, report.failed_service_revision),
    ];
    if service_revision_pairs
        .iter()
        .any(|(epoch, revision)| (*epoch == 0) != (*revision == 0))
    {
        return Err(ApiError::bad_request(
            "service epoch and revision must both be zero or both be nonzero",
        ));
    }
    validate_service_status_counts(report)?;
    validate_load_balancer_status(report)
}

fn validate_load_balancer_status(report: &AgentStateReport) -> Result<(), ApiError> {
    if report.load_balancer_reachability_schema_version
        > unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION
    {
        return Err(ApiError::bad_request(
            "reported LoadBalancer reachability schema is newer than the controller",
        ));
    }
    for (epoch, revision) in [
        (
            report.desired_load_balancer_epoch,
            report.desired_load_balancer_revision,
        ),
        (
            report.applied_load_balancer_epoch,
            report.applied_load_balancer_revision,
        ),
    ] {
        if (epoch == 0) != (revision == 0) {
            return Err(ApiError::bad_request(
                "LoadBalancer epoch and revision must both be zero or both be nonzero",
            ));
        }
    }
    if report.active_load_balancer_bank > 1
        || (report.applied_load_balancer_revision == 0
            && (report.load_balancer_frontend_count != 0
                || report.load_balancer_cluster_frontend_count != 0
                || report.load_balancer_local_frontend_count != 0
                || report.load_balancer_source_range_count != 0))
        || (report.desired_load_balancer_revision == 0
            && report.desired_load_balancer_allocation_revision != 0)
        || (report.applied_load_balancer_revision == 0
            && report.applied_load_balancer_allocation_revision != 0)
        || (report.load_balancer_last_error.is_some() && report.load_balancer_reconcile_errors == 0)
        || report.load_balancer_frontend_count
            > u64::try_from(unf_loadbalancer::LOAD_BALANCER_FRONTEND_BANK_CAPACITY)
                .expect("LoadBalancer capacity fits u64")
        || report.load_balancer_frontend_count
            != report
                .load_balancer_cluster_frontend_count
                .saturating_add(report.load_balancer_local_frontend_count)
        || report.load_balancer_source_range_count
            > u64::try_from(unf_loadbalancer::LOAD_BALANCER_FRONTEND_BANK_CAPACITY)
                .expect("LoadBalancer capacity fits u64")
        || report.load_balancer_health_check_ready_count > report.load_balancer_health_check_count
        || report
            .load_balancer_last_error
            .as_ref()
            .is_some_and(|error| error.is_empty() || error.len() > 1_024)
    {
        return Err(ApiError::bad_request(
            "LoadBalancer host-state status is internally inconsistent",
        ));
    }
    Ok(())
}

fn validate_service_status_counts(report: &AgentStateReport) -> Result<(), ApiError> {
    if report.applied_service_revision == 0
        && (report.service_count != 0
            || report.service_frontend_count != 0
            || report.service_backend_count != 0
            || report.applied_node_port_frontend_count != 0)
    {
        return Err(ApiError::bad_request(
            "service counts require a nonzero applied service revision",
        ));
    }
    if report.desired_service_revision == 0 && report.desired_node_port_frontend_count != 0 {
        return Err(ApiError::bad_request(
            "desired NodePort count requires a nonzero desired service revision",
        ));
    }
    if report
        .node_port_cluster_frontend_count
        .saturating_add(report.node_port_local_frontend_count)
        != report.applied_node_port_frontend_count
    {
        return Err(ApiError::bad_request(
            "NodePort Cluster and Local counts must sum to the applied NodePort count",
        ));
    }
    Ok(())
}

fn validate_service_dataplane_status(report: &AgentStateReport) -> Result<(), ApiError> {
    if report
        .service_translations
        .saturating_add(report.service_drops)
        .saturating_add(report.service_expirations)
        != report.service_dataplane_events
    {
        return Err(ApiError::bad_request(
            "service dataplane outcome counters must sum to service_dataplane_events",
        ));
    }
    if report
        .node_port_cluster_translations
        .saturating_add(report.node_port_local_translations)
        > report.service_translations
        || report.node_port_no_backend_drops > report.service_drops
    {
        return Err(ApiError::bad_request(
            "NodePort outcome counters must be bounded by service outcome counters",
        ));
    }
    let last_is_empty = report.last_service_id == 0
        && report.last_backend_id == 0
        && report.last_service_revision == 0
        && report.last_service_action == 0
        && report.last_service_reason == 0;
    let last_action_reason_is_valid = matches!(
        (report.last_service_action, report.last_service_reason),
        (1, 1 | 2) | (2, 3..=10) | (3, 11)
    );
    if (report.service_dataplane_events == 0 && !last_is_empty)
        || (report.service_dataplane_events != 0
            && (!last_action_reason_is_valid
                || report.last_service_id == 0
                || report.last_service_revision == 0
                || (report.last_service_action == 1 && report.last_backend_id == 0)))
    {
        return Err(ApiError::bad_request(
            "last service dataplane outcome is inconsistent with its event count",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn agent_convergence_snapshot(
    state: &ControllerState,
    identity_revision: Revision,
    policy_revision: Revision,
    now_unix_ms: u64,
) -> AgentConvergenceSnapshot {
    let expected_nodes: BTreeSet<_> = read_lock(&state.nodes)
        .values()
        .filter(|node| agent_node_matches(node, state.agent_node_selector.as_deref()))
        .map(|node| node.name.clone())
        .collect();
    let reports = read_lock(&state.agent_reports);
    let node_block_revisions: BTreeMap<_, _> = read_lock(&state.node_blocks)
        .iter()
        .map(|(node_name, assignment)| (node_name.clone(), assignment.revision))
        .collect();
    let routing_revision = mutex_lock(&state.revisions).routing;
    let service_revision = read_lock(&state.compiled_service_snapshot)
        .as_ref()
        .map(|snapshot| {
            (
                snapshot.source_epoch,
                snapshot.revision,
                snapshot.services.iter().any(|service| {
                    !service.node_ports.is_empty() || service.load_balancer.is_some()
                }),
            )
        })
        .unwrap_or_default();
    let load_balancer_revision = read_lock(&state.compiled_load_balancer_reachability)
        .as_ref()
        .map(|snapshot| {
            (
                snapshot.source_epoch,
                snapshot.revision,
                snapshot.allocation_revision,
            )
        });
    let unexpected_agents = reports
        .iter()
        .filter(|(node_name, stored)| {
            !expected_nodes.contains(*node_name)
                && now_unix_ms.saturating_sub(stored.last_received_unix_ms)
                    <= AGENT_STATUS_FRESHNESS_MILLIS
        })
        .count();
    let mut reporting_agents = 0;
    let mut stale_agents = 0;
    let mut converged_agents = 0;
    let nodes = expected_nodes
        .iter()
        .map(|node_name| {
            let stored = reports.get(node_name);
            let fresh = stored.is_some_and(|stored| {
                now_unix_ms.saturating_sub(stored.last_received_unix_ms)
                    <= AGENT_STATUS_FRESHNESS_MILLIS
            });
            if stored.is_some() {
                reporting_agents += 1;
            }
            if stored.is_some() && !fresh {
                stale_agents += 1;
            }
            let converged = stored.is_some_and(|stored| {
                fresh
                    && agent_report_matches(
                        &stored.report,
                        state.identity_epoch,
                        identity_revision,
                        policy_revision,
                        service_revision,
                        load_balancer_revision,
                        node_block_revisions
                            .get(node_name)
                            .copied()
                            .unwrap_or_default(),
                        if node_block_revisions.contains_key(node_name) {
                            (state.identity_epoch, routing_revision)
                        } else {
                            Default::default()
                        },
                    )
            });
            if converged {
                converged_agents += 1;
            }
            AgentConvergenceEntry {
                node_name: node_name.clone(),
                fresh,
                converged,
                last_received_unix_ms: stored.map(|stored| stored.last_received_unix_ms),
                report: stored.map(|stored| stored.report.clone()),
            }
        })
        .collect();
    let expected_agents = expected_nodes.len();
    AgentConvergenceSnapshot {
        schema_version: AGENT_STATUS_SCHEMA_VERSION,
        expected_agents,
        reporting_agents,
        missing_agents: expected_agents.saturating_sub(reporting_agents),
        stale_agents,
        converged_agents,
        unexpected_agents,
        all_converged: expected_agents != 0
            && converged_agents == expected_agents
            && unexpected_agents == 0,
        nodes,
    }
}

fn validate_agent_node_selector(value: &str) -> std::result::Result<String, String> {
    let value = value.trim();
    let (key, expected_value) = value
        .split_once('=')
        .map_or((value, None), |(key, expected)| (key, Some(expected)));
    if key.is_empty()
        || expected_value.is_some_and(str::is_empty)
        || value.chars().any(char::is_whitespace)
        || expected_value.is_some_and(|expected| expected.contains('='))
    {
        return Err("agent Node selector must be an exact label key or key=value pair".to_owned());
    }
    Ok(value.to_owned())
}

fn parse_flow_export_queue_capacity(value: &str) -> std::result::Result<usize, String> {
    let capacity = value
        .parse::<usize>()
        .map_err(|_| "flow-export queue capacity must be an integer".to_owned())?;
    (1..=4_096)
        .contains(&capacity)
        .then_some(capacity)
        .ok_or_else(|| "flow-export queue capacity must be between 1 and 4096".to_owned())
}

fn parse_flow_export_max_attempts(value: &str) -> std::result::Result<u8, String> {
    let attempts = value
        .parse::<u8>()
        .map_err(|_| "flow-export max attempts must be an integer".to_owned())?;
    (1..=10)
        .contains(&attempts)
        .then_some(attempts)
        .ok_or_else(|| "flow-export max attempts must be between 1 and 10".to_owned())
}

fn parse_flow_export_timeout_seconds(value: &str) -> std::result::Result<u64, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| "flow-export timeout must be an integer".to_owned())?;
    (1..=300)
        .contains(&seconds)
        .then_some(seconds)
        .ok_or_else(|| "flow-export timeout must be between 1 and 300 seconds".to_owned())
}

fn agent_node_matches(node: &TopologyNode, selector: Option<&str>) -> bool {
    let Some(selector) = selector else {
        return true;
    };
    if let Some((key, expected)) = selector.split_once('=') {
        node.labels.get(key).is_some_and(|value| value == expected)
    } else {
        node.labels.contains_key(selector)
    }
}

#[allow(clippy::too_many_arguments)]
fn agent_report_matches(
    report: &AgentStateReport,
    expected_epoch: u64,
    identity_revision: Revision,
    policy_revision: Revision,
    service_revision: (u64, Revision, bool),
    load_balancer_revision: Option<(u64, Revision, Revision)>,
    node_block_revision: Revision,
    remote_route_revision: (u64, Revision),
) -> bool {
    report.ready
        && report.bpf_loaded
        && report.desired_identity_epoch == expected_epoch
        && report.applied_identity_epoch == expected_epoch
        && report.desired_identity_revision == identity_revision.get()
        && report.applied_identity_revision == identity_revision.get()
        && report.desired_policy_epoch == expected_epoch
        && report.applied_policy_epoch == expected_epoch
        && report.desired_policy_revision == policy_revision.get()
        && report.applied_policy_revision == policy_revision.get()
        && report.desired_service_epoch == service_revision.0
        && report.applied_service_epoch == service_revision.0
        && report.desired_service_revision == service_revision.1.get()
        && report.applied_service_revision == service_revision.1.get()
        && (!service_revision.2
            || report.service_snapshot_schema_version >= SERVICE_SNAPSHOT_SCHEMA_VERSION)
        && report.failed_service_epoch == 0
        && report.failed_service_revision == 0
        && report.service_last_error.is_none()
        && load_balancer_revision.is_none_or(|(epoch, revision, allocation_revision)| {
            report.load_balancer_reachability_schema_version
                >= unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION
                && report.desired_load_balancer_epoch == epoch
                && report.applied_load_balancer_epoch == epoch
                && report.desired_load_balancer_revision == revision.get()
                && report.applied_load_balancer_revision == revision.get()
                && report.desired_load_balancer_allocation_revision == allocation_revision.get()
                && report.applied_load_balancer_allocation_revision == allocation_revision.get()
                && report.load_balancer_last_error.is_none()
        })
        && report.desired_node_block_revision == node_block_revision.get()
        && report.applied_node_block_revision == node_block_revision.get()
        && report.desired_remote_route_epoch == remote_route_revision.0
        && report.applied_remote_route_epoch == remote_route_revision.0
        && report.desired_remote_route_revision == remote_route_revision.1.get()
        && report.applied_remote_route_revision == remote_route_revision.1.get()
}

async fn identity_snapshot(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
) -> Result<Json<IdentityStateSnapshot>, ApiError> {
    authenticate_internal_agent(&state, &headers).await?;
    Ok(Json(
        mutex_lock(&state.identities).identity_snapshot(state.identity_epoch),
    ))
}

async fn policy_snapshot(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
) -> Result<Json<PolicyStateSnapshot>, ApiError> {
    authenticate_internal_agent(&state, &headers).await?;
    let (revision, entries, ipv4_entries, ipv6_entries, egress_ipv4_entries, egress_ipv6_entries) =
        dataplane_policy_state(&state)?;
    Ok(Json(PolicyStateSnapshot {
        schema_version: POLICY_SNAPSHOT_SCHEMA_VERSION,
        source_epoch: state.identity_epoch,
        revision,
        entries,
        ipv4_entries,
        ipv6_entries,
        egress_ipv4_entries,
        egress_ipv6_entries,
    }))
}

async fn service_snapshot(
    State(state): State<Arc<ControllerState>>,
    Query(query): Query<ServiceSchemaQuery>,
    headers: HeaderMap,
) -> Result<Json<ServiceSnapshot>, ApiError> {
    authenticate_internal_agent(&state, &headers).await?;
    service_snapshot_for_schema(&state, requested_service_schema(&query)?).map(Json)
}

fn service_snapshot_for(state: &ControllerState) -> Result<ServiceSnapshot, ApiError> {
    read_lock(&state.compiled_service_snapshot)
        .clone()
        .ok_or_else(|| {
            ApiError::service_unavailable("service state has no authoritative compiled revision")
        })
}

fn service_snapshot_for_schema(
    state: &ControllerState,
    requested_service_schema: u16,
) -> Result<ServiceSnapshot, ApiError> {
    let snapshot = service_snapshot_for(state)?;
    match requested_service_schema {
        SERVICE_SNAPSHOT_SCHEMA_VERSION => Ok(snapshot),
        NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION => {
            snapshot.node_port_v2_projection().map_err(|error| {
                ApiError::internal(format!("project NodePort service snapshot: {error}"))
            })
        }
        LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION => {
            snapshot.legacy_v1_projection().map_err(|error| {
                ApiError::internal(format!("project legacy service snapshot: {error}"))
            })
        }
        _ => Err(ApiError::bad_request(format!(
            "unsupported requested service snapshot schema {requested_service_schema}"
        ))),
    }
}

async fn node_block_snapshot(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
) -> Result<Json<NodeBlockSnapshot>, ApiError> {
    let agent = authenticate_internal_agent(&state, &headers).await?;
    Ok(Json(node_block_snapshot_for(&state, &agent.node_name)?))
}

async fn node_port_node_snapshot(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
) -> Result<Json<NodePortNodeSnapshot>, ApiError> {
    let agent = authenticate_internal_agent(&state, &headers).await?;
    node_port_node_snapshot_for(&state, &agent.node_name).map(Json)
}

async fn load_balancer_reachability_snapshot(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
) -> Result<Json<NodeReachabilitySnapshot>, ApiError> {
    let agent = authenticate_internal_agent(&state, &headers).await?;
    load_balancer_reachability_snapshot_for(&state, &agent.node_name).map(Json)
}

fn load_balancer_reachability_snapshot_for(
    state: &ControllerState,
    node_name: &str,
) -> Result<NodeReachabilitySnapshot, ApiError> {
    let node_uid = read_lock(&state.node_port_nodes)
        .get(node_name)
        .map(|node| node.node_uid.clone())
        .ok_or_else(|| {
            ApiError::service_unavailable(format!(
                "node {node_name} has no authoritative UID for LoadBalancer reachability"
            ))
        })?;
    read_lock(&state.compiled_load_balancer_reachability)
        .as_ref()
        .ok_or_else(|| {
            ApiError::service_unavailable(
                "LoadBalancer reachability has no authoritative desired revision",
            )
        })?
        .for_node(node_name, &node_uid)
        .map_err(|error| {
            ApiError::internal(format!(
                "project LoadBalancer reachability for node {node_name}: {error}"
            ))
        })
}

fn node_port_node_snapshot_for(
    state: &ControllerState,
    node_name: &str,
) -> Result<NodePortNodeSnapshot, ApiError> {
    let record = read_lock(&state.node_port_nodes)
        .get(node_name)
        .cloned()
        .ok_or_else(|| {
            let detail = read_lock(&state.rejected_node_port_nodes)
                .get(node_name)
                .cloned()
                .unwrap_or_else(|| "Node has not published eligible addresses".to_owned());
            ApiError::service_unavailable(format!(
                "node {node_name} has no valid NodePort address intent: {detail}"
            ))
        })?;
    NodePortNodeSnapshot {
        schema_version: NODE_PORT_NODE_SNAPSHOT_SCHEMA_VERSION,
        source_epoch: state.identity_epoch,
        revision: record.revision,
        node_name: node_name.to_owned(),
        node_uid: record.node_uid,
        addresses: record.addresses,
    }
    .validate_and_normalize()
    .map_err(|error| ApiError::internal(format!("validate NodePort Node state: {error}")))
}

async fn remote_route_snapshot(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
) -> Result<Json<RemoteRouteSnapshot>, ApiError> {
    let agent = authenticate_internal_agent(&state, &headers).await?;
    Ok(Json(remote_route_snapshot_for(&state, &agent.node_name)?))
}

fn node_block_snapshot_for(
    state: &ControllerState,
    node_name: &str,
) -> Result<NodeBlockSnapshot, ApiError> {
    let assignment = read_lock(&state.node_blocks)
        .get(node_name)
        .cloned()
        .ok_or_else(|| {
            ApiError::service_unavailable(format!(
                "node {node_name} has no valid opt-in dual-stack block assignment"
            ))
        })?;
    Ok(NodeBlockSnapshot {
        schema_version: NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION,
        revision: assignment.revision.get(),
        node_name: node_name.to_owned(),
        node_uid: assignment.node_uid,
        provider: assignment.provider,
    })
}

fn remote_route_snapshot_for(
    state: &ControllerState,
    node_name: &str,
) -> Result<RemoteRouteSnapshot, ApiError> {
    let assignments = read_lock(&state.node_blocks);
    let local = assignments.get(node_name).ok_or_else(|| {
        ApiError::service_unavailable(format!(
            "node {node_name} has no valid opt-in dual-stack block assignment"
        ))
    })?;
    if assignments.len().saturating_sub(1) > MAX_REMOTE_NODES {
        return Err(ApiError::service_unavailable(format!(
            "remote route snapshot exceeds the {MAX_REMOTE_NODES}-node safety bound"
        )));
    }
    let mut remote_nodes = Vec::with_capacity(assignments.len().saturating_sub(1));
    let mut ipv4_transports = BTreeSet::new();
    let mut ipv6_transports = BTreeSet::new();
    for (remote_name, assignment) in assignments.iter() {
        let transport = assignment.transport.as_ref().map_err(|error| {
            ApiError::service_unavailable(format!(
                "remote route snapshot is incomplete because node {remote_name} has invalid transport addresses: {error}"
            ))
        })?;
        if !ipv4_transports.insert(transport.ipv4) || !ipv6_transports.insert(transport.ipv6) {
            return Err(ApiError::service_unavailable(format!(
                "remote route snapshot has duplicate Node transport addresses at node {remote_name}"
            )));
        }
        if remote_name == node_name {
            continue;
        }
        remote_nodes.push(RemoteRouteSnapshotNode {
            intent: RemoteNodeIntent {
                node_name: remote_name.clone(),
                node_uid: assignment.node_uid.clone(),
                assignment_revision: assignment.revision.get(),
                blocks: assignment.provider,
            },
            ipv4_transport: transport.ipv4,
            ipv6_transport: transport.ipv6,
        });
    }
    let revision = mutex_lock(&state.revisions).routing.get();
    if revision == 0 {
        return Err(ApiError::service_unavailable(
            "remote route state has no authoritative revision",
        ));
    }
    Ok(RemoteRouteSnapshot {
        schema_version: REMOTE_ROUTE_SNAPSHOT_SCHEMA_VERSION,
        source_epoch: state.identity_epoch,
        revision,
        node_name: node_name.to_owned(),
        node_uid: local.node_uid.clone(),
        local_assignment_revision: local.revision.get(),
        local_blocks: local.provider,
        remote_nodes,
    })
}

async fn topology(State(state): State<Arc<ControllerState>>) -> Json<TopologyStateSnapshot> {
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    Json(topology_snapshot(&state))
}

async fn topology_history(
    State(state): State<Arc<ControllerState>>,
    Query(query): Query<TopologyHistoryQuery>,
) -> Result<Json<TopologyHistorySnapshot>, ApiError> {
    let limit = validate_topology_history_query(&query)?;
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    let checkpointed = usize::try_from(
        state
            .topology_history_checkpointed_snapshots
            .load(Ordering::Acquire),
    )
    .unwrap_or(usize::MAX);
    let mut snapshot = mutex_lock(&state.topology_history).snapshot_window(
        query.since_revision,
        query.until_revision,
        query.since_unix_ms,
        query.until_unix_ms,
        limit,
        checkpointed,
    );
    snapshot.durable_omitted_snapshots = state
        .topology_history_checkpoint_omitted_snapshots
        .load(Ordering::Acquire);
    Ok(Json(snapshot))
}

fn validate_topology_history_query(query: &TopologyHistoryQuery) -> Result<usize, ApiError> {
    let limit = query.limit.unwrap_or(TOPOLOGY_HISTORY_CAPACITY);
    if limit == 0 || limit > TOPOLOGY_HISTORY_CAPACITY {
        return Err(ApiError::bad_request(format!(
            "topology-history limit must be between 1 and {TOPOLOGY_HISTORY_CAPACITY}"
        )));
    }
    if query
        .since_revision
        .zip(query.until_revision)
        .is_some_and(|(since, until)| since > until)
    {
        return Err(ApiError::bad_request(
            "topology-history since_revision must not exceed until_revision",
        ));
    }
    if query
        .since_unix_ms
        .zip(query.until_unix_ms)
        .is_some_and(|(since, until)| since > until)
    {
        return Err(ApiError::bad_request(
            "topology-history since_unix_ms must not exceed until_unix_ms",
        ));
    }
    Ok(limit)
}

fn topology_snapshot(state: &ControllerState) -> TopologyStateSnapshot {
    let pods = read_lock(&state.pods);
    let mut service_backends: BTreeMap<String, Vec<TopologyServiceBackend>> = BTreeMap::new();
    for endpoint_slice in read_lock(&state.endpoint_slices).values() {
        service_backends
            .entry(endpoint_slice.service_reference.clone())
            .or_default()
            .extend(endpoint_slice.backends.iter().cloned());
    }
    for backends in service_backends.values_mut() {
        backends.sort();
        backends.dedup();
    }
    let nodes = read_lock(&state.nodes).values().cloned().collect();
    let workloads = pods
        .iter()
        .map(|(reference, pod)| TopologyWorkload {
            reference: reference.clone(),
            identity_id: pod.endpoint.identity,
            namespace: pod.namespace.clone(),
            name: pod.name.clone(),
            node_name: pod.node_name.clone(),
            service_account: pod.endpoint.service_account.clone(),
            application: pod.endpoint.application.clone(),
            labels: pod.endpoint.labels.clone(),
            ipv4_addresses: pod.ipv4_addresses.iter().copied().collect(),
            ipv6_addresses: pod.ipv6_addresses.iter().copied().collect(),
        })
        .collect();
    let services = read_lock(&state.services)
        .iter()
        .map(|(reference, service)| {
            let selected_workloads = if service.selector.is_empty() {
                Vec::new()
            } else {
                pods.iter()
                    .filter(|(_, pod)| {
                        pod.namespace == service.namespace
                            && service
                                .selector
                                .iter()
                                .all(|(key, value)| pod.endpoint.labels.get(key) == Some(value))
                    })
                    .map(|(reference, _)| reference.clone())
                    .collect()
            };
            TopologyService {
                reference: reference.clone(),
                namespace: service.namespace.clone(),
                name: service.name.clone(),
                service_type: service.service_type.clone(),
                cluster_ips: service.cluster_ips.iter().copied().collect(),
                selector: service.selector.clone(),
                ports: service.ports.clone(),
                selected_workloads,
                backends: service_backends.get(reference).cloned().unwrap_or_default(),
            }
        })
        .collect();
    let identity_revision = mutex_lock(&state.identities).revision();
    let revisions = mutex_lock(&state.revisions).clone();
    TopologyStateSnapshot {
        schema_version: TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
        source_epoch: state.identity_epoch,
        revision: revisions.topology,
        identity_revision,
        nodes,
        workloads,
        services,
    }
}

async fn flow_history(
    State(state): State<Arc<ControllerState>>,
    Query(query): Query<FlowHistoryQuery>,
) -> Result<Json<FlowHistorySnapshot>, ApiError> {
    let limit = validate_flow_history_query(&query)?;
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    Ok(Json(flow_history_snapshot_window(
        &state,
        query.since_unix_ms,
        query.until_unix_ms,
        limit,
    )))
}

async fn explain_service(
    State(state): State<Arc<ControllerState>>,
    Query(query): Query<ServiceExplainQuery>,
) -> Result<Json<ServiceExplanation>, ApiError> {
    if query.service_id == 0 || query.backend_id == Some(0) {
        return Err(ApiError::bad_request(
            "service_id and backend_id must be nonzero",
        ));
    }
    let limit = validate_flow_history_query(&FlowHistoryQuery {
        since_unix_ms: query.since_unix_ms,
        until_unix_ms: query.until_unix_ms,
        limit: query.limit,
    })?;
    let service_id = ServiceId::new(query.service_id);
    let backend_id = query.backend_id.map(BackendId::new);
    let current_snapshot = read_lock(&state.compiled_service_snapshot).clone();
    let current_service_revision = current_snapshot.as_ref().map(|snapshot| snapshot.revision);
    let current_service = current_snapshot.and_then(|snapshot| {
        snapshot
            .services
            .into_iter()
            .find(|service| service.id == service_id)
    });
    let current_backend = current_service.as_ref().and_then(|service| {
        backend_id.and_then(|backend_id| {
            service
                .backends
                .iter()
                .find(|backend| backend.id == backend_id)
                .cloned()
        })
    });
    let load_balancer = current_service
        .as_ref()
        .and_then(|service| service.load_balancer.as_ref())
        .map(|_| load_balancer_explanation(&state, service_id));
    let mut history = flow_history_snapshot_window(
        &state,
        query.since_unix_ms,
        query.until_unix_ms,
        FLOW_HISTORY_CAPACITY,
    );
    history.entries.retain(|entry| {
        entry.service.is_some_and(|outcome| {
            outcome.service_id == service_id
                && backend_id.is_none_or(|backend_id| outcome.backend_id == Some(backend_id))
                && query
                    .frontend_kind
                    .is_none_or(|frontend_kind| outcome.frontend_kind == frontend_kind)
        })
    });
    let matched_outcomes = history.entries.len();
    let matched_observations = history
        .entries
        .iter()
        .map(|entry| entry.observed_events)
        .fold(0_u64, u64::saturating_add);
    history.entries.truncate(limit);
    if current_service.is_none() && history.entries.is_empty() {
        return Err(ApiError::not_found(format!(
            "service ID {} has no current state or retained outcomes",
            query.service_id
        )));
    }
    Ok(Json(ServiceExplanation {
        schema_version: 1,
        service_id,
        backend_id,
        frontend_kind: query.frontend_kind,
        current_service_revision,
        current_service,
        current_backend,
        load_balancer,
        matched_outcomes,
        matched_observations,
        outcomes: history.entries,
        note: "Current compiled intent is correlated with bounded, durable dataplane outcomes; absence of an outcome is not proof that no traffic occurred.",
    }))
}

fn load_balancer_explanation(
    state: &ControllerState,
    service_id: ServiceId,
) -> LoadBalancerExplanation {
    let allocation = mutex_lock(&state.load_balancer_runtime)
        .as_ref()
        .and_then(|runtime| {
            runtime
                .allocator
                .checkpoint()
                .leases
                .into_iter()
                .find(|lease| lease.owner.service_id == service_id)
        });
    let reachability = read_lock(&state.compiled_load_balancer_reachability).clone();
    let mut reachable_nodes = reachability
        .as_ref()
        .into_iter()
        .flat_map(|snapshot| &snapshot.targets)
        .filter(|target| target.owner.service_id == service_id)
        .map(|target| target.node.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    reachable_nodes.sort();
    let now = unix_time_millis();
    let reports = read_lock(&state.agent_reports);
    let converged_nodes = reachable_nodes
        .iter()
        .filter(|node| {
            let Some(snapshot) = reachability.as_ref() else {
                return false;
            };
            reports.get(*node).is_some_and(|stored| {
                now.saturating_sub(stored.last_received_unix_ms) <= AGENT_STATUS_FRESHNESS_MILLIS
                    && stored.report.ready
                    && stored.report.bpf_loaded
                    && stored.report.applied_load_balancer_epoch == snapshot.source_epoch
                    && stored.report.applied_load_balancer_revision == snapshot.revision.get()
                    && stored.report.applied_load_balancer_allocation_revision
                        == snapshot.allocation_revision.get()
                    && stored.report.load_balancer_last_error.is_none()
            })
        })
        .cloned()
        .collect();
    LoadBalancerExplanation {
        allocation,
        provider: reachability
            .as_ref()
            .map(|snapshot| snapshot.provider.clone()),
        reachability_revision: reachability.as_ref().map(|snapshot| snapshot.revision),
        allocation_revision: reachability
            .as_ref()
            .map(|snapshot| snapshot.allocation_revision),
        reachable_nodes,
        converged_nodes,
    }
}

async fn simulate_node_port(
    State(state): State<Arc<ControllerState>>,
    Query(query): Query<NodePortSimulationQuery>,
) -> Result<Json<NodePortSimulation>, ApiError> {
    if query.node_name.is_empty() || query.node_name.len() > 253 || query.port == 0 {
        return Err(ApiError::bad_request(
            "node_name must be nonempty and port must be nonzero",
        ));
    }
    let protocol = node_port_simulation_protocol(&query.protocol)?;
    let node = read_lock(&state.node_port_nodes)
        .get(&query.node_name)
        .cloned()
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "node {} has no admitted NodePort address state",
                query.node_name
            ))
        })?;
    if !node
        .addresses
        .iter()
        .any(|address| address.address == query.address)
    {
        return Err(ApiError::bad_request(format!(
            "address {} is not an admitted NodePort address for node {}",
            query.address, query.node_name
        )));
    }
    let snapshot = service_snapshot_for(&state)?;
    let family = if query.address.is_ipv4() {
        AddressFamily::Ipv4
    } else {
        AddressFamily::Ipv6
    };
    let (service, node_port) =
        find_node_port_owner(&snapshot, family, query.port, protocol, query.address)?;
    let eligible_backends = eligible_node_port_backends(service, node_port, &query.node_name);
    let eligible_backend_ids = eligible_backends.iter().map(|backend| backend.id).collect();
    let (frontend_kind, source_preserved) = match node_port.traffic_policy {
        ServiceTrafficPolicy::Cluster => (ServiceFrontendKind::NodePortCluster, false),
        ServiceTrafficPolicy::Local => (ServiceFrontendKind::NodePortLocal, true),
    };
    let decision = if eligible_backends.is_empty() {
        "drop_no_backend"
    } else {
        "translate"
    };
    Ok(Json(NodePortSimulation {
        schema_version: 1,
        node_name: query.node_name,
        address: query.address,
        port: query.port,
        protocol,
        service_revision: snapshot.revision,
        service_id: service.id,
        namespace: service.namespace.clone(),
        name: service.name.clone(),
        frontend_kind,
        traffic_policy: node_port.traffic_policy,
        source_preserved,
        eligible_backend_ids,
        eligible_backends,
        decision,
        note: "Read-only prediction from the current validated Service and Node snapshots; an existing connection may retain its revision-local backend until expiry.",
    }))
}

#[allow(clippy::too_many_lines)]
async fn simulate_load_balancer(
    State(state): State<Arc<ControllerState>>,
    Query(query): Query<LoadBalancerSimulationQuery>,
) -> Result<Json<LoadBalancerSimulation>, ApiError> {
    if query.node_name.is_empty()
        || query.node_name.len() > 253
        || query.port == 0
        || query.address.is_ipv4() != query.source_address.is_ipv4()
    {
        return Err(ApiError::bad_request(
            "node_name and port must be valid and source_address must match the VIP family",
        ));
    }
    let protocol = node_port_simulation_protocol(&query.protocol)?;
    let reachability = read_lock(&state.compiled_load_balancer_reachability)
        .clone()
        .ok_or_else(|| ApiError::not_found("LoadBalancer reachability state is unavailable"))?;
    let mut targets = reachability
        .targets
        .iter()
        .filter(|target| target.node.name == query.node_name && target.address == query.address);
    let target = targets
        .next()
        .ok_or_else(|| ApiError::not_found("VIP is not reachable through the requested Node"))?;
    if targets.next().is_some() {
        return Err(ApiError::bad_request(
            "VIP reachability ownership is ambiguous",
        ));
    }
    let services = service_snapshot_for(&state)?;
    let service = services
        .services
        .iter()
        .find(|service| service.id == target.owner.service_id)
        .ok_or_else(|| ApiError::not_found("VIP owner has no current compiled Service"))?;
    let intent = service
        .load_balancer
        .as_ref()
        .ok_or_else(|| ApiError::not_found("VIP owner has no LoadBalancer intent"))?;
    let family = if query.address.is_ipv4() {
        AddressFamily::Ipv4
    } else {
        AddressFamily::Ipv6
    };
    let frontend = intent
        .frontends
        .iter()
        .find(|frontend| {
            frontend.family == family
                && frontend.service_port == query.port
                && frontend.protocol == protocol
        })
        .ok_or_else(|| ApiError::not_found("VIP port and protocol have no admitted frontend"))?;
    let source_allowed = intent.source_ranges.is_empty()
        || intent
            .source_ranges
            .iter()
            .copied()
            .any(|prefix| service_prefix_contains(prefix, query.source_address));
    let eligible_backends = frontend
        .backend_ids
        .iter()
        .filter_map(|backend_id| {
            service.backends.iter().find(|backend| {
                backend.id == *backend_id
                    && backend.ready
                    && !backend.terminating
                    && (intent.traffic_policy == ServiceTrafficPolicy::Cluster
                        || backend.node_name.as_deref() == Some(query.node_name.as_str()))
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    let eligible_backend_ids = eligible_backends.iter().map(|backend| backend.id).collect();
    let (frontend_kind, source_preserved) = match intent.traffic_policy {
        ServiceTrafficPolicy::Cluster => (ServiceFrontendKind::LoadBalancerCluster, false),
        ServiceTrafficPolicy::Local => (ServiceFrontendKind::LoadBalancerLocal, true),
    };
    let decision = if !source_allowed {
        "drop_source_range"
    } else if eligible_backends.is_empty() {
        "drop_no_backend"
    } else {
        "translate"
    };
    let allocation = mutex_lock(&state.load_balancer_runtime)
        .as_ref()
        .and_then(|runtime| runtime.allocator.lease(&target.owner).cloned());
    Ok(Json(LoadBalancerSimulation {
        schema_version: 1,
        node_name: query.node_name,
        address: query.address,
        source_address: query.source_address,
        port: query.port,
        protocol,
        service_revision: services.revision,
        reachability_revision: reachability.revision,
        allocation_revision: reachability.allocation_revision,
        provider: reachability.provider,
        allocation,
        service_id: service.id,
        namespace: service.namespace.clone(),
        name: service.name.clone(),
        frontend_kind,
        traffic_policy: intent.traffic_policy,
        source_preserved,
        source_allowed,
        eligible_backend_ids,
        eligible_backends,
        decision,
        note: "Read-only prediction from the exact current Service, allocation, reachability, source-range, and receiving-Node state; an existing connection may retain its revision-local backend until expiry.",
    }))
}

fn service_prefix_contains(prefix: ServiceIpPrefix, address: IpAddr) -> bool {
    match (prefix.address, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = if prefix.prefix_length == 0 {
                0
            } else {
                u32::MAX << (32 - prefix.prefix_length)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = if prefix.prefix_length == 0 {
                0
            } else {
                u128::MAX << (128 - prefix.prefix_length)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn node_port_simulation_protocol(value: &str) -> Result<Protocol, ApiError> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        _ => Err(ApiError::bad_request(
            "NodePort simulation protocol must be tcp or udp",
        )),
    }
}

fn find_node_port_owner(
    snapshot: &ServiceSnapshot,
    family: AddressFamily,
    port: u16,
    protocol: Protocol,
    address: IpAddr,
) -> Result<(&ServiceIr, &ServiceNodePort), ApiError> {
    let mut matched = snapshot.services.iter().filter_map(|service| {
        service
            .node_ports
            .iter()
            .find(|node_port| {
                node_port.family == family
                    && node_port.port == port
                    && node_port.protocol == protocol
            })
            .map(|node_port| (service, node_port))
    });
    let owner = matched.next().ok_or_else(|| {
        ApiError::not_found(format!(
            "no NodePort owns {port}/{protocol:?} on address {address}"
        ))
    })?;
    if matched.next().is_some() {
        return Err(ApiError::internal(
            "validated service state contains an ambiguous NodePort owner",
        ));
    }
    Ok(owner)
}

fn eligible_node_port_backends(
    service: &ServiceIr,
    node_port: &ServiceNodePort,
    node_name: &str,
) -> Vec<ServiceBackend> {
    node_port
        .backend_ids
        .iter()
        .filter_map(|backend_id| {
            service.backends.iter().find(|backend| {
                backend.id == *backend_id
                    && backend.ready
                    && !backend.terminating
                    && (node_port.traffic_policy == ServiceTrafficPolicy::Cluster
                        || backend.node_name.as_deref() == Some(node_name))
            })
        })
        .cloned()
        .collect()
}

fn validate_flow_history_query(query: &FlowHistoryQuery) -> Result<usize, ApiError> {
    let limit = query.limit.unwrap_or(FLOW_HISTORY_CAPACITY);
    if limit == 0 || limit > FLOW_HISTORY_CAPACITY {
        return Err(ApiError::bad_request(format!(
            "flow-history limit must be between 1 and {FLOW_HISTORY_CAPACITY}"
        )));
    }
    if query
        .since_unix_ms
        .zip(query.until_unix_ms)
        .is_some_and(|(since, until)| since > until)
    {
        return Err(ApiError::bad_request(
            "flow-history since_unix_ms must not exceed until_unix_ms",
        ));
    }
    Ok(limit)
}

#[cfg(test)]
fn flow_history_snapshot(state: &ControllerState) -> FlowHistorySnapshot {
    flow_history_snapshot_window(state, None, None, FLOW_HISTORY_CAPACITY)
}

fn flow_history_snapshot_window(
    state: &ControllerState,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: usize,
) -> FlowHistorySnapshot {
    let mut snapshot = mutex_lock(&state.flow_history).snapshot_window(
        state.identity_epoch,
        since_unix_ms,
        until_unix_ms,
        limit,
    );
    snapshot.durable_checkpointed_flows = usize::try_from(
        state
            .flow_history_checkpointed_flows
            .load(Ordering::Acquire),
    )
    .unwrap_or(usize::MAX);
    snapshot.durable_omitted_flows = usize::try_from(
        state
            .flow_history_checkpoint_omitted_flows
            .load(Ordering::Acquire),
    )
    .unwrap_or(usize::MAX);
    snapshot.durable_omitted_observations = state
        .flow_history_checkpoint_omitted_observations
        .load(Ordering::Acquire);
    let pods = read_lock(&state.pods);
    for entry in &mut snapshot.entries {
        entry.source_workloads = pods
            .iter()
            .filter(|(_, pod)| pod.endpoint.identity == entry.key.source_identity)
            .map(|(reference, _)| reference.clone())
            .collect();
        entry.destination_workloads = pods
            .iter()
            .filter(|(_, pod)| pod.endpoint.identity == entry.key.destination_identity)
            .map(|(reference, _)| reference.clone())
            .collect();
    }
    snapshot
}

async fn ingest_flows(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
    Json(batch): Json<FlowExportBatch>,
) -> Result<StatusCode, ApiError> {
    let agent = authenticate_internal_agent(&state, &headers).await?;
    if agent.node_name != batch.node_name {
        state.metrics.agent_authentication_failures.inc();
        return Err(ApiError::forbidden(
            "flow export does not match its authoritative Pod placement",
        ));
    }
    ingest_flow_batch(&state, batch)
}

fn ingest_flow_batch(
    state: &ControllerState,
    batch: FlowExportBatch,
) -> Result<StatusCode, ApiError> {
    validate_flow_export_batch(&batch)?;
    let received_unix_ms = unix_time_millis();
    let external_exporter = read_lock(&state.external_flow_export).clone();
    let external_batch = external_exporter.as_ref().map(|_| batch.clone());
    let observations = batch
        .entries
        .iter()
        .map(|entry| entry.observed_events)
        .fold(0_u64, u64::saturating_add);
    let (revision, changed) = {
        let mut history = mutex_lock(&state.flow_history);
        let changed = history.ingest(batch, received_unix_ms);
        (history.revision(), changed)
    };
    if changed {
        state.flow_history_dirty.store(true, Ordering::Release);
    }
    let topology_revision = {
        let mut revisions = mutex_lock(&state.revisions);
        revisions.telemetry = revision;
        revisions.topology
    };
    state.metrics.telemetry_batches.inc();
    state.metrics.telemetry_observations.inc_by(observations);
    if let (Some(exporter), Some(batch)) = (external_exporter, external_batch) {
        exporter.enqueue(ExternalFlowExportEnvelope {
            schema_version: external_flow_export::EXTERNAL_FLOW_EXPORT_SCHEMA_VERSION,
            controller_epoch: state.identity_epoch,
            export_sequence: 0,
            topology_revision,
            received_unix_ms,
            batch,
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

fn validate_flow_export_batch(batch: &FlowExportBatch) -> Result<(), ApiError> {
    if batch.schema_version != FLOW_EXPORT_SCHEMA_VERSION {
        return Err(ApiError::bad_request(format!(
            "unsupported flow export schema {}; expected {}",
            batch.schema_version, FLOW_EXPORT_SCHEMA_VERSION
        )));
    }
    if batch.node_name.is_empty()
        || batch.node_name.len() > 253
        || batch.node_name.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "node_name must contain 1 to 253 non-control characters",
        ));
    }
    if batch.entries.len() > FLOW_EXPORT_BATCH_LIMIT {
        return Err(ApiError::bad_request(format!(
            "flow export batch contains {} entries; limit is {FLOW_EXPORT_BATCH_LIMIT}",
            batch.entries.len()
        )));
    }
    for entry in &batch.entries {
        let ipv4_pair = entry.key.source_ipv4.is_some() && entry.key.destination_ipv4.is_some();
        let ipv6_pair = entry.key.source_ipv6.is_some() && entry.key.destination_ipv6.is_some();
        if ipv4_pair == ipv6_pair
            || entry.key.source_ipv4.is_some() != entry.key.destination_ipv4.is_some()
            || entry.key.source_ipv6.is_some() != entry.key.destination_ipv6.is_some()
        {
            return Err(ApiError::bad_request(
                "flow export must contain exactly one complete IPv4 or IPv6 address pair",
            ));
        }
        if entry.observed_events == 0 {
            return Err(ApiError::bad_request(
                "flow export observed_events must be greater than zero",
            ));
        }
        if !matches!(entry.key.protocol, 1 | 6 | 17 | 132) {
            return Err(ApiError::bad_request(format!(
                "unsupported flow export IP protocol {}",
                entry.key.protocol
            )));
        }
        if matches!(entry.key.protocol, 6 | 17 | 132) && entry.key.destination_port == 0 {
            return Err(ApiError::bad_request(
                "TCP/UDP/SCTP flow export destination_port must be greater than zero",
            ));
        }
        if let Some(service) = entry.service {
            validate_service_flow_export(entry, service)?;
        } else {
            if entry.key.service.is_some() {
                return Err(ApiError::bad_request(
                    "policy flow export must not contain a service history key",
                ));
            }
            let selected_identity = match entry.key.direction {
                PolicyDirection::Ingress => entry.key.destination_identity,
                PolicyDirection::Egress => entry.key.source_identity,
            };
            if selected_identity.get() == 0 {
                return Err(ApiError::bad_request(format!(
                    "flow export selected {:?} identity must be resolved",
                    entry.key.direction
                )));
            }
            if entry.decision.reason > 6 || entry.shadow.is_some_and(|shadow| shadow.reason > 6) {
                return Err(ApiError::bad_request(
                    "flow export decision reason must be a known ABI reason code",
                ));
            }
        }
    }
    Ok(())
}

fn validate_service_flow_export(
    entry: &FlowExportRecord,
    service: unf_state::ServiceFlowOutcome,
) -> Result<(), ApiError> {
    let action_reason_valid = matches!(
        (service.action, service.reason),
        (1, 1 | 2) | (2, 3..=10) | (3, 11)
    );
    let backend_address_valid = service.backend_ipv4.is_some() ^ service.backend_ipv6.is_some();
    let backend_family_matches = (service.backend_ipv4.is_some()
        && entry.key.source_ipv4.is_some())
        || (service.backend_ipv6.is_some() && entry.key.source_ipv6.is_some())
        || service.backend_id.is_none();
    let backend_complete = service.backend_id.is_some()
        == (backend_address_valid && service.backend_port.is_some_and(|port| port != 0));
    let verdict_matches = matches!(
        (service.action, entry.decision.verdict),
        (1, Verdict::Allow) | (2, Verdict::Deny) | (3, Verdict::Audit)
    );
    let service_key_matches = entry.key.service.as_ref().is_some_and(|key| {
        key.service_id == service.service_id
            && key.backend_id == service.backend_id
            && key.service_revision == service.service_revision
            && key.action == service.action
            && key.reason == service.reason
            && key.frontend_kind == service.frontend_kind
    });
    if !service_key_matches
        || !action_reason_valid
        || service.service_id.get() == 0
        || service.service_revision.get() == 0
        || service.frontend_port == 0
        || service.frontend_port != entry.key.destination_port
        || !backend_complete
        || !backend_family_matches
        || !verdict_matches
        || (service.action == 1 && service.backend_id.is_none())
        || !matches!(entry.key.protocol, 6 | 17)
        || entry.policy_revision.get() != 0
        || entry.decision.reason != service.reason
        || entry.decision.policy_id.is_some()
        || entry.decision.rule_id.is_some()
        || entry.shadow.is_some()
    {
        return Err(ApiError::bad_request(
            "service flow export contains inconsistent dataplane provenance",
        ));
    }
    Ok(())
}

fn dataplane_policy_state(state: &ControllerState) -> Result<DataplanePolicyState, ApiError> {
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    let revision = mutex_lock(&state.revisions).policy;
    let mut cache = mutex_lock(&state.dataplane_policy_cache);
    if let Some(snapshot) = cache.as_ref()
        && snapshot.0 == revision
    {
        return Ok(snapshot.clone());
    }
    let policies = compiled_policies(state);
    let (ingress_policies, egress_policies): (Vec<_>, Vec<_>) = policies
        .into_iter()
        .partition(|policy| policy.direction == PolicyDirection::Ingress);
    let endpoints = endpoints_with_namespace_labels(state);
    let entries = compile_dataplane_entries(&ingress_policies, &endpoints)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let ipv4_endpoints = ipv4_endpoints_with_namespace_labels(state);
    let mut ipv4_entries =
        compile_ipv4_dataplane_entries(&ingress_policies, &endpoints, &ipv4_endpoints)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    let ipv6_endpoints = ipv6_endpoints_with_namespace_labels(state);
    let mut ipv6_entries =
        compile_ipv6_dataplane_entries(&ingress_policies, &endpoints, &ipv6_endpoints)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    add_host_network_ingress_entries(
        state,
        &ingress_policies,
        &endpoints,
        &mut ipv4_entries,
        &mut ipv6_entries,
    )?;
    let mut egress_ipv4_entries =
        compile_egress_ipv4_dataplane_entries(&egress_policies, &endpoints, &ipv4_endpoints)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    let mut egress_ipv6_entries =
        compile_egress_ipv6_dataplane_entries(&egress_policies, &endpoints, &ipv6_endpoints)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    add_primary_node_traffic_entries(
        state,
        &mut ipv4_entries,
        &mut ipv6_entries,
        &mut egress_ipv4_entries,
        &mut egress_ipv6_entries,
    )?;
    add_ovn_host_network_reply_entries(
        state,
        &ingress_policies,
        &egress_policies,
        &endpoints,
        &mut egress_ipv4_entries,
        &mut egress_ipv6_entries,
    )?;
    let snapshot = (
        revision,
        entries,
        ipv4_entries,
        ipv6_entries,
        egress_ipv4_entries,
        egress_ipv6_entries,
    );
    *cache = Some(snapshot.clone());
    Ok(snapshot)
}

fn add_host_network_ingress_entries(
    state: &ControllerState,
    ingress_policies: &[PolicyIr],
    endpoints: &[Endpoint],
    ipv4_entries: &mut Vec<Ipv4PolicyMapEntry>,
    ipv6_entries: &mut Vec<Ipv6PolicyMapEntry>,
) -> Result<(), ApiError> {
    let namespaces = read_lock(&state.namespaces);
    let pods = read_lock(&state.pods);
    for pod in pods.values().filter(|pod| pod.host_network) {
        let endpoint = endpoint_with_namespace_labels(&pod.endpoint, &namespaces);
        for address in &pod.ipv4_addresses {
            let source = Ipv4Endpoint {
                address: *address,
                endpoint: endpoint.clone(),
            };
            let candidates = compile_ipv4_dataplane_entries(
                ingress_policies,
                endpoints,
                std::slice::from_ref(&source),
            )
            .map_err(|error| ApiError::internal(error.to_string()))?;
            for candidate in candidates
                .into_iter()
                .filter(|entry| entry.key.source_address == *address)
            {
                merge_host_network_ipv4_entry(ipv4_entries, candidate)?;
            }
        }
        for address in &pod.ipv6_addresses {
            let source = Ipv6Endpoint {
                address: *address,
                endpoint: endpoint.clone(),
            };
            let candidates = compile_ipv6_dataplane_entries(
                ingress_policies,
                endpoints,
                std::slice::from_ref(&source),
            )
            .map_err(|error| ApiError::internal(error.to_string()))?;
            for candidate in candidates.into_iter().filter(|entry| {
                entry.key.source_network == *address && entry.key.source_prefix_len == 128
            }) {
                merge_host_network_ipv6_entry(ipv6_entries, candidate)?;
            }
        }
    }
    ipv4_entries.sort_by_key(|entry| entry.key);
    ipv6_entries.sort_by_key(|entry| entry.key);
    Ok(())
}

fn add_primary_node_traffic_entries(
    state: &ControllerState,
    ingress_ipv4_entries: &mut Vec<Ipv4PolicyMapEntry>,
    ingress_ipv6_entries: &mut Vec<Ipv6PolicyMapEntry>,
    egress_ipv4_entries: &mut Vec<EgressIpv4PolicyMapEntry>,
    egress_ipv6_entries: &mut Vec<EgressIpv6PolicyMapEntry>,
) -> Result<(), ApiError> {
    let node_transports: BTreeSet<_> = read_lock(&state.node_blocks)
        .values()
        .filter_map(|assignment| assignment.transport.as_ref().ok().copied())
        .collect();
    if node_transports.is_empty() {
        return Ok(());
    }

    let decision = PolicyDecisionRecord {
        verdict: Verdict::Allow,
        reason: PolicyReason::NoApplicablePolicy,
        policy_id: None,
        rule_id: None,
    };
    for transport in node_transports {
        merge_host_network_ipv4_entry(
            ingress_ipv4_entries,
            Ipv4PolicyMapEntry {
                key: Ipv4PolicyMapKey {
                    source_address: transport.ipv4,
                    destination_identity: IdentityId::new(0),
                    protocol: 0,
                    destination_port: 0,
                },
                decision,
                shadow: None,
            },
        )?;
        merge_host_network_ipv6_entry(
            ingress_ipv6_entries,
            Ipv6PolicyMapEntry {
                key: Ipv6PolicyMapKey {
                    source_network: transport.ipv6,
                    source_prefix_len: 128,
                    destination_identity: IdentityId::new(0),
                    protocol: 0,
                    destination_port: 0,
                },
                decision,
                shadow: None,
            },
        )?;
        upsert_egress_ipv4_entry(
            egress_ipv4_entries,
            EgressIpv4PolicyMapEntry {
                key: EgressIpv4PolicyMapKey {
                    source_identity: IdentityId::new(0),
                    destination_address: transport.ipv4,
                    protocol: 0,
                    destination_port: 0,
                },
                decision,
                shadow: None,
            },
        )?;
        upsert_egress_ipv6_entry(
            egress_ipv6_entries,
            EgressIpv6PolicyMapEntry {
                key: EgressIpv6PolicyMapKey {
                    source_identity: IdentityId::new(0),
                    destination_network: transport.ipv6,
                    destination_prefix_len: 128,
                    protocol: 0,
                    destination_port: 0,
                },
                decision,
                shadow: None,
            },
        )?;
    }
    ingress_ipv4_entries.sort_by_key(|entry| entry.key);
    ingress_ipv6_entries.sort_by_key(|entry| entry.key);
    egress_ipv4_entries.sort_by_key(|entry| entry.key);
    egress_ipv6_entries.sort_by_key(|entry| entry.key);
    Ok(())
}

fn merge_host_network_ipv4_entry(
    entries: &mut Vec<Ipv4PolicyMapEntry>,
    candidate: Ipv4PolicyMapEntry,
) -> Result<(), ApiError> {
    if let Some(existing) = entries.iter_mut().find(|entry| entry.key == candidate.key) {
        if candidate.decision.verdict == Verdict::Allow
            && existing.decision.verdict != Verdict::Allow
        {
            *existing = candidate;
        }
        return Ok(());
    }
    if entries.len() >= unf_state::POLICY_MAP_BANK_ENTRY_LIMIT {
        return Err(ApiError::internal(format!(
            "IPv4 policy entry limit {} exceeded while adding host-network peers",
            unf_state::POLICY_MAP_BANK_ENTRY_LIMIT
        )));
    }
    entries.push(candidate);
    Ok(())
}

fn merge_host_network_ipv6_entry(
    entries: &mut Vec<Ipv6PolicyMapEntry>,
    candidate: Ipv6PolicyMapEntry,
) -> Result<(), ApiError> {
    if let Some(existing) = entries.iter_mut().find(|entry| entry.key == candidate.key) {
        if candidate.decision.verdict == Verdict::Allow
            && existing.decision.verdict != Verdict::Allow
        {
            *existing = candidate;
        }
        return Ok(());
    }
    if entries.len() >= unf_state::POLICY_MAP_BANK_ENTRY_LIMIT {
        return Err(ApiError::internal(format!(
            "IPv6 policy entry limit {} exceeded while adding host-network peers",
            unf_state::POLICY_MAP_BANK_ENTRY_LIMIT
        )));
    }
    entries.push(candidate);
    Ok(())
}

fn add_ovn_host_network_reply_entries(
    state: &ControllerState,
    ingress_policies: &[PolicyIr],
    egress_policies: &[PolicyIr],
    endpoints: &[Endpoint],
    ipv4_entries: &mut Vec<EgressIpv4PolicyMapEntry>,
    ipv6_entries: &mut Vec<EgressIpv6PolicyMapEntry>,
) -> Result<(), ApiError> {
    use unf_policy::PolicyOrigin;

    let namespaces = read_lock(&state.namespaces);
    let gateway_endpoint = host_network_gateway_endpoint(&namespaces);
    drop(namespaces);
    let gateways = read_lock(&state.host_network_gateways);
    if gateways.is_empty() {
        return Ok(());
    }

    for endpoint in endpoints {
        let egress_isolated = egress_policies.iter().any(|policy| {
            policy.origin == PolicyOrigin::KubernetesNetworkPolicy
                && policy.target.matches(endpoint)
        });
        if !egress_isolated {
            continue;
        }

        for policy in ingress_policies.iter().filter(|policy| {
            policy.origin == PolicyOrigin::KubernetesNetworkPolicy
                && policy.target.matches(endpoint)
        }) {
            for rule in policy.rules.iter().filter(|rule| {
                rule.action == PolicyAction::Allow && rule.source.matches(&gateway_endpoint)
            }) {
                let decision = PolicyDecisionRecord {
                    verdict: Verdict::Allow,
                    reason: PolicyReason::ExplicitRule,
                    policy_id: Some(policy.id),
                    rule_id: Some(rule.id),
                };
                let protocol = rule.protocol.map_or(0, |protocol| protocol as u8);
                for gateway in gateways.values() {
                    for destination_address in &gateway.ipv4 {
                        upsert_egress_ipv4_entry(
                            ipv4_entries,
                            EgressIpv4PolicyMapEntry {
                                key: EgressIpv4PolicyMapKey {
                                    source_identity: endpoint.identity,
                                    destination_address: *destination_address,
                                    protocol,
                                    destination_port: 0,
                                },
                                decision,
                                shadow: None,
                            },
                        )?;
                    }
                    for destination_network in &gateway.ipv6 {
                        upsert_egress_ipv6_entry(
                            ipv6_entries,
                            EgressIpv6PolicyMapEntry {
                                key: EgressIpv6PolicyMapKey {
                                    source_identity: endpoint.identity,
                                    destination_network: *destination_network,
                                    destination_prefix_len: 128,
                                    protocol,
                                    destination_port: 0,
                                },
                                decision,
                                shadow: None,
                            },
                        )?;
                    }
                }
            }
        }
    }
    ipv4_entries.sort_by_key(|entry| entry.key);
    ipv6_entries.sort_by_key(|entry| entry.key);
    Ok(())
}

fn upsert_egress_ipv4_entry(
    entries: &mut Vec<EgressIpv4PolicyMapEntry>,
    entry: EgressIpv4PolicyMapEntry,
) -> Result<(), ApiError> {
    if let Some(existing) = entries
        .iter_mut()
        .find(|existing| existing.key == entry.key)
    {
        *existing = entry;
    } else {
        if entries.len() >= unf_state::POLICY_MAP_BANK_ENTRY_LIMIT {
            return Err(ApiError::internal(format!(
                "egress IPv4 policy entry limit {} exceeded while adding compatibility state",
                unf_state::POLICY_MAP_BANK_ENTRY_LIMIT
            )));
        }
        entries.push(entry);
    }
    Ok(())
}

fn upsert_egress_ipv6_entry(
    entries: &mut Vec<EgressIpv6PolicyMapEntry>,
    entry: EgressIpv6PolicyMapEntry,
) -> Result<(), ApiError> {
    if let Some(existing) = entries
        .iter_mut()
        .find(|existing| existing.key == entry.key)
    {
        *existing = entry;
    } else {
        if entries.len() >= unf_state::POLICY_MAP_BANK_ENTRY_LIMIT {
            return Err(ApiError::internal(format!(
                "egress IPv6 policy entry limit {} exceeded while adding compatibility state",
                unf_state::POLICY_MAP_BANK_ENTRY_LIMIT
            )));
        }
        entries.push(entry);
    }
    Ok(())
}

async fn explain(
    State(state): State<Arc<ControllerState>>,
    Json(request): Json<ExplainRequest>,
) -> Result<Json<ExplainResponse>, ApiError> {
    explain_response(&state, &request).map(Json)
}

fn explain_response(
    state: &ControllerState,
    request: &ExplainRequest,
) -> Result<ExplainResponse, ApiError> {
    if request.port == 0 {
        return Err(ApiError::bad_request("port must be between 1 and 65535"));
    }
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    let pods = read_lock(&state.pods);
    let source = pods
        .get(&request.from)
        .ok_or_else(|| ApiError::not_found(format!("source pod {} not found", request.from)))?;
    let destination = pods
        .get(&request.to)
        .ok_or_else(|| ApiError::not_found(format!("destination pod {} not found", request.to)))?;
    let namespaces = read_lock(&state.namespaces);
    let source_endpoint = endpoint_with_namespace_labels(&source.endpoint, &namespaces);
    let destination_endpoint = endpoint_with_namespace_labels(&destination.endpoint, &namespaces);
    let protocol = match request.protocol {
        RequestProtocol::Tcp => Protocol::Tcp,
        RequestProtocol::Udp => Protocol::Udp,
        RequestProtocol::Sctp => Protocol::Sctp,
    };
    let direction = match request.direction {
        RequestPolicyDirection::Ingress => PolicyDirection::Ingress,
        RequestPolicyDirection::Egress => PolicyDirection::Egress,
    };
    let (ip_family, source_address, destination_address) =
        explain_addresses(source, destination, request.ip_family)?;
    let (source_ipv4, source_ipv6) = match source_address {
        IpAddr::V4(address) => (Some(address), None),
        IpAddr::V6(address) => (None, Some(address)),
    };
    let destination_addresses = match destination_address {
        IpAddr::V4(address) => DestinationAddresses {
            ipv4: Some(address),
            ipv6: None,
        },
        IpAddr::V6(address) => DestinationAddresses {
            ipv4: None,
            ipv6: Some(address),
        },
    };
    let policies = compiled_policies(state);
    let decision = evaluate_for_direction_with_addresses(
        &policies,
        direction,
        Flow {
            source: &source_endpoint,
            destination: &destination_endpoint,
            protocol,
            destination_port: request.port,
            source_ipv4,
            source_ipv6,
        },
        destination_addresses,
    );
    let revision = mutex_lock(&state.revisions).policy;
    Ok(ExplainResponse {
        source: resolved(source),
        destination: resolved(destination),
        direction,
        ip_family,
        source_address,
        destination_address,
        decision,
        policy_revision: revision,
        dataplane_enforcement: true,
        note: "decision is enforceable after traffic-path nodes report this policy revision as applied",
    })
}

fn explain_addresses(
    source: &PodRecord,
    destination: &PodRecord,
    requested_family: Option<RequestIpFamily>,
) -> Result<(RequestIpFamily, IpAddr, IpAddr), ApiError> {
    let family = requested_family.unwrap_or({
        if !source.ipv4_addresses.is_empty() && !destination.ipv4_addresses.is_empty() {
            RequestIpFamily::Ipv4
        } else {
            RequestIpFamily::Ipv6
        }
    });
    match family {
        RequestIpFamily::Ipv4 => {
            let source_address = source.ipv4_addresses.iter().next().copied();
            let destination_address = destination.ipv4_addresses.iter().next().copied();
            match (source_address, destination_address) {
                (Some(source_address), Some(destination_address)) => Ok((
                    family,
                    IpAddr::V4(source_address),
                    IpAddr::V4(destination_address),
                )),
                _ => Err(ApiError::unprocessable(
                    "source and destination Pods must both have an IPv4 address",
                )),
            }
        }
        RequestIpFamily::Ipv6 => {
            let source_address = source.ipv6_addresses.iter().next().copied();
            let destination_address = destination.ipv6_addresses.iter().next().copied();
            match (source_address, destination_address) {
                (Some(source_address), Some(destination_address)) => Ok((
                    family,
                    IpAddr::V6(source_address),
                    IpAddr::V6(destination_address),
                )),
                _ => Err(ApiError::unprocessable(
                    "source and destination Pods must both have an IPv6 address",
                )),
            }
        }
    }
}

async fn simulate_policy(
    State(state): State<Arc<ControllerState>>,
    Json(request): Json<PolicySimulationRequest>,
) -> Result<Json<PolicySimulationResponse>, ApiError> {
    let history_query = request.flow_history.unwrap_or_default();
    let candidate = compile_simulation_candidate(request.policy)?;

    let _policy_state_guard = read_lock(&state.policy_state_guard);
    let pod_records: Vec<_> = read_lock(&state.pods).values().cloned().collect();
    let flow_history = simulation_flow_history_snapshot(&state, &history_query)?;
    let namespaces = read_lock(&state.namespaces).clone();
    let current_policies = compiled_policies(&state);
    let (current_candidate, candidate_exists) =
        simulation_current_candidate(&state, candidate.resource_kind, &candidate.key);
    let operation = if candidate_exists {
        PolicySimulationOperation::Replace
    } else {
        PolicySimulationOperation::Add
    };
    let proposed_policies = simulation_proposed_policies(
        &state,
        candidate.resource_kind,
        &candidate.key,
        &candidate.policies,
    );

    let endpoints: Vec<_> = pod_records
        .iter()
        .map(|pod| endpoint_with_namespace_labels(&pod.endpoint, &namespaces))
        .collect();
    let affected_sources = simulation_selected_endpoints(
        &endpoints,
        &candidate.policies,
        &current_candidate,
        PolicyDirection::Egress,
    );
    let affected_destinations = simulation_selected_endpoints(
        &endpoints,
        &candidate.policies,
        &current_candidate,
        PolicyDirection::Ingress,
    );
    let matrix = simulation_matrix(
        &pod_records,
        &endpoints,
        &affected_sources,
        &affected_destinations,
        &current_policies,
        &proposed_policies,
    )?;
    let service_destinations: BTreeSet<_> =
        matrix.iter().map(|flow| flow.destination_index).collect();
    let affected_services =
        simulation_affected_services(&state, &pod_records, &service_destinations);

    let (summary, changes) = evaluate_simulation_matrix(
        &pod_records,
        &endpoints,
        &matrix,
        &current_policies,
        &proposed_policies,
    );
    let (historical_summary, historical_changes) = evaluate_historical_simulation(
        &flow_history,
        &pod_records,
        &endpoints,
        &current_policies,
        &proposed_policies,
    );

    let identity_revision = mutex_lock(&state.identities).revision();
    let revisions = mutex_lock(&state.revisions).clone();
    Ok(Json(PolicySimulationResponse {
        schema_version: POLICY_SIMULATION_SCHEMA_VERSION,
        resource_kind: candidate.resource_kind,
        policy: candidate.key,
        policy_id: candidate.policy_id,
        operation,
        snapshot: PolicySimulationSnapshot {
            identity_epoch: state.identity_epoch,
            identity_revision,
            policy_revision: revisions.policy,
            topology_revision: revisions.topology,
            flow_history_revision: flow_history.revision,
            pods: pod_records.len(),
            flow_source: "current-topology representative matrix",
        },
        affected_sources: affected_sources.len(),
        affected_destinations: affected_destinations.len(),
        affected_services,
        summary,
        changes,
        historical_query: flow_history.query,
        historical_summary,
        historical_changes,
        note: "read-only what-if result; the candidate was not applied and historical impact uses bounded last-received-time telemetry",
    }))
}

fn compile_simulation_candidate(
    value: serde_json::Value,
) -> Result<CompiledSimulationCandidate, ApiError> {
    let kind = value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::bad_request("policy kind is required"))?;
    match kind {
        "SecurityPolicy" => {
            let policy: SecurityPolicy = serde_json::from_value(value).map_err(|error| {
                ApiError::bad_request(format!("invalid SecurityPolicy: {error}"))
            })?;
            let key = object_key(&policy);
            let policy_id = stable_policy_id(&key);
            let compiled = PolicyCompiler::compile(policy_id, policy)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            Ok(CompiledSimulationCandidate {
                resource_kind: PolicySimulationResourceKind::SecurityPolicy,
                key,
                policy_id,
                policies: vec![compiled],
            })
        }
        "NetworkPolicy" => {
            let policy: NetworkPolicy = serde_json::from_value(value).map_err(|error| {
                ApiError::bad_request(format!("invalid NetworkPolicy: {error}"))
            })?;
            let key = object_key(&policy);
            let policy_id = stable_policy_id(&format!("networkpolicy:{key}"));
            let policies = NetworkPolicyCompiler::compile_directions(policy_id, policy)
                .map_err(|error| ApiError::bad_request(error.to_string()))?;
            Ok(CompiledSimulationCandidate {
                resource_kind: PolicySimulationResourceKind::NetworkPolicy,
                key,
                policy_id,
                policies,
            })
        }
        _ => Err(ApiError::bad_request(format!(
            "unsupported policy kind {kind:?}; expected SecurityPolicy or NetworkPolicy"
        ))),
    }
}

fn simulation_flow_history_snapshot(
    state: &ControllerState,
    query: &FlowHistoryQuery,
) -> Result<FlowHistorySnapshot, ApiError> {
    let limit = validate_flow_history_query(query)?;
    Ok(mutex_lock(&state.flow_history).snapshot_window(
        state.identity_epoch,
        query.since_unix_ms,
        query.until_unix_ms,
        limit,
    ))
}

fn simulation_current_candidate(
    state: &ControllerState,
    resource_kind: PolicySimulationResourceKind,
    candidate_key: &str,
) -> (Vec<PolicyIr>, bool) {
    match resource_kind {
        PolicySimulationResourceKind::SecurityPolicy => {
            let policies = read_lock(&state.compiled_security_policies);
            let current = policies.get(candidate_key).cloned().into_iter().collect();
            (current, policies.contains_key(candidate_key))
        }
        PolicySimulationResourceKind::NetworkPolicy => {
            let current = read_lock(&state.compiled_network_policies)
                .get(candidate_key)
                .cloned()
                .unwrap_or_default();
            let exists = !current.is_empty()
                || read_lock(&state.rejected_network_policies).contains_key(candidate_key);
            (current, exists)
        }
    }
}

fn simulation_proposed_policies(
    state: &ControllerState,
    resource_kind: PolicySimulationResourceKind,
    candidate_key: &str,
    candidate: &[PolicyIr],
) -> Vec<PolicyIr> {
    let mut policies: Vec<_> = read_lock(&state.compiled_security_policies)
        .iter()
        .filter(|(existing_key, _)| {
            resource_kind != PolicySimulationResourceKind::SecurityPolicy
                || existing_key.as_str() != candidate_key
        })
        .map(|(_, policy)| policy.clone())
        .collect();
    policies.extend(
        read_lock(&state.compiled_network_policies)
            .iter()
            .filter(|(existing_key, _)| {
                resource_kind != PolicySimulationResourceKind::NetworkPolicy
                    || existing_key.as_str() != candidate_key
            })
            .flat_map(|(_, policies)| policies.iter().cloned()),
    );
    policies.extend(candidate.iter().cloned());
    policies
}

fn simulation_selected_endpoints(
    endpoints: &[Endpoint],
    candidate: &[PolicyIr],
    current_candidate: &[PolicyIr],
    direction: PolicyDirection,
) -> BTreeSet<usize> {
    endpoints
        .iter()
        .enumerate()
        .filter(|(_, endpoint)| {
            candidate
                .iter()
                .chain(current_candidate)
                .any(|policy| policy.direction == direction && policy.target.matches(endpoint))
        })
        .map(|(index, _)| index)
        .collect()
}

fn simulation_affected_services(
    state: &ControllerState,
    pods: &[PodRecord],
    affected_destinations: &BTreeSet<usize>,
) -> Vec<String> {
    let affected_workloads: BTreeSet<_> = affected_destinations
        .iter()
        .map(|index| format!("{}/{}", pods[*index].namespace, pods[*index].name))
        .collect();
    let runtime_services: BTreeSet<_> = read_lock(&state.endpoint_slices)
        .values()
        .filter(|endpoint_slice| {
            endpoint_slice.backends.iter().any(|backend| {
                backend.ready
                    && !backend.terminating
                    && backend
                        .target_workload
                        .as_ref()
                        .is_some_and(|target| affected_workloads.contains(target))
            })
        })
        .map(|endpoint_slice| endpoint_slice.service_reference.clone())
        .collect();
    read_lock(&state.services)
        .iter()
        .filter(|(reference, service)| {
            runtime_services.contains(*reference)
                || (!service.selector.is_empty()
                    && affected_destinations.iter().any(|index| {
                        let pod = &pods[*index];
                        pod.namespace == service.namespace
                            && service
                                .selector
                                .iter()
                                .all(|(key, value)| pod.endpoint.labels.get(key) == Some(value))
                    }))
        })
        .map(|(reference, _)| reference.clone())
        .collect()
}

fn evaluate_historical_simulation(
    history: &FlowHistorySnapshot,
    pod_records: &[PodRecord],
    endpoints: &[Endpoint],
    current_policies: &[PolicyIr],
    proposed_policies: &[PolicyIr],
) -> (
    PolicySimulationHistoricalSummary,
    Vec<PolicySimulationHistoricalChange>,
) {
    let endpoint_indexes: BTreeMap<IdentityId, usize> = pod_records
        .iter()
        .enumerate()
        .map(|(index, pod)| (pod.endpoint.identity, index))
        .collect();
    let mut summary = PolicySimulationHistoricalSummary {
        retained_flows: history.retained_flows,
        retained_observations: history.retained_observations,
        ..PolicySimulationHistoricalSummary::default()
    };
    let mut changes = Vec::new();
    let mut affected_workloads = BTreeSet::new();
    for entry in &history.entries {
        let Some(source_index) = endpoint_indexes.get(&entry.key.source_identity).copied() else {
            summary.skipped_unresolved_flows += 1;
            continue;
        };
        let Some(destination_index) = endpoint_indexes
            .get(&entry.key.destination_identity)
            .copied()
        else {
            summary.skipped_unresolved_flows += 1;
            continue;
        };
        let Some(protocol) = history_protocol(entry.key.protocol) else {
            summary.skipped_unresolved_flows += 1;
            continue;
        };
        let (current, proposed) = evaluate_historical_flow(
            entry,
            &pod_records[source_index],
            &endpoints[source_index],
            &endpoints[destination_index],
            protocol,
            current_policies,
            proposed_policies,
        );
        summary.evaluated_flows += 1;
        summary.evaluated_observations = summary
            .evaluated_observations
            .saturating_add(entry.observed_events);
        match (current.verdict, proposed.verdict) {
            (Verdict::Allow, Verdict::Deny) => {
                summary.would_be_denied_observations = summary
                    .would_be_denied_observations
                    .saturating_add(entry.observed_events);
            }
            (Verdict::Deny, Verdict::Allow) => {
                summary.would_be_allowed_observations = summary
                    .would_be_allowed_observations
                    .saturating_add(entry.observed_events);
            }
            (_, Verdict::Allow) => {
                summary.remain_allowed_observations = summary
                    .remain_allowed_observations
                    .saturating_add(entry.observed_events);
            }
            (_, Verdict::Deny) => {
                summary.remain_denied_observations = summary
                    .remain_denied_observations
                    .saturating_add(entry.observed_events);
            }
            _ => {}
        }
        if current.verdict != proposed.verdict {
            summary.verdict_change_flows += 1;
        }
        if current != proposed {
            summary.decision_change_flows += 1;
            summary.affected_observations = summary
                .affected_observations
                .saturating_add(entry.observed_events);
            affected_workloads.insert(source_index);
            affected_workloads.insert(destination_index);
            changes.push(PolicySimulationHistoricalChange {
                source: resolved(&pod_records[source_index]),
                destination: resolved(&pod_records[destination_index]),
                direction: entry.key.direction,
                protocol: protocol_name(protocol),
                destination_port: entry.key.destination_port,
                observed_events: entry.observed_events,
                first_received_unix_ms: entry.first_received_unix_ms,
                last_received_unix_ms: entry.last_received_unix_ms,
                reporting_nodes: entry.reporting_nodes.clone(),
                current,
                proposed,
            });
        }
    }
    summary.affected_workloads = affected_workloads.len();
    (summary, changes)
}

fn evaluate_historical_flow(
    entry: &unf_state::FlowHistoryEntry,
    source_pod: &PodRecord,
    source: &Endpoint,
    destination: &Endpoint,
    protocol: Protocol,
    current_policies: &[PolicyIr],
    proposed_policies: &[PolicyIr],
) -> (unf_policy::PolicyDecision, unf_policy::PolicyDecision) {
    let (source_ipv4, source_ipv6) =
        source_addresses(source_pod, entry.key.source_ipv4, entry.key.source_ipv6);
    let flow = Flow {
        source,
        destination,
        protocol,
        destination_port: entry.key.destination_port,
        source_ipv4,
        source_ipv6,
    };
    let destination_addresses = DestinationAddresses {
        ipv4: entry.key.destination_ipv4,
        ipv6: entry.key.destination_ipv6,
    };
    (
        evaluate_for_direction_with_addresses(
            current_policies,
            entry.key.direction,
            flow,
            destination_addresses,
        ),
        evaluate_for_direction_with_addresses(
            proposed_policies,
            entry.key.direction,
            flow,
            destination_addresses,
        ),
    )
}

fn source_addresses(
    pod: &PodRecord,
    source_ipv4: Option<std::net::Ipv4Addr>,
    source_ipv6: Option<Ipv6Addr>,
) -> (Option<std::net::Ipv4Addr>, Option<Ipv6Addr>) {
    if source_ipv4.is_some() {
        return (source_ipv4, None);
    }
    if source_ipv6.is_some() {
        return (None, source_ipv6);
    }
    let source_ipv4 = pod.ipv4_addresses.iter().next().copied();
    let source_ipv6 = source_ipv4
        .is_none()
        .then(|| pod.ipv6_addresses.iter().next().copied())
        .flatten();
    (source_ipv4, source_ipv6)
}

fn evaluate_simulation_matrix(
    pod_records: &[PodRecord],
    endpoints: &[Endpoint],
    matrix: &[SimulationMatrixFlow],
    current_policies: &[PolicyIr],
    proposed_policies: &[PolicyIr],
) -> (PolicySimulationSummary, Vec<PolicySimulationChange>) {
    let mut summary = PolicySimulationSummary::default();
    let mut changes = Vec::new();
    let mut affected_workloads = BTreeSet::new();
    for candidate_flow in matrix {
        let flow = Flow {
            source: &endpoints[candidate_flow.source_index],
            destination: &endpoints[candidate_flow.destination_index],
            protocol: candidate_flow.protocol,
            destination_port: candidate_flow.destination_port,
            source_ipv4: candidate_flow.addresses.source_ipv4,
            source_ipv6: candidate_flow.addresses.source_ipv6,
        };
        let current = evaluate_for_direction_with_addresses(
            current_policies,
            candidate_flow.direction,
            flow,
            candidate_flow.addresses.destination,
        );
        let proposed = evaluate_for_direction_with_addresses(
            proposed_policies,
            candidate_flow.direction,
            flow,
            candidate_flow.addresses.destination,
        );
        summary.evaluated_flows += 1;
        match (current.verdict, proposed.verdict) {
            (Verdict::Allow, Verdict::Deny) => summary.would_be_denied += 1,
            (Verdict::Deny, Verdict::Allow) => summary.would_be_allowed += 1,
            (_, Verdict::Allow) => summary.remain_allowed += 1,
            (_, Verdict::Deny) => summary.remain_denied += 1,
            _ => {}
        }
        if current.verdict != proposed.verdict {
            summary.verdict_changes += 1;
        }
        if current != proposed {
            summary.decision_changes += 1;
            affected_workloads.insert(candidate_flow.source_index);
            affected_workloads.insert(candidate_flow.destination_index);
            changes.push(PolicySimulationChange {
                source: resolved(&pod_records[candidate_flow.source_index]),
                destination: resolved(&pod_records[candidate_flow.destination_index]),
                direction: candidate_flow.direction,
                ip_family: candidate_flow.addresses.ip_family,
                source_address: simulation_source_address(candidate_flow.addresses),
                destination_address: simulation_destination_address(candidate_flow.addresses),
                protocol: protocol_name(candidate_flow.protocol),
                destination_port: candidate_flow.destination_port,
                current,
                proposed,
            });
        }
    }
    summary.affected_workloads = affected_workloads.len();
    (summary, changes)
}

fn simulation_matrix(
    pod_records: &[PodRecord],
    endpoints: &[Endpoint],
    affected_sources: &BTreeSet<usize>,
    affected_destinations: &BTreeSet<usize>,
    current_policies: &[PolicyIr],
    proposed_policies: &[PolicyIr],
) -> Result<Vec<SimulationMatrixFlow>, ApiError> {
    let mut matrix = Vec::new();
    for destination_index in affected_destinations {
        for source_index in 0..endpoints.len() {
            append_simulation_flows(
                &mut matrix,
                pod_records,
                endpoints,
                PolicyDirection::Ingress,
                source_index,
                *destination_index,
                current_policies,
                proposed_policies,
            )?;
        }
    }
    for source_index in affected_sources {
        for destination_index in 0..endpoints.len() {
            append_simulation_flows(
                &mut matrix,
                pod_records,
                endpoints,
                PolicyDirection::Egress,
                *source_index,
                destination_index,
                current_policies,
                proposed_policies,
            )?;
        }
    }
    Ok(matrix)
}

#[allow(clippy::too_many_arguments)]
fn append_simulation_flows(
    matrix: &mut Vec<SimulationMatrixFlow>,
    pod_records: &[PodRecord],
    endpoints: &[Endpoint],
    direction: PolicyDirection,
    source_index: usize,
    destination_index: usize,
    current_policies: &[PolicyIr],
    proposed_policies: &[PolicyIr],
) -> Result<(), ApiError> {
    let tuples = simulation_protocol_ports(
        current_policies,
        proposed_policies,
        direction,
        &endpoints[source_index],
        &endpoints[destination_index],
    );
    let addresses =
        simulation_address_pairs(&pod_records[source_index], &pod_records[destination_index]);
    for (protocol, destination_port) in tuples {
        for addresses in &addresses {
            matrix.push(SimulationMatrixFlow {
                direction,
                source_index,
                destination_index,
                protocol,
                destination_port,
                addresses: *addresses,
            });
            if matrix.len() > POLICY_SIMULATION_FLOW_LIMIT {
                return Err(ApiError::unprocessable(format!(
                    "policy simulation requires more than {POLICY_SIMULATION_FLOW_LIMIT} topology-derived flows; limit is {POLICY_SIMULATION_FLOW_LIMIT}"
                )));
            }
        }
    }
    Ok(())
}

fn simulation_protocol_ports(
    current_policies: &[PolicyIr],
    proposed_policies: &[PolicyIr],
    direction: PolicyDirection,
    source: &Endpoint,
    destination: &Endpoint,
) -> BTreeSet<(Protocol, u16)> {
    let mut tuples = BTreeSet::new();
    for policy in current_policies.iter().chain(proposed_policies) {
        let selected = match direction {
            PolicyDirection::Ingress => destination,
            PolicyDirection::Egress => source,
        };
        if policy.direction != direction || !policy.target.matches(selected) {
            continue;
        }
        for rule in &policy.rules {
            if !rule.destination.matches(destination) {
                continue;
            }
            let protocols: &[Protocol] = match rule.protocol {
                Some(Protocol::Tcp) => &[Protocol::Tcp],
                Some(Protocol::Udp) => &[Protocol::Udp],
                Some(Protocol::Sctp) => &[Protocol::Sctp],
                Some(Protocol::Icmp) => continue,
                None => &[Protocol::Tcp, Protocol::Udp, Protocol::Sctp],
            };
            for protocol in protocols {
                match &rule.destination_port {
                    DestinationPort::Any => {}
                    DestinationPort::Number(port) => {
                        tuples.insert((*protocol, *port));
                    }
                    DestinationPort::Named(name) => {
                        let named_port = NamedPort {
                            name: name.clone(),
                            protocol: *protocol,
                        };
                        if let Some(port) = destination.named_ports.get(&named_port) {
                            tuples.insert((*protocol, *port));
                        }
                    }
                    DestinationPort::Range { start, end } => {
                        tuples.extend((*start..=*end).map(|port| (*protocol, port)));
                    }
                }
            }
        }
    }
    for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Sctp] {
        if let Some(port) = (1..=u16::MAX).find(|port| !tuples.contains(&(protocol, *port))) {
            tuples.insert((protocol, port));
        }
    }
    tuples
}

fn simulation_address_pairs(
    source: &PodRecord,
    destination: &PodRecord,
) -> Vec<SimulationAddresses> {
    let mut pairs = Vec::with_capacity(2);
    if let (Some(source), Some(destination)) = (
        source.ipv4_addresses.iter().next().copied(),
        destination.ipv4_addresses.iter().next().copied(),
    ) {
        pairs.push(SimulationAddresses {
            ip_family: Some(RequestIpFamily::Ipv4),
            source_ipv4: Some(source),
            source_ipv6: None,
            destination: DestinationAddresses {
                ipv4: Some(destination),
                ipv6: None,
            },
        });
    }
    if let (Some(source), Some(destination)) = (
        source.ipv6_addresses.iter().next().copied(),
        destination.ipv6_addresses.iter().next().copied(),
    ) {
        pairs.push(SimulationAddresses {
            ip_family: Some(RequestIpFamily::Ipv6),
            source_ipv4: None,
            source_ipv6: Some(source),
            destination: DestinationAddresses {
                ipv4: None,
                ipv6: Some(destination),
            },
        });
    }
    if pairs.is_empty() {
        pairs.push(SimulationAddresses {
            ip_family: None,
            source_ipv4: None,
            source_ipv6: None,
            destination: DestinationAddresses::default(),
        });
    }
    pairs
}

fn simulation_source_address(addresses: SimulationAddresses) -> Option<IpAddr> {
    addresses
        .source_ipv4
        .map(IpAddr::V4)
        .or_else(|| addresses.source_ipv6.map(IpAddr::V6))
}

fn simulation_destination_address(addresses: SimulationAddresses) -> Option<IpAddr> {
    addresses
        .destination
        .ipv4
        .map(IpAddr::V4)
        .or_else(|| addresses.destination.ipv6.map(IpAddr::V6))
}

const fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Sctp => "sctp",
        Protocol::Icmp => "icmp",
    }
}

const fn history_protocol(protocol: u8) -> Option<Protocol> {
    match protocol {
        6 => Some(Protocol::Tcp),
        17 => Some(Protocol::Udp),
        132 => Some(Protocol::Sctp),
        _ => None,
    }
}

fn endpoints_with_namespace_labels(state: &ControllerState) -> Vec<Endpoint> {
    let namespaces = read_lock(&state.namespaces);
    read_lock(&state.pods)
        .values()
        .map(|pod| endpoint_with_namespace_labels(&pod.endpoint, &namespaces))
        .collect()
}

fn ipv4_endpoints_with_namespace_labels(state: &ControllerState) -> Vec<Ipv4Endpoint> {
    let namespaces = read_lock(&state.namespaces);
    let mut endpoints: Vec<_> = read_lock(&state.pods)
        .values()
        .filter(|pod| !pod.host_network)
        .flat_map(|pod| {
            let endpoint = endpoint_with_namespace_labels(&pod.endpoint, &namespaces);
            pod.ipv4_addresses
                .iter()
                .copied()
                .map(move |address| Ipv4Endpoint {
                    address,
                    endpoint: endpoint.clone(),
                })
        })
        .collect();
    let gateway = host_network_gateway_endpoint(&namespaces);
    endpoints.extend(
        read_lock(&state.host_network_gateways)
            .values()
            .flat_map(|gateways| gateways.ipv4.iter().copied())
            .map(|address| Ipv4Endpoint {
                address,
                endpoint: gateway.clone(),
            }),
    );
    endpoints
}

fn ipv6_endpoints_with_namespace_labels(state: &ControllerState) -> Vec<Ipv6Endpoint> {
    let namespaces = read_lock(&state.namespaces);
    let mut endpoints: Vec<_> = read_lock(&state.pods)
        .values()
        .filter(|pod| !pod.host_network)
        .flat_map(|pod| {
            let endpoint = endpoint_with_namespace_labels(&pod.endpoint, &namespaces);
            pod.ipv6_addresses
                .iter()
                .copied()
                .map(move |address| Ipv6Endpoint {
                    address,
                    endpoint: endpoint.clone(),
                })
        })
        .collect();
    let gateway = host_network_gateway_endpoint(&namespaces);
    endpoints.extend(
        read_lock(&state.host_network_gateways)
            .values()
            .flat_map(|gateways| gateways.ipv6.iter().copied())
            .map(|address| Ipv6Endpoint {
                address,
                endpoint: gateway.clone(),
            }),
    );
    endpoints
}

fn host_network_gateway_endpoint(
    namespaces: &BTreeMap<String, BTreeMap<String, String>>,
) -> Endpoint {
    const HOST_NETWORK_NAMESPACE: &str = "openshift-host-network";
    endpoint_with_namespace_labels(
        &Endpoint {
            identity: IdentityId::new(u32::MAX),
            namespace: HOST_NETWORK_NAMESPACE.to_owned(),
            namespace_labels: BTreeMap::new(),
            service_account: String::new(),
            application: None,
            labels: BTreeMap::new(),
            named_ports: BTreeMap::new(),
        },
        namespaces,
    )
}

fn endpoint_with_namespace_labels(
    endpoint: &Endpoint,
    namespaces: &BTreeMap<String, BTreeMap<String, String>>,
) -> Endpoint {
    let mut endpoint = endpoint.clone();
    endpoint.namespace_labels = namespaces
        .get(&endpoint.namespace)
        .cloned()
        .unwrap_or_else(|| {
            BTreeMap::from([(
                "kubernetes.io/metadata.name".to_owned(),
                endpoint.namespace.clone(),
            )])
        });
    endpoint
}

fn compiled_policies(state: &ControllerState) -> Vec<PolicyIr> {
    let mut policies: Vec<_> = read_lock(&state.compiled_security_policies)
        .values()
        .cloned()
        .collect();
    policies.extend(
        read_lock(&state.compiled_network_policies)
            .values()
            .flatten()
            .cloned(),
    );
    policies
}

fn resolved(pod: &PodRecord) -> ResolvedEndpoint {
    ResolvedEndpoint {
        reference: format!("{}/{}", pod.namespace, pod.name),
        identity: pod.endpoint.identity.get(),
        namespace: pod.endpoint.namespace.clone(),
        service_account: pod.endpoint.service_account.clone(),
        application: pod.endpoint.application.clone(),
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn unprocessable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

fn object_key(resource: &impl ResourceExt) -> String {
    format!(
        "{}/{}",
        resource.namespace().unwrap_or_default(),
        resource.name_any()
    )
}

fn stable_policy_id(key: &str) -> PolicyId {
    PolicyId::new(provisional_identity_id(key).get())
}

fn canonical_identity_key(
    cluster: &str,
    namespace: &str,
    service_account: &str,
    workload: &str,
    labels: &BTreeMap<String, String>,
    named_ports: &BTreeMap<NamedPort, u16>,
) -> String {
    fn append_component(key: &mut String, value: &str) {
        key.push('|');
        key.push_str(&value.len().to_string());
        key.push(':');
        key.push_str(value);
    }

    let mut key = "v2".to_owned();
    append_component(&mut key, cluster);
    append_component(&mut key, namespace);
    append_component(&mut key, service_account);
    append_component(&mut key, workload);
    append_component(&mut key, &labels.len().to_string());
    for (label, value) in labels {
        append_component(&mut key, label);
        append_component(&mut key, value);
    }
    append_component(&mut key, &named_ports.len().to_string());
    for (named_port, number) in named_ports {
        append_component(&mut key, &named_port.name);
        append_component(&mut key, &(named_port.protocol as u8).to_string());
        append_component(&mut key, &number.to_string());
    }
    key
}

fn bump_policy_revision(state: &ControllerState) {
    let mut revisions = mutex_lock(&state.revisions);
    revisions.policy = revisions.policy.next();
}

fn bump_topology_revision(state: &ControllerState) {
    {
        let mut revisions = mutex_lock(&state.revisions);
        revisions.topology = revisions.topology.next();
    }
    capture_topology_history(state);
}

fn bump_routing_revision(state: &ControllerState) {
    let mut revisions = mutex_lock(&state.revisions);
    revisions.routing = revisions.routing.next();
}

fn bump_service_and_topology_revision(state: &ControllerState) {
    {
        let mut revisions = mutex_lock(&state.revisions);
        revisions.service = revisions.service.next();
        revisions.topology = revisions.topology.next();
    }
    reconcile_service_snapshot(state);
    capture_topology_history(state);
}

fn reconcile_service_snapshot(state: &ControllerState) {
    let revision = mutex_lock(&state.revisions).service;
    let services = read_lock(&state.services)
        .values()
        .map(|record| record.compiler_source.clone())
        .collect();
    let endpoint_slices = read_lock(&state.endpoint_slices)
        .values()
        .map(|record| record.compiler_source.clone())
        .collect();
    match compile_service_snapshot(state.identity_epoch, revision, services, endpoint_slices) {
        Ok(snapshot) => {
            *write_lock(&state.compiled_service_snapshot) = Some(snapshot);
            write_lock(&state.service_compilation_error).take();
        }
        Err(error) => {
            state.metrics.errors.inc();
            *write_lock(&state.service_compilation_error) = Some(error.to_string());
            warn!(%error, revision = revision.get(), "retaining last-valid compiled service snapshot");
        }
    }
}

fn capture_topology_history(state: &ControllerState) {
    if state.topology_initializations.load(Ordering::Acquire) != 0 {
        return;
    }
    let snapshot = topology_snapshot(state);
    mutex_lock(&state.topology_history).record(snapshot, unix_time_millis());
    state.topology_history_dirty.store(true, Ordering::Release);
}

fn begin_topology_initialization(state: &ControllerState) {
    state
        .topology_initializations
        .fetch_add(1, Ordering::AcqRel);
}

fn finish_topology_initialization(state: &ControllerState) {
    let mut current = state.topology_initializations.load(Ordering::Acquire);
    loop {
        if current == 0 {
            return;
        }
        match state.topology_initializations.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                if current == 1 {
                    capture_topology_history(state);
                }
                return;
            }
            Err(actual) => current = actual,
        }
    }
}

fn controller_epoch() -> u64 {
    let time_component = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_secs().rotate_left(32) ^ u64::from(duration.subsec_nanos())
        });
    time_component ^ u64::from(std::process::id())
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
                .unwrap_or_else(|_| "unf_controller=info".into()),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_version_exposes_the_controller_compatibility_tuple() {
        let version = component_compatibility();
        assert_eq!(version.component, "unf-controller");
        assert_eq!(version.software_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(version.build_revision, BUILD_REVISION);
        assert_eq!(
            version.policy_snapshot_schema_version,
            POLICY_SNAPSHOT_SCHEMA_VERSION
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
    fn service_schema_transition_negotiates_and_projects_v1_v2_state() {
        assert_eq!(
            requested_service_schema(&ServiceSchemaQuery::default()).unwrap(),
            LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        let current_compatibility =
            compatibility_for_service_schema(SERVICE_SNAPSHOT_SCHEMA_VERSION).unwrap();
        assert_eq!(
            current_compatibility.service_snapshot_schema_version,
            SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        let legacy_compatibility =
            compatibility_for_service_schema(LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION).unwrap();
        assert_eq!(
            legacy_compatibility.service_snapshot_schema_version,
            LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        let node_port_compatibility =
            compatibility_for_service_schema(NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION).unwrap();
        assert_eq!(
            node_port_compatibility.service_snapshot_schema_version,
            NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        assert!(compatibility_for_service_schema(SERVICE_SNAPSHOT_SCHEMA_VERSION + 1).is_err());

        let state = new_state(true);
        apply_service_event(&state, Event::Apply(node_port_service()));
        let current = service_snapshot_for_schema(&state, SERVICE_SNAPSHOT_SCHEMA_VERSION)
            .expect("schema-v3 state is available");
        assert_eq!(current.schema_version, SERVICE_SNAPSHOT_SCHEMA_VERSION);
        assert!(!current.services[0].node_ports.is_empty());
        let node_port =
            service_snapshot_for_schema(&state, NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION)
                .expect("schema-v2 projection is available");
        assert_eq!(
            node_port.schema_version,
            NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        assert!(!node_port.services[0].node_ports.is_empty());
        assert!(node_port.services[0].load_balancer.is_none());
        let legacy = service_snapshot_for_schema(&state, LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION)
            .expect("schema-v1 projection is available");
        assert_eq!(
            legacy.schema_version,
            LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION
        );
        assert!(legacy.services[0].node_ports.is_empty());
        let encoded = serde_json::to_value(legacy).expect("legacy projection encodes");
        assert!(encoded["services"][0].get("nodePorts").is_none());
    }

    fn security_policy(name: &str, action: &str) -> SecurityPolicy {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "network.unf.io/v1alpha1",
            "kind": "SecurityPolicy",
            "metadata": {
                "name": name,
                "namespace": "backend"
            },
            "spec": {
                "target": {"application": "server"},
                "priority": 100,
                "ingress": [{
                    "from": {
                        "namespace": "frontend",
                        "application": "client"
                    },
                    "protocols": [{"protocol": "Tcp", "port": 8080}],
                    "action": action
                }],
                "defaultAction": "Deny",
                "enforcementMode": "Enforce"
            }
        }))
        .expect("test SecurityPolicy is valid Kubernetes JSON")
    }

    fn pod_record(id: u32, namespace: &str, name: &str, application: &str) -> PodRecord {
        PodRecord {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            uid: format!("{namespace}-{name}-uid"),
            node_name: Some("worker-a".to_owned()),
            host_network: false,
            endpoint: Endpoint {
                identity: unf_common::IdentityId::new(id),
                namespace: namespace.to_owned(),
                namespace_labels: BTreeMap::new(),
                service_account: "default".to_owned(),
                application: Some(application.to_owned()),
                labels: BTreeMap::from([("app".to_owned(), application.to_owned())]),
                named_ports: BTreeMap::new(),
            },
            ipv4_addresses: BTreeSet::new(),
            ipv6_addresses: BTreeSet::new(),
        }
    }

    fn network_policy(port: &serde_json::Value, protocol: &str) -> NetworkPolicy {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-client",
                "namespace": "backend"
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": "np-server"}},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "frontend"}
                        },
                        "podSelector": {"matchLabels": {"app": "client"}}
                    }],
                    "ports": [{"protocol": protocol, "port": port}]
                }]
            }
        }))
        .expect("test NetworkPolicy is valid Kubernetes JSON")
    }

    fn egress_policy_state() -> ControllerState {
        let state = new_state(true);
        let mut source = pod_record(10, "frontend", "client", "client");
        source
            .ipv4_addresses
            .insert("10.244.0.10".parse().expect("valid source IPv4"));
        source
            .ipv6_addresses
            .insert("fd00:10:244::10".parse().expect("valid source IPv6"));
        let mut destination = pod_record(20, "backend", "server", "server");
        destination
            .ipv4_addresses
            .insert("10.244.1.20".parse().expect("valid destination IPv4"));
        destination
            .ipv6_addresses
            .insert("fd00:10:244::20".parse().expect("valid destination IPv6"));
        write_lock(&state.pods).insert("frontend/client".to_owned(), source);
        write_lock(&state.pods).insert("backend/server".to_owned(), destination);
        let policy: NetworkPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-server-egress",
                "namespace": "frontend"
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": "client"}},
                "policyTypes": ["Egress"],
                "egress": [{
                    "to": [{
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "backend"}
                        },
                        "podSelector": {"matchLabels": {"app": "server"}}
                    }],
                    "ports": [{"protocol": "TCP", "port": 8080}]
                }]
            }
        }))
        .expect("test egress NetworkPolicy is valid Kubernetes JSON");
        apply_network_policy_event(&state, Event::Apply(policy));
        state
    }

    fn namespace(environment: &str) -> Namespace {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "frontend",
                "labels": {"environment": environment}
            }
        }))
        .expect("test Namespace is valid Kubernetes JSON")
    }

    #[test]
    fn ovn_node_subnets_create_virtual_host_network_peers() {
        let node: Node = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "worker-a",
                "annotations": {
                    "k8s.ovn.org/node-subnets":
                        "{\"default\":[\"10.131.0.0/23\",\"fd01:0:0:4::/64\"]}"
                }
            }
        }))
        .expect("test Node is valid Kubernetes JSON");
        let gateways = ovn_host_network_gateways(&node);
        assert_eq!(
            gateways.ipv4,
            BTreeSet::from(["10.131.0.2".parse().expect("valid IPv4 gateway")])
        );
        assert_eq!(
            gateways.ipv6,
            BTreeSet::from(["fd01:0:0:4::2".parse().expect("valid IPv6 gateway")])
        );

        let state = new_state(true);
        write_lock(&state.host_network_gateways).insert("worker-a".to_owned(), gateways);
        write_lock(&state.namespaces).insert(
            "openshift-host-network".to_owned(),
            BTreeMap::from([(
                "policy-group.network.openshift.io/host-network".to_owned(),
                String::new(),
            )]),
        );
        let endpoint = ipv4_endpoints_with_namespace_labels(&state)
            .into_iter()
            .find(|endpoint| endpoint.address == "10.131.0.2".parse::<Ipv4Addr>().unwrap())
            .expect("OVN gateway becomes an IPv4 policy peer");
        assert_eq!(endpoint.endpoint.namespace, "openshift-host-network");
        assert_eq!(
            endpoint
                .endpoint
                .namespace_labels
                .get("policy-group.network.openshift.io/host-network"),
            Some(&String::new())
        );
    }

    #[test]
    fn ovn_host_network_ingress_allow_creates_scoped_egress_reply_entries() {
        let state = egress_policy_state();
        write_lock(&state.host_network_gateways).insert(
            "worker-a".to_owned(),
            HostNetworkGateways {
                ipv4: BTreeSet::from(["10.131.0.2".parse().expect("valid IPv4 gateway")]),
                ipv6: BTreeSet::from(["fd01:0:0:4::2".parse().expect("valid IPv6 gateway")]),
            },
        );
        write_lock(&state.namespaces).insert(
            "openshift-host-network".to_owned(),
            BTreeMap::from([(
                "policy-group.network.openshift.io/host-network".to_owned(),
                String::new(),
            )]),
        );
        let ingress_policy: NetworkPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-router-ingress",
                "namespace": "frontend"
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": "client"}},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{
                        "namespaceSelector": {
                            "matchLabels": {
                                "policy-group.network.openshift.io/host-network": ""
                            }
                        }
                    }],
                    "ports": [{"protocol": "TCP", "port": 8443}]
                }]
            }
        }))
        .expect("test ingress NetworkPolicy is valid Kubernetes JSON");
        apply_network_policy_event(&state, Event::Apply(ingress_policy));

        let (_, _, _, _, egress_ipv4, egress_ipv6) =
            dataplane_policy_state(&state).expect("OVN reply entries lower into the snapshot");
        let ipv4_reply = egress_ipv4
            .iter()
            .find(|entry| {
                entry.key.source_identity == IdentityId::new(10)
                    && entry.key.destination_address == "10.131.0.2".parse::<Ipv4Addr>().unwrap()
                    && entry.key.protocol == Protocol::Tcp as u8
                    && entry.key.destination_port == 0
            })
            .expect("isolated target gets a TCP reply allow to the IPv4 gateway");
        assert_eq!(ipv4_reply.decision.verdict, Verdict::Allow);
        assert_eq!(ipv4_reply.decision.reason, PolicyReason::ExplicitRule);
        assert!(ipv4_reply.decision.policy_id.is_some());
        assert!(ipv4_reply.decision.rule_id.is_some());
        assert!(egress_ipv6.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(10)
                && entry.key.destination_network == "fd01:0:0:4::2".parse::<Ipv6Addr>().unwrap()
                && entry.key.destination_prefix_len == 128
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 0
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(!egress_ipv4.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(10)
                && entry.key.destination_address == "10.131.0.2".parse::<Ipv4Addr>().unwrap()
                && entry.key.protocol == Protocol::Udp as u8
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(!egress_ipv4.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(20)
                && entry.key.destination_address == "10.131.0.2".parse::<Ipv4Addr>().unwrap()
                && entry.decision.verdict == Verdict::Allow
        }));
    }

    #[test]
    fn primary_node_transport_bypasses_namespace_policy_isolation() {
        let state = egress_policy_state();
        apply_node_event(
            &state,
            Event::Apply(primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64")),
        );
        let ingress_deny: NetworkPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "deny-ingress", "namespace": "frontend"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "client"}},
                "policyTypes": ["Ingress"]
            }
        }))
        .expect("test ingress deny NetworkPolicy is valid Kubernetes JSON");
        apply_network_policy_event(&state, Event::Apply(ingress_deny));

        let (_, _, ingress_ipv4, ingress_ipv6, egress_ipv4, egress_ipv6) =
            dataplane_policy_state(&state)
                .expect("primary Node exception lowers into the snapshot");
        let node_ipv4 = "192.0.2.1".parse::<Ipv4Addr>().expect("valid Node IPv4");
        let node_ipv6 = "fdff::1".parse::<Ipv6Addr>().expect("valid Node IPv6");
        let client_identity = IdentityId::new(10);
        let platform_allow = |decision: &PolicyDecisionRecord| {
            decision.verdict == Verdict::Allow
                && decision.reason == PolicyReason::NoApplicablePolicy
                && decision.policy_id.is_none()
                && decision.rule_id.is_none()
        };

        assert!(ingress_ipv4.iter().any(|entry| {
            entry.key.source_address == node_ipv4
                && entry.key.destination_identity == IdentityId::new(0)
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && platform_allow(&entry.decision)
        }));
        assert!(ingress_ipv6.iter().any(|entry| {
            entry.key.source_network == node_ipv6
                && entry.key.source_prefix_len == 128
                && entry.key.destination_identity == IdentityId::new(0)
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && platform_allow(&entry.decision)
        }));
        assert!(egress_ipv4.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(0)
                && entry.key.destination_address == node_ipv4
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && platform_allow(&entry.decision)
        }));
        assert!(egress_ipv6.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(0)
                && entry.key.destination_network == node_ipv6
                && entry.key.destination_prefix_len == 128
                && entry.key.protocol == 0
                && entry.key.destination_port == 0
                && platform_allow(&entry.decision)
        }));
        assert!(ingress_ipv4.iter().any(|entry| {
            entry.key.source_address == Ipv4Addr::UNSPECIFIED
                && entry.key.destination_identity == client_identity
                && entry.decision.verdict == Verdict::Deny
        }));
        assert!(egress_ipv4.iter().any(|entry| {
            entry.key.source_identity == client_identity
                && entry.key.destination_address == Ipv4Addr::UNSPECIFIED
                && entry.decision.verdict == Verdict::Deny
        }));
    }

    #[test]
    fn physical_host_network_sources_use_pod_namespace_identity() {
        let state = new_state(true);
        write_lock(&state.namespaces).extend([
            (
                "openshift-ingress".to_owned(),
                BTreeMap::from([(
                    "kubernetes.io/metadata.name".to_owned(),
                    "openshift-ingress".to_owned(),
                )]),
            ),
            (
                "other".to_owned(),
                BTreeMap::from([("kubernetes.io/metadata.name".to_owned(), "other".to_owned())]),
            ),
        ]);
        let mut target = pod_record(10, "openshift-ingress-canary", "canary", "canary");
        target
            .ipv4_addresses
            .insert("10.128.0.10".parse().expect("valid target IPv4"));
        target
            .ipv6_addresses
            .insert("fd01::10".parse().expect("valid target IPv6"));
        let mut router = pod_record(20, "openshift-ingress", "router", "router");
        router.host_network = true;
        router
            .ipv4_addresses
            .insert("10.50.60.202".parse().expect("valid Node IPv4"));
        router
            .ipv6_addresses
            .insert("fdff::202".parse().expect("valid Node IPv6"));
        let mut unrelated = pod_record(30, "other", "host-daemon", "host-daemon");
        unrelated.host_network = true;
        unrelated.ipv4_addresses = router.ipv4_addresses.clone();
        unrelated.ipv6_addresses = router.ipv6_addresses.clone();
        write_lock(&state.pods).extend([
            ("openshift-ingress-canary/canary".to_owned(), target),
            ("openshift-ingress/router".to_owned(), router),
            ("other/host-daemon".to_owned(), unrelated),
        ]);
        let policy: NetworkPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "ingress-canary",
                "namespace": "openshift-ingress-canary"
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": "canary"}},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "openshift-ingress"
                            }
                        }
                    }],
                    "ports": [{"protocol": "TCP", "port": 8443}]
                }]
            }
        }))
        .expect("test host-network policy is valid Kubernetes JSON");
        apply_network_policy_event(&state, Event::Apply(policy));

        let (_, _, ipv4, ipv6, _, _) =
            dataplane_policy_state(&state).expect("host-network peers lower without conflicts");
        assert!(ipv4.iter().any(|entry| {
            entry.key.source_address == "10.50.60.202".parse::<Ipv4Addr>().unwrap()
                && entry.key.destination_identity == IdentityId::new(10)
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 8443
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(ipv6.iter().any(|entry| {
            entry.key.source_network == "fdff::202".parse::<Ipv6Addr>().unwrap()
                && entry.key.source_prefix_len == 128
                && entry.key.destination_identity == IdentityId::new(10)
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 8443
                && entry.decision.verdict == Verdict::Allow
        }));
    }

    fn pod_with_named_ports() -> Pod {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "server", "namespace": "backend"},
            "spec": {
                "containers": [{
                    "name": "server",
                    "image": "example.invalid/server",
                    "ports": [
                        {"name": "http", "containerPort": 8081},
                        {"name": "dns", "containerPort": 5353, "protocol": "UDP"},
                        {"name": "sctp", "containerPort": 7777, "protocol": "SCTP"}
                    ]
                }]
            }
        }))
        .expect("test Pod is valid Kubernetes JSON")
    }

    fn scheduled_pod(node_name: &str) -> Pod {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "client",
                "namespace": "frontend",
                "labels": {"app": "client"}
            },
            "spec": {
                "nodeName": node_name,
                "containers": [{"name": "client", "image": "example.invalid/client"}]
            },
            "status": {
                "podIP": "10.42.0.10",
                "podIPs": [
                    {"ip": "10.42.0.10"},
                    {"ip": "fd00:10:42::10"}
                ]
            }
        }))
        .expect("test scheduled Pod is valid Kubernetes JSON")
    }

    fn node(ready: bool) -> Node {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "worker-a",
                "uid": "worker-a-uid",
                "labels": {"kubernetes.io/hostname": "worker-a"}
            },
            "status": {
                "addresses": [
                    {"type": "InternalIP", "address": "192.0.2.1"},
                    {"type": "InternalIP", "address": "fdff::1"}
                ],
                "conditions": [{
                    "type": "Ready",
                    "status": if ready { "True" } else { "False" },
                    "lastHeartbeatTime": "2026-08-24T00:00:00Z",
                    "lastTransitionTime": "2026-08-24T00:00:00Z",
                    "reason": "Test",
                    "message": "test fixture"
                }]
            }
        }))
        .expect("test Node is valid Kubernetes JSON")
    }

    fn primary_node(name: &str, ipv4: &str, ipv6: &str) -> Node {
        let suffix = if name.ends_with('b') { 2 } else { 1 };
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": name,
                "uid": format!("{name}-uid"),
                "labels": {
                    "kubernetes.io/hostname": name,
                    (PRIMARY_CNI_NODE_LABEL): PRIMARY_CNI_NODE_LABEL_VALUE
                }
            },
            "spec": {"podCIDRs": [ipv4, ipv6]},
            "status": {"addresses": [
                {"type": "InternalIP", "address": format!("192.0.2.{suffix}")},
                {"type": "InternalIP", "address": format!("fdff::{suffix}")}
            ]}
        }))
        .expect("primary-CNI test Node is valid Kubernetes JSON")
    }

    fn service() -> Service {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "client", "namespace": "frontend"},
            "spec": {
                "type": "ClusterIP",
                "clusterIP": "10.43.0.10",
                "clusterIPs": ["10.43.0.10"],
                "selector": {"app": "client"},
                "ports": [{
                    "name": "http",
                    "protocol": "TCP",
                    "port": 80,
                    "targetPort": 8080,
                    "appProtocol": "kubernetes.io/h2c"
                }]
            }
        }))
        .expect("test Service is valid Kubernetes JSON")
    }

    fn node_port_service() -> Service {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "edge", "namespace": "frontend"},
            "spec": {
                "type": "NodePort",
                "clusterIP": "10.43.0.20",
                "clusterIPs": ["10.43.0.20", "fd02::20"],
                "ipFamilies": ["IPv4", "IPv6"],
                "externalTrafficPolicy": "Local",
                "selector": {"app": "edge"},
                "ports": [{
                    "name": "https",
                    "protocol": "TCP",
                    "port": 443,
                    "targetPort": 8443,
                    "nodePort": 30443,
                    "appProtocol": "kubernetes.io/h2c"
                }]
            }
        }))
        .expect("test NodePort Service is valid Kubernetes JSON")
    }

    fn load_balancer_service() -> Service {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "public-api", "namespace": "frontend"},
            "spec": {
                "type": "LoadBalancer",
                "loadBalancerClass": "network.unf.io/load-balancer",
                "clusterIP": "10.43.0.30",
                "clusterIPs": ["10.43.0.30", "fd02::30"],
                "ipFamilies": ["IPv4", "IPv6"],
                "ipFamilyPolicy": "RequireDualStack",
                "externalTrafficPolicy": "Local",
                "allocateLoadBalancerNodePorts": false,
                "loadBalancerIP": "192.0.2.60",
                "loadBalancerSourceRanges": ["198.51.100.0/24", "2001:db8:100::/56"],
                "healthCheckNodePort": 32000,
                "selector": {"app": "public-api"},
                "ports": [
                    {
                        "name": "https",
                        "protocol": "TCP",
                        "port": 443,
                        "targetPort": 8443,
                        "appProtocol": "kubernetes.io/h2c"
                    },
                    {
                        "name": "dns",
                        "protocol": "UDP",
                        "port": 53,
                        "targetPort": 5353
                    }
                ]
            }
        }))
        .expect("test LoadBalancer Service is valid Kubernetes JSON")
    }

    fn endpoint_slice(ready: bool) -> EndpointSlice {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "client-abc",
                "namespace": "frontend",
                "labels": {"kubernetes.io/service-name": "client"}
            },
            "addressType": "IPv4",
            "ports": [{
                "name": "http",
                "protocol": "TCP",
                "port": 8080,
                "appProtocol": "kubernetes.io/h2c"
            }],
            "endpoints": [{
                "addresses": ["10.42.0.10"],
                "conditions": {
                    "ready": ready,
                    "serving": true,
                    "terminating": false
                },
                "nodeName": "worker-a",
                "zone": "zone-a",
                "targetRef": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "namespace": "frontend",
                    "name": "client"
                }
            }]
        }))
        .expect("test EndpointSlice is valid Kubernetes JSON")
    }

    fn topology_only_service_record() -> ServiceRecord {
        ServiceRecord {
            namespace: "backend".to_owned(),
            name: "server".to_owned(),
            uid: "server-uid".to_owned(),
            resource_version: "1".to_owned(),
            finalizers: Vec::new(),
            deleting: false,
            service_type: "ClusterIP".to_owned(),
            cluster_ips: BTreeSet::new(),
            selector: BTreeMap::new(),
            ports: Vec::new(),
            compiler_source: ServiceSource {
                namespace: "backend".to_owned(),
                name: "server".to_owned(),
                cluster_ips: Vec::new(),
                external_traffic_policy: ServiceTrafficPolicy::Cluster,
                load_balancer: None,
                ports: Vec::new(),
            },
        }
    }

    fn topology_only_endpoint_slice_record() -> EndpointSliceRecord {
        EndpointSliceRecord {
            service_reference: "backend/server".to_owned(),
            backends: vec![TopologyServiceBackend {
                endpoint_slice: "backend/server-abc".to_owned(),
                address_type: "IPv4".to_owned(),
                addresses: vec!["10.42.1.20".to_owned()],
                target_workload: Some("backend/server".to_owned()),
                node_name: Some("worker-a".to_owned()),
                zone: None,
                ready: true,
                serving: true,
                terminating: false,
                ports: Vec::new(),
            }],
            compiler_source: EndpointSliceSource {
                namespace: "backend".to_owned(),
                name: "server-abc".to_owned(),
                service_name: "server".to_owned(),
                address_family: AddressFamily::Ipv4,
                endpoints: Vec::new(),
            },
        }
    }

    fn flow_batch(observed_events: u64) -> FlowExportBatch {
        FlowExportBatch {
            schema_version: FLOW_EXPORT_SCHEMA_VERSION,
            node_name: "worker-a".to_owned(),
            dropped_events: 2,
            entries: vec![unf_state::FlowExportRecord {
                key: unf_state::FlowHistoryKey {
                    direction: PolicyDirection::Ingress,
                    source_identity: IdentityId::new(1),
                    destination_identity: IdentityId::new(2),
                    source_ipv4: Some("10.42.0.10".parse().expect("valid test address")),
                    destination_ipv4: Some("10.42.1.20".parse().expect("valid test address")),
                    source_ipv6: None,
                    destination_ipv6: None,
                    protocol: 6,
                    destination_port: 8080,
                    service: None,
                },
                policy_revision: Revision::new(7),
                decision: unf_state::FlowExportDecision {
                    verdict: Verdict::Allow,
                    reason: 1,
                    policy_id: Some(PolicyId::new(9)),
                    rule_id: Some(unf_common::RuleId::new(0)),
                },
                shadow: None,
                service: None,
                observed_events,
            }],
        }
    }

    #[test]
    fn canonical_identity_key_is_order_independent_and_label_sensitive() {
        let left = BTreeMap::from([
            ("app".to_owned(), "server".to_owned()),
            ("track".to_owned(), "stable".to_owned()),
        ]);
        let right = BTreeMap::from([
            ("track".to_owned(), "stable".to_owned()),
            ("app".to_owned(), "server".to_owned()),
        ]);
        let base = canonical_identity_key(
            "local",
            "backend",
            "default",
            "server",
            &left,
            &BTreeMap::new(),
        );
        assert_eq!(
            base,
            canonical_identity_key(
                "local",
                "backend",
                "default",
                "server",
                &right,
                &BTreeMap::new(),
            )
        );

        let changed = BTreeMap::from([
            ("app".to_owned(), "server".to_owned()),
            ("track".to_owned(), "canary".to_owned()),
        ]);
        assert_ne!(
            base,
            canonical_identity_key(
                "local",
                "backend",
                "default",
                "server",
                &changed,
                &BTreeMap::new(),
            )
        );
    }

    #[test]
    fn canonical_identity_key_is_unambiguous_for_delimiters() {
        let labels = BTreeMap::new();
        assert_ne!(
            canonical_identity_key("local", "a|1:b", "c", "d", &labels, &BTreeMap::new(),),
            canonical_identity_key("local", "a", "1:b|c", "d", &labels, &BTreeMap::new(),)
        );
    }

    #[test]
    fn canonical_identity_key_includes_named_port_mappings() {
        let labels = BTreeMap::from([("app".to_owned(), "server".to_owned())]);
        let named_port = NamedPort {
            name: "http".to_owned(),
            protocol: Protocol::Tcp,
        };
        let first = BTreeMap::from([(named_port.clone(), 8080)]);
        let second = BTreeMap::from([(named_port, 9090)]);
        assert_ne!(
            canonical_identity_key("local", "backend", "default", "server", &labels, &first),
            canonical_identity_key("local", "backend", "default", "server", &labels, &second,)
        );
    }

    #[test]
    fn pod_named_ports_extract_supported_protocols_and_reject_conflicts() {
        let mut pod = pod_with_named_ports();
        let ports = pod_named_ports(&pod).expect("valid named ports resolve");
        assert_eq!(
            ports[&NamedPort {
                name: "http".to_owned(),
                protocol: Protocol::Tcp,
            }],
            8081
        );
        assert_eq!(
            ports[&NamedPort {
                name: "dns".to_owned(),
                protocol: Protocol::Udp,
            }],
            5353
        );
        assert_eq!(
            ports[&NamedPort {
                name: "sctp".to_owned(),
                protocol: Protocol::Sctp,
            }],
            7777
        );
        assert_eq!(ports.len(), 3);

        let containers = &mut pod.spec.as_mut().expect("spec exists").containers;
        containers.push(
            serde_json::from_value(serde_json::json!({
                "name": "other",
                "image": "example.invalid/other",
                "ports": [{"name": "http", "containerPort": 9090}]
            }))
            .expect("test Container is valid Kubernetes JSON"),
        );
        assert!(pod_named_ports(&pod).is_err());
    }

    #[test]
    fn network_policy_reconciliation_accepts_sctp_and_removes_stale_state_on_rejection() {
        let state = new_state(true);
        apply_network_policy_event(
            &state,
            Event::Apply(network_policy(&serde_json::json!("http"), "TCP")),
        );
        assert_eq!(read_lock(&state.network_policies).len(), 1);
        assert_eq!(read_lock(&state.compiled_network_policies).len(), 1);
        assert!(read_lock(&state.rejected_network_policies).is_empty());
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(1));

        apply_network_policy_event(
            &state,
            Event::Apply(network_policy(&serde_json::json!("http"), "SCTP")),
        );
        assert_eq!(read_lock(&state.network_policies).len(), 1);
        assert_eq!(read_lock(&state.compiled_network_policies).len(), 1);
        assert!(read_lock(&state.rejected_network_policies).is_empty());
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(2));

        apply_network_policy_event(
            &state,
            Event::Apply(network_policy(&serde_json::json!("http"), "ICMP")),
        );
        assert!(read_lock(&state.network_policies).is_empty());
        assert!(read_lock(&state.compiled_network_policies).is_empty());
        assert_eq!(read_lock(&state.rejected_network_policies).len(), 1);
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(3));
    }

    #[test]
    fn network_policy_reconciliation_distributes_egress_without_ingress_cross_contamination() {
        let state = egress_policy_state();

        assert_eq!(read_lock(&state.network_policies).len(), 1);
        let compiled = read_lock(&state.compiled_network_policies);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled["frontend/allow-server-egress"].len(), 1);
        assert_eq!(
            compiled["frontend/allow-server-egress"][0].direction,
            PolicyDirection::Egress
        );
        drop(compiled);
        assert!(read_lock(&state.rejected_network_policies).is_empty());
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(1));

        let (_, ingress, ingress_ipv4, ingress_ipv6, egress_ipv4, egress_ipv6) =
            dataplane_policy_state(&state).expect("egress policy lowers into one snapshot");
        assert!(ingress.is_empty());
        assert!(ingress_ipv4.is_empty());
        assert!(ingress_ipv6.is_empty());
        assert!(egress_ipv4.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(10)
                && entry.key.destination_address
                    == "10.244.1.20"
                        .parse::<std::net::Ipv4Addr>()
                        .expect("valid expected IPv4")
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 8080
                && entry.decision.verdict == Verdict::Allow
        }));
        assert!(egress_ipv6.iter().any(|entry| {
            entry.key.source_identity == IdentityId::new(10)
                && entry.key.destination_network
                    == "fd00:10:244::20"
                        .parse::<Ipv6Addr>()
                        .expect("valid expected IPv6")
                && entry.key.destination_prefix_len == 128
                && entry.key.protocol == Protocol::Tcp as u8
                && entry.key.destination_port == 8080
                && entry.decision.verdict == Verdict::Allow
        }));
    }

    #[test]
    fn direction_aware_explanation_uses_the_requested_address_family() {
        let state = egress_policy_state();
        let allowed = explain_response(
            &state,
            &ExplainRequest {
                from: "frontend/client".to_owned(),
                to: "backend/server".to_owned(),
                direction: RequestPolicyDirection::Egress,
                ip_family: Some(RequestIpFamily::Ipv6),
                protocol: RequestProtocol::Tcp,
                port: 8080,
            },
        )
        .expect("IPv6 egress allow is explainable");
        assert_eq!(allowed.direction, PolicyDirection::Egress);
        assert_eq!(
            allowed.source_address,
            "fd00:10:244::10".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            allowed.destination_address,
            "fd00:10:244::20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(allowed.decision.direction, PolicyDirection::Egress);
        assert_eq!(allowed.decision.verdict, Verdict::Allow);

        let denied = explain_response(
            &state,
            &ExplainRequest {
                from: "frontend/client".to_owned(),
                to: "backend/server".to_owned(),
                direction: RequestPolicyDirection::Egress,
                ip_family: Some(RequestIpFamily::Ipv4),
                protocol: RequestProtocol::Tcp,
                port: 8081,
            },
        )
        .expect("IPv4 egress default isolation is explainable");
        assert_eq!(denied.decision.direction, PolicyDirection::Egress);
        assert_eq!(denied.decision.verdict, Verdict::Deny);
    }

    #[test]
    fn namespace_label_changes_advance_policy_revision_without_identity_churn() {
        let state = new_state(true);
        apply_namespace_event(&state, Event::Apply(namespace("production")));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(1));
        assert_eq!(mutex_lock(&state.revisions).identity, Revision::default());
        assert_eq!(
            read_lock(&state.namespaces)["frontend"]["kubernetes.io/metadata.name"],
            "frontend"
        );

        let mut unchanged = namespace("production");
        unchanged.metadata.resource_version = Some("2".to_owned());
        apply_namespace_event(&state, Event::Apply(unchanged));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(1));

        apply_namespace_event(&state, Event::Apply(namespace("staging")));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(2));
        assert_eq!(mutex_lock(&state.revisions).identity, Revision::default());
    }

    fn converged_agent_report(epoch: u64) -> AgentStateReport {
        AgentStateReport {
            schema_version: AGENT_STATUS_SCHEMA_VERSION,
            node_name: "worker-a".to_owned(),
            pod_name: "unf-agent-test".to_owned(),
            pod_uid: "unf-agent-test-uid".to_owned(),
            version_transition: unf_state::VersionTransition::Normal,
            ready: true,
            bpf_loaded: true,
            desired_identity_revision: 0,
            applied_identity_revision: 0,
            desired_identity_epoch: epoch,
            applied_identity_epoch: epoch,
            identity_map_entries: 2,
            ipv4_identity_map_entries: 1,
            ipv6_identity_map_entries: 1,
            desired_policy_revision: 0,
            applied_policy_revision: 0,
            desired_policy_epoch: epoch,
            applied_policy_epoch: epoch,
            policy_map_entries: 1,
            active_policy_bank: 0,
            desired_service_epoch: 0,
            desired_service_revision: 0,
            applied_service_epoch: 0,
            applied_service_revision: 0,
            service_snapshot_schema_version: SERVICE_SNAPSHOT_SCHEMA_VERSION,
            failed_service_epoch: 0,
            failed_service_revision: 0,
            service_count: 0,
            service_frontend_count: 0,
            service_backend_count: 0,
            desired_node_port_frontend_count: 0,
            applied_node_port_frontend_count: 0,
            node_port_cluster_frontend_count: 0,
            node_port_local_frontend_count: 0,
            load_balancer_reachability_schema_version:
                unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION,
            desired_load_balancer_epoch: 0,
            desired_load_balancer_revision: 0,
            desired_load_balancer_allocation_revision: 0,
            applied_load_balancer_epoch: 0,
            applied_load_balancer_revision: 0,
            applied_load_balancer_allocation_revision: 0,
            load_balancer_frontend_count: 0,
            load_balancer_cluster_frontend_count: 0,
            load_balancer_local_frontend_count: 0,
            load_balancer_source_range_count: 0,
            load_balancer_health_check_count: 0,
            load_balancer_health_check_ready_count: 0,
            active_load_balancer_bank: 0,
            load_balancer_reconcile_errors: 0,
            load_balancer_last_error: None,
            service_reconcile_errors: 0,
            service_last_error: None,
            service_dataplane_events: 0,
            service_translations: 0,
            service_drops: 0,
            service_expirations: 0,
            node_port_cluster_translations: 0,
            node_port_local_translations: 0,
            node_port_no_backend_drops: 0,
            load_balancer_cluster_translations: 0,
            load_balancer_local_translations: 0,
            load_balancer_no_backend_drops: 0,
            load_balancer_source_range_drops: 0,
            invalid_service_events: 0,
            last_service_id: 0,
            last_backend_id: 0,
            last_service_revision: 0,
            last_service_action: 0,
            last_service_reason: 0,
            desired_node_block_revision: 0,
            applied_node_block_revision: 0,
            desired_remote_route_epoch: 0,
            applied_remote_route_epoch: 0,
            desired_remote_route_revision: 0,
            applied_remote_route_revision: 0,
            remote_route_entries: 0,
            remote_route_reconcile_errors: 0,
        }
    }

    #[test]
    fn durable_agent_report_store_round_trips_validated_state() {
        let stored = StoredAgentReport {
            report: converged_agent_report(7),
            last_received_unix_ms: 10_000,
        };
        let store = DurableAgentReportStore {
            schema_version: AGENT_REPORT_STORE_SCHEMA_VERSION,
            reports: BTreeMap::from([("worker-a".to_owned(), stored.clone())]),
        };
        let encoded = serde_json::to_string(&store).expect("durable store encodes");

        let (decoded, ignored) = decode_agent_report_store(&encoded, 10_001)
            .expect("valid durable acknowledgement is restored");

        assert_eq!(decoded, BTreeMap::from([("worker-a".to_owned(), stored)]));
        assert_eq!(ignored, 0);
    }

    #[test]
    fn durable_agent_report_store_ignores_only_older_status_schemas() {
        let current = StoredAgentReport {
            report: converged_agent_report(7),
            last_received_unix_ms: 10_000,
        };
        let mut older = current.clone();
        older.report.node_name = "worker-old".to_owned();
        older.report.schema_version = AGENT_STATUS_SCHEMA_VERSION - 1;
        let store = DurableAgentReportStore {
            schema_version: AGENT_REPORT_STORE_SCHEMA_VERSION,
            reports: BTreeMap::from([
                ("worker-a".to_owned(), current.clone()),
                ("worker-old".to_owned(), older),
            ]),
        };

        let (decoded, ignored) = decode_agent_report_store(
            &serde_json::to_string(&store).expect("store encodes"),
            10_001,
        )
        .expect("older report schemas are safely omitted during upgrade");

        assert_eq!(decoded, BTreeMap::from([("worker-a".to_owned(), current)]));
        assert_eq!(ignored, 1);

        let mut future = converged_agent_report(7);
        future.schema_version = AGENT_STATUS_SCHEMA_VERSION + 1;
        let future_store = DurableAgentReportStore {
            schema_version: AGENT_REPORT_STORE_SCHEMA_VERSION,
            reports: BTreeMap::from([(
                "worker-a".to_owned(),
                StoredAgentReport {
                    report: future,
                    last_received_unix_ms: 10_000,
                },
            )]),
        };
        assert!(
            decode_agent_report_store(
                &serde_json::to_string(&future_store).expect("store encodes"),
                10_001,
            )
            .is_err()
        );
    }

    #[test]
    fn durable_agent_report_store_rejects_untrusted_shape_and_time() {
        let stored = StoredAgentReport {
            report: converged_agent_report(7),
            last_received_unix_ms: 100_000,
        };
        let mismatched = DurableAgentReportStore {
            schema_version: AGENT_REPORT_STORE_SCHEMA_VERSION,
            reports: BTreeMap::from([("worker-b".to_owned(), stored.clone())]),
        };
        assert!(
            decode_agent_report_store(
                &serde_json::to_string(&mismatched).expect("store encodes"),
                100_000,
            )
            .is_err()
        );

        let future = DurableAgentReportStore {
            schema_version: AGENT_REPORT_STORE_SCHEMA_VERSION,
            reports: BTreeMap::from([("worker-a".to_owned(), stored)]),
        };
        assert!(
            decode_agent_report_store(&serde_json::to_string(&future).expect("store encodes"), 1,)
                .is_err()
        );

        let wrong_schema = DurableAgentReportStore {
            schema_version: AGENT_REPORT_STORE_SCHEMA_VERSION + 1,
            reports: BTreeMap::new(),
        };
        assert!(
            decode_agent_report_store(
                &serde_json::to_string(&wrong_schema).expect("store encodes"),
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn node_deletion_retires_its_durable_agent_report() {
        let state = new_state(true);
        let mut node = Node::default();
        node.metadata.name = Some("worker-a".to_owned());
        apply_node_event(&state, Event::Apply(node.clone()));
        write_lock(&state.agent_reports).insert(
            "worker-a".to_owned(),
            StoredAgentReport {
                report: converged_agent_report(state.identity_epoch),
                last_received_unix_ms: 10_000,
            },
        );

        apply_node_event(&state, Event::Delete(node));

        assert!(read_lock(&state.agent_reports).is_empty());
        assert!(state.agent_reports_dirty.load(Ordering::Acquire));
    }

    #[test]
    fn opt_in_node_blocks_are_dual_stack_non_overlapping_and_revisioned() {
        let state = new_state(true);
        let worker_a = primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64");
        apply_node_event(&state, Event::Apply(worker_a.clone()));
        let first = node_block_snapshot_for(&state, "worker-a").unwrap();
        assert_eq!(first.schema_version, NODE_BLOCK_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(first.revision, 1);
        assert_eq!(first.node_uid, "worker-a-uid");
        assert_eq!(first.provider.ipv4_block.to_string(), "10.42.0.0/24");

        apply_node_event(&state, Event::Apply(worker_a));
        assert_eq!(mutex_lock(&state.revisions).routing, Revision::new(1));

        let mut report = converged_agent_report(state.identity_epoch);
        write_lock(&state.agent_reports).insert(
            "worker-a".to_owned(),
            StoredAgentReport {
                report: report.clone(),
                last_received_unix_ms: 100,
            },
        );
        assert!(
            !agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100,)
                .all_converged
        );
        report.desired_node_block_revision = first.revision;
        report.applied_node_block_revision = first.revision;
        report.desired_remote_route_epoch = state.identity_epoch;
        report.applied_remote_route_epoch = state.identity_epoch;
        report.desired_remote_route_revision = 1;
        report.applied_remote_route_revision = 1;
        write_lock(&state.agent_reports).insert(
            "worker-a".to_owned(),
            StoredAgentReport {
                report,
                last_received_unix_ms: 100,
            },
        );
        assert!(
            agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100,)
                .all_converged
        );

        apply_node_event(
            &state,
            Event::Apply(primary_node("worker-b", "10.43.0.0/24", "fd00:43::/64")),
        );
        assert_eq!(
            node_block_snapshot_for(&state, "worker-a")
                .unwrap()
                .revision,
            1
        );
        assert_eq!(
            node_block_snapshot_for(&state, "worker-b")
                .unwrap()
                .revision,
            2
        );

        let overlapping = primary_node("worker-b", "10.42.0.128/25", "fd00:43::/64");
        apply_node_event(&state, Event::Apply(overlapping.clone()));
        assert!(read_lock(&state.node_blocks).is_empty());
        assert_eq!(read_lock(&state.rejected_node_blocks).len(), 2);
        assert!(node_block_snapshot_for(&state, "worker-a").is_err());

        apply_node_event(&state, Event::Delete(overlapping));
        assert_eq!(
            node_block_snapshot_for(&state, "worker-a")
                .unwrap()
                .revision,
            4
        );
        assert_eq!(read_lock(&state.rejected_node_blocks).len(), 0);
        assert_eq!(mutex_lock(&state.revisions).routing, Revision::new(4));

        apply_node_event(&state, Event::Init);
        assert_eq!(
            node_block_snapshot_for(&state, "worker-a")
                .unwrap()
                .revision,
            4
        );
        apply_node_event(
            &state,
            Event::InitApply(primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64")),
        );
        apply_node_event(&state, Event::InitDone);
        assert_eq!(
            node_block_snapshot_for(&state, "worker-a")
                .unwrap()
                .revision,
            4
        );
        assert_eq!(mutex_lock(&state.revisions).routing, Revision::new(4));

        apply_node_event(&state, Event::Init);
        assert!(node_block_snapshot_for(&state, "worker-a").is_ok());
        apply_node_event(&state, Event::InitDone);
        assert!(node_block_snapshot_for(&state, "worker-a").is_err());
        assert_eq!(mutex_lock(&state.revisions).routing, Revision::new(5));
    }

    #[test]
    fn node_block_distribution_requires_explicit_label_and_exact_family_pair() {
        let state = new_state(true);
        apply_node_event(&state, Event::Apply(node(true)));
        assert!(read_lock(&state.node_block_inputs).is_empty());
        assert_eq!(mutex_lock(&state.revisions).routing, Revision::default());

        let mut invalid = primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64");
        invalid.spec.as_mut().unwrap().pod_cidrs = Some(vec!["10.42.0.0/24".to_owned()]);
        apply_node_event(&state, Event::Apply(invalid));
        assert!(read_lock(&state.node_blocks).is_empty());
        assert!(read_lock(&state.rejected_node_blocks)["worker-a"].contains("exactly one"));
    }

    #[test]
    fn node_port_node_intent_is_scoped_revisioned_and_last_valid() {
        let state = new_state(true);
        let mut source = primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64");
        source
            .status
            .as_mut()
            .unwrap()
            .addresses
            .as_mut()
            .unwrap()
            .push(k8s_openapi::api::core::v1::NodeAddress {
                type_: "ExternalIP".to_owned(),
                address: "198.51.100.10".to_owned(),
            });
        apply_node_event(&state, Event::Apply(source.clone()));
        let first = node_port_node_snapshot_for(&state, "worker-a").unwrap();
        assert_eq!(first.revision, Revision::new(1));
        assert_eq!(first.addresses.len(), 3);
        assert!(
            first
                .addresses
                .iter()
                .any(|address| address.kind == NodeAddressKind::External)
        );
        assert!(node_port_node_snapshot_for(&state, "worker-b").is_err());

        apply_node_event(&state, Event::Apply(source.clone()));
        assert_eq!(
            node_port_node_snapshot_for(&state, "worker-a")
                .unwrap()
                .revision,
            Revision::new(1)
        );
        source.status.as_mut().unwrap().addresses.as_mut().unwrap()[0].address =
            "not-an-address".to_owned();
        apply_node_event(&state, Event::Apply(source));
        assert_eq!(
            node_port_node_snapshot_for(&state, "worker-a")
                .unwrap()
                .revision,
            Revision::new(1)
        );
        assert!(read_lock(&state.rejected_node_port_nodes).contains_key("worker-a"));

        let relisted = primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64");
        apply_node_event(&state, Event::Init);
        apply_node_event(&state, Event::InitApply(relisted.clone()));
        apply_node_event(&state, Event::InitDone);
        assert_eq!(
            node_port_node_snapshot_for(&state, "worker-a")
                .unwrap()
                .revision,
            Revision::new(2)
        );
        assert!(read_lock(&state.rejected_node_port_nodes).is_empty());

        apply_node_event(&state, Event::Init);
        apply_node_event(&state, Event::InitApply(relisted));
        apply_node_event(&state, Event::InitDone);
        assert_eq!(
            node_port_node_snapshot_for(&state, "worker-a")
                .unwrap()
                .revision,
            Revision::new(2)
        );

        apply_node_event(&state, Event::Init);
        apply_node_event(&state, Event::InitDone);
        assert!(node_port_node_snapshot_for(&state, "worker-a").is_err());
    }

    #[test]
    fn remote_route_snapshots_are_complete_revisioned_and_transport_strict() {
        let state = new_state(true);
        apply_node_event(
            &state,
            Event::Apply(primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64")),
        );
        apply_node_event(
            &state,
            Event::Apply(primary_node("worker-b", "10.43.0.0/24", "fd00:43::/64")),
        );

        let snapshot = remote_route_snapshot_for(&state, "worker-a").unwrap();
        assert_eq!(
            snapshot.schema_version,
            REMOTE_ROUTE_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(snapshot.source_epoch, state.identity_epoch);
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.local_assignment_revision, 1);
        assert_eq!(snapshot.remote_nodes.len(), 1);
        assert_eq!(snapshot.remote_nodes[0].intent.node_name, "worker-b");
        assert_eq!(snapshot.remote_nodes[0].intent.assignment_revision, 2);
        assert_eq!(
            snapshot.remote_nodes[0].ipv4_transport,
            "192.0.2.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            snapshot.remote_nodes[0].ipv6_transport,
            "fdff::2".parse::<Ipv6Addr>().unwrap()
        );

        let mut moved = primary_node("worker-b", "10.43.0.0/24", "fd00:43::/64");
        moved.status.as_mut().unwrap().addresses.as_mut().unwrap()[0].address =
            "192.0.2.22".to_owned();
        apply_node_event(&state, Event::Apply(moved));
        let moved = remote_route_snapshot_for(&state, "worker-a").unwrap();
        assert_eq!(moved.revision, 3);
        assert_eq!(moved.remote_nodes[0].intent.assignment_revision, 2);
        assert_eq!(
            moved.remote_nodes[0].ipv4_transport,
            "192.0.2.22".parse::<Ipv4Addr>().unwrap()
        );

        let mut invalid = primary_node("worker-b", "10.43.0.0/24", "fd00:43::/64");
        invalid
            .status
            .as_mut()
            .unwrap()
            .addresses
            .as_mut()
            .unwrap()
            .pop();
        apply_node_event(&state, Event::Apply(invalid));
        assert!(remote_route_snapshot_for(&state, "worker-a").is_err());
        assert_eq!(
            read_lock(&state.node_blocks)
                .values()
                .filter(|assignment| assignment.transport.is_err())
                .count(),
            1
        );

        apply_node_event(
            &state,
            Event::Delete(primary_node("worker-b", "10.43.0.0/24", "fd00:43::/64")),
        );
        let retired = remote_route_snapshot_for(&state, "worker-a").unwrap();
        assert_eq!(retired.revision, 5);
        assert!(retired.remote_nodes.is_empty());

        apply_node_event(
            &state,
            Event::Apply(primary_node("worker-c", "10.44.0.0/24", "fd00:44::/64")),
        );
        assert!(remote_route_snapshot_for(&state, "worker-a").is_err());
    }

    #[test]
    fn node_initialization_retires_reports_deleted_while_controller_was_offline() {
        let state = new_state(true);
        for node_name in ["worker-a", "departed-worker"] {
            let mut report = converged_agent_report(state.identity_epoch);
            report.node_name = node_name.to_owned();
            write_lock(&state.agent_reports).insert(
                node_name.to_owned(),
                StoredAgentReport {
                    report,
                    last_received_unix_ms: 10_000,
                },
            );
        }
        let mut active_node = Node::default();
        active_node.metadata.name = Some("worker-a".to_owned());

        apply_node_event(&state, Event::Init);
        apply_node_event(&state, Event::InitApply(active_node));
        apply_node_event(&state, Event::InitDone);

        assert_eq!(
            read_lock(&state.agent_reports)
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["worker-a"]
        );
        assert!(state.agent_reports_dirty.load(Ordering::Acquire));
        let history = mutex_lock(&state.topology_history).snapshot_window(
            None,
            None,
            None,
            None,
            TOPOLOGY_HISTORY_CAPACITY,
            0,
        );
        assert_eq!(history.retained_snapshots, 1);
        assert_eq!(history.entries[0].snapshot.revision, Revision::new(1));
        assert_eq!(history.entries[0].snapshot.nodes.len(), 1);
        assert_eq!(state.topology_initializations.load(Ordering::Acquire), 0);
    }

    fn successful_agent_token_review(report: &AgentStateReport) -> TokenReviewStatus {
        TokenReviewStatus {
            audiences: Some(vec![AGENT_TOKEN_AUDIENCE.to_owned()]),
            authenticated: Some(true),
            error: None,
            user: Some(k8s_openapi::api::authentication::v1::UserInfo {
                username: Some(AGENT_SERVICE_ACCOUNT_USERNAME.to_owned()),
                extra: Some(BTreeMap::from([
                    (POD_NAME_EXTRA.to_owned(), vec![report.pod_name.clone()]),
                    (POD_UID_EXTRA.to_owned(), vec![report.pod_uid.clone()]),
                ])),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn agent_status_authentication_binds_service_account_pod_and_node() {
        let report = converged_agent_report(7);
        let mut pod = pod_record(1, "unf-system", &report.pod_name, "unf-agent");
        pod.uid.clone_from(&report.pod_uid);
        pod.endpoint.service_account = "unf-agent".to_owned();
        let pods = BTreeMap::from([(format!("unf-system/{}", report.pod_name), pod)]);
        let status = successful_agent_token_review(&report);
        let identity = validate_agent_token_identity(&status, &pods)
            .expect("Pod-bound UNF agent identity is accepted");
        validate_agent_claims(
            &identity,
            &report.node_name,
            &report.pod_name,
            &report.pod_uid,
        )
        .expect("matching report claims are accepted");

        let mut wrong_node = report.clone();
        wrong_node.node_name = "worker-b".to_owned();
        assert_eq!(
            validate_agent_claims(
                &identity,
                &wrong_node.node_name,
                &wrong_node.pod_name,
                &wrong_node.pod_uid,
            )
            .expect_err("cross-node claim is rejected")
            .status,
            StatusCode::FORBIDDEN
        );

        let mut wrong_pod = report.clone();
        wrong_pod.pod_uid = "another-pod-uid".to_owned();
        assert_eq!(
            validate_agent_claims(
                &identity,
                &wrong_pod.node_name,
                &wrong_pod.pod_name,
                &wrong_pod.pod_uid,
            )
            .expect_err("another Pod identity is rejected")
            .status,
            StatusCode::FORBIDDEN
        );

        let mut wrong_service_account = status.clone();
        wrong_service_account
            .user
            .as_mut()
            .expect("review has user")
            .username = Some("system:serviceaccount:default:default".to_owned());
        assert_eq!(
            validate_agent_token_identity(&wrong_service_account, &pods)
                .expect_err("another service account is rejected")
                .status,
            StatusCode::FORBIDDEN
        );

        let mut wrong_audience = status;
        wrong_audience.audiences = Some(vec!["another-service".to_owned()]);
        assert_eq!(
            validate_agent_token_identity(&wrong_audience, &pods)
                .expect_err("another audience is rejected")
                .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn agent_status_bearer_header_is_strict() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            bearer_token(&headers)
                .expect_err("missing credentials are rejected")
                .status,
            StatusCode::UNAUTHORIZED
        );
        headers.insert(AUTHORIZATION, "Basic credential".parse().unwrap());
        assert!(bearer_token(&headers).is_err());
        headers.insert(AUTHORIZATION, "Bearer token-value".parse().unwrap());
        assert_eq!(bearer_token(&headers).unwrap(), "token-value");
        headers.insert(AUTHORIZATION, "Bearer token value".parse().unwrap());
        assert!(bearer_token(&headers).is_err());
    }

    #[test]
    fn agent_status_aggregation_requires_fresh_matching_acknowledgements() {
        let state = new_state(true);
        apply_node_event(&state, Event::Apply(node(true)));
        let report = converged_agent_report(state.identity_epoch);
        validate_agent_status(&report).expect("valid agent report is accepted");
        let missing =
            agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100);
        assert_eq!(missing.expected_agents, 1);
        assert_eq!(missing.missing_agents, 1);
        assert!(!missing.all_converged);
        write_lock(&state.agent_reports).insert(
            report.node_name.clone(),
            StoredAgentReport {
                report: report.clone(),
                last_received_unix_ms: 100,
            },
        );

        let converged =
            agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100);
        assert_eq!(converged.expected_agents, 1);
        assert_eq!(converged.reporting_agents, 1);
        assert_eq!(converged.converged_agents, 1);
        assert!(converged.all_converged);
        assert!(converged.nodes[0].fresh);
        assert!(converged.nodes[0].converged);

        let mut unexpected_report = report.clone();
        unexpected_report.node_name = "worker-b".to_owned();
        write_lock(&state.agent_reports).insert(
            unexpected_report.node_name.clone(),
            StoredAgentReport {
                report: unexpected_report,
                last_received_unix_ms: 100,
            },
        );
        let unexpected =
            agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100);
        assert_eq!(unexpected.unexpected_agents, 1);
        assert!(!unexpected.all_converged);

        let expired_snapshot = agent_convergence_snapshot(
            &state,
            Revision::default(),
            Revision::default(),
            AGENT_STATUS_FRESHNESS_MILLIS + 101,
        );
        assert_eq!(expired_snapshot.stale_agents, 1);
        assert_eq!(expired_snapshot.unexpected_agents, 0);
        assert_eq!(expired_snapshot.converged_agents, 0);
        assert!(!expired_snapshot.all_converged);

        let mismatched =
            agent_convergence_snapshot(&state, Revision::new(1), Revision::default(), 100);
        assert_eq!(mismatched.converged_agents, 0);
        assert!(!mismatched.all_converged);

        let mut invalid_node_port = report.clone();
        invalid_node_port.applied_node_port_frontend_count = 1;
        assert!(validate_agent_status(&invalid_node_port).is_err());
        let mut invalid_outcomes = report.clone();
        invalid_outcomes.node_port_cluster_translations = 1;
        assert!(validate_agent_status(&invalid_outcomes).is_err());

        let mut invalid = report;
        invalid.active_policy_bank = 2;
        assert!(validate_agent_status(&invalid).is_err());
    }

    #[test]
    fn agent_status_aggregation_honors_the_configured_node_selector() {
        let state = new_state_with_client_and_selector(
            true,
            None,
            Some("node-role.kubernetes.io/worker".to_owned()),
        );
        let mut worker = node(true);
        worker
            .metadata
            .labels
            .get_or_insert_default()
            .insert("node-role.kubernetes.io/worker".to_owned(), String::new());
        let mut control_plane = node(true);
        control_plane.metadata.name = Some("control-plane-a".to_owned());
        control_plane
            .metadata
            .labels
            .get_or_insert_default()
            .insert(
                "node-role.kubernetes.io/control-plane".to_owned(),
                String::new(),
            );
        apply_node_event(&state, Event::Apply(worker));
        apply_node_event(&state, Event::Apply(control_plane));

        let report = converged_agent_report(state.identity_epoch);
        write_lock(&state.agent_reports).insert(
            report.node_name.clone(),
            StoredAgentReport {
                report,
                last_received_unix_ms: 100,
            },
        );
        let snapshot =
            agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100);
        assert_eq!(snapshot.expected_agents, 1);
        assert_eq!(snapshot.reporting_agents, 1);
        assert_eq!(snapshot.nodes[0].node_name, "worker-a");
        assert!(snapshot.all_converged);
    }

    #[test]
    fn agent_convergence_requires_the_compiled_service_revision() {
        let state = new_state(true);
        apply_node_event(&state, Event::Apply(node(true)));
        apply_service_event(&state, Event::Apply(service()));
        let snapshot = service_snapshot_for(&state).expect("compiled service snapshot");
        let mut report = converged_agent_report(state.identity_epoch);
        report.desired_service_epoch = snapshot.source_epoch;
        report.applied_service_epoch = snapshot.source_epoch;
        report.desired_service_revision = snapshot.revision.get();
        report.applied_service_revision = snapshot.revision.get();
        report.service_count = snapshot.services.len() as u64;
        report.service_frontend_count = snapshot.services[0].frontends.len() as u64;
        validate_agent_status(&report).expect("service acknowledgement is valid");
        write_lock(&state.agent_reports).insert(
            report.node_name.clone(),
            StoredAgentReport {
                report: report.clone(),
                last_received_unix_ms: 100,
            },
        );
        assert!(
            agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100)
                .all_converged
        );

        report.applied_service_epoch = 0;
        report.applied_service_revision = 0;
        report.service_count = 0;
        report.service_frontend_count = 0;
        write_lock(&state.agent_reports).insert(
            report.node_name.clone(),
            StoredAgentReport {
                report,
                last_received_unix_ms: 100,
            },
        );
        assert!(
            !agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100)
                .all_converged
        );

        apply_service_event(&state, Event::Apply(node_port_service()));
        let snapshot = service_snapshot_for(&state).expect("NodePort intent compiled");
        let mut legacy_report = converged_agent_report(state.identity_epoch);
        legacy_report.desired_service_epoch = snapshot.source_epoch;
        legacy_report.applied_service_epoch = snapshot.source_epoch;
        legacy_report.desired_service_revision = snapshot.revision.get();
        legacy_report.applied_service_revision = snapshot.revision.get();
        legacy_report.service_count = snapshot.services.len() as u64;
        legacy_report.service_frontend_count = snapshot
            .services
            .iter()
            .map(|service| service.frontends.len() as u64)
            .sum();
        legacy_report.service_snapshot_schema_version = LEGACY_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        write_lock(&state.agent_reports).insert(
            legacy_report.node_name.clone(),
            StoredAgentReport {
                report: legacy_report.clone(),
                last_received_unix_ms: 100,
            },
        );
        assert!(
            !agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100)
                .all_converged
        );

        legacy_report.service_snapshot_schema_version = SERVICE_SNAPSHOT_SCHEMA_VERSION;
        write_lock(&state.agent_reports).insert(
            legacy_report.node_name.clone(),
            StoredAgentReport {
                report: legacy_report,
                last_received_unix_ms: 100,
            },
        );
        assert!(
            agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100)
                .all_converged
        );

        apply_service_event(&state, Event::Apply(load_balancer_service()));
        let snapshot = service_snapshot_for(&state).expect("LoadBalancer intent compiled");
        let mut node_port_report = converged_agent_report(state.identity_epoch);
        node_port_report.desired_service_epoch = snapshot.source_epoch;
        node_port_report.applied_service_epoch = snapshot.source_epoch;
        node_port_report.desired_service_revision = snapshot.revision.get();
        node_port_report.applied_service_revision = snapshot.revision.get();
        node_port_report.service_snapshot_schema_version =
            NODE_PORT_SERVICE_SNAPSHOT_SCHEMA_VERSION;
        write_lock(&state.agent_reports).insert(
            node_port_report.node_name.clone(),
            StoredAgentReport {
                report: node_port_report,
                last_received_unix_ms: 100,
            },
        );
        assert!(
            !agent_convergence_snapshot(&state, Revision::default(), Revision::default(), 100)
                .all_converged
        );
    }

    #[test]
    fn agent_node_selector_accepts_presence_and_exact_value_forms() {
        let mut candidate = topology_node(&node(true));
        candidate
            .labels
            .insert("node-role.kubernetes.io/worker".to_owned(), String::new());
        candidate
            .labels
            .insert("unf.io/pool".to_owned(), "qualification".to_owned());

        assert!(agent_node_matches(&candidate, None));
        assert!(agent_node_matches(
            &candidate,
            Some("node-role.kubernetes.io/worker")
        ));
        assert!(agent_node_matches(
            &candidate,
            Some("unf.io/pool=qualification")
        ));
        assert!(!agent_node_matches(&candidate, Some("unf.io/pool=other")));
        assert!(validate_agent_node_selector("unf.io/pool=qualification").is_ok());
        assert!(validate_agent_node_selector("unf.io/pool=").is_err());
        assert!(validate_agent_node_selector("unf.io/pool = qualification").is_err());
    }

    #[test]
    fn load_balancer_reachability_projection_is_node_uid_bound() {
        let state = new_state(true);
        let provider = unf_loadbalancer::ReachabilityProviderRef {
            name: "direct-node".to_owned(),
            instance: "qualification-a".to_owned(),
            mode: unf_loadbalancer::ReachabilityMode::DirectNode,
        };
        let owner = unf_loadbalancer::LoadBalancerOwner {
            service_id: ServiceId::new(44),
            namespace: "apps".to_owned(),
            name: "api".to_owned(),
            uid: "api-uid".to_owned(),
        };
        let lease = unf_loadbalancer::LoadBalancerLease {
            owner,
            pool: "public".to_owned(),
            pool_uid: "public-uid".to_owned(),
            provider: provider.clone(),
            families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
            requested_ips: Vec::new(),
            addresses: vec!["192.0.2.4".parse().unwrap(), "2001:db8::4".parse().unwrap()],
            intent_epoch: state.identity_epoch,
            intent_revision: Revision::new(2),
            allocation_revision: Revision::new(3),
        };
        let desired = unf_loadbalancer::compile_direct_node_reachability(
            state.identity_epoch,
            Revision::new(4),
            Revision::new(3),
            provider,
            &[lease],
            vec![unf_loadbalancer::ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            }],
        )
        .unwrap();
        write_lock(&state.node_port_nodes).insert(
            "worker-a".to_owned(),
            NodePortNodeRecord {
                node_uid: "worker-a-uid".to_owned(),
                revision: Revision::new(1),
                addresses: Vec::new(),
            },
        );
        *write_lock(&state.compiled_load_balancer_reachability) = Some(desired.clone());

        let projected = load_balancer_reachability_snapshot_for(&state, "worker-a").unwrap();
        assert_eq!(projected.node.name, "worker-a");
        assert_eq!(projected.node.uid, "worker-a-uid");
        assert_eq!(projected.targets.len(), 2);

        write_lock(&state.node_port_nodes)
            .get_mut("worker-a")
            .unwrap()
            .node_uid = "replacement-uid".to_owned();
        assert!(load_balancer_reachability_snapshot_for(&state, "worker-a").is_err());
        assert!(load_balancer_reachability_snapshot_for(&state, "worker-b").is_err());
    }

    #[test]
    fn load_balancer_convergence_is_capability_revision_and_error_exact() {
        let state = new_state(true);
        write_lock(&state.node_port_nodes).insert(
            "worker-a".to_owned(),
            NodePortNodeRecord {
                node_uid: "worker-a-uid".to_owned(),
                revision: Revision::new(1),
                addresses: Vec::new(),
            },
        );
        let desired = compile_direct_node_reachability(
            state.identity_epoch,
            Revision::new(4),
            Revision::new(3),
            ReachabilityProviderRef {
                name: "direct-node".to_owned(),
                instance: "qualification-a".to_owned(),
                mode: ReachabilityMode::DirectNode,
            },
            &[],
            vec![ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            }],
        )
        .unwrap();
        let mut report = converged_agent_report(state.identity_epoch);
        report.desired_load_balancer_epoch = desired.source_epoch;
        report.applied_load_balancer_epoch = desired.source_epoch;
        report.desired_load_balancer_revision = desired.revision.get();
        report.applied_load_balancer_revision = desired.revision.get();
        report.desired_load_balancer_allocation_revision = desired.allocation_revision.get();
        report.applied_load_balancer_allocation_revision = desired.allocation_revision.get();
        report.load_balancer_frontend_count = 2;
        report.load_balancer_local_frontend_count = 2;
        report.load_balancer_source_range_count = 2;
        report.load_balancer_health_check_count = 1;
        report.load_balancer_health_check_ready_count = 1;
        validate_agent_status(&report).expect("bounded LoadBalancer operations status is valid");
        write_lock(&state.agent_reports).insert(
            "worker-a".to_owned(),
            StoredAgentReport {
                report: report.clone(),
                last_received_unix_ms: unix_time_millis(),
            },
        );
        assert!(load_balancer_agents_converged(&state, &desired));

        let mut malformed_counts = report.clone();
        malformed_counts.load_balancer_cluster_frontend_count = 1;
        assert!(validate_agent_status(&malformed_counts).is_err());
        let mut malformed_health = report.clone();
        malformed_health.load_balancer_health_check_ready_count = 2;
        assert!(validate_agent_status(&malformed_health).is_err());

        report.load_balancer_reachability_schema_version = 0;
        write_lock(&state.agent_reports)
            .get_mut("worker-a")
            .unwrap()
            .report = report.clone();
        assert!(!load_balancer_agents_converged(&state, &desired));
        report.load_balancer_reachability_schema_version =
            unf_loadbalancer::NODE_REACHABILITY_SCHEMA_VERSION;
        report.applied_load_balancer_allocation_revision -= 1;
        write_lock(&state.agent_reports)
            .get_mut("worker-a")
            .unwrap()
            .report = report.clone();
        assert!(!load_balancer_agents_converged(&state, &desired));
        report.applied_load_balancer_allocation_revision += 1;
        report.load_balancer_reconcile_errors = 1;
        report.load_balancer_last_error = Some("injected failure".to_owned());
        write_lock(&state.agent_reports)
            .get_mut("worker-a")
            .unwrap()
            .report = report;
        assert!(!load_balancer_agents_converged(&state, &desired));

        let mut malformed = converged_agent_report(state.identity_epoch);
        malformed.desired_load_balancer_allocation_revision = 1;
        assert!(validate_agent_status(&malformed).is_err());
        malformed.desired_load_balancer_allocation_revision = 0;
        malformed.load_balancer_last_error = Some("failure without counter".to_owned());
        assert!(validate_agent_status(&malformed).is_err());
    }

    #[tokio::test]
    async fn load_balancer_runtime_requires_an_explicit_stable_pool() {
        let disabled = Args::try_parse_from(["unf-controller", "--offline"]).unwrap();
        let disabled_state = new_state(true);
        configure_load_balancer_runtime(&disabled_state, &disabled)
            .await
            .unwrap();
        assert!(mutex_lock(&disabled_state.load_balancer_runtime).is_none());

        let missing_uid = Args::try_parse_from([
            "unf-controller",
            "--offline",
            "--load-balancer-ipv4-pool",
            "192.0.2.0/29",
        ])
        .unwrap();
        assert!(
            configure_load_balancer_runtime(&new_state(true), &missing_uid)
                .await
                .is_err()
        );

        let configured = Args::try_parse_from([
            "unf-controller",
            "--offline",
            "--load-balancer-pool-uid",
            "qualification-pool-uid",
            "--load-balancer-ipv4-pool",
            "192.0.2.0/29",
            "--load-balancer-ipv6-pool",
            "2001:db8::/125",
            "--load-balancer-provider-instance",
            "qualification-a",
        ])
        .unwrap();
        let state = new_state(true);
        configure_load_balancer_runtime(&state, &configured)
            .await
            .unwrap();
        let runtime = mutex_lock(&state.load_balancer_runtime)
            .clone()
            .expect("an explicit pool enables the runtime");
        assert_eq!(runtime.pool_name, "public");
        assert_eq!(runtime.provider.instance, "qualification-a");
        assert_eq!(runtime.allocator.checkpoint().pools.len(), 1);
        assert!(runtime.allocator.checkpoint().leases.is_empty());
        assert_eq!(runtime.reachability_revision, Revision::INITIAL);
    }

    #[tokio::test]
    async fn load_balancer_runtime_recovery_is_provider_exact_and_replayable() {
        let configured = Args::try_parse_from([
            "unf-controller",
            "--offline",
            "--load-balancer-pool-uid",
            "recovery-pool-uid",
            "--load-balancer-ipv4-pool",
            "192.0.2.0/29",
            "--load-balancer-ipv6-pool",
            "2001:db8::/125",
            "--load-balancer-provider-instance",
            "provider-a",
        ])
        .unwrap();
        let state = new_state(true);
        configure_load_balancer_runtime(&state, &configured)
            .await
            .unwrap();
        let mut runtime = mutex_lock(&state.load_balancer_runtime).clone().unwrap();
        let owner = LoadBalancerOwner {
            service_id: ServiceId::new(44),
            namespace: "apps".to_owned(),
            name: "api".to_owned(),
            uid: "api-uid".to_owned(),
        };
        let lease = runtime
            .allocator
            .allocate(unf_loadbalancer::AllocationRequest {
                owner: owner.clone(),
                pool: runtime.pool_name.clone(),
                families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
                requested_ips: Vec::new(),
                intent_epoch: state.identity_epoch,
                intent_revision: Revision::new(7),
            })
            .unwrap();
        runtime.reachability_revision = Revision::new(5);
        let durable = DurableLoadBalancerState {
            schema_version: LOAD_BALANCER_STORE_SCHEMA_VERSION,
            reachability_revision: runtime.reachability_revision,
            allocation: runtime.allocator.checkpoint(),
        };
        let encoded = serde_json::to_vec(&durable).unwrap();
        let restored: DurableLoadBalancerState = serde_json::from_slice(&encoded).unwrap();
        let allocator = LoadBalancerAllocator::restore(restored.allocation.clone()).unwrap();
        assert_eq!(allocator.lease(&owner), Some(&lease));
        let reachability = compile_direct_node_reachability(
            state.identity_epoch,
            restored.reachability_revision,
            restored.allocation.revision,
            runtime.provider.clone(),
            &restored.allocation.leases,
            vec![ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            }],
        )
        .unwrap();
        assert_eq!(reachability.revision, Revision::new(5));
        assert_eq!(reachability.targets.len(), 2);

        let mut foreign = restored.allocation;
        foreign.pools[0].provider.instance = "provider-b".to_owned();
        assert!(LoadBalancerAllocator::restore(foreign).is_err());
    }

    #[test]
    fn load_balancer_operations_fields_preserve_the_adjacent_compatibility_tuple() {
        assert_eq!(AGENT_STATUS_SCHEMA_VERSION, 6);
        assert_eq!(FLOW_EXPORT_SCHEMA_VERSION, 5);
        let report = converged_agent_report(7);
        let mut legacy = serde_json::to_value(&report).unwrap();
        for field in [
            "load_balancer_cluster_frontend_count",
            "load_balancer_local_frontend_count",
            "load_balancer_source_range_count",
            "load_balancer_health_check_count",
            "load_balancer_health_check_ready_count",
            "load_balancer_cluster_translations",
            "load_balancer_local_translations",
            "load_balancer_no_backend_drops",
            "load_balancer_source_range_drops",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let migrated: AgentStateReport = serde_json::from_value(legacy).unwrap();
        assert_eq!(migrated.schema_version, AGENT_STATUS_SCHEMA_VERSION);
        assert_eq!(migrated.load_balancer_local_translations, 0);
        assert_eq!(migrated.load_balancer_health_check_count, 0);

        let mut additive = serde_json::to_value(report).unwrap();
        additive["future_bounded_load_balancer_field"] = serde_json::json!(1);
        serde_json::from_value::<AgentStateReport>(additive)
            .expect("adjacent readers ignore additive status fields");
        assert_eq!(
            serde_json::from_str::<ServiceFrontendKind>("\"load_balancer_local\"").unwrap(),
            ServiceFrontendKind::LoadBalancerLocal
        );
    }

    #[test]
    fn pod_placement_changes_only_advance_topology_revision() {
        let state = new_state(true);
        apply_pod_event(&state, Event::Apply(scheduled_pod("worker-a")));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(1));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(1));
        assert_eq!(
            read_lock(&state.pods)["frontend/client"]
                .ipv6_addresses
                .len(),
            1
        );
        assert_eq!(mutex_lock(&state.identities).address_count(), 2);

        let mut rescheduled = scheduled_pod("worker-b");
        rescheduled.metadata.resource_version = Some("2".to_owned());
        apply_pod_event(&state, Event::Apply(rescheduled.clone()));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(1));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(2));

        rescheduled.metadata.resource_version = Some("3".to_owned());
        apply_pod_event(&state, Event::Apply(rescheduled));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(1));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(2));
    }

    #[test]
    fn terminal_pod_releases_identity_for_same_ip_replacement() {
        let state = new_state(true);
        let address = "10.42.0.10".parse().expect("valid test address");
        let pod = scheduled_pod("worker-a");
        apply_pod_event(&state, Event::Apply(pod.clone()));
        let original_identity = mutex_lock(&state.identities)
            .identity_for_ip(address)
            .expect("running Pod IP is indexed");

        let mut terminal = pod;
        terminal.metadata.resource_version = Some("2".to_owned());
        terminal.status.get_or_insert_default().phase = Some("Succeeded".to_owned());
        apply_pod_event(&state, Event::Apply(terminal));

        assert!(!read_lock(&state.pods).contains_key("frontend/client"));
        assert_eq!(mutex_lock(&state.identities).identity_for_ip(address), None);

        let mut replacement = scheduled_pod("worker-b");
        replacement.metadata.name = Some("replacement".to_owned());
        replacement
            .metadata
            .labels
            .get_or_insert_default()
            .insert("app".to_owned(), "replacement".to_owned());
        apply_pod_event(&state, Event::Apply(replacement));

        let replacement_identity = mutex_lock(&state.identities)
            .identity_for_ip(address)
            .expect("replacement Pod reuses the released IP");
        assert_ne!(replacement_identity, original_identity);
        assert!(read_lock(&state.pods).contains_key("frontend/replacement"));
        assert_eq!(mutex_lock(&state.identities).revision(), Revision::new(3));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(3));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(3));
    }

    #[test]
    fn terminal_pods_in_initial_list_are_not_admitted() {
        let state = new_state(true);
        let mut terminal = scheduled_pod("worker-a");
        terminal.status.get_or_insert_default().phase = Some("Failed".to_owned());

        apply_pod_event(&state, Event::Init);
        apply_pod_event(&state, Event::InitApply(terminal));
        apply_pod_event(&state, Event::InitDone);

        assert!(read_lock(&state.pods).is_empty());
        assert_eq!(mutex_lock(&state.identities).identity_count(), 0);
        assert_eq!(mutex_lock(&state.identities).address_count(), 0);
        assert_eq!(
            mutex_lock(&state.identities).revision(),
            Revision::default()
        );
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::default());
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::default());
    }

    #[test]
    fn topology_snapshot_tracks_semantic_node_and_service_state() {
        let state = new_state(true);
        write_lock(&state.pods).insert(
            "frontend/client".to_owned(),
            pod_record(1, "frontend", "client", "client"),
        );

        apply_node_event(&state, Event::Apply(node(true)));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(1));
        let mut unchanged_node = node(true);
        unchanged_node.metadata.resource_version = Some("2".to_owned());
        apply_node_event(&state, Event::Apply(unchanged_node));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(1));

        apply_service_event(&state, Event::Apply(service()));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(1));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(2));
        let snapshot = topology_snapshot(&state);
        assert_eq!(snapshot.schema_version, TOPOLOGY_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(snapshot.revision, Revision::new(2));
        assert_eq!(snapshot.nodes.len(), 1);
        assert!(snapshot.nodes[0].ready);
        assert_eq!(snapshot.workloads[0].node_name.as_deref(), Some("worker-a"));
        assert_eq!(snapshot.services.len(), 1);
        assert_eq!(snapshot.services[0].selected_workloads, ["frontend/client"]);
        assert!(snapshot.services[0].backends.is_empty());
        assert_eq!(
            snapshot.services[0].ports[0].target_port.as_deref(),
            Some("8080")
        );
        {
            let compiled = read_lock(&state.compiled_service_snapshot);
            let compiled = compiled.as_ref().expect("service intent compiled");
            assert_eq!(compiled.revision, Revision::new(1));
            assert_eq!(compiled.services.len(), 1);
            assert_eq!(compiled.services[0].frontends.len(), 1);
            assert!(compiled.services[0].backends.is_empty());
        }

        let mut unchanged_service = service();
        unchanged_service.metadata.resource_version = Some("2".to_owned());
        apply_service_event(&state, Event::Apply(unchanged_service));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(1));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(2));

        apply_service_event(&state, Event::Delete(service()));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(2));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(3));
        assert!(topology_snapshot(&state).services.is_empty());

        let history =
            mutex_lock(&state.topology_history).snapshot_window(Some(2), Some(3), None, None, 1, 0);
        assert_eq!(history.retained_snapshots, 3);
        assert_eq!(history.query.matched_snapshots, 2);
        assert_eq!(history.query.returned_snapshots, 1);
        assert!(history.query.truncated);
        assert_eq!(history.entries[0].snapshot.revision, Revision::new(3));
        assert!(history.entries[0].snapshot.services.is_empty());
        assert!(state.topology_history_dirty.load(Ordering::Acquire));

        assert!(validate_topology_history_query(&TopologyHistoryQuery::default()).is_ok());
        assert!(
            validate_topology_history_query(&TopologyHistoryQuery {
                since_revision: Some(4),
                until_revision: Some(3),
                ..TopologyHistoryQuery::default()
            })
            .is_err()
        );
        assert!(
            validate_topology_history_query(&TopologyHistoryQuery {
                limit: Some(TOPOLOGY_HISTORY_CAPACITY + 1),
                ..TopologyHistoryQuery::default()
            })
            .is_err()
        );
    }

    #[test]
    fn node_port_service_translation_preserves_family_port_and_policy() {
        let record = service_record(&node_port_service()).expect("valid NodePort source");
        assert_eq!(record.service_type, "NodePort");
        assert_eq!(
            record.compiler_source.external_traffic_policy,
            ServiceTrafficPolicy::Local
        );
        assert_eq!(record.compiler_source.ports[0].node_port, Some(30_443));
        let snapshot = compile_service_snapshot(
            7,
            Revision::new(1),
            vec![record.compiler_source],
            Vec::new(),
        )
        .expect("valid NodePort intent");
        assert_eq!(snapshot.services[0].node_ports.len(), 2);
        assert!(snapshot.services[0].node_ports.iter().all(|node_port| {
            node_port.port == 30_443
                && node_port.service_port == 443
                && node_port.protocol == Protocol::Tcp
                && node_port.traffic_policy == ServiceTrafficPolicy::Local
                && node_port.backend_ids.is_empty()
        }));

        let mut invalid = node_port_service();
        invalid.spec.as_mut().unwrap().external_traffic_policy = Some("Nearest".to_owned());
        assert!(service_record(&invalid).is_err());
    }

    #[test]
    fn load_balancer_translation_is_explicit_exact_and_last_valid() {
        let service = load_balancer_service();
        let record = service_record(&service).expect("valid UNF LoadBalancer source");
        assert_eq!(record.service_type, "LoadBalancer");
        assert!(
            record
                .compiler_source
                .ports
                .iter()
                .all(|port| port.node_port.is_none())
        );
        let source = record
            .compiler_source
            .load_balancer
            .as_ref()
            .expect("explicit UNF class is admitted");
        assert_eq!(source.class, UNF_LOAD_BALANCER_CLASS);
        assert_eq!(
            source.ip_families,
            [AddressFamily::Ipv4, AddressFamily::Ipv6]
        );
        assert_eq!(
            source.ip_family_policy,
            ServiceIpFamilyPolicy::RequireDualStack
        );
        assert!(!source.allocate_node_ports);
        assert_eq!(source.health_check_node_port, Some(32_000));
        assert_eq!(
            source.requested_ips,
            ["192.0.2.60".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(source.source_ranges.len(), 2);

        let snapshot = compile_service_snapshot(
            7,
            Revision::new(1),
            vec![record.compiler_source],
            Vec::new(),
        )
        .expect("valid LoadBalancer intent");
        let intent = snapshot.services[0]
            .load_balancer
            .as_ref()
            .expect("LoadBalancer intent compiled");
        assert_eq!(intent.frontends.len(), 4);
        assert!(intent.frontends.iter().all(|frontend| {
            matches!(frontend.protocol, Protocol::Tcp | Protocol::Udp)
                && frontend.backend_ids.is_empty()
        }));

        let mut classless = service.clone();
        classless.spec.as_mut().unwrap().load_balancer_class = None;
        assert!(
            service_record(&classless)
                .expect("classless Service remains foreign")
                .compiler_source
                .load_balancer
                .is_none()
        );
        let mut foreign = service.clone();
        foreign.spec.as_mut().unwrap().load_balancer_class = Some("example.com/foreign".to_owned());
        assert!(
            service_record(&foreign)
                .expect("foreign-class Service remains foreign")
                .compiler_source
                .load_balancer
                .is_none()
        );

        let state = new_state(true);
        apply_service_event(&state, Event::Apply(service.clone()));
        let retained_revision = read_lock(&state.compiled_service_snapshot)
            .as_ref()
            .expect("valid LoadBalancer snapshot")
            .revision;
        let mut malformed = service;
        malformed.spec.as_mut().unwrap().load_balancer_source_ranges =
            Some(vec!["198.51.100.1/24".to_owned()]);
        apply_service_event(&state, Event::Apply(malformed));
        assert_eq!(
            read_lock(&state.compiled_service_snapshot)
                .as_ref()
                .expect("last-valid LoadBalancer snapshot retained")
                .revision,
            retained_revision
        );
        assert_eq!(read_lock(&state.rejected_service_sources).len(), 1);
    }

    #[tokio::test]
    async fn node_port_simulation_is_node_local_read_only_and_fail_closed() {
        let state = Arc::new(new_state(true));
        apply_node_event(
            &state,
            Event::Apply(primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64")),
        );
        apply_service_event(&state, Event::Apply(node_port_service()));
        let endpoint: EndpointSlice = serde_json::from_value(serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "edge-v4",
                "namespace": "frontend",
                "labels": {"kubernetes.io/service-name": "edge"}
            },
            "addressType": "IPv4",
            "ports": [{"name": "https", "protocol": "TCP", "port": 8443,
                "appProtocol": "kubernetes.io/h2c"}],
            "endpoints": [{
                "addresses": ["10.42.0.20"],
                "conditions": {"ready": true, "serving": true, "terminating": false},
                "nodeName": "worker-a"
            }]
        }))
        .expect("test NodePort EndpointSlice is valid");
        apply_endpoint_slice_event(&state, Event::Apply(endpoint.clone()));

        let Json(allowed) = simulate_node_port(
            State(Arc::clone(&state)),
            Query(NodePortSimulationQuery {
                node_name: "worker-a".to_owned(),
                address: "192.0.2.1".parse().unwrap(),
                port: 30_443,
                protocol: "tcp".to_owned(),
            }),
        )
        .await
        .expect("local NodePort simulation succeeds");
        assert_eq!(allowed.frontend_kind, ServiceFrontendKind::NodePortLocal);
        assert!(allowed.source_preserved);
        assert_eq!(allowed.decision, "translate");
        assert_eq!(allowed.eligible_backends.len(), 1);

        let mut remote_only = endpoint;
        remote_only.endpoints[0].node_name = Some("worker-b".to_owned());
        remote_only.metadata.resource_version = Some("2".to_owned());
        apply_endpoint_slice_event(&state, Event::Apply(remote_only));
        let Json(denied) = simulate_node_port(
            State(Arc::clone(&state)),
            Query(NodePortSimulationQuery {
                node_name: "worker-a".to_owned(),
                address: "192.0.2.1".parse().unwrap(),
                port: 30_443,
                protocol: "TCP".to_owned(),
            }),
        )
        .await
        .expect("backendless Local NodePort remains explainable");
        assert_eq!(denied.decision, "drop_no_backend");
        assert!(denied.eligible_backend_ids.is_empty());

        assert!(
            simulate_node_port(
                State(state),
                Query(NodePortSimulationQuery {
                    node_name: "worker-a".to_owned(),
                    address: "192.0.2.99".parse().unwrap(),
                    port: 30_443,
                    protocol: "tcp".to_owned(),
                }),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn load_balancer_simulation_and_explanation_are_provenance_exact_and_read_only() {
        let state = Arc::new(new_state(true));
        apply_node_event(
            &state,
            Event::Apply(primary_node("worker-a", "10.42.0.0/24", "fd00:42::/64")),
        );
        apply_service_event(&state, Event::Apply(load_balancer_service()));
        let endpoint: EndpointSlice = serde_json::from_value(serde_json::json!({
            "apiVersion": "discovery.k8s.io/v1",
            "kind": "EndpointSlice",
            "metadata": {
                "name": "public-api-v4",
                "namespace": "frontend",
                "labels": {"kubernetes.io/service-name": "public-api"}
            },
            "addressType": "IPv4",
            "ports": [{"name": "https", "protocol": "TCP", "port": 8443,
                "appProtocol": "kubernetes.io/h2c"}],
            "endpoints": [{
                "addresses": ["10.42.0.30"],
                "conditions": {"ready": true, "serving": true, "terminating": false},
                "nodeName": "worker-a"
            }]
        }))
        .unwrap();
        apply_endpoint_slice_event(&state, Event::Apply(endpoint));
        let services = service_snapshot_for(&state).unwrap();
        let service = &services.services[0];
        let provider = ReachabilityProviderRef {
            name: "direct-node".to_owned(),
            instance: "simulation".to_owned(),
            mode: ReachabilityMode::DirectNode,
        };
        let owner = LoadBalancerOwner {
            service_id: service.id,
            namespace: service.namespace.clone(),
            name: service.name.clone(),
            uid: "public-api-uid".to_owned(),
        };
        let pool = LoadBalancerPool {
            name: "public".to_owned(),
            uid: "public-pool-uid".to_owned(),
            provider: provider.clone(),
            ipv4: Some("192.0.2.0/24".parse().unwrap()),
            ipv6: Some("2001:db8::/64".parse().unwrap()),
        };
        let lease = LoadBalancerLease {
            owner: owner.clone(),
            pool: pool.name.clone(),
            pool_uid: pool.uid.clone(),
            provider: provider.clone(),
            families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
            requested_ips: vec!["192.0.2.60".parse().unwrap()],
            addresses: vec![
                "192.0.2.60".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
            intent_epoch: services.source_epoch,
            intent_revision: services.revision,
            allocation_revision: Revision::new(3),
        };
        let allocator = LoadBalancerAllocator::restore(AllocationCheckpoint {
            schema_version: unf_loadbalancer::ALLOCATION_CHECKPOINT_SCHEMA_VERSION,
            revision: Revision::new(3),
            pools: vec![pool],
            leases: vec![lease.clone()],
        })
        .unwrap();
        *mutex_lock(&state.load_balancer_runtime) = Some(LoadBalancerRuntime {
            pool_name: "public".to_owned(),
            provider: provider.clone(),
            allocator,
            reachability_revision: Revision::new(4),
        });
        let reachability = compile_direct_node_reachability(
            services.source_epoch,
            Revision::new(4),
            Revision::new(3),
            provider.clone(),
            &[lease],
            vec![ReachabilityNode {
                name: "worker-a".to_owned(),
                uid: "worker-a-uid".to_owned(),
            }],
        )
        .unwrap();
        *write_lock(&state.compiled_load_balancer_reachability) = Some(reachability.clone());
        let service_before = read_lock(&state.compiled_service_snapshot).clone();
        let runtime_before = mutex_lock(&state.load_balancer_runtime)
            .as_ref()
            .unwrap()
            .allocator
            .checkpoint();

        let Json(allowed) = simulate_load_balancer(
            State(Arc::clone(&state)),
            Query(LoadBalancerSimulationQuery {
                node_name: "worker-a".to_owned(),
                address: "192.0.2.60".parse().unwrap(),
                source_address: "198.51.100.10".parse().unwrap(),
                port: 443,
                protocol: "tcp".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(allowed.decision, "translate");
        assert_eq!(
            allowed.frontend_kind,
            ServiceFrontendKind::LoadBalancerLocal
        );
        assert!(allowed.source_allowed);
        assert!(allowed.source_preserved);
        assert_eq!(allowed.eligible_backends.len(), 1);
        assert_eq!(allowed.provider, provider);
        assert_eq!(
            allowed.allocation.as_ref().unwrap().pool_uid,
            "public-pool-uid"
        );

        let Json(denied) = simulate_load_balancer(
            State(Arc::clone(&state)),
            Query(LoadBalancerSimulationQuery {
                node_name: "worker-a".to_owned(),
                address: "192.0.2.60".parse().unwrap(),
                source_address: "203.0.113.10".parse().unwrap(),
                port: 443,
                protocol: "TCP".to_owned(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(denied.decision, "drop_source_range");
        assert!(!denied.source_allowed);

        let Json(explanation) = explain_service(
            State(Arc::clone(&state)),
            Query(ServiceExplainQuery {
                service_id: service.id.get(),
                frontend_kind: Some(ServiceFrontendKind::LoadBalancerLocal),
                ..ServiceExplainQuery::default()
            }),
        )
        .await
        .unwrap();
        let provenance = explanation.load_balancer.unwrap();
        assert_eq!(provenance.provider, Some(provider));
        assert_eq!(provenance.reachability_revision, Some(Revision::new(4)));
        assert_eq!(provenance.allocation_revision, Some(Revision::new(3)));
        assert_eq!(provenance.reachable_nodes, ["worker-a"]);
        assert_eq!(
            read_lock(&state.compiled_service_snapshot).clone(),
            service_before
        );
        assert_eq!(
            mutex_lock(&state.load_balancer_runtime)
                .as_ref()
                .unwrap()
                .allocator
                .checkpoint(),
            runtime_before
        );
        assert_eq!(
            read_lock(&state.compiled_load_balancer_reachability).clone(),
            Some(reachability)
        );
    }

    #[test]
    fn endpoint_slice_readiness_is_revisioned_and_rejection_retains_valid_state() {
        let state = new_state(true);
        write_lock(&state.pods).insert(
            "frontend/client".to_owned(),
            pod_record(1, "frontend", "client", "client"),
        );
        apply_service_event(&state, Event::Apply(service()));

        apply_endpoint_slice_event(&state, Event::Apply(endpoint_slice(false)));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(2));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(2));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::default());
        let snapshot = topology_snapshot(&state);
        assert_eq!(snapshot.schema_version, TOPOLOGY_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(snapshot.services[0].selected_workloads, ["frontend/client"]);
        assert_eq!(snapshot.services[0].backends.len(), 1);
        let backend = &snapshot.services[0].backends[0];
        assert_eq!(backend.target_workload.as_deref(), Some("frontend/client"));
        assert_eq!(backend.addresses, ["10.42.0.10"]);
        assert!(!backend.ready);
        assert!(backend.serving);
        assert!(!backend.terminating);
        assert_eq!(backend.ports[0].port, Some(8080));
        {
            let compiled = read_lock(&state.compiled_service_snapshot);
            let compiled = compiled.as_ref().expect("EndpointSlice intent compiled");
            assert_eq!(compiled.revision, Revision::new(2));
            assert_eq!(compiled.services[0].backends.len(), 1);
            let compiled_backend = &compiled.services[0].backends[0];
            assert_eq!(compiled_backend.protocol, Protocol::Tcp);
            assert_eq!(compiled_backend.port_name.as_deref(), Some("http"));
            assert_eq!(
                compiled_backend.app_protocol.as_deref(),
                Some("kubernetes.io/h2c")
            );
            assert_eq!(
                compiled_backend.target_workload.as_deref(),
                Some("frontend/client")
            );
            assert!(!compiled_backend.ready);
        }

        let mut metadata_only = endpoint_slice(false);
        metadata_only.metadata.resource_version = Some("2".to_owned());
        apply_endpoint_slice_event(&state, Event::Apply(metadata_only));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(2));

        apply_endpoint_slice_event(&state, Event::Apply(endpoint_slice(true)));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(3));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(3));
        assert!(topology_snapshot(&state).services[0].backends[0].ready);

        let mut malformed = endpoint_slice(true);
        malformed.metadata.labels = None;
        apply_endpoint_slice_event(&state, Event::Apply(malformed));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(3));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(3));
        assert!(topology_snapshot(&state).services[0].backends[0].ready);
        assert_eq!(read_lock(&state.rejected_endpoint_slice_sources).len(), 1);
        assert_eq!(
            read_lock(&state.compiled_service_snapshot)
                .as_ref()
                .expect("last-valid service intent retained")
                .revision,
            Revision::new(3)
        );

        apply_endpoint_slice_event(&state, Event::Apply(endpoint_slice(true)));
        assert!(read_lock(&state.rejected_endpoint_slice_sources).is_empty());
        apply_endpoint_slice_event(&state, Event::Delete(endpoint_slice(true)));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(4));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(4));
        assert!(topology_snapshot(&state).services[0].backends.is_empty());
    }

    #[tokio::test]
    async fn service_snapshot_collision_retains_last_valid_ir_and_is_reported() {
        let state = Arc::new(new_state(true));
        apply_service_event(&state, Event::Apply(service()));

        let mut conflicting = service();
        conflicting.metadata.name = Some("conflicting".to_owned());
        apply_service_event(&state, Event::Apply(conflicting.clone()));

        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(2));
        assert!(
            read_lock(&state.service_compilation_error)
                .as_deref()
                .is_some_and(|error| error.contains("owned by more than one service"))
        );
        {
            let snapshot = read_lock(&state.compiled_service_snapshot);
            let snapshot = snapshot.as_ref().expect("last-valid snapshot retained");
            assert_eq!(snapshot.revision, Revision::new(1));
            assert_eq!(snapshot.services.len(), 1);
        }
        assert_eq!(
            service_snapshot_for(&state)
                .expect("distribution retains last-valid snapshot")
                .revision,
            Revision::new(1)
        );

        let status = status(State(Arc::clone(&state)))
            .await
            .expect("status remains available")
            .0;
        assert_eq!(status.services, 2);
        assert_eq!(status.compiled_services, 1);
        assert_eq!(status.compiled_service_frontends, 1);
        assert_eq!(status.compiled_service_backends, 0);
        assert_eq!(status.compiled_service_revision, 1);
        assert!(status.service_compilation_error.is_some());

        apply_service_event(&state, Event::Delete(conflicting));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(3));
        assert!(read_lock(&state.service_compilation_error).is_none());
        assert_eq!(
            read_lock(&state.compiled_service_snapshot)
                .as_ref()
                .expect("valid state recompiles")
                .revision,
            Revision::new(3)
        );
    }

    #[tokio::test]
    async fn flow_ingestion_is_validated_revisioned_and_enriched() {
        let state = Arc::new(new_state(true));
        let external_metrics = state.metrics.external_flow_export.clone();
        let (external_exporter, _external_worker) = build_external_flow_export(
            ExternalFlowExportConfig::new(
                "http://127.0.0.1:9/flows",
                true,
                None,
                None,
                1,
                1,
                Duration::from_secs(1),
            )
            .expect("valid flow-ingestion exporter config"),
            external_metrics.clone(),
        )
        .expect("build flow-ingestion exporter");
        *write_lock(&state.external_flow_export) = Some(external_exporter);
        write_lock(&state.pods).insert(
            "frontend/client".to_owned(),
            pod_record(1, "frontend", "client", "client"),
        );
        write_lock(&state.pods).insert(
            "backend/server".to_owned(),
            pod_record(2, "backend", "server", "server"),
        );
        assert_eq!(
            ingest_flow_batch(&state, flow_batch(5)).expect("valid flow batch is accepted"),
            StatusCode::NO_CONTENT
        );
        let snapshot = flow_history_snapshot(&state);
        assert_eq!(snapshot.revision, Revision::new(1));
        assert_eq!(snapshot.retained_flows, 1);
        assert_eq!(snapshot.retained_observations, 5);
        assert_eq!(snapshot.agent_dropped_events, 2);
        assert_eq!(snapshot.entries[0].source_workloads, ["frontend/client"]);
        assert_eq!(
            snapshot.entries[0].destination_workloads,
            ["backend/server"]
        );
        assert_eq!(mutex_lock(&state.revisions).telemetry, Revision::new(1));
        assert_eq!(external_metrics.enqueued_batches.get(), 1);
        assert_eq!(external_metrics.dropped_batches.get(), 0);

        let mut sctp = flow_batch(1);
        sctp.entries[0].key.protocol = Protocol::Sctp as u8;
        sctp.entries[0].key.destination_port = 8086;
        validate_flow_export_batch(&sctp).expect("SCTP flow export is accepted");

        let mut established = flow_batch(1);
        established.entries[0].decision.reason = 6;
        validate_flow_export_batch(&established)
            .expect("established-reply flow provenance is accepted");
        established.entries[0].decision.reason = 7;
        assert!(validate_flow_export_batch(&established).is_err());

        let mut ipv6 = flow_batch(1);
        ipv6.entries[0].key.source_ipv4 = None;
        ipv6.entries[0].key.destination_ipv4 = None;
        ipv6.entries[0].key.source_ipv6 = Some("fd00:10:42::10".parse().unwrap());
        ipv6.entries[0].key.destination_ipv6 = Some("fd00:10:42:1::20".parse().unwrap());
        validate_flow_export_batch(&ipv6).expect("complete IPv6 flow export is accepted");

        let mut mixed_family = flow_batch(1);
        mixed_family.entries[0].key.source_ipv6 = Some("fd00:10:42::10".parse().unwrap());
        mixed_family.entries[0].key.destination_ipv6 = Some("fd00:10:42:1::20".parse().unwrap());
        assert!(validate_flow_export_batch(&mixed_family).is_err());

        let mut incomplete_ipv6 = ipv6;
        incomplete_ipv6.entries[0].key.destination_ipv6 = None;
        assert!(validate_flow_export_batch(&incomplete_ipv6).is_err());

        let mut external_egress = flow_batch(1);
        external_egress.entries[0].key.direction = PolicyDirection::Egress;
        external_egress.entries[0].key.destination_identity = IdentityId::default();
        validate_flow_export_batch(&external_egress)
            .expect("egress export requires only its selected source identity");
        external_egress.entries[0].key.source_identity = IdentityId::default();
        assert!(validate_flow_export_batch(&external_egress).is_err());

        let mut unresolved_ingress = flow_batch(1);
        unresolved_ingress.entries[0].key.destination_identity = IdentityId::default();
        assert!(validate_flow_export_batch(&unresolved_ingress).is_err());

        let mut invalid = flow_batch(1);
        invalid.schema_version = FLOW_EXPORT_SCHEMA_VERSION + 1;
        let error =
            ingest_flow_batch(&state, invalid).expect_err("unknown flow schema is rejected");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(external_metrics.enqueued_batches.get(), 1);
    }

    #[test]
    fn service_flow_ingestion_validates_bounded_dataplane_provenance() {
        let mut batch = flow_batch(1);
        let entry = &mut batch.entries[0];
        entry.key.source_identity = IdentityId::default();
        entry.key.destination_identity = IdentityId::default();
        entry.key.destination_ipv4 = Some("10.96.0.80".parse().unwrap());
        entry.key.destination_port = 80;
        entry.key.service = Some(unf_state::ServiceFlowKey {
            service_id: ServiceId::new(11),
            backend_id: Some(BackendId::new(13)),
            service_revision: Revision::new(7),
            action: 1,
            reason: 1,
            frontend_kind: unf_state::ServiceFrontendKind::NodePortCluster,
        });
        entry.policy_revision = Revision::default();
        entry.decision.reason = 1;
        entry.decision.policy_id = None;
        entry.decision.rule_id = None;
        entry.service = Some(unf_state::ServiceFlowOutcome {
            service_id: ServiceId::new(11),
            backend_id: Some(BackendId::new(13)),
            service_revision: Revision::new(7),
            backend_ipv4: Some("10.42.1.20".parse().unwrap()),
            backend_ipv6: None,
            frontend_port: 80,
            backend_port: Some(8080),
            action: 1,
            reason: 1,
            frontend_kind: unf_state::ServiceFrontendKind::NodePortCluster,
        });
        validate_flow_export_batch(&batch)
            .expect("service outcomes use service provenance instead of identities");
        batch.entries[0]
            .service
            .as_mut()
            .expect("service outcome")
            .backend_id = None;
        assert!(validate_flow_export_batch(&batch).is_err());
    }

    #[test]
    fn flow_history_windows_and_durable_checkpoint_validation_are_bounded() {
        let state = new_state(true);
        write_lock(&state.pods).insert(
            "frontend/client".to_owned(),
            pod_record(1, "frontend", "client", "client"),
        );
        write_lock(&state.pods).insert(
            "backend/server".to_owned(),
            pod_record(2, "backend", "server", "server"),
        );
        mutex_lock(&state.flow_history).ingest(flow_batch(5), 1_000);

        let snapshot = flow_history_snapshot_window(&state, Some(1_000), Some(1_000), 1);
        assert_eq!(
            snapshot.schema_version,
            unf_state::FLOW_HISTORY_SNAPSHOT_SCHEMA_VERSION
        );
        assert_eq!(snapshot.query.matched_flows, 1);
        assert_eq!(snapshot.query.matched_observations, 5);
        assert_eq!(snapshot.query.returned_flows, 1);
        assert_eq!(snapshot.entries[0].source_workloads, ["frontend/client"]);
        assert_eq!(
            snapshot.entries[0].destination_workloads,
            ["backend/server"]
        );
        assert_eq!(
            flow_history_snapshot_window(&state, Some(1_001), None, 1)
                .query
                .matched_flows,
            0
        );

        assert!(validate_flow_history_query(&FlowHistoryQuery::default()).is_ok());
        assert!(
            validate_flow_history_query(&FlowHistoryQuery {
                since_unix_ms: Some(2),
                until_unix_ms: Some(1),
                limit: None,
            })
            .is_err()
        );
        assert!(
            validate_flow_history_query(&FlowHistoryQuery {
                limit: Some(FLOW_HISTORY_CAPACITY + 1),
                ..FlowHistoryQuery::default()
            })
            .is_err()
        );

        let mut checkpoint = mutex_lock(&state.flow_history).checkpoint(1);
        validate_flow_history_checkpoint(&checkpoint, 1_000)
            .expect("current durable flow history validates");
        checkpoint.entries[0].last_received_unix_ms =
            1_000 + FLOW_HISTORY_MAX_FUTURE_SKEW_MILLIS + 1;
        assert!(validate_flow_history_checkpoint(&checkpoint, 1_000).is_err());
    }

    #[tokio::test]
    async fn policy_simulation_detects_replacement_without_mutating_state() {
        let state = Arc::new(new_state(true));
        write_lock(&state.pods).insert(
            "frontend/client".to_owned(),
            pod_record(1, "frontend", "client", "client"),
        );
        write_lock(&state.pods).insert(
            "backend/server".to_owned(),
            pod_record(2, "backend", "server", "server"),
        );
        let key = "backend/frontend-to-backend";
        let current = PolicyCompiler::compile(
            stable_policy_id(key),
            security_policy("frontend-to-backend", "Allow"),
        )
        .expect("current policy compiles");
        write_lock(&state.compiled_security_policies).insert(key.to_owned(), current.clone());
        write_lock(&state.services)
            .insert("backend/server".to_owned(), topology_only_service_record());
        write_lock(&state.endpoint_slices).insert(
            "backend/server-abc".to_owned(),
            topology_only_endpoint_slice_record(),
        );
        mutex_lock(&state.flow_history).ingest(flow_batch(12), 100);
        mutex_lock(&state.revisions).policy = Revision::new(7);

        let response = simulate_policy(
            State(Arc::clone(&state)),
            Json(PolicySimulationRequest {
                policy: serde_json::to_value(security_policy("frontend-to-backend", "Deny"))
                    .expect("candidate serializes"),
                flow_history: Some(FlowHistoryQuery {
                    since_unix_ms: Some(100),
                    until_unix_ms: Some(100),
                    limit: Some(1),
                }),
            }),
        )
        .await
        .expect("candidate policy simulates")
        .0;

        assert!(matches!(
            response.operation,
            PolicySimulationOperation::Replace
        ));
        assert_eq!(response.policy, key);
        assert_eq!(response.snapshot.policy_revision, Revision::new(7));
        assert_eq!(response.snapshot.flow_history_revision, Revision::new(1));
        assert_eq!(response.affected_destinations, 1);
        assert_eq!(response.affected_services, ["backend/server"]);
        assert_eq!(response.summary.evaluated_flows, 8);
        assert_eq!(response.summary.would_be_denied, 1);
        assert_eq!(response.summary.would_be_allowed, 0);
        assert_eq!(response.summary.verdict_changes, 1);
        assert_eq!(response.changes.len(), 1);
        assert_eq!(response.changes[0].source.reference, "frontend/client");
        assert_eq!(response.changes[0].destination.reference, "backend/server");
        assert_eq!(response.changes[0].protocol, "tcp");
        assert_eq!(response.changes[0].destination_port, 8080);
        assert_eq!(response.changes[0].current.verdict, Verdict::Allow);
        assert_eq!(response.changes[0].proposed.verdict, Verdict::Deny);
        assert_eq!(response.historical_summary.retained_flows, 1);
        assert_eq!(response.historical_query.since_unix_ms, Some(100));
        assert_eq!(response.historical_query.until_unix_ms, Some(100));
        assert_eq!(response.historical_query.limit, 1);
        assert_eq!(response.historical_query.matched_flows, 1);
        assert_eq!(response.historical_query.matched_observations, 12);
        assert_eq!(response.historical_query.returned_flows, 1);
        assert!(!response.historical_query.truncated);
        assert_eq!(response.historical_summary.evaluated_flows, 1);
        assert_eq!(response.historical_summary.would_be_denied_observations, 12);
        assert_eq!(response.historical_changes.len(), 1);
        assert_eq!(response.historical_changes[0].observed_events, 12);

        assert_future_simulation_window_is_empty(&state).await;

        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(7));
        assert_eq!(
            read_lock(&state.compiled_security_policies).get(key),
            Some(&current)
        );
    }

    async fn assert_future_simulation_window_is_empty(state: &Arc<ControllerState>) {
        let future = simulate_policy(
            State(Arc::clone(state)),
            Json(PolicySimulationRequest {
                policy: serde_json::to_value(security_policy("frontend-to-backend", "Deny"))
                    .expect("candidate serializes"),
                flow_history: Some(FlowHistoryQuery {
                    since_unix_ms: Some(101),
                    until_unix_ms: None,
                    limit: None,
                }),
            }),
        )
        .await
        .expect("empty historical window still simulates topology")
        .0;
        assert_eq!(future.schema_version, 4);
        assert_eq!(future.summary.would_be_denied, 1);
        assert_eq!(future.historical_query.matched_flows, 0);
        assert_eq!(future.historical_query.returned_flows, 0);
        assert_eq!(future.historical_summary.evaluated_flows, 0);
        assert!(future.historical_changes.is_empty());
    }

    #[tokio::test]
    async fn policy_simulation_supports_read_only_addition() {
        let state = Arc::new(new_state(true));
        write_lock(&state.pods).insert(
            "frontend/client".to_owned(),
            pod_record(1, "frontend", "client", "client"),
        );
        write_lock(&state.pods).insert(
            "backend/server".to_owned(),
            pod_record(2, "backend", "server", "server"),
        );

        let response = simulate_policy(
            State(Arc::clone(&state)),
            Json(PolicySimulationRequest {
                policy: serde_json::to_value(security_policy("candidate-deny", "Deny"))
                    .expect("candidate serializes"),
                flow_history: None,
            }),
        )
        .await
        .expect("new candidate policy simulates")
        .0;

        assert!(matches!(response.operation, PolicySimulationOperation::Add));
        assert_eq!(response.schema_version, 4);
        assert_eq!(response.affected_sources, 0);
        assert_eq!(response.historical_query.since_unix_ms, None);
        assert_eq!(response.historical_query.until_unix_ms, None);
        assert_eq!(response.historical_query.limit, FLOW_HISTORY_CAPACITY);
        assert_eq!(response.summary.evaluated_flows, 8);
        assert_eq!(response.summary.would_be_denied, 8);
        assert!(read_lock(&state.compiled_security_policies).is_empty());
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::default());
    }

    #[tokio::test]
    async fn network_policy_simulation_is_direction_aware_and_read_only() {
        let state = Arc::new(egress_policy_state());
        let key = "frontend/allow-server-egress";
        let current = read_lock(&state.compiled_network_policies)
            .get(key)
            .cloned()
            .expect("live egress policy exists");
        let revision = mutex_lock(&state.revisions).policy;
        let candidate = serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-server-egress",
                "namespace": "frontend"
            },
            "spec": {
                "podSelector": {"matchLabels": {"app": "client"}},
                "policyTypes": ["Egress"],
                "egress": []
            }
        });

        let response = simulate_policy(
            State(Arc::clone(&state)),
            Json(PolicySimulationRequest {
                policy: candidate,
                flow_history: None,
            }),
        )
        .await
        .expect("egress NetworkPolicy candidate simulates")
        .0;

        assert_eq!(response.schema_version, 4);
        assert_eq!(
            response.resource_kind,
            PolicySimulationResourceKind::NetworkPolicy
        );
        assert!(matches!(
            response.operation,
            PolicySimulationOperation::Replace
        ));
        assert_eq!(response.policy, key);
        assert_eq!(response.affected_sources, 1);
        assert_eq!(response.affected_destinations, 0);
        assert_eq!(response.summary.evaluated_flows, 14);
        assert_eq!(response.summary.would_be_denied, 2);
        assert_eq!(response.summary.verdict_changes, 2);
        assert_eq!(response.changes.len(), 2);
        assert!(response.changes.iter().all(|change| {
            change.direction == PolicyDirection::Egress
                && change.destination_port == 8080
                && change.current.verdict == Verdict::Allow
                && change.proposed.verdict == Verdict::Deny
        }));
        assert!(
            response
                .changes
                .iter()
                .any(|change| matches!(change.ip_family, Some(RequestIpFamily::Ipv4)))
        );
        assert!(
            response
                .changes
                .iter()
                .any(|change| matches!(change.ip_family, Some(RequestIpFamily::Ipv6)))
        );
        assert_eq!(mutex_lock(&state.revisions).policy, revision);
        assert_eq!(
            read_lock(&state.compiled_network_policies).get(key),
            Some(&current)
        );
    }

    #[tokio::test]
    async fn policy_simulation_rejects_an_unbounded_topology_matrix() {
        let state = Arc::new(new_state(true));
        write_lock(&state.pods).insert(
            "backend/server".to_owned(),
            pod_record(1, "backend", "server", "server"),
        );
        for index in 0..3_333_u32 {
            let name = format!("client-{index}");
            write_lock(&state.pods).insert(
                format!("frontend/{name}"),
                pod_record(index + 2, "frontend", &name, "client"),
            );
        }

        let error = simulate_policy(
            State(Arc::clone(&state)),
            Json(PolicySimulationRequest {
                policy: serde_json::to_value(security_policy("candidate-deny", "Deny"))
                    .expect("candidate serializes"),
                flow_history: None,
            }),
        )
        .await
        .expect_err("oversized simulation matrix is rejected");

        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains("limit is 10000"));
        assert!(read_lock(&state.compiled_security_policies).is_empty());
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::default());
    }
}
