use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Node, Pod, Service};
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
use unf_common::{IdentityId, PolicyDirection, PolicyId, Protocol, Revision, Verdict};
use unf_policy::{
    DestinationAddresses, DestinationPort, Endpoint, Flow, Ipv4Endpoint, Ipv6Endpoint, NamedPort,
    NetworkPolicyCompiler, PolicyCompiler, PolicyIr, compile_dataplane_entries,
    compile_egress_ipv4_dataplane_entries, compile_egress_ipv6_dataplane_entries,
    compile_ipv4_dataplane_entries, compile_ipv6_dataplane_entries,
    evaluate_for_direction_with_addresses,
};
use unf_state::{
    AGENT_STATUS_SCHEMA_VERSION, AgentConvergenceEntry, AgentConvergenceSnapshot, AgentStateReport,
    FLOW_EXPORT_BATCH_LIMIT, FLOW_EXPORT_SCHEMA_VERSION, FLOW_HISTORY_CAPACITY, FlowExportBatch,
    FlowExportRecord, FlowHistoryCheckpoint, FlowHistoryQuerySummary, FlowHistorySnapshot,
    FlowHistoryStore, IdentityRegistry, IdentityStateSnapshot, NetworkIdentity,
    POLICY_SNAPSHOT_SCHEMA_VERSION, PolicyStateSnapshot, RevisionSet,
    TOPOLOGY_SNAPSHOT_SCHEMA_VERSION, TopologyNode, TopologyService, TopologyServiceBackend,
    TopologyServiceBackendPort, TopologyServicePort, TopologyStateSnapshot, TopologyWorkload,
    provisional_identity_id,
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
    services: RwLock<BTreeMap<String, ServiceRecord>>,
    endpoint_slices: RwLock<BTreeMap<String, EndpointSliceRecord>>,
    namespaces: RwLock<BTreeMap<String, BTreeMap<String, String>>>,
    security_policies: RwLock<BTreeMap<String, SecurityPolicy>>,
    compiled_security_policies: RwLock<BTreeMap<String, PolicyIr>>,
    network_policies: RwLock<BTreeMap<String, NetworkPolicy>>,
    compiled_network_policies: RwLock<BTreeMap<String, Vec<PolicyIr>>>,
    rejected_network_policies: RwLock<BTreeMap<String, String>>,
    policy_state_guard: RwLock<()>,
    identities: Mutex<IdentityRegistry>,
    flow_history: Mutex<FlowHistoryStore>,
    flow_history_dirty: AtomicBool,
    flow_history_store: Option<Api<ConfigMap>>,
    flow_history_checkpointed_flows: AtomicU64,
    flow_history_checkpoint_omitted_flows: AtomicU64,
    flow_history_checkpoint_omitted_observations: AtomicU64,
    agent_reports: RwLock<BTreeMap<String, StoredAgentReport>>,
    agent_reports_dirty: AtomicBool,
    agent_report_store: Option<Api<ConfigMap>>,
    agent_authentication_cache: Mutex<BTreeMap<String, CachedAgentAuthentication>>,
    token_review_client: Option<Client>,
    revisions: Mutex<RevisionSet>,
    registry: Mutex<Registry>,
    metrics: ControllerMetrics,
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
    service_type: String,
    cluster_ips: BTreeSet<IpAddr>,
    selector: BTreeMap<String, String>,
    ports: Vec<TopologyServicePort>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointSliceRecord {
    service_reference: String,
    backends: Vec<TopologyServiceBackend>,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    component: &'static str,
    healthy: bool,
    ready: bool,
    mode: &'static str,
    pods: usize,
    nodes: usize,
    services: usize,
    endpoint_slices: usize,
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
    limitations: [&'static str; 2],
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

    if args.offline {
        warn!("running without Kubernetes watchers");
    } else {
        restore_agent_reports(&state)
            .await
            .context("restore durable agent acknowledgements")?;
        restore_flow_history(&state)
            .await
            .context("restore durable flow history")?;
        spawn_agent_report_persistence(Arc::clone(&state), cancellation.clone(), &mut tasks);
        spawn_flow_history_persistence(Arc::clone(&state), cancellation.clone(), &mut tasks);
        let client = client.context("Kubernetes client is required in connected mode")?;
        spawn_watchers(&mut tasks, client, Arc::clone(&state), cancellation.clone());
        state.ready.store(true, Ordering::Release);
    }

    let public_app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/state/agents", get(agent_state))
        .route("/v1/topology", get(topology))
        .route("/v1/flows", get(flow_history))
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
        .route("/v1/state/identities", get(identity_snapshot))
        .route("/v1/state/policies", get(policy_snapshot))
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
        services: RwLock::new(BTreeMap::new()),
        endpoint_slices: RwLock::new(BTreeMap::new()),
        namespaces: RwLock::new(BTreeMap::new()),
        security_policies: RwLock::new(BTreeMap::new()),
        compiled_security_policies: RwLock::new(BTreeMap::new()),
        network_policies: RwLock::new(BTreeMap::new()),
        compiled_network_policies: RwLock::new(BTreeMap::new()),
        rejected_network_policies: RwLock::new(BTreeMap::new()),
        policy_state_guard: RwLock::new(()),
        identities: Mutex::new(IdentityRegistry::default()),
        flow_history: Mutex::new(FlowHistoryStore::default()),
        flow_history_dirty: AtomicBool::new(false),
        flow_history_store: config_map_store.clone(),
        flow_history_checkpointed_flows: AtomicU64::new(0),
        flow_history_checkpoint_omitted_flows: AtomicU64::new(0),
        flow_history_checkpoint_omitted_observations: AtomicU64::new(0),
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
    let reports = decode_agent_report_store(encoded, unix_time_millis())?;
    let restored = reports.len() as u64;
    *write_lock(&state.agent_reports) = reports;
    state.metrics.agent_reports_restored.inc_by(restored);
    info!(restored, "restored durable agent acknowledgements");
    Ok(())
}

fn decode_agent_report_store(
    encoded: &str,
    now_unix_ms: u64,
) -> Result<BTreeMap<String, StoredAgentReport>> {
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
    for (node_name, stored) in &store.reports {
        if node_name != &stored.report.node_name {
            return Err(anyhow!(
                "durable agent-report key {node_name:?} does not match report node {:?}",
                stored.report.node_name
            ));
        }
        validate_agent_status(&stored.report).map_err(|error| {
            anyhow!("invalid durable report for {node_name}: {}", error.message)
        })?;
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
    }
    Ok(store.reports)
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
        Event::Apply(pod) | Event::InitApply(pod) => upsert_pod(state, &pod),
        Event::Delete(pod) => {
            let key = object_key(&pod);
            let removed = write_lock(&state.pods).remove(&key);
            mutex_lock(&state.identities).remove_pod(&key);
            if let Some(removed) = removed {
                bump_topology_revision(state);
                if !removed.ipv4_addresses.is_empty()
                    || !read_lock(&state.pods)
                        .values()
                        .any(|pod| pod.endpoint.identity == removed.endpoint.identity)
                {
                    bump_policy_revision(state);
                }
            }
        }
        Event::Init => {
            let had_pods = !read_lock(&state.pods).is_empty();
            write_lock(&state.pods).clear();
            mutex_lock(&state.identities).clear();
            if had_pods {
                bump_policy_revision(state);
                bump_topology_revision(state);
            }
        }
        Event::InitDone => {}
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
    let record = PodRecord {
        namespace,
        name,
        uid: pod.metadata.uid.clone().unwrap_or_default(),
        node_name: pod.spec.as_ref().and_then(|spec| spec.node_name.clone()),
        endpoint,
        ipv4_addresses: addresses
            .iter()
            .filter_map(|address| match address {
                IpAddr::V4(address) => Some(*address),
                IpAddr::V6(_) => None,
            })
            .collect(),
        ipv6_addresses: addresses
            .iter()
            .filter_map(|address| match address {
                IpAddr::V4(_) => None,
                IpAddr::V6(address) => Some(*address),
            })
            .collect(),
    };
    let previous = write_lock(&state.pods).insert(key, record.clone());
    if previous.as_ref().is_none_or(|previous| {
        previous.endpoint != record.endpoint || previous.ipv4_addresses != record.ipv4_addresses
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
    let mut addresses = BTreeSet::new();
    if pod
        .spec
        .as_ref()
        .and_then(|spec| spec.host_network)
        .unwrap_or(false)
    {
        return addresses;
    }
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
        Event::Apply(node) | Event::InitApply(node) => {
            let normalized = topology_node(&node);
            let previous =
                write_lock(&state.nodes).insert(normalized.name.clone(), normalized.clone());
            state.metrics.reconciles.inc();
            if previous.as_ref() != Some(&normalized) {
                bump_topology_revision(state);
            }
        }
        Event::Delete(node) => {
            let node_name = node.name_any();
            if write_lock(&state.nodes).remove(&node_name).is_some() {
                bump_topology_revision(state);
            }
            if write_lock(&state.agent_reports)
                .remove(&node_name)
                .is_some()
            {
                state.agent_reports_dirty.store(true, Ordering::Release);
            }
        }
        Event::Init => {
            let had_nodes = !read_lock(&state.nodes).is_empty();
            write_lock(&state.nodes).clear();
            if had_nodes {
                bump_topology_revision(state);
            }
        }
        Event::InitDone => {
            let nodes = read_lock(&state.nodes);
            let mut reports = write_lock(&state.agent_reports);
            let previous_len = reports.len();
            reports.retain(|node_name, _| nodes.contains_key(node_name));
            if reports.len() != previous_len {
                state.agent_reports_dirty.store(true, Ordering::Release);
            }
        }
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
                    let previous = write_lock(&state.services).insert(key, record.clone());
                    state.metrics.reconciles.inc();
                    if previous.as_ref() != Some(&record) {
                        bump_service_and_topology_revision(state);
                    }
                }
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, %key, "Service topology admission failed");
                }
            }
        }
        Event::Delete(service) => {
            if write_lock(&state.services)
                .remove(&object_key(&service))
                .is_some()
            {
                bump_service_and_topology_revision(state);
            }
        }
        Event::Init => {
            let had_services = !read_lock(&state.services).is_empty();
            write_lock(&state.services).clear();
            if had_services {
                bump_service_and_topology_revision(state);
            }
        }
        Event::InitDone => {}
    }
}

fn service_record(service: &Service) -> Result<ServiceRecord> {
    let namespace = service.namespace().unwrap_or_default();
    let name = service.name_any();
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
        ports.push(TopologyServicePort {
            name: port.name.clone(),
            protocol: port.protocol.clone().unwrap_or_else(|| "TCP".to_owned()),
            port: number,
            target_port: Some(port.target_port.as_ref().map_or_else(
                || number.to_string(),
                |target| match target {
                    IntOrString::Int(number) => number.to_string(),
                    IntOrString::String(name) => name.clone(),
                },
            )),
        });
    }
    ports.sort();
    Ok(ServiceRecord {
        namespace,
        name,
        service_type: spec.type_.clone().unwrap_or_else(|| "ClusterIP".to_owned()),
        cluster_ips,
        selector: spec
            .selector
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        ports,
    })
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
                    let previous = write_lock(&state.endpoint_slices).insert(key, record.clone());
                    state.metrics.reconciles.inc();
                    if previous.as_ref() != Some(&record) {
                        bump_service_and_topology_revision(state);
                    }
                }
                Err(error) => {
                    state.metrics.errors.inc();
                    if write_lock(&state.endpoint_slices).remove(&key).is_some() {
                        bump_service_and_topology_revision(state);
                    }
                    warn!(%error, %key, "EndpointSlice topology admission failed");
                }
            }
        }
        Event::Delete(endpoint_slice) => {
            if write_lock(&state.endpoint_slices)
                .remove(&object_key(&endpoint_slice))
                .is_some()
            {
                bump_service_and_topology_revision(state);
            }
        }
        Event::Init => {
            let had_endpoint_slices = !read_lock(&state.endpoint_slices).is_empty();
            write_lock(&state.endpoint_slices).clear();
            if had_endpoint_slices {
                bump_service_and_topology_revision(state);
            }
        }
        Event::InitDone => {}
    }
}

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

    let mut backends = Vec::with_capacity(endpoint_slice.endpoints.len());
    for endpoint in &endpoint_slice.endpoints {
        let mut addresses = endpoint.addresses.clone();
        addresses.sort();
        addresses.dedup();
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
            target_workload,
            node_name: endpoint.node_name.clone(),
            zone: endpoint.zone.clone(),
            ready,
            serving,
            terminating,
            ports: ports.clone(),
        });
    }
    backends.sort();
    Ok(EndpointSliceRecord {
        service_reference: format!("{namespace}/{service_name}"),
        backends,
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
        services: read_lock(&state.services).len(),
        endpoint_slices: read_lock(&state.endpoint_slices).len(),
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
        ],
    }))
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
    Ok(())
}

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

fn agent_report_matches(
    report: &AgentStateReport,
    expected_epoch: u64,
    identity_revision: Revision,
    policy_revision: Revision,
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

async fn topology(State(state): State<Arc<ControllerState>>) -> Json<TopologyStateSnapshot> {
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    Json(topology_snapshot(&state))
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
    let observations = batch
        .entries
        .iter()
        .map(|entry| entry.observed_events)
        .fold(0_u64, u64::saturating_add);
    let (revision, changed) = {
        let mut history = mutex_lock(&state.flow_history);
        let changed = history.ingest(batch, unix_time_millis());
        (history.revision(), changed)
    };
    if changed {
        state.flow_history_dirty.store(true, Ordering::Release);
    }
    mutex_lock(&state.revisions).telemetry = revision;
    state.metrics.telemetry_batches.inc();
    state.metrics.telemetry_observations.inc_by(observations);
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
        if entry.decision.reason > 5 || entry.shadow.is_some_and(|shadow| shadow.reason > 5) {
            return Err(ApiError::bad_request(
                "flow export decision reason must be a known ABI reason code",
            ));
        }
    }
    Ok(())
}

fn dataplane_policy_state(state: &ControllerState) -> Result<DataplanePolicyState, ApiError> {
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    let policies = compiled_policies(state);
    let (ingress_policies, egress_policies): (Vec<_>, Vec<_>) = policies
        .into_iter()
        .partition(|policy| policy.direction == PolicyDirection::Ingress);
    let endpoints = endpoints_with_namespace_labels(state);
    let entries = compile_dataplane_entries(&ingress_policies, &endpoints)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let ipv4_endpoints = ipv4_endpoints_with_namespace_labels(state);
    let ipv4_entries =
        compile_ipv4_dataplane_entries(&ingress_policies, &endpoints, &ipv4_endpoints)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    let ipv6_endpoints = ipv6_endpoints_with_namespace_labels(state);
    let ipv6_entries =
        compile_ipv6_dataplane_entries(&ingress_policies, &endpoints, &ipv6_endpoints)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    let egress_ipv4_entries =
        compile_egress_ipv4_dataplane_entries(&egress_policies, &endpoints, &ipv4_endpoints)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    let egress_ipv6_entries =
        compile_egress_ipv6_dataplane_entries(&egress_policies, &endpoints, &ipv6_endpoints)
            .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok((
        mutex_lock(&state.revisions).policy,
        entries,
        ipv4_entries,
        ipv6_entries,
        egress_ipv4_entries,
        egress_ipv6_entries,
    ))
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
    read_lock(&state.pods)
        .values()
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
        .collect()
}

fn ipv6_endpoints_with_namespace_labels(state: &ControllerState) -> Vec<Ipv6Endpoint> {
    let namespaces = read_lock(&state.namespaces);
    read_lock(&state.pods)
        .values()
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
        .collect()
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
    let mut revisions = mutex_lock(&state.revisions);
    revisions.topology = revisions.topology.next();
}

fn bump_service_and_topology_revision(state: &ControllerState) {
    let mut revisions = mutex_lock(&state.revisions);
    revisions.service = revisions.service.next();
    revisions.topology = revisions.topology.next();
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
                "labels": {"kubernetes.io/hostname": "worker-a"}
            },
            "status": {
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
                    "targetPort": 8080
                }]
            }
        }))
        .expect("test Service is valid Kubernetes JSON")
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
            "ports": [{"name": "http", "protocol": "TCP", "port": 8080}],
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
                },
                policy_revision: Revision::new(7),
                decision: unf_state::FlowExportDecision {
                    verdict: Verdict::Allow,
                    reason: 1,
                    policy_id: Some(PolicyId::new(9)),
                    rule_id: Some(unf_common::RuleId::new(0)),
                },
                shadow: None,
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

        let decoded = decode_agent_report_store(&encoded, 10_001)
            .expect("valid durable acknowledgement is restored");

        assert_eq!(decoded, BTreeMap::from([("worker-a".to_owned(), stored)]));
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

        let mut unchanged_service = service();
        unchanged_service.metadata.resource_version = Some("2".to_owned());
        apply_service_event(&state, Event::Apply(unchanged_service));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(1));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(2));

        apply_service_event(&state, Event::Delete(service()));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(2));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(3));
        assert!(topology_snapshot(&state).services.is_empty());
    }

    #[test]
    fn endpoint_slice_readiness_is_revisioned_and_removes_stale_state() {
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
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(4));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(4));
        assert!(topology_snapshot(&state).services[0].backends.is_empty());

        apply_endpoint_slice_event(&state, Event::Apply(endpoint_slice(true)));
        apply_endpoint_slice_event(&state, Event::Delete(endpoint_slice(true)));
        assert_eq!(mutex_lock(&state.revisions).service, Revision::new(6));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(6));
        assert!(topology_snapshot(&state).services[0].backends.is_empty());
    }

    #[tokio::test]
    async fn flow_ingestion_is_validated_revisioned_and_enriched() {
        let state = Arc::new(new_state(true));
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

        let mut sctp = flow_batch(1);
        sctp.entries[0].key.protocol = Protocol::Sctp as u8;
        sctp.entries[0].key.destination_port = 8086;
        validate_flow_export_batch(&sctp).expect("SCTP flow export is accepted");

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
        write_lock(&state.services).insert(
            "backend/server".to_owned(),
            ServiceRecord {
                namespace: "backend".to_owned(),
                name: "server".to_owned(),
                service_type: "ClusterIP".to_owned(),
                cluster_ips: BTreeSet::new(),
                selector: BTreeMap::new(),
                ports: Vec::new(),
            },
        );
        write_lock(&state.endpoint_slices).insert(
            "backend/server-abc".to_owned(),
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
            },
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
