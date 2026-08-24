use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, ValueEnum};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Namespace, Node, Pod, Service};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
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
use unf_common::{PolicyId, Protocol, Revision, Verdict};
use unf_policy::{
    DestinationPort, Endpoint, Flow, Ipv4Endpoint, NamedPort, NetworkPolicyCompiler,
    PolicyCompiler, PolicyIr, compile_dataplane_entries, compile_ipv4_dataplane_entries, evaluate,
};
use unf_state::{
    IdentityRegistry, IdentityStateSnapshot, NetworkIdentity, POLICY_SNAPSHOT_SCHEMA_VERSION,
    PolicyStateSnapshot, RevisionSet, TOPOLOGY_SNAPSHOT_SCHEMA_VERSION, TopologyNode,
    TopologyService, TopologyServicePort, TopologyStateSnapshot, TopologyWorkload,
    provisional_identity_id,
};

#[derive(Debug, Parser)]
#[command(about = "UNF Kubernetes desired-state controller")]
struct Args {
    #[arg(long, env = "UNF_CONTROLLER_LISTEN", default_value = "0.0.0.0:9962")]
    listen: SocketAddr,
    /// Run the API server without connecting to Kubernetes (development only).
    #[arg(long)]
    offline: bool,
}

#[derive(Default)]
struct ControllerMetrics {
    reconciles: Counter,
    errors: Counter,
}

struct ControllerState {
    ready: AtomicBool,
    identity_epoch: u64,
    offline: bool,
    pods: RwLock<BTreeMap<String, PodRecord>>,
    nodes: RwLock<BTreeMap<String, TopologyNode>>,
    services: RwLock<BTreeMap<String, ServiceRecord>>,
    namespaces: RwLock<BTreeMap<String, BTreeMap<String, String>>>,
    security_policies: RwLock<BTreeMap<String, SecurityPolicy>>,
    compiled_security_policies: RwLock<BTreeMap<String, PolicyIr>>,
    network_policies: RwLock<BTreeMap<String, NetworkPolicy>>,
    compiled_network_policies: RwLock<BTreeMap<String, PolicyIr>>,
    rejected_network_policies: RwLock<BTreeMap<String, String>>,
    policy_state_guard: RwLock<()>,
    identities: Mutex<IdentityRegistry>,
    revisions: Mutex<RevisionSet>,
    registry: Mutex<Registry>,
    metrics: ControllerMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PodRecord {
    namespace: String,
    name: String,
    node_name: Option<String>,
    endpoint: Endpoint,
    ipv4_addresses: BTreeSet<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceRecord {
    namespace: String,
    name: String,
    service_type: String,
    cluster_ips: BTreeSet<IpAddr>,
    selector: BTreeMap<String, String>,
    ports: Vec<TopologyServicePort>,
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
    namespaces: usize,
    security_policies: usize,
    network_policies: usize,
    rejected_network_policies: usize,
    compiled_policies: usize,
    resolved_policy_entries: usize,
    identities: usize,
    indexed_pod_ips: usize,
    identity_epoch: u64,
    revisions: RevisionSet,
    limitations: [&'static str; 2],
}

#[derive(Debug, Deserialize)]
struct ExplainRequest {
    from: String,
    to: String,
    protocol: RequestProtocol,
    port: u16,
}

#[derive(Debug, Clone, Copy, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum RequestProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Serialize)]
struct ExplainResponse {
    source: ResolvedEndpoint,
    destination: ResolvedEndpoint,
    decision: unf_policy::PolicyDecision,
    policy_revision: Revision,
    dataplane_enforcement: bool,
    note: &'static str,
}

const POLICY_SIMULATION_SCHEMA_VERSION: u16 = 1;
const POLICY_SIMULATION_FLOW_LIMIT: usize = 10_000;

#[derive(Debug, Deserialize)]
struct PolicySimulationRequest {
    policy: SecurityPolicy,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum PolicySimulationOperation {
    Add,
    Replace,
}

#[derive(Debug, Serialize)]
struct PolicySimulationSnapshot {
    identity_epoch: u64,
    identity_revision: Revision,
    policy_revision: Revision,
    topology_revision: Revision,
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
    protocol: &'static str,
    destination_port: u16,
    current: unf_policy::PolicyDecision,
    proposed: unf_policy::PolicyDecision,
}

#[derive(Debug, Serialize)]
struct PolicySimulationResponse {
    schema_version: u16,
    policy: String,
    policy_id: PolicyId,
    operation: PolicySimulationOperation,
    snapshot: PolicySimulationSnapshot,
    affected_destinations: usize,
    summary: PolicySimulationSummary,
    changes: Vec<PolicySimulationChange>,
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

#[tokio::main]
async fn main() -> Result<()> {
    install_crypto_provider()?;
    init_tracing();
    let args = Args::parse();
    let state = Arc::new(new_state(args.offline));
    let cancellation = CancellationToken::new();
    let mut tasks = JoinSet::new();

    if args.offline {
        warn!("running without Kubernetes watchers");
    } else {
        let client = Client::try_default()
            .await
            .context("create Kubernetes client from in-cluster or kubeconfig settings")?;
        spawn_watchers(&mut tasks, client, Arc::clone(&state), cancellation.clone());
        state.ready.store(true, Ordering::Release);
    }

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/status", get(status))
        .route("/v1/state/identities", get(identity_snapshot))
        .route("/v1/state/policies", get(policy_snapshot))
        .route("/v1/topology", get(topology))
        .route("/v1/explain", post(explain))
        .route("/v1/policy/simulate", post(simulate_policy))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("bind controller API to {}", args.listen))?;
    info!(address = %args.listen, "controller API listening");

    let shutdown = cancellation.clone();
    tasks.spawn(async move {
        if let Err(error) = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
        {
            error!(%error, "controller API server failed");
        }
    });

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

fn install_crypto_provider() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("install process-wide Rustls crypto provider"))
}

fn new_state(offline: bool) -> ControllerState {
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
    ControllerState {
        ready: AtomicBool::new(offline),
        identity_epoch: controller_epoch(),
        offline,
        pods: RwLock::new(BTreeMap::new()),
        nodes: RwLock::new(BTreeMap::new()),
        services: RwLock::new(BTreeMap::new()),
        namespaces: RwLock::new(BTreeMap::new()),
        security_policies: RwLock::new(BTreeMap::new()),
        compiled_security_policies: RwLock::new(BTreeMap::new()),
        network_policies: RwLock::new(BTreeMap::new()),
        compiled_network_policies: RwLock::new(BTreeMap::new()),
        rejected_network_policies: RwLock::new(BTreeMap::new()),
        policy_state_guard: RwLock::new(()),
        identities: Mutex::new(IdentityRegistry::default()),
        revisions: Mutex::new(RevisionSet::default()),
        registry: Mutex::new(registry),
        metrics,
    }
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
        node_name: pod.spec.as_ref().and_then(|spec| spec.node_name.clone()),
        endpoint,
        ipv4_addresses: addresses
            .into_iter()
            .filter_map(|address| match address {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
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
            if write_lock(&state.nodes).remove(&node.name_any()).is_some() {
                bump_topology_revision(state);
            }
        }
        Event::Init => {
            let had_nodes = !read_lock(&state.nodes).is_empty();
            write_lock(&state.nodes).clear();
            if had_nodes {
                bump_topology_revision(state);
            }
        }
        Event::InitDone => {}
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
            match NetworkPolicyCompiler::compile(id, policy.clone()) {
                Ok(ir) => {
                    let previous = write_lock(&state.compiled_network_policies)
                        .insert(key.clone(), ir.clone());
                    write_lock(&state.network_policies).insert(key.clone(), policy);
                    write_lock(&state.rejected_network_policies).remove(&key);
                    state.metrics.reconciles.inc();
                    if previous.as_ref() != Some(&ir) {
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
    let (_, policy_entries, ipv4_policy_entries) = dataplane_policy_state(&state)?;
    let resolved_policy_entries = policy_entries.len() + ipv4_policy_entries.len();
    let (identity_revision, identity_count, indexed_pod_ips) = {
        let identities = mutex_lock(&state.identities);
        (
            identities.revision(),
            identities.identity_count(),
            identities.address_count(),
        )
    };
    let mut revisions = mutex_lock(&state.revisions).clone();
    revisions.identity = identity_revision;
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
        namespaces: read_lock(&state.namespaces).len(),
        security_policies: read_lock(&state.security_policies).len(),
        network_policies: read_lock(&state.network_policies).len(),
        rejected_network_policies: read_lock(&state.rejected_network_policies).len(),
        compiled_policies: read_lock(&state.compiled_security_policies).len()
            + read_lock(&state.compiled_network_policies).len(),
        resolved_policy_entries,
        identities: identity_count,
        indexed_pod_ips,
        identity_epoch: state.identity_epoch,
        revisions,
        limitations: [
            "desired state and identity allocations are currently in-memory only",
            "dataplane status is node-local and policy maps are currently unpinned",
        ],
    }))
}

async fn identity_snapshot(
    State(state): State<Arc<ControllerState>>,
) -> Json<IdentityStateSnapshot> {
    Json(mutex_lock(&state.identities).ipv4_snapshot(state.identity_epoch))
}

async fn policy_snapshot(
    State(state): State<Arc<ControllerState>>,
) -> Result<Json<PolicyStateSnapshot>, ApiError> {
    let (revision, entries, ipv4_entries) = dataplane_policy_state(&state)?;
    Ok(Json(PolicyStateSnapshot {
        schema_version: POLICY_SNAPSHOT_SCHEMA_VERSION,
        source_epoch: state.identity_epoch,
        revision,
        entries,
        ipv4_entries,
    }))
}

async fn topology(State(state): State<Arc<ControllerState>>) -> Json<TopologyStateSnapshot> {
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    Json(topology_snapshot(&state))
}

fn topology_snapshot(state: &ControllerState) -> TopologyStateSnapshot {
    let pods = read_lock(&state.pods);
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

fn dataplane_policy_state(
    state: &ControllerState,
) -> Result<
    (
        Revision,
        Vec<unf_state::PolicyMapEntry>,
        Vec<unf_state::Ipv4PolicyMapEntry>,
    ),
    ApiError,
> {
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    let policies = compiled_policies(state);
    let endpoints = endpoints_with_namespace_labels(state);
    let entries = compile_dataplane_entries(&policies, &endpoints)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    let ipv4_endpoints = ipv4_endpoints_with_namespace_labels(state);
    let ipv4_entries = compile_ipv4_dataplane_entries(&policies, &endpoints, &ipv4_endpoints)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok((mutex_lock(&state.revisions).policy, entries, ipv4_entries))
}

async fn explain(
    State(state): State<Arc<ControllerState>>,
    Json(request): Json<ExplainRequest>,
) -> Result<Json<ExplainResponse>, ApiError> {
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
    };
    let policies = compiled_policies(&state);
    let decision = evaluate(
        &policies,
        Flow {
            source: &source_endpoint,
            destination: &destination_endpoint,
            protocol,
            destination_port: request.port,
            source_ipv4: source.ipv4_addresses.iter().next().copied(),
        },
    );
    let revision = mutex_lock(&state.revisions).policy;
    Ok(Json(ExplainResponse {
        source: resolved(source),
        destination: resolved(destination),
        decision,
        policy_revision: revision,
        dataplane_enforcement: true,
        note: "decision is enforceable after traffic-path nodes report this policy revision as applied",
    }))
}

async fn simulate_policy(
    State(state): State<Arc<ControllerState>>,
    Json(request): Json<PolicySimulationRequest>,
) -> Result<Json<PolicySimulationResponse>, ApiError> {
    let key = object_key(&request.policy);
    let policy_id = stable_policy_id(&key);
    let candidate = PolicyCompiler::compile(policy_id, request.policy)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;

    let _policy_state_guard = read_lock(&state.policy_state_guard);
    let pod_records: Vec<_> = read_lock(&state.pods).values().cloned().collect();
    let namespaces = read_lock(&state.namespaces).clone();
    let current_policies = compiled_policies(&state);
    let current_candidate = read_lock(&state.compiled_security_policies)
        .get(&key)
        .cloned();
    let operation = if current_candidate.is_some() {
        PolicySimulationOperation::Replace
    } else {
        PolicySimulationOperation::Add
    };
    let mut proposed_policies: Vec<_> = read_lock(&state.compiled_security_policies)
        .iter()
        .filter(|(existing_key, _)| *existing_key != &key)
        .map(|(_, policy)| policy.clone())
        .collect();
    proposed_policies.extend(
        read_lock(&state.compiled_network_policies)
            .values()
            .cloned(),
    );
    proposed_policies.push(candidate.clone());

    let endpoints: Vec<_> = pod_records
        .iter()
        .map(|pod| endpoint_with_namespace_labels(&pod.endpoint, &namespaces))
        .collect();
    let affected_destinations: BTreeSet<_> = endpoints
        .iter()
        .enumerate()
        .filter(|(_, endpoint)| {
            candidate.target.matches(endpoint)
                || current_candidate
                    .as_ref()
                    .is_some_and(|policy| policy.target.matches(endpoint))
        })
        .map(|(index, _)| index)
        .collect();

    let mut flow_count = 0_usize;
    let mut destination_tuples = BTreeMap::new();
    for destination_index in &affected_destinations {
        let tuples = simulation_protocol_ports(
            &current_policies,
            &proposed_policies,
            &endpoints[*destination_index],
        );
        flow_count = flow_count
            .checked_add(pod_records.len().saturating_mul(tuples.len()))
            .ok_or_else(|| ApiError::bad_request("policy simulation flow count overflow"))?;
        if flow_count > POLICY_SIMULATION_FLOW_LIMIT {
            return Err(ApiError::unprocessable(format!(
                "policy simulation requires {flow_count} topology-derived flows; limit is {POLICY_SIMULATION_FLOW_LIMIT}"
            )));
        }
        destination_tuples.insert(*destination_index, tuples);
    }

    let (summary, changes) = evaluate_simulation_matrix(
        &pod_records,
        &endpoints,
        &destination_tuples,
        &current_policies,
        &proposed_policies,
    );

    let identity_revision = mutex_lock(&state.identities).revision();
    let revisions = mutex_lock(&state.revisions).clone();
    Ok(Json(PolicySimulationResponse {
        schema_version: POLICY_SIMULATION_SCHEMA_VERSION,
        policy: key,
        policy_id,
        operation,
        snapshot: PolicySimulationSnapshot {
            identity_epoch: state.identity_epoch,
            identity_revision,
            policy_revision: revisions.policy,
            topology_revision: revisions.topology,
            pods: pod_records.len(),
            flow_source: "current-topology representative matrix",
        },
        affected_destinations: affected_destinations.len(),
        summary,
        changes,
        note: "read-only what-if result; the candidate was not applied and historical flows are not included",
    }))
}

fn evaluate_simulation_matrix(
    pod_records: &[PodRecord],
    endpoints: &[Endpoint],
    destination_tuples: &BTreeMap<usize, BTreeSet<(Protocol, u16)>>,
    current_policies: &[PolicyIr],
    proposed_policies: &[PolicyIr],
) -> (PolicySimulationSummary, Vec<PolicySimulationChange>) {
    let mut summary = PolicySimulationSummary::default();
    let mut changes = Vec::new();
    let mut affected_workloads = BTreeSet::new();
    for (source_index, source) in endpoints.iter().enumerate() {
        for (destination_index, tuples) in destination_tuples {
            let destination = &endpoints[*destination_index];
            for (protocol, destination_port) in tuples {
                let flow = Flow {
                    source,
                    destination,
                    protocol: *protocol,
                    destination_port: *destination_port,
                    source_ipv4: pod_records[source_index]
                        .ipv4_addresses
                        .iter()
                        .next()
                        .copied(),
                };
                let current = evaluate(current_policies, flow);
                let proposed = evaluate(proposed_policies, flow);
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
                    affected_workloads.insert(source_index);
                    affected_workloads.insert(*destination_index);
                    changes.push(PolicySimulationChange {
                        source: resolved(&pod_records[source_index]),
                        destination: resolved(&pod_records[*destination_index]),
                        protocol: protocol_name(*protocol),
                        destination_port: *destination_port,
                        current,
                        proposed,
                    });
                }
            }
        }
    }
    summary.affected_workloads = affected_workloads.len();
    (summary, changes)
}

fn simulation_protocol_ports(
    current_policies: &[PolicyIr],
    proposed_policies: &[PolicyIr],
    destination: &Endpoint,
) -> BTreeSet<(Protocol, u16)> {
    let mut tuples = BTreeSet::new();
    for policy in current_policies.iter().chain(proposed_policies) {
        if !policy.target.matches(destination) {
            continue;
        }
        for rule in &policy.rules {
            if !rule.destination.matches(destination) {
                continue;
            }
            let protocols: &[Protocol] = match rule.protocol {
                Some(Protocol::Tcp) => &[Protocol::Tcp],
                Some(Protocol::Udp) => &[Protocol::Udp],
                Some(Protocol::Icmp) => continue,
                None => &[Protocol::Tcp, Protocol::Udp],
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
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        if let Some(port) = (1..=u16::MAX).find(|port| !tuples.contains(&(protocol, *port))) {
            tuples.insert((protocol, port));
        }
    }
    tuples
}

const fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
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
            "status": {"podIP": "10.42.0.10", "podIPs": [{"ip": "10.42.0.10"}]}
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
        assert_eq!(ports.len(), 2, "unsupported SCTP metadata is ignored");

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
    fn network_policy_reconciliation_removes_stale_state_on_rejection() {
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
        assert!(read_lock(&state.network_policies).is_empty());
        assert!(read_lock(&state.compiled_network_policies).is_empty());
        assert_eq!(read_lock(&state.rejected_network_policies).len(), 1);
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(2));
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

    #[test]
    fn pod_placement_changes_only_advance_topology_revision() {
        let state = new_state(true);
        apply_pod_event(&state, Event::Apply(scheduled_pod("worker-a")));
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(1));
        assert_eq!(mutex_lock(&state.revisions).topology, Revision::new(1));

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
        mutex_lock(&state.revisions).policy = Revision::new(7);

        let response = simulate_policy(
            State(Arc::clone(&state)),
            Json(PolicySimulationRequest {
                policy: security_policy("frontend-to-backend", "Deny"),
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
        assert_eq!(response.affected_destinations, 1);
        assert_eq!(response.summary.evaluated_flows, 6);
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

        assert_eq!(mutex_lock(&state.revisions).policy, Revision::new(7));
        assert_eq!(
            read_lock(&state.compiled_security_policies).get(key),
            Some(&current)
        );
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
                policy: security_policy("candidate-deny", "Deny"),
            }),
        )
        .await
        .expect("new candidate policy simulates")
        .0;

        assert!(matches!(response.operation, PolicySimulationOperation::Add));
        assert_eq!(response.summary.evaluated_flows, 6);
        assert_eq!(response.summary.would_be_denied, 6);
        assert!(read_lock(&state.compiled_security_policies).is_empty());
        assert_eq!(mutex_lock(&state.revisions).policy, Revision::default());
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
                policy: security_policy("candidate-deny", "Deny"),
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
