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
use k8s_openapi::api::core::v1::{Namespace, Pod};
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
use unf_common::{PolicyId, Protocol, Revision};
use unf_policy::{Endpoint, Flow, PolicyCompiler, PolicyIr, compile_dataplane_entries, evaluate};
use unf_state::{
    IdentityRegistry, IdentityStateSnapshot, NetworkIdentity, POLICY_SNAPSHOT_SCHEMA_VERSION,
    PolicyStateSnapshot, RevisionSet, provisional_identity_id,
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
    namespaces: RwLock<BTreeMap<String, Namespace>>,
    policies: RwLock<BTreeMap<String, SecurityPolicy>>,
    compiled: RwLock<BTreeMap<String, PolicyIr>>,
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
    endpoint: Endpoint,
}

#[derive(Debug, Serialize)]
struct StatusBody {
    component: &'static str,
    healthy: bool,
    ready: bool,
    mode: &'static str,
    pods: usize,
    namespaces: usize,
    security_policies: usize,
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
        .route("/v1/explain", post(explain))
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
        namespaces: RwLock::new(BTreeMap::new()),
        policies: RwLock::new(BTreeMap::new()),
        compiled: RwLock::new(BTreeMap::new()),
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

    let policy_api = Api::<SecurityPolicy>::all(client);
    tasks.spawn(async move {
        watch_policies(policy_api, state, cancellation).await;
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
            if let Some(removed) = removed
                && !read_lock(&state.pods)
                    .values()
                    .any(|pod| pod.endpoint.identity == removed.endpoint.identity)
            {
                bump_policy_revision(state);
            }
        }
        Event::Init => {
            let had_pods = !read_lock(&state.pods).is_empty();
            write_lock(&state.pods).clear();
            mutex_lock(&state.identities).clear();
            if had_pods {
                bump_policy_revision(state);
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
    let identity_key =
        canonical_identity_key("local", &namespace, &service_account, &workload, &labels);
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
    if let Err(error) = mutex_lock(&state.identities).admit_pod(
        key.clone(),
        identity_key,
        &identity,
        pod_addresses(pod),
    ) {
        state.metrics.errors.inc();
        warn!(%error, %key, "Pod identity admission failed");
        return;
    }
    let endpoint = Endpoint {
        identity: identity_id,
        namespace: namespace.clone(),
        service_account,
        application,
        labels,
    };
    let record = PodRecord {
        namespace,
        name,
        endpoint,
    };
    let previous = write_lock(&state.pods).insert(key, record.clone());
    if previous.as_ref() != Some(&record) {
        bump_policy_revision(state);
    }
    state.metrics.reconciles.inc();
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
    match event {
        Event::Apply(namespace) | Event::InitApply(namespace) => {
            write_lock(&state.namespaces).insert(namespace.name_any(), namespace);
            state.metrics.reconciles.inc();
        }
        Event::Delete(namespace) => {
            write_lock(&state.namespaces).remove(&namespace.name_any());
        }
        Event::Init => write_lock(&state.namespaces).clear(),
        Event::InitDone => {}
    }
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
                    let previous = write_lock(&state.compiled).insert(key.clone(), ir.clone());
                    write_lock(&state.policies).insert(key, policy);
                    state.metrics.reconciles.inc();
                    if previous.as_ref() != Some(&ir) {
                        bump_policy_revision(state);
                    }
                }
                Err(error) => {
                    state.metrics.errors.inc();
                    warn!(%error, %key, "policy compilation failed");
                }
            }
        }
        Event::Delete(policy) => {
            let key = object_key(&policy);
            write_lock(&state.policies).remove(&key);
            if write_lock(&state.compiled).remove(&key).is_some() {
                bump_policy_revision(state);
            }
        }
        Event::Init => {
            write_lock(&state.policies).clear();
            let had_policies = !read_lock(&state.compiled).is_empty();
            write_lock(&state.compiled).clear();
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
    let (_, policy_entries) = dataplane_policy_state(&state)?;
    let resolved_policy_entries = policy_entries.len();
    let identities = mutex_lock(&state.identities);
    let mut revisions = mutex_lock(&state.revisions).clone();
    revisions.identity = identities.revision();
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
        namespaces: read_lock(&state.namespaces).len(),
        security_policies: read_lock(&state.policies).len(),
        compiled_policies: read_lock(&state.compiled).len(),
        resolved_policy_entries,
        identities: identities.identity_count(),
        indexed_pod_ips: identities.address_count(),
        identity_epoch: state.identity_epoch,
        revisions,
        limitations: [
            "desired state and identity allocations are currently in-memory only",
            "identity and policy state are distributed; TC enforcement is not enabled",
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
    let (revision, entries) = dataplane_policy_state(&state)?;
    Ok(Json(PolicyStateSnapshot {
        schema_version: POLICY_SNAPSHOT_SCHEMA_VERSION,
        source_epoch: state.identity_epoch,
        revision,
        entries,
    }))
}

fn dataplane_policy_state(
    state: &ControllerState,
) -> Result<(Revision, Vec<unf_state::PolicyMapEntry>), ApiError> {
    let _policy_state_guard = read_lock(&state.policy_state_guard);
    let policies: Vec<_> = read_lock(&state.compiled).values().cloned().collect();
    let endpoints: Vec<_> = read_lock(&state.pods)
        .values()
        .map(|pod| pod.endpoint.clone())
        .collect();
    let entries = compile_dataplane_entries(&policies, &endpoints)
        .map_err(|error| ApiError::internal(error.to_string()))?;
    Ok((mutex_lock(&state.revisions).policy, entries))
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
    let protocol = match request.protocol {
        RequestProtocol::Tcp => Protocol::Tcp,
        RequestProtocol::Udp => Protocol::Udp,
    };
    let policies: Vec<PolicyIr> = read_lock(&state.compiled).values().cloned().collect();
    let decision = evaluate(
        &policies,
        Flow {
            source: &source.endpoint,
            destination: &destination.endpoint,
            protocol,
            destination_port: request.port,
        },
    );
    let revision = mutex_lock(&state.revisions).policy;
    Ok(Json(ExplainResponse {
        source: resolved(source),
        destination: resolved(destination),
        decision,
        policy_revision: revision,
        dataplane_enforcement: false,
        note: "policy desired state is distributed; TC enforcement is not enabled",
    }))
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
) -> String {
    fn append_component(key: &mut String, value: &str) {
        key.push('|');
        key.push_str(&value.len().to_string());
        key.push(':');
        key.push_str(value);
    }

    let mut key = "v1".to_owned();
    append_component(&mut key, cluster);
    append_component(&mut key, namespace);
    append_component(&mut key, service_account);
    append_component(&mut key, workload);
    append_component(&mut key, &labels.len().to_string());
    for (label, value) in labels {
        append_component(&mut key, label);
        append_component(&mut key, value);
    }
    key
}

fn bump_policy_revision(state: &ControllerState) {
    let mut revisions = mutex_lock(&state.revisions);
    revisions.policy = revisions.policy.next();
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
        let base = canonical_identity_key("local", "backend", "default", "server", &left);
        assert_eq!(
            base,
            canonical_identity_key("local", "backend", "default", "server", &right)
        );

        let changed = BTreeMap::from([
            ("app".to_owned(), "server".to_owned()),
            ("track".to_owned(), "canary".to_owned()),
        ]);
        assert_ne!(
            base,
            canonical_identity_key("local", "backend", "default", "server", &changed)
        );
    }

    #[test]
    fn canonical_identity_key_is_unambiguous_for_delimiters() {
        let labels = BTreeMap::new();
        assert_ne!(
            canonical_identity_key("local", "a|1:b", "c", "d", &labels),
            canonical_identity_key("local", "a", "1:b|c", "d", &labels)
        );
    }
}
