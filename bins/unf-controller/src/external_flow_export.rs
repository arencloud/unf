use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use reqwest::{StatusCode, Url, redirect};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use unf_common::Revision;
use unf_state::FlowExportBatch;

pub const EXTERNAL_FLOW_EXPORT_SCHEMA_VERSION: u16 = 1;
const RETRY_INITIAL_DELAY: Duration = Duration::from_millis(250);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalFlowExportEnvelope {
    pub schema_version: u16,
    pub controller_epoch: u64,
    pub export_sequence: u64,
    pub topology_revision: Revision,
    pub received_unix_ms: u64,
    pub batch: FlowExportBatch,
}

impl ExternalFlowExportEnvelope {
    pub fn observations(&self) -> u64 {
        self.batch
            .entries
            .iter()
            .map(|entry| entry.observed_events)
            .fold(0_u64, u64::saturating_add)
    }
}

#[derive(Clone, Default)]
pub struct ExternalFlowExportMetrics {
    pub queue_capacity: Gauge<u64, AtomicU64>,
    pub queue_depth: Gauge<u64, AtomicU64>,
    pub queue_high_watermark: Gauge<u64, AtomicU64>,
    pub enqueued_batches: Counter,
    pub delivery_attempts: Counter,
    pub delivered_batches: Counter,
    pub delivered_observations: Counter,
    pub delivery_errors: Counter,
    pub dropped_batches: Counter,
    pub dropped_observations: Counter,
}

#[derive(Debug, Clone)]
pub struct ExternalFlowExportConfig {
    endpoint: Url,
    allow_plaintext: bool,
    ca_path: Option<PathBuf>,
    bearer_token_file: Option<PathBuf>,
    queue_capacity: usize,
    max_attempts: u8,
    request_timeout: Duration,
    retry_initial_delay: Duration,
}

impl ExternalFlowExportConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: &str,
        allow_plaintext: bool,
        ca_path: Option<PathBuf>,
        bearer_token_file: Option<PathBuf>,
        queue_capacity: usize,
        max_attempts: u8,
        request_timeout: Duration,
    ) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("parse external flow-export HTTP URL")?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            bail!("external flow-export URL scheme must be http or https");
        }
        if endpoint.scheme() == "http" && !allow_plaintext {
            bail!(
                "external flow-export URL must use HTTPS; set the explicit plaintext development flag to permit HTTP"
            );
        }
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            bail!("external flow-export URL must not contain credentials");
        }
        if endpoint.fragment().is_some() {
            bail!("external flow-export URL must not contain a fragment");
        }
        if endpoint.host_str().is_none() {
            bail!("external flow-export URL must contain a host");
        }
        if !(1..=4_096).contains(&queue_capacity) {
            bail!("external flow-export queue capacity must be between 1 and 4096");
        }
        if !(1..=10).contains(&max_attempts) {
            bail!("external flow-export max attempts must be between 1 and 10");
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(300)).contains(&request_timeout) {
            bail!("external flow-export request timeout must be between 1 and 300 seconds");
        }
        if let Some(path) = bearer_token_file.as_ref() {
            read_bearer_token(path).with_context(|| {
                format!(
                    "validate external flow-export bearer token file {}",
                    path.display()
                )
            })?;
        }
        Ok(Self {
            endpoint,
            allow_plaintext,
            ca_path,
            bearer_token_file,
            queue_capacity,
            max_attempts,
            request_timeout,
            retry_initial_delay: RETRY_INITIAL_DELAY,
        })
    }

    #[cfg(test)]
    fn with_retry_initial_delay(mut self, delay: Duration) -> Self {
        self.retry_initial_delay = delay;
        self
    }
}

#[derive(Clone)]
pub struct ExternalFlowExporter {
    sender: mpsc::Sender<ExternalFlowExportEnvelope>,
    metrics: ExternalFlowExportMetrics,
    sequence: Arc<AtomicU64>,
    enqueue_guard: Arc<Mutex<()>>,
}

impl ExternalFlowExporter {
    pub fn enqueue(&self, mut envelope: ExternalFlowExportEnvelope) {
        let observations = envelope.observations();
        let _guard = self
            .enqueue_guard
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match self.sender.try_reserve() {
            Ok(permit) => {
                envelope.export_sequence = self
                    .sequence
                    .fetch_add(1, Ordering::AcqRel)
                    .saturating_add(1);
                let depth = self.metrics.queue_depth.inc().saturating_add(1);
                self.metrics
                    .queue_high_watermark
                    .inner()
                    .fetch_max(depth, Ordering::AcqRel);
                permit.send(envelope);
                self.metrics.enqueued_batches.inc();
            }
            Err(error) => {
                self.metrics.dropped_batches.inc();
                self.metrics.dropped_observations.inc_by(observations);
                match error {
                    mpsc::error::TrySendError::Full(()) => warn!(
                        observations,
                        "external flow-export queue is full; dropping validated batch"
                    ),
                    mpsc::error::TrySendError::Closed(()) => warn!(
                        observations,
                        "external flow-export worker is unavailable; dropping validated batch"
                    ),
                }
            }
        }
    }
}

pub struct ExternalFlowExportWorker {
    config: ExternalFlowExportConfig,
    client: reqwest::Client,
    receiver: mpsc::Receiver<ExternalFlowExportEnvelope>,
    metrics: ExternalFlowExportMetrics,
}

pub fn build_external_flow_export(
    config: ExternalFlowExportConfig,
    metrics: ExternalFlowExportMetrics,
) -> Result<(ExternalFlowExporter, ExternalFlowExportWorker)> {
    let mut client_builder = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .https_only(!config.allow_plaintext)
        .redirect(redirect::Policy::none())
        .user_agent(concat!("unf-controller/", env!("CARGO_PKG_VERSION")));
    if let Some(ca_path) = config.ca_path.as_ref() {
        let ca_pem = std::fs::read(ca_path).with_context(|| {
            format!("read external flow-export CA bundle {}", ca_path.display())
        })?;
        let certificates = reqwest::Certificate::from_pem_bundle(&ca_pem).with_context(|| {
            format!("parse external flow-export CA bundle {}", ca_path.display())
        })?;
        if certificates.is_empty() {
            bail!(
                "external flow-export CA bundle {} is empty",
                ca_path.display()
            );
        }
        client_builder = client_builder.tls_certs_merge(certificates);
    }
    let client = client_builder
        .build()
        .context("construct external flow-export HTTP client")?;
    let (sender, receiver) = mpsc::channel(config.queue_capacity);
    metrics.queue_capacity.set(
        u64::try_from(config.queue_capacity)
            .context("external flow-export queue capacity does not fit metric representation")?,
    );
    Ok((
        ExternalFlowExporter {
            sender,
            metrics: metrics.clone(),
            sequence: Arc::new(AtomicU64::new(0)),
            enqueue_guard: Arc::new(Mutex::new(())),
        },
        ExternalFlowExportWorker {
            config,
            client,
            receiver,
            metrics,
        },
    ))
}

impl ExternalFlowExportWorker {
    pub async fn run(mut self, cancellation: CancellationToken) {
        info!(
            endpoint = %self.config.endpoint,
            queue_capacity = self.config.queue_capacity,
            max_attempts = self.config.max_attempts,
            "external flow-export HTTP worker started"
        );
        loop {
            let envelope = tokio::select! {
                () = cancellation.cancelled() => {
                    self.drop_pending();
                    break;
                }
                envelope = self.receiver.recv() => match envelope {
                    Some(envelope) => {
                        self.metrics.queue_depth.dec();
                        envelope
                    },
                    None => break,
                },
            };
            if !self.deliver(&envelope, &cancellation).await {
                self.drop_envelope(&envelope);
                if cancellation.is_cancelled() {
                    self.drop_pending();
                    break;
                }
            }
        }
        info!("external flow-export HTTP worker stopped");
    }

    async fn deliver(
        &self,
        envelope: &ExternalFlowExportEnvelope,
        cancellation: &CancellationToken,
    ) -> bool {
        let mut delay = self.config.retry_initial_delay;
        for attempt in 1..=self.config.max_attempts {
            self.metrics.delivery_attempts.inc();
            let request = match self.request(envelope).await {
                Ok(request) => request,
                Err(error) => {
                    self.metrics.delivery_errors.inc();
                    warn!(attempt, %error, "external flow-export request could not be prepared");
                    if !self.wait_to_retry(attempt, delay, cancellation).await {
                        return false;
                    }
                    delay = delay.saturating_mul(2).min(RETRY_MAX_DELAY);
                    continue;
                }
            };
            let result = tokio::select! {
                () = cancellation.cancelled() => return false,
                result = request.send() => result,
            };
            match result {
                Ok(response) if response.status().is_success() => {
                    self.metrics.delivered_batches.inc();
                    self.metrics
                        .delivered_observations
                        .inc_by(envelope.observations());
                    return true;
                }
                Ok(response) if !retryable_status(response.status()) => {
                    self.metrics.delivery_errors.inc();
                    warn!(
                        attempt,
                        status = %response.status(),
                        "external flow-export receiver rejected batch without a retryable status"
                    );
                    return false;
                }
                Ok(response) => {
                    self.metrics.delivery_errors.inc();
                    warn!(
                        attempt,
                        status = %response.status(),
                        "external flow-export receiver returned a retryable status"
                    );
                }
                Err(error) => {
                    self.metrics.delivery_errors.inc();
                    warn!(attempt, %error, "external flow-export delivery failed");
                }
            }
            if !self.wait_to_retry(attempt, delay, cancellation).await {
                return false;
            }
            delay = delay.saturating_mul(2).min(RETRY_MAX_DELAY);
        }
        false
    }

    async fn request(
        &self,
        envelope: &ExternalFlowExportEnvelope,
    ) -> Result<reqwest::RequestBuilder> {
        let mut request = self
            .client
            .post(self.config.endpoint.clone())
            .json(envelope);
        if let Some(path) = self.config.bearer_token_file.as_ref() {
            request = request.bearer_auth(read_bearer_token_async(path).await?);
        }
        Ok(request)
    }

    async fn wait_to_retry(
        &self,
        attempt: u8,
        delay: Duration,
        cancellation: &CancellationToken,
    ) -> bool {
        if attempt == self.config.max_attempts {
            return false;
        }
        tokio::select! {
            () = cancellation.cancelled() => false,
            () = tokio::time::sleep(delay) => true,
        }
    }

    fn drop_envelope(&self, envelope: &ExternalFlowExportEnvelope) {
        self.metrics.dropped_batches.inc();
        self.metrics
            .dropped_observations
            .inc_by(envelope.observations());
    }

    fn drop_pending(&mut self) {
        self.receiver.close();
        while let Ok(envelope) = self.receiver.try_recv() {
            self.metrics.queue_depth.dec();
            self.drop_envelope(&envelope);
        }
        self.metrics.queue_depth.set(0);
    }
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn read_bearer_token(path: &Path) -> Result<String> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("read external flow-export bearer token {}", path.display()))?;
    validate_bearer_token(&token, path)
}

async fn read_bearer_token_async(path: &Path) -> Result<String> {
    let token = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read external flow-export bearer token {}", path.display()))?;
    validate_bearer_token(&token, path)
}

fn validate_bearer_token(token: &str, path: &Path) -> Result<String> {
    let token = token.trim();
    if token.is_empty() || token.chars().any(char::is_control) {
        bail!(
            "external flow-export bearer token {} must contain non-control characters",
            path.display()
        );
    }
    Ok(token.to_owned())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use unf_common::{IdentityId, PolicyDirection, Revision, Verdict};
    use unf_state::{
        FLOW_EXPORT_SCHEMA_VERSION, FlowExportBatch, FlowExportDecision, FlowExportRecord,
        FlowHistoryKey,
    };

    use super::*;

    #[derive(Clone)]
    struct ReceiverState {
        attempts: Arc<AtomicU64>,
        fail_attempts: u64,
        expected_authorization: Option<String>,
        envelopes: Arc<Mutex<Vec<ExternalFlowExportEnvelope>>>,
    }

    async fn receive(
        State(state): State<ReceiverState>,
        headers: HeaderMap,
        Json(envelope): Json<ExternalFlowExportEnvelope>,
    ) -> StatusCode {
        if state.expected_authorization.as_deref()
            != headers
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
        {
            return StatusCode::UNAUTHORIZED;
        }
        state
            .envelopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(envelope);
        let attempt = state.attempts.fetch_add(1, Ordering::AcqRel) + 1;
        if attempt <= state.fail_attempts {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::NO_CONTENT
        }
    }

    fn envelope(observed_events: u64) -> ExternalFlowExportEnvelope {
        ExternalFlowExportEnvelope {
            schema_version: EXTERNAL_FLOW_EXPORT_SCHEMA_VERSION,
            controller_epoch: 42,
            export_sequence: 1,
            topology_revision: Revision::new(8),
            received_unix_ms: 1_000,
            batch: FlowExportBatch {
                schema_version: FLOW_EXPORT_SCHEMA_VERSION,
                node_name: "worker-a".to_owned(),
                dropped_events: 0,
                entries: vec![FlowExportRecord {
                    key: FlowHistoryKey {
                        direction: PolicyDirection::Egress,
                        source_identity: IdentityId::new(10),
                        destination_identity: IdentityId::new(0),
                        source_ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
                        destination_ipv4: Some(Ipv4Addr::new(203, 0, 113, 1)),
                        source_ipv6: None,
                        destination_ipv6: None,
                        protocol: 6,
                        destination_port: 443,
                        service: None,
                    },
                    policy_revision: Revision::new(7),
                    decision: FlowExportDecision {
                        verdict: Verdict::Allow,
                        reason: 1,
                        policy_id: None,
                        rule_id: None,
                    },
                    shadow: None,
                    service: None,
                    observed_events,
                }],
            },
        }
    }

    async fn spawn_receiver(
        fail_attempts: u64,
        expected_authorization: Option<String>,
    ) -> (
        String,
        ReceiverState,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let state = ReceiverState {
            attempts: Arc::new(AtomicU64::new(0)),
            fail_attempts,
            expected_authorization,
            envelopes: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test receiver");
        let address = listener.local_addr().expect("test receiver address");
        let app = Router::new()
            .route("/flows", post(receive))
            .with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        (format!("http://{address}/flows"), state, task)
    }

    fn config(endpoint: &str, token_file: Option<PathBuf>) -> ExternalFlowExportConfig {
        ExternalFlowExportConfig::new(
            endpoint,
            true,
            None,
            token_file,
            4,
            3,
            Duration::from_secs(1),
        )
        .expect("valid test flow-export config")
        .with_retry_initial_delay(Duration::from_millis(1))
    }

    fn temporary_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "unf-flow-export-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("current time after epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn configuration_requires_explicit_plaintext_and_rejects_url_credentials() {
        assert!(
            ExternalFlowExportConfig::new(
                "http://receiver.example/flows",
                false,
                None,
                None,
                1,
                1,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            ExternalFlowExportConfig::new(
                "https://user:secret@receiver.example/flows",
                false,
                None,
                None,
                1,
                1,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    #[test]
    fn additional_private_ca_bundle_builds_with_platform_trust() {
        let ca_path = temporary_path("ca");
        std::fs::write(&ca_path, include_bytes!("../../unf-agent/testdata/ca.crt"))
            .expect("write test CA bundle");
        let metrics = ExternalFlowExportMetrics::default();
        let result = build_external_flow_export(
            ExternalFlowExportConfig::new(
                "https://receiver.example/flows",
                false,
                Some(ca_path.clone()),
                None,
                1,
                1,
                Duration::from_secs(1),
            )
            .expect("valid private-CA configuration"),
            metrics,
        );
        std::fs::remove_file(ca_path).expect("remove test CA bundle");
        assert!(result.is_ok());
    }

    #[test]
    fn bounded_queue_drops_without_waiting_for_the_worker() {
        let metrics = ExternalFlowExportMetrics::default();
        let (exporter, _worker) = build_external_flow_export(
            ExternalFlowExportConfig::new(
                "http://127.0.0.1:9/flows",
                true,
                None,
                None,
                1,
                1,
                Duration::from_secs(1),
            )
            .expect("valid queue test config"),
            metrics.clone(),
        )
        .expect("build queue test exporter");
        exporter.enqueue(envelope(3));
        exporter.enqueue(envelope(5));
        assert_eq!(metrics.enqueued_batches.get(), 1);
        assert_eq!(metrics.queue_capacity.get(), 1);
        assert_eq!(metrics.queue_depth.get(), 1);
        assert_eq!(metrics.queue_high_watermark.get(), 1);
        assert_eq!(metrics.dropped_batches.get(), 1);
        assert_eq!(metrics.dropped_observations.get(), 5);
    }

    #[tokio::test]
    async fn delivery_retries_with_bearer_authentication() {
        let token_path = temporary_path("token");
        std::fs::write(&token_path, "secret\n").expect("write test bearer token");
        let (endpoint, receiver_state, receiver_task) =
            spawn_receiver(1, Some("Bearer secret".to_owned())).await;
        let metrics = ExternalFlowExportMetrics::default();
        let (exporter, worker) = build_external_flow_export(
            config(&endpoint, Some(token_path.clone())),
            metrics.clone(),
        )
        .expect("build test exporter");
        let cancellation = CancellationToken::new();
        let worker_task = tokio::spawn(worker.run(cancellation.clone()));
        exporter.enqueue(envelope(7));
        tokio::time::timeout(Duration::from_secs(2), async {
            while metrics.delivered_batches.get() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("flow export delivered after retry");
        assert_eq!(metrics.delivery_attempts.get(), 2);
        assert_eq!(metrics.delivery_errors.get(), 1);
        assert_eq!(metrics.delivered_observations.get(), 7);
        assert_eq!(metrics.queue_depth.get(), 0);
        assert!(metrics.queue_high_watermark.get() <= metrics.queue_capacity.get());
        assert_eq!(metrics.dropped_batches.get(), 0);
        assert_eq!(receiver_state.attempts.load(Ordering::Acquire), 2);
        {
            let received = receiver_state
                .envelopes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(received.len(), 2);
            assert_eq!(received[0], envelope(7));
        }
        cancellation.cancel();
        worker_task.await.expect("join test flow-export worker");
        receiver_task.abort();
        std::fs::remove_file(token_path).expect("remove test bearer token");
    }

    #[tokio::test]
    async fn concurrent_enqueue_preserves_published_sequence_order() {
        let (endpoint, receiver_state, receiver_task) = spawn_receiver(0, None).await;
        let metrics = ExternalFlowExportMetrics::default();
        let configuration = ExternalFlowExportConfig::new(
            &endpoint,
            true,
            None,
            None,
            64,
            1,
            Duration::from_secs(1),
        )
        .expect("valid concurrent queue test config")
        .with_retry_initial_delay(Duration::from_millis(1));
        let (exporter, worker) =
            build_external_flow_export(configuration, metrics.clone()).expect("build exporter");
        let cancellation = CancellationToken::new();
        let worker_task = tokio::spawn(worker.run(cancellation.clone()));

        let mut enqueue_tasks = Vec::new();
        for observed_events in 1..=32 {
            let exporter = exporter.clone();
            enqueue_tasks.push(tokio::spawn(async move {
                exporter.enqueue(envelope(observed_events));
            }));
        }
        for task in enqueue_tasks {
            task.await.expect("join concurrent enqueue task");
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while metrics.delivered_batches.get() != 32 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all concurrently enqueued flow exports delivered");

        let sequences = receiver_state
            .envelopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|received| received.export_sequence)
            .collect::<Vec<_>>();
        assert_eq!(sequences, (1..=32).collect::<Vec<_>>());
        assert_eq!(metrics.enqueued_batches.get(), 32);
        assert_eq!(metrics.dropped_batches.get(), 0);
        assert_eq!(metrics.queue_depth.get(), 0);
        assert!(metrics.queue_high_watermark.get() <= metrics.queue_capacity.get());

        cancellation.cancel();
        worker_task.await.expect("join test flow-export worker");
        receiver_task.abort();
    }
}
