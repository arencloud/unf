use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use unf_cni_state::{
    AttachmentKey, AttachmentPhase, AttachmentRecord, AttachmentSpec,
    CNI_TRANSACTION_SCHEMA_VERSION, MAX_TRANSACTION_MESSAGE_BYTES, TransactionErrorCode,
    TransactionOperation, TransactionOutcome, TransactionRequest, TransactionResponse,
};
use unf_link::{LinkReadback, VethPlan};
use unf_route::{NativeRoutePlan, NativeRoutingProvider, RoutingProvider};

use super::{
    AddResult, CniError, Command, InvocationEnvironment, NetworkConfig, ResultDns, ResultInterface,
    ResultIp, ResultRoute, Success,
};

const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MTU: u32 = 1_500;

/// Versioned request boundary used by the CNI lifecycle.
pub trait TransactionApi {
    /// Sends exactly one transaction request and returns its bounded response.
    ///
    /// # Errors
    ///
    /// Returns a transport or framing message when the local agent cannot serve
    /// the request. Protocol-level errors remain in `TransactionResponse`.
    fn transact(&mut self, request: TransactionRequest) -> Result<TransactionResponse, String>;
}

/// One-request-per-connection client for the root-authenticated agent socket.
pub struct SocketTransactionApi {
    path: PathBuf,
}

impl SocketTransactionApi {
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl TransactionApi for SocketTransactionApi {
    fn transact(&mut self, request: TransactionRequest) -> Result<TransactionResponse, String> {
        let mut stream = UnixStream::connect(&self.path)
            .map_err(|error| format!("connect to unf-agent {}: {error}", self.path.display()))?;
        stream
            .set_read_timeout(Some(TRANSACTION_TIMEOUT))
            .map_err(|error| format!("set agent response timeout: {error}"))?;
        stream
            .set_write_timeout(Some(TRANSACTION_TIMEOUT))
            .map_err(|error| format!("set agent request timeout: {error}"))?;
        let encoded = serde_json::to_vec(&request)
            .map_err(|error| format!("encode agent transaction request: {error}"))?;
        if encoded.len() > MAX_TRANSACTION_MESSAGE_BYTES {
            return Err("encoded agent request exceeds the transaction bound".to_owned());
        }
        stream
            .write_all(&encoded)
            .map_err(|error| format!("write agent transaction request: {error}"))?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| format!("finish agent transaction request: {error}"))?;

        let mut response = Vec::new();
        stream
            .take(u64::try_from(MAX_TRANSACTION_MESSAGE_BYTES).expect("message bound fits u64") + 1)
            .read_to_end(&mut response)
            .map_err(|error| format!("read agent transaction response: {error}"))?;
        if response.len() > MAX_TRANSACTION_MESSAGE_BYTES {
            return Err("agent response exceeds the transaction bound".to_owned());
        }
        serde_json::from_slice(&response)
            .map_err(|error| format!("decode agent transaction response: {error}"))
    }
}

/// Runs one validated lifecycle command with a supplied durable transaction API.
///
/// This is public so the privileged integration harness can exercise the same
/// production orchestration against a disposable journal.
///
/// # Errors
///
/// Returns a structured CNI error for transaction, kernel, replay, or readback
/// failure.
pub(crate) async fn execute_validated<T: TransactionApi>(
    environment: &InvocationEnvironment,
    config: &NetworkConfig,
    command: Command,
    transaction: &mut T,
) -> Result<Success, CniError> {
    match command {
        Command::Add => add(environment, config, transaction)
            .await
            .map(Success::Add),
        Command::Check => {
            check(environment, config, transaction).await?;
            Ok(Success::Empty)
        }
        Command::Delete => {
            delete(environment, config, transaction).await?;
            Ok(Success::Empty)
        }
        Command::Status => {
            operation(
                transaction,
                &config.cni_version,
                TransactionOperation::Status,
            )
            .map_err(|error| {
                CniError::new(
                    &config.cni_version,
                    50,
                    "Plugin not available",
                    error.details,
                )
            })?;
            Ok(Success::Empty)
        }
        Command::GarbageCollect => Ok(Success::Empty),
        Command::Version => unreachable!("VERSION is handled before lifecycle execution"),
    }
}

async fn add<T: TransactionApi>(
    environment: &InvocationEnvironment,
    config: &NetworkConfig,
    transaction: &mut T,
) -> Result<AddResult, CniError> {
    let spec = attachment_spec(environment, config)?;
    if let Some(record) = operation(
        transaction,
        &config.cni_version,
        TransactionOperation::Inspect {
            key: spec.key.clone(),
        },
    )? {
        ensure_spec(&record, &spec, &config.cni_version)?;
        match record.phase {
            AttachmentPhase::Ready => return verify_ready(config, &record).await,
            AttachmentPhase::Preparing => return finish_add(config, record, transaction).await,
            AttachmentPhase::Aborting => {
                recover_abort(config, &record, transaction).await?;
            }
            AttachmentPhase::Deleting => {
                return Err(CniError::retry_with_details(
                    &config.cni_version,
                    "attachment deletion is still in progress",
                ));
            }
        }
    }

    let record = require_attachment(
        operation(
            transaction,
            &config.cni_version,
            TransactionOperation::Prepare { attachment: spec },
        )?,
        &config.cni_version,
        "prepare",
    )?;
    finish_add(config, record, transaction).await
}

async fn finish_add<T: TransactionApi>(
    config: &NetworkConfig,
    record: AttachmentRecord,
    transaction: &mut T,
) -> Result<AddResult, CniError> {
    let links = match VethPlan::from_attachment(&record) {
        Ok(links) => links,
        Err(error) => {
            return Err(abort_without_resources(
                config,
                transaction,
                &record,
                format!("build veth plan: {error}"),
            ));
        }
    };
    let link_state = match links.apply().await {
        Ok(state) => state,
        Err(error) => {
            let cause = format!("apply veth: {error}");
            return Err(
                abort_after_link_failure(config, transaction, &record, &links, cause).await,
            );
        }
    };
    let routes = match route_plan(&record, &link_state, &config.cni_version) {
        Ok(routes) => routes,
        Err(error) => {
            return Err(abort_after_link_failure(
                config,
                transaction,
                &record,
                &links,
                format!("build native routing after link apply: {}", error.details),
            )
            .await);
        }
    };
    if let Err(error) = routes.apply().await {
        let cause = format!("apply native routing: {error}");
        return Err(
            abort_with_resources(config, transaction, &record, &links, &routes, cause).await,
        );
    }

    let committed = match operation(
        transaction,
        &config.cni_version,
        TransactionOperation::Commit {
            key: record.spec.key.clone(),
        },
    ) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Err(abort_with_resources(
                config,
                transaction,
                &record,
                &links,
                &routes,
                "agent commit returned no attachment".to_owned(),
            )
            .await);
        }
        Err(error) => {
            return Err(abort_with_resources(
                config,
                transaction,
                &record,
                &links,
                &routes,
                format!("commit durable attachment: {}", error.details),
            )
            .await);
        }
    };
    if committed.phase != AttachmentPhase::Ready {
        return Err(CniError::retry_with_details(
            &config.cni_version,
            format!(
                "agent commit returned unexpected phase {:?}",
                committed.phase
            ),
        ));
    }
    Ok(add_result(config, &committed, &link_state))
}

async fn check<T: TransactionApi>(
    environment: &InvocationEnvironment,
    config: &NetworkConfig,
    transaction: &mut T,
) -> Result<(), CniError> {
    let spec = attachment_spec(environment, config)?;
    let record = require_attachment(
        operation(
            transaction,
            &config.cni_version,
            TransactionOperation::Check { attachment: spec },
        )?,
        &config.cni_version,
        "check",
    )?;
    let actual = verify_ready(config, &record).await?;
    let mut expected = serde_json::to_value(&actual).map_err(|error| {
        CniError::io(format!(
            "encode expected CHECK result for comparison: {error}"
        ))
    })?;
    let mut supplied = config.prev_result.clone().ok_or_else(|| {
        CniError::invalid_config(&config.cni_version, "CHECK requires prevResult")
    })?;
    normalize_empty_dns(&mut expected);
    normalize_empty_dns(&mut supplied);
    if supplied != expected {
        return Err(CniError::retry_with_details(
            &config.cni_version,
            "CHECK prevResult differs from the durable and kernel attachment result",
        ));
    }
    Ok(())
}

// CNI runtimes are permitted to normalize an empty DNS result while caching
// ADD output. containerd removes `dns: {}` before constructing CHECK's
// prevResult, so treat those two representations as the same semantic result.
fn normalize_empty_dns(result: &mut Value) {
    let Some(object) = result.as_object_mut() else {
        return;
    };
    if object
        .get("dns")
        .is_some_and(|dns| dns.as_object().is_some_and(serde_json::Map::is_empty))
    {
        object.remove("dns");
    }
}

async fn delete<T: TransactionApi>(
    environment: &InvocationEnvironment,
    config: &NetworkConfig,
    transaction: &mut T,
) -> Result<(), CniError> {
    let key = attachment_key(environment, config)?;
    let Some(record) = operation(
        transaction,
        &config.cni_version,
        TransactionOperation::BeginDelete { key: key.clone() },
    )?
    else {
        return Ok(());
    };
    cleanup_record(config, &record).await?;
    operation(
        transaction,
        &config.cni_version,
        TransactionOperation::CompleteDelete { key },
    )?;
    Ok(())
}

async fn verify_ready(
    config: &NetworkConfig,
    record: &AttachmentRecord,
) -> Result<AddResult, CniError> {
    let links = VethPlan::from_attachment(record).map_err(|error| {
        CniError::retry_with_details(&config.cni_version, format!("build veth plan: {error}"))
    })?;
    let link_state = links.readback().await.map_err(|error| {
        CniError::retry_with_details(&config.cni_version, format!("read back veth: {error}"))
    })?;
    route_plan(record, &link_state, &config.cni_version)?
        .readback()
        .await
        .map_err(|error| {
            CniError::retry_with_details(
                &config.cni_version,
                format!("read back native routing: {error}"),
            )
        })?;
    Ok(add_result(config, record, &link_state))
}

async fn recover_abort<T: TransactionApi>(
    config: &NetworkConfig,
    record: &AttachmentRecord,
    transaction: &mut T,
) -> Result<(), CniError> {
    cleanup_record(config, record).await?;
    operation(
        transaction,
        &config.cni_version,
        TransactionOperation::CompleteAbort {
            key: record.spec.key.clone(),
        },
    )?;
    Ok(())
}

async fn cleanup_record(config: &NetworkConfig, record: &AttachmentRecord) -> Result<(), CniError> {
    let links = VethPlan::from_attachment(record).map_err(|error| {
        CniError::retry_with_details(&config.cni_version, format!("build cleanup plan: {error}"))
    })?;
    let link_state = links.cleanup_readback().await.map_err(|error| {
        CniError::retry_with_details(
            &config.cni_version,
            format!("read link ownership for cleanup: {error}"),
        )
    })?;
    NativeRoutingProvider::new(record.spec.mtu)
        .cleanup_plan(record, &link_state)
        .map_err(|error| {
            CniError::retry_with_details(
                &config.cni_version,
                format!("build native route cleanup plan: {error}"),
            )
        })?
        .delete()
        .await
        .map_err(|error| {
            CniError::retry_with_details(
                &config.cni_version,
                format!("delete native routing: {error}"),
            )
        })?;
    links.delete().await.map_err(|error| {
        CniError::retry_with_details(&config.cni_version, format!("delete veth: {error}"))
    })?;
    Ok(())
}

async fn abort_after_link_failure<T: TransactionApi>(
    config: &NetworkConfig,
    transaction: &mut T,
    record: &AttachmentRecord,
    links: &VethPlan,
    cause: String,
) -> CniError {
    if let Err(error) = begin_abort(config, transaction, record) {
        return combined_rollback(config, &cause, &error.details);
    }
    if let Err(error) = links.delete().await {
        return combined_rollback(config, &cause, &format!("delete veth: {error}"));
    }
    if let Err(error) = complete_abort(config, transaction, record) {
        return combined_rollback(config, &cause, &error.details);
    }
    CniError::retry_with_details(&config.cni_version, cause)
}

fn abort_without_resources<T: TransactionApi>(
    config: &NetworkConfig,
    transaction: &mut T,
    record: &AttachmentRecord,
    cause: String,
) -> CniError {
    if let Err(error) = begin_abort(config, transaction, record) {
        return combined_rollback(config, &cause, &error.details);
    }
    if let Err(error) = complete_abort(config, transaction, record) {
        return combined_rollback(config, &cause, &error.details);
    }
    CniError::retry_with_details(&config.cni_version, cause)
}

async fn abort_with_resources<T: TransactionApi>(
    config: &NetworkConfig,
    transaction: &mut T,
    record: &AttachmentRecord,
    links: &VethPlan,
    routes: &NativeRoutePlan,
    cause: String,
) -> CniError {
    if let Err(error) = begin_abort(config, transaction, record) {
        return combined_rollback(config, &cause, &error.details);
    }
    if let Err(error) = routes.delete().await {
        return combined_rollback(config, &cause, &format!("delete native routing: {error}"));
    }
    if let Err(error) = links.delete().await {
        return combined_rollback(config, &cause, &format!("delete veth: {error}"));
    }
    if let Err(error) = complete_abort(config, transaction, record) {
        return combined_rollback(config, &cause, &error.details);
    }
    CniError::retry_with_details(&config.cni_version, cause)
}

fn begin_abort<T: TransactionApi>(
    config: &NetworkConfig,
    transaction: &mut T,
    record: &AttachmentRecord,
) -> Result<(), CniError> {
    operation(
        transaction,
        &config.cni_version,
        TransactionOperation::BeginAbort {
            key: record.spec.key.clone(),
        },
    )?;
    Ok(())
}

fn complete_abort<T: TransactionApi>(
    config: &NetworkConfig,
    transaction: &mut T,
    record: &AttachmentRecord,
) -> Result<(), CniError> {
    operation(
        transaction,
        &config.cni_version,
        TransactionOperation::CompleteAbort {
            key: record.spec.key.clone(),
        },
    )?;
    Ok(())
}

fn route_plan(
    record: &AttachmentRecord,
    links: &LinkReadback,
    version: &str,
) -> Result<NativeRoutePlan, CniError> {
    NativeRoutingProvider::new(record.spec.mtu)
        .plan(record, links)
        .map_err(|error| {
            CniError::retry_with_details(version, format!("build native route plan: {error}"))
        })
}

fn operation<T: TransactionApi>(
    transaction: &mut T,
    version: &str,
    operation: TransactionOperation,
) -> Result<Option<AttachmentRecord>, CniError> {
    let response = transaction
        .transact(TransactionRequest::new(
            CNI_TRANSACTION_SCHEMA_VERSION,
            operation,
        ))
        .map_err(|error| {
            CniError::retry_with_details(version, format!("unf-agent transaction failed: {error}"))
        })?;
    if response.schema_version != CNI_TRANSACTION_SCHEMA_VERSION {
        return Err(CniError::retry_with_details(
            version,
            format!(
                "unf-agent returned transaction schema {}, expected {}",
                response.schema_version, CNI_TRANSACTION_SCHEMA_VERSION
            ),
        ));
    }
    match response.outcome {
        TransactionOutcome::Ok { attachment, .. } => Ok(attachment),
        TransactionOutcome::Error { code, message } => {
            Err(transaction_error(version, code, &message))
        }
    }
}

fn transaction_error(version: &str, code: TransactionErrorCode, message: &str) -> CniError {
    match code {
        TransactionErrorCode::InvalidRequest => CniError::invalid_config(
            version,
            format!("unf-agent rejected the request: {message}"),
        ),
        TransactionErrorCode::IncompatibleSchema => CniError::new(
            version,
            1,
            "Incompatible CNI version",
            format!("unf-agent transaction schema is incompatible: {message}"),
        ),
        TransactionErrorCode::Unauthorized => CniError::new(
            version,
            50,
            "Plugin not available",
            format!("unf-agent rejected CNI credentials: {message}"),
        ),
        TransactionErrorCode::NotFound
        | TransactionErrorCode::Conflict
        | TransactionErrorCode::InvalidTransition
        | TransactionErrorCode::PersistenceFailure
        | TransactionErrorCode::Exhausted => CniError::retry_with_details(
            version,
            format!("unf-agent transaction {code:?}: {message}"),
        ),
    }
}

fn attachment_spec(
    environment: &InvocationEnvironment,
    config: &NetworkConfig,
) -> Result<AttachmentSpec, CniError> {
    Ok(AttachmentSpec {
        key: attachment_key(environment, config)?,
        netns: environment
            .netns
            .clone()
            .ok_or_else(|| CniError::invalid_environment("CNI_NETNS is required".to_owned()))?,
        mtu: config.mtu.unwrap_or(DEFAULT_MTU),
    })
}

fn attachment_key(
    environment: &InvocationEnvironment,
    config: &NetworkConfig,
) -> Result<AttachmentKey, CniError> {
    Ok(AttachmentKey {
        network: config.name.clone(),
        container_id: environment.container_id.clone().ok_or_else(|| {
            CniError::invalid_environment("CNI_CONTAINERID is required".to_owned())
        })?,
        ifname: environment
            .ifname
            .clone()
            .ok_or_else(|| CniError::invalid_environment("CNI_IFNAME is required".to_owned()))?,
    })
}

fn require_attachment(
    record: Option<AttachmentRecord>,
    version: &str,
    operation: &str,
) -> Result<AttachmentRecord, CniError> {
    record.ok_or_else(|| {
        CniError::retry_with_details(
            version,
            format!("unf-agent {operation} returned no attachment"),
        )
    })
}

fn ensure_spec(
    record: &AttachmentRecord,
    spec: &AttachmentSpec,
    version: &str,
) -> Result<(), CniError> {
    if record.spec == *spec {
        Ok(())
    } else {
        Err(CniError::retry_with_details(
            version,
            "durable attachment conflicts with the requested namespace or MTU",
        ))
    }
}

fn add_result(
    config: &NetworkConfig,
    record: &AttachmentRecord,
    links: &LinkReadback,
) -> AddResult {
    AddResult {
        cni_version: config.cni_version.clone(),
        interfaces: vec![
            ResultInterface {
                name: links.host_name.clone(),
                mac: format_mac(links.host_address),
                sandbox: None,
            },
            ResultInterface {
                name: links.peer_name.clone(),
                mac: format_mac(links.peer_address),
                sandbox: Some(record.spec.netns.clone()),
            },
        ],
        ips: vec![
            ResultIp {
                interface: 1,
                address: format!("{}/32", record.lease.ipv4.address),
                gateway: record.lease.ipv4.gateway.to_string(),
            },
            ResultIp {
                interface: 1,
                address: format!("{}/128", record.lease.ipv6.address),
                gateway: record.lease.ipv6.gateway.to_string(),
            },
        ],
        routes: vec![
            ResultRoute {
                dst: "0.0.0.0/0".to_owned(),
                gw: record.lease.ipv4.gateway.to_string(),
            },
            ResultRoute {
                dst: "::/0".to_owned(),
                gw: record.lease.ipv6.gateway.to_string(),
            },
        ],
        dns: ResultDns::default(),
    }
}

fn format_mac(address: [u8; 6]) -> String {
    address.map(|byte| format!("{byte:02x}")).join(":")
}

fn combined_rollback(config: &NetworkConfig, cause: &str, rollback: &str) -> CniError {
    CniError::retry_with_details(
        &config.cni_version,
        format!("{cause}; rollback remains pending: {rollback}"),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::net::UnixListener;

    use super::*;

    struct Responses(VecDeque<Result<TransactionResponse, String>>);

    impl TransactionApi for Responses {
        fn transact(
            &mut self,
            _request: TransactionRequest,
        ) -> Result<TransactionResponse, String> {
            self.0.pop_front().expect("prepared response")
        }
    }

    #[test]
    fn transaction_transport_and_protocol_fail_closed() {
        let mut transport = Responses(VecDeque::from([Err("offline".to_owned())]));
        let error = operation(&mut transport, "1.1.0", TransactionOperation::Status)
            .expect_err("offline agent must fail");
        assert_eq!(error.code, 11);

        let mut incompatible = Responses(VecDeque::from([Ok(TransactionResponse {
            schema_version: 1,
            outcome: TransactionOutcome::Ok {
                attachment: None,
                attachment_count: 0,
            },
        })]));
        assert!(operation(&mut incompatible, "1.1.0", TransactionOperation::Status).is_err());
    }

    #[test]
    fn add_result_is_dual_stack_and_binds_ips_to_the_container_interface() {
        let record = AttachmentRecord {
            spec: AttachmentSpec {
                key: AttachmentKey {
                    network: "unf-test".to_owned(),
                    container_id: "container-1".to_owned(),
                    ifname: "eth0".to_owned(),
                },
                netns: "/run/netns/pod-1".to_owned(),
                mtu: 1_400,
            },
            host_interface: "unf123".to_owned(),
            lease: unf_ipam::DualStackLease {
                ipv4: unf_ipam::Ipv4Lease {
                    address: "10.42.0.2".parse().unwrap(),
                    gateway: "10.42.0.1".parse().unwrap(),
                    prefix_len: 24,
                },
                ipv6: unf_ipam::Ipv6Lease {
                    address: "fd00:42::2".parse().unwrap(),
                    gateway: "fd00:42::1".parse().unwrap(),
                    prefix_len: 120,
                },
            },
            phase: AttachmentPhase::Ready,
        };
        let links = LinkReadback {
            host_index: 4,
            peer_index: 2,
            host_name: "unf123".to_owned(),
            peer_name: "eth0".to_owned(),
            host_address: [2, 0, 0, 0, 0, 1],
            peer_address: [2, 0, 0, 0, 0, 2],
            mtu: 1_400,
            addresses: std::collections::BTreeSet::new(),
        };
        let config: NetworkConfig = serde_json::from_str(
            r#"{"cniVersion":"1.1.0","name":"unf-test","type":"unf","mtu":1400,"ipam":{"type":"unf"}}"#,
        )
        .unwrap();
        let result = add_result(&config, &record, &links);
        assert_eq!(result.ips.len(), 2);
        assert!(result.ips.iter().all(|ip| ip.interface == 1));
        assert_eq!(result.routes[1].dst, "::/0");
        assert_eq!(result.interfaces[0].mac, "02:00:00:00:00:01");
    }

    #[test]
    fn check_result_normalizes_runtime_omission_of_empty_dns() {
        let mut emitted = serde_json::json!({
            "cniVersion": "1.1.0",
            "interfaces": [],
            "ips": [],
            "routes": [],
            "dns": {}
        });
        let mut cached = serde_json::json!({
            "cniVersion": "1.1.0",
            "interfaces": [],
            "ips": [],
            "routes": []
        });

        normalize_empty_dns(&mut emitted);
        normalize_empty_dns(&mut cached);

        assert_eq!(emitted, cached);
    }

    #[test]
    fn socket_client_uses_one_bounded_request_response_connection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = Vec::new();
            stream.read_to_end(&mut input).unwrap();
            let request: TransactionRequest = serde_json::from_slice(&input).unwrap();
            assert_eq!(
                request,
                TransactionRequest::new(
                    CNI_TRANSACTION_SCHEMA_VERSION,
                    TransactionOperation::Status,
                )
            );
            serde_json::to_writer(
                &mut stream,
                &TransactionResponse {
                    schema_version: CNI_TRANSACTION_SCHEMA_VERSION,
                    outcome: TransactionOutcome::Ok {
                        attachment: None,
                        attachment_count: 0,
                    },
                },
            )
            .unwrap();
        });
        let mut client = SocketTransactionApi::new(path);
        let response = client
            .transact(TransactionRequest::new(
                CNI_TRANSACTION_SCHEMA_VERSION,
                TransactionOperation::Status,
            ))
            .unwrap();
        assert!(matches!(response.outcome, TransactionOutcome::Ok { .. }));
        server.join().unwrap();
    }
}
