use std::env;

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod lifecycle;

pub use lifecycle::{SocketTransactionApi, TransactionApi};

pub const MAX_CONFIG_BYTES: usize = 1_048_576;
pub const CURRENT_CNI_VERSION: &str = "1.1.0";
pub const SUPPORTED_CNI_VERSIONS: [&str; 2] = ["1.0.0", CURRENT_CNI_VERSION];

const DEFAULT_AGENT_SOCKET: &str = "/run/unf/cni.sock";
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Add,
    Delete,
    Check,
    Status,
    GarbageCollect,
    Version,
}

impl Command {
    fn parse(value: Option<&str>) -> Result<Self, CniError> {
        match value {
            Some("ADD") => Ok(Self::Add),
            Some("DEL") => Ok(Self::Delete),
            Some("CHECK") => Ok(Self::Check),
            Some("STATUS") => Ok(Self::Status),
            Some("GC") => Ok(Self::GarbageCollect),
            Some("VERSION") => Ok(Self::Version),
            Some(other) => Err(CniError::invalid_environment(format!(
                "CNI_COMMAND has unsupported value {other:?}"
            ))),
            None => Err(CniError::invalid_environment(
                "CNI_COMMAND is required".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InvocationEnvironment {
    pub command: Option<String>,
    pub container_id: Option<String>,
    pub netns: Option<String>,
    pub ifname: Option<String>,
    pub args: Option<String>,
    pub path: Option<String>,
}

impl InvocationEnvironment {
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            command: env::var("CNI_COMMAND").ok(),
            container_id: env::var("CNI_CONTAINERID").ok(),
            netns: env::var("CNI_NETNS").ok(),
            ifname: env::var("CNI_IFNAME").ok(),
            args: env::var("CNI_ARGS").ok(),
            path: env::var("CNI_PATH").ok(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkConfig {
    cni_version: String,
    name: String,
    #[serde(rename = "type")]
    plugin_type: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    dataplane: Option<String>,
    #[serde(default)]
    agent_socket: Option<String>,
    #[serde(default)]
    mtu: Option<u32>,
    ipam: IpamConfig,
    #[serde(default)]
    prev_result: Option<Value>,
    #[serde(default, rename = "cni.dev/valid-attachments")]
    valid_attachments: Vec<ValidAttachment>,
}

#[derive(Clone, Debug, Deserialize)]
struct IpamConfig {
    #[serde(rename = "type")]
    plugin_type: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidAttachment {
    container_id: String,
    ifname: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionRequest {
    cni_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionResponse {
    pub cni_version: String,
    pub supported_versions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CniError {
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
    pub details: String,
}

impl CniError {
    #[must_use]
    pub fn io(details: impl Into<String>) -> Self {
        Self::new(CURRENT_CNI_VERSION, 5, "I/O failure", details)
    }

    #[must_use]
    pub fn oversized_config(actual_bytes: usize) -> Self {
        Self::new(
            CURRENT_CNI_VERSION,
            7,
            "Invalid network config",
            format!("configuration is {actual_bytes} bytes; maximum is {MAX_CONFIG_BYTES} bytes"),
        )
    }

    fn new(
        cni_version: impl Into<String>,
        code: u32,
        msg: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            cni_version: cni_version.into(),
            code,
            msg: msg.into(),
            details: details.into(),
        }
    }

    fn invalid_environment(details: String) -> Self {
        Self::new(
            CURRENT_CNI_VERSION,
            4,
            "Invalid necessary environment variables",
            details,
        )
    }

    fn decode(details: impl Into<String>) -> Self {
        Self::new(CURRENT_CNI_VERSION, 6, "Failed to decode content", details)
    }

    fn invalid_config(version: &str, details: impl Into<String>) -> Self {
        Self::new(version, 7, "Invalid network config", details)
    }

    fn incompatible_version(version: &str) -> Self {
        Self::new(
            version,
            1,
            "Incompatible CNI version",
            format!(
                "supported versions are {}",
                SUPPORTED_CNI_VERSIONS.join(", ")
            ),
        )
    }

    fn retry_with_details(version: &str, details: impl Into<String>) -> Self {
        Self::new(version, 11, "Try again later", details)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Success {
    Empty,
    Add(AddResult),
    Version(VersionResponse),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddResult {
    pub cni_version: String,
    pub interfaces: Vec<ResultInterface>,
    pub ips: Vec<ResultIp>,
    pub routes: Vec<ResultRoute>,
    pub dns: ResultDns,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultInterface {
    pub name: String,
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultIp {
    pub interface: usize,
    pub address: String,
    pub gateway: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultRoute {
    pub dst: String,
    pub gw: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ResultDns {}

/// Validates and executes one bounded CNI invocation.
///
/// # Errors
///
/// Returns a structured CNI error when the command, environment, configuration,
/// version, or currently available lifecycle capability is invalid.
pub fn execute(environment: &InvocationEnvironment, input: &[u8]) -> Result<Success, CniError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(CniError::oversized_config(input.len()));
    }

    let command = Command::parse(environment.command.as_deref())?;
    if command == Command::Version {
        let request: VersionRequest = serde_json::from_slice(input)
            .map_err(|error| CniError::decode(format!("invalid VERSION input: {error}")))?;
        return Ok(Success::Version(VersionResponse {
            cni_version: request.cni_version,
            supported_versions: SUPPORTED_CNI_VERSIONS
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }));
    }

    let config: NetworkConfig = serde_json::from_slice(input)
        .map_err(|error| CniError::decode(format!("invalid network config JSON: {error}")))?;
    validate_config(&config, command)?;
    validate_environment(environment, command, &config.cni_version)?;

    let socket = config
        .agent_socket
        .as_deref()
        .unwrap_or(DEFAULT_AGENT_SOCKET);
    let mut transaction = SocketTransactionApi::new(socket.into());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| CniError::io(format!("create CNI lifecycle runtime: {error}")))?;
    runtime.block_on(lifecycle::execute_validated(
        environment,
        &config,
        command,
        &mut transaction,
    ))
}

/// Validates and runs one invocation through a supplied durable transaction API.
///
/// The privileged integration harness uses this boundary with a disposable
/// journal; the production executable uses the root-authenticated Unix client.
///
/// # Errors
///
/// Returns the same structured CNI errors as [`execute`].
pub async fn execute_with_transaction<T: TransactionApi>(
    environment: &InvocationEnvironment,
    input: &[u8],
    transaction: &mut T,
) -> Result<Success, CniError> {
    if input.len() > MAX_CONFIG_BYTES {
        return Err(CniError::oversized_config(input.len()));
    }
    let command = Command::parse(environment.command.as_deref())?;
    if command == Command::Version {
        let request: VersionRequest = serde_json::from_slice(input)
            .map_err(|error| CniError::decode(format!("invalid VERSION input: {error}")))?;
        return Ok(Success::Version(VersionResponse {
            cni_version: request.cni_version,
            supported_versions: SUPPORTED_CNI_VERSIONS
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }));
    }
    let config: NetworkConfig = serde_json::from_slice(input)
        .map_err(|error| CniError::decode(format!("invalid network config JSON: {error}")))?;
    validate_config(&config, command)?;
    validate_environment(environment, command, &config.cni_version)?;
    lifecycle::execute_validated(environment, &config, command, transaction).await
}

fn validate_config(config: &NetworkConfig, command: Command) -> Result<(), CniError> {
    if !SUPPORTED_CNI_VERSIONS.contains(&config.cni_version.as_str()) {
        return Err(CniError::incompatible_version(&config.cni_version));
    }
    if matches!(command, Command::Status | Command::GarbageCollect)
        && config.cni_version != CURRENT_CNI_VERSION
    {
        return Err(CniError::invalid_config(
            &config.cni_version,
            format!("{command:?} requires CNI {CURRENT_CNI_VERSION}"),
        ));
    }
    if !valid_identifier(&config.name) {
        return Err(CniError::invalid_config(
            &config.cni_version,
            "name must be a non-empty CNI identifier",
        ));
    }
    if config.plugin_type != "unf" {
        return Err(CniError::invalid_config(
            &config.cni_version,
            "type must be \"unf\"",
        ));
    }
    if config.mode.as_deref().unwrap_or("primary") != "primary" {
        return Err(CniError::invalid_config(
            &config.cni_version,
            "only explicit primary-interface ownership is supported",
        ));
    }
    if config.dataplane.as_deref().unwrap_or("veth") != "veth" {
        return Err(CniError::invalid_config(
            &config.cni_version,
            "only the portable veth dataplane is accepted; netkit remains gated",
        ));
    }
    if config.ipam.plugin_type != "unf" {
        return Err(CniError::invalid_config(
            &config.cni_version,
            "ipam.type must be \"unf\"",
        ));
    }

    let socket = config
        .agent_socket
        .as_deref()
        .unwrap_or(DEFAULT_AGENT_SOCKET);
    if !socket.starts_with('/') || socket.as_bytes().contains(&0) {
        return Err(CniError::invalid_config(
            &config.cni_version,
            "agentSocket must be an absolute path without NUL bytes",
        ));
    }
    if socket.len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(CniError::invalid_config(
            &config.cni_version,
            format!("agentSocket exceeds {MAX_UNIX_SOCKET_PATH_BYTES} bytes"),
        ));
    }
    if let Some(mtu) = config.mtu
        && !(1280..=65_535).contains(&mtu)
    {
        return Err(CniError::invalid_config(
            &config.cni_version,
            "mtu must be between the IPv6 minimum 1280 and 65535",
        ));
    }
    if command == Command::Check && config.prev_result.is_none() {
        return Err(CniError::invalid_config(
            &config.cni_version,
            "CHECK requires prevResult",
        ));
    }
    if command == Command::GarbageCollect {
        for attachment in &config.valid_attachments {
            if !valid_identifier(&attachment.container_id)
                || !valid_interface_name(&attachment.ifname)
            {
                return Err(CniError::invalid_config(
                    &config.cni_version,
                    "cni.dev/valid-attachments contains an invalid containerID or ifname",
                ));
            }
        }
    }
    Ok(())
}

fn validate_environment(
    environment: &InvocationEnvironment,
    command: Command,
    version: &str,
) -> Result<(), CniError> {
    let mut invalid = Vec::new();
    if matches!(command, Command::Add | Command::Delete | Command::Check)
        && !environment
            .container_id
            .as_deref()
            .is_some_and(valid_identifier)
    {
        invalid.push("CNI_CONTAINERID");
    }
    if matches!(command, Command::Add | Command::Check)
        && !environment.netns.as_deref().is_some_and(valid_netns)
    {
        invalid.push("CNI_NETNS");
    }
    if matches!(command, Command::Add | Command::Delete | Command::Check)
        && !environment
            .ifname
            .as_deref()
            .is_some_and(valid_interface_name)
    {
        invalid.push("CNI_IFNAME");
    }
    if command == Command::GarbageCollect && environment.path.as_deref().is_none_or(str::is_empty) {
        invalid.push("CNI_PATH");
    }
    if invalid.is_empty() {
        return Ok(());
    }
    Err(CniError::new(
        version,
        4,
        "Invalid necessary environment variables",
        format!("invalid or missing: {}", invalid.join(", ")),
    ))
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn valid_netns(value: &str) -> bool {
    value.starts_with('/') && !value.as_bytes().contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(command: &str) -> InvocationEnvironment {
        InvocationEnvironment {
            command: Some(command.to_owned()),
            container_id: Some("container-1".to_owned()),
            netns: Some("/run/netns/pod-1".to_owned()),
            ifname: Some("eth0".to_owned()),
            args: None,
            path: Some("/opt/cni/bin".to_owned()),
        }
    }

    fn config(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"cniVersion":"1.1.0","name":"unf-test","type":"unf","ipam":{{"type":"unf"}}{extra}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn version_reports_only_supported_modern_spec_versions() {
        let result = execute(
            &InvocationEnvironment {
                command: Some("VERSION".to_owned()),
                ..InvocationEnvironment::default()
            },
            br#"{"cniVersion":"1.1.0"}"#,
        )
        .expect("VERSION should succeed");
        assert_eq!(
            result,
            Success::Version(VersionResponse {
                cni_version: "1.1.0".to_owned(),
                supported_versions: vec!["1.0.0".to_owned(), "1.1.0".to_owned()],
            })
        );
    }

    #[test]
    fn add_is_validated_then_fails_closed_until_agent_is_available() {
        let error = execute(&environment("ADD"), &config("")).expect_err("ADD is gated");
        assert_eq!(error.code, 11);
        assert!(error.details.contains("unf-agent"));
    }

    #[test]
    fn delete_fails_retryably_when_durable_ownership_is_unavailable() {
        let mut invocation = environment("DEL");
        invocation.netns = None;
        let error = execute(&invocation, &config(""))
            .expect_err("DEL cannot release ownership while its journal is unavailable");
        assert_eq!(error.code, 11);
    }

    #[test]
    fn check_requires_the_runtime_add_result() {
        let error = execute(&environment("CHECK"), &config(""))
            .expect_err("CHECK without prevResult must fail");
        assert_eq!(error.code, 7);
        assert!(error.details.contains("prevResult"));
    }

    #[test]
    fn status_reports_not_available_until_agent_readiness_is_connected() {
        let error = execute(&environment("STATUS"), &config(""))
            .expect_err("STATUS must not claim readiness");
        assert_eq!(error.code, 50);
    }

    #[test]
    fn netkit_and_small_dual_stack_mtu_are_rejected() {
        let netkit = execute(&environment("ADD"), &config(r#","dataplane":"netkit""#))
            .expect_err("netkit remains gated");
        assert_eq!(netkit.code, 7);

        let mtu = execute(&environment("ADD"), &config(r#","mtu":1279"#))
            .expect_err("IPv6 requires at least 1280 bytes");
        assert_eq!(mtu.code, 7);
    }

    #[test]
    fn invalid_environment_names_every_missing_add_parameter() {
        let error = execute(
            &InvocationEnvironment {
                command: Some("ADD".to_owned()),
                ..InvocationEnvironment::default()
            },
            &config(""),
        )
        .expect_err("missing ADD environment must fail");
        assert_eq!(error.code, 4);
        assert!(error.details.contains("CNI_CONTAINERID"));
        assert!(error.details.contains("CNI_NETNS"));
        assert!(error.details.contains("CNI_IFNAME"));
    }

    #[test]
    fn unsupported_versions_and_oversized_input_are_bounded() {
        let old = br#"{"cniVersion":"0.4.0","name":"unf-test","type":"unf","ipam":{"type":"unf"}}"#;
        let version = execute(&environment("ADD"), old).expect_err("old version must fail");
        assert_eq!(version.code, 1);

        let oversized = vec![b' '; MAX_CONFIG_BYTES + 1];
        let size = execute(&environment("ADD"), &oversized).expect_err("input is bounded");
        assert_eq!(size.code, 7);
    }

    #[test]
    fn status_and_gc_require_cni_1_1() {
        let version_1_0 =
            br#"{"cniVersion":"1.0.0","name":"unf-test","type":"unf","ipam":{"type":"unf"}}"#;
        for command in ["STATUS", "GC"] {
            let error = execute(&environment(command), version_1_0)
                .expect_err("modern operations require CNI 1.1");
            assert_eq!(error.code, 7);
            assert!(error.details.contains("1.1.0"));
        }
    }
}
