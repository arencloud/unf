use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::Value;
use unf_state::{FlowHistorySnapshot, analyze_shadow_impact};

#[derive(Debug, Parser)]
#[command(about = "Inspect, explain, simulate, and analyze the UNF network fabric")]
struct Cli {
    #[arg(
        long,
        env = "UNF_CONTROLLER_URL",
        default_value = "http://127.0.0.1:9962"
    )]
    controller_url: String,
    #[arg(long, global = true, value_enum, default_value = "table")]
    output: Output,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show controller health and state revisions.
    Status,
    /// Show the current versioned Node, workload, and Service topology.
    Topology,
    /// Show bounded historical topology revisions.
    TopologyHistory {
        /// Restrict to snapshots captured within this duration.
        #[arg(long, value_parser = parse_duration_millis, conflicts_with = "since_unix_ms")]
        last: Option<u64>,
        /// Inclusive lower topology revision bound.
        #[arg(long)]
        since_revision: Option<u64>,
        /// Inclusive upper topology revision bound.
        #[arg(long)]
        until_revision: Option<u64>,
        /// Inclusive lower snapshot-capture timestamp bound.
        #[arg(long)]
        since_unix_ms: Option<u64>,
        /// Inclusive upper snapshot-capture timestamp bound.
        #[arg(long)]
        until_unix_ms: Option<u64>,
        /// Maximum number of newest matching snapshots to return.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show bounded flow history exported by node agents.
    Flows {
        /// Restrict to flows last received within this duration (for example 15m or 2h).
        #[arg(long, value_parser = parse_duration_millis, conflicts_with = "since_unix_ms")]
        last: Option<u64>,
        /// Inclusive lower bound for the last-received timestamp.
        #[arg(long)]
        since_unix_ms: Option<u64>,
        /// Inclusive upper bound for the last-received timestamp.
        #[arg(long)]
        until_unix_ms: Option<u64>,
        /// Maximum number of newest matching flows to return.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Correlate a Service/backend with current intent and observed dataplane outcomes.
    ServiceExplain {
        /// Stable service ID reported by agent status, flow history, or metrics.
        #[arg(long)]
        service_id: u32,
        /// Optional stable backend ID to narrow the explanation.
        #[arg(long)]
        backend_id: Option<u32>,
        /// Restrict outcomes to one service frontend class.
        #[arg(long, value_enum)]
        frontend_kind: Option<ServiceFrontend>,
        /// Restrict outcomes to this recent duration (for example 15m or 2h).
        #[arg(long, value_parser = parse_duration_millis, conflicts_with = "since_unix_ms")]
        last: Option<u64>,
        /// Inclusive lower bound for the outcome timestamp.
        #[arg(long)]
        since_unix_ms: Option<u64>,
        /// Inclusive upper bound for the outcome timestamp.
        #[arg(long)]
        until_unix_ms: Option<u64>,
        /// Maximum number of newest matching outcomes to return.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Predict a `ClusterIP` outcome from the current digest-bound per-Node selection contract.
    ClusterIpSimulate {
        /// Receiving Node name.
        #[arg(long)]
        node: String,
        /// Exact `ClusterIP` address.
        #[arg(long)]
        address: IpAddr,
        /// Service frontend port.
        #[arg(long)]
        port: u16,
        /// Transport protocol.
        #[arg(long, value_enum, default_value = "tcp")]
        protocol: NodePortProtocol,
    },
    /// Predict a `NodePort` outcome from current validated Service and Node state.
    ServiceSimulate {
        /// Receiving Node name.
        #[arg(long)]
        node: String,
        /// Exact admitted Node address.
        #[arg(long)]
        address: IpAddr,
        /// `NodePort` number.
        #[arg(long)]
        port: u16,
        /// Transport protocol.
        #[arg(long, value_enum, default_value = "tcp")]
        protocol: NodePortProtocol,
    },
    /// Predict a `LoadBalancer` VIP outcome from current allocation, reachability, and Service state.
    LoadBalancerSimulate {
        /// Receiving Node name.
        #[arg(long)]
        node: String,
        /// Exact allocated VIP.
        #[arg(long)]
        address: IpAddr,
        /// External client address used for source-range evaluation.
        #[arg(long)]
        source_address: IpAddr,
        /// Service port exposed by the VIP.
        #[arg(long)]
        port: u16,
        /// Transport protocol.
        #[arg(long, value_enum, default_value = "tcp")]
        protocol: NodePortProtocol,
    },
    /// Explain a policy decision using live controller state.
    Explain {
        /// Source pod as namespace/name.
        #[arg(long)]
        from: String,
        /// Destination pod as namespace/name.
        #[arg(long)]
        to: String,
        /// Policy isolation direction to evaluate.
        #[arg(long, value_enum, default_value = "ingress")]
        direction: Direction,
        /// Concrete Pod address family to use; defaults to IPv4 when both Pods have it.
        #[arg(long, value_enum)]
        ip_family: Option<IpFamily>,
        #[arg(long, value_enum, default_value = "tcp")]
        protocol: Protocol,
        #[arg(long)]
        port: u16,
    },
    /// Inspect policy intent without changing live desired state.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Compare a candidate `SecurityPolicy` or `NetworkPolicy` with live state.
    Simulate {
        /// Policy YAML file to evaluate without applying.
        policy_file: PathBuf,
        /// Restrict historical impact to flows last received within this duration.
        #[arg(long, value_parser = parse_duration_millis, conflicts_with = "since_unix_ms")]
        last: Option<u64>,
        /// Inclusive historical lower bound for the last-received timestamp.
        #[arg(long)]
        since_unix_ms: Option<u64>,
        /// Inclusive historical upper bound for the last-received timestamp.
        #[arg(long)]
        until_unix_ms: Option<u64>,
        /// Maximum number of newest matching historical flows to evaluate.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Summarize recorded shadow decisions from live or saved flow history.
    ShadowImpact {
        /// Analyze a saved JSON/YAML flow-history snapshot without contacting a controller.
        #[arg(
            long,
            conflicts_with_all = ["last", "since_unix_ms", "until_unix_ms", "limit"]
        )]
        flows_file: Option<PathBuf>,
        /// Restrict live history to flows last received within this duration.
        #[arg(long, value_parser = parse_duration_millis, conflicts_with = "since_unix_ms")]
        last: Option<u64>,
        /// Inclusive lower bound for live history's last-received timestamp.
        #[arg(long)]
        since_unix_ms: Option<u64>,
        /// Inclusive upper bound for live history's last-received timestamp.
        #[arg(long)]
        until_unix_ms: Option<u64>,
        /// Maximum number of newest matching live flows to analyze.
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Output {
    Table,
    Json,
    Yaml,
}

#[derive(Debug, Clone, Copy, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NodePortProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ServiceFrontend {
    ClusterIp,
    NodePortCluster,
    NodePortLocal,
    LoadBalancerCluster,
    LoadBalancerLocal,
}

impl ServiceFrontend {
    const fn query_value(self) -> &'static str {
        match self {
            Self::ClusterIp => "cluster_ip",
            Self::NodePortCluster => "node_port_cluster",
            Self::NodePortLocal => "node_port_local",
            Self::LoadBalancerCluster => "load_balancer_cluster",
            Self::LoadBalancerLocal => "load_balancer_local",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum Direction {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, Copy, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Serialize)]
struct ExplainRequest<'a> {
    from: &'a str,
    to: &'a str,
    direction: Direction,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_family: Option<IpFamily>,
    protocol: Protocol,
    port: u16,
}

#[derive(Debug, Serialize)]
struct PolicySimulationRequest<'a> {
    policy: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow_history: Option<PolicySimulationFlowHistoryQuery>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct PolicySimulationFlowHistoryQuery {
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();
    let value = match &cli.command {
        Command::Status => get_json(&client, &format!("{}/v1/status", cli.controller_url)).await?,
        Command::Topology => {
            get_json(&client, &format!("{}/v1/topology", cli.controller_url)).await?
        }
        Command::TopologyHistory {
            last,
            since_revision,
            until_revision,
            since_unix_ms,
            until_unix_ms,
            limit,
        } => {
            topology_history_value(
                &client,
                &cli.controller_url,
                *last,
                *since_revision,
                *until_revision,
                *since_unix_ms,
                *until_unix_ms,
                *limit,
            )
            .await?
        }
        Command::Flows {
            last,
            since_unix_ms,
            until_unix_ms,
            limit,
        } => {
            flow_history_value(
                &client,
                &cli.controller_url,
                *last,
                *since_unix_ms,
                *until_unix_ms,
                *limit,
            )
            .await?
        }
        Command::ServiceExplain {
            service_id,
            backend_id,
            frontend_kind,
            last,
            since_unix_ms,
            until_unix_ms,
            limit,
        } => {
            let (since_unix_ms, until_unix_ms) =
                resolve_time_window(*last, *since_unix_ms, *until_unix_ms, unix_time_millis()?)?;
            get_json(
                &client,
                &service_explanation_url(
                    &cli.controller_url,
                    *service_id,
                    *backend_id,
                    *frontend_kind,
                    since_unix_ms,
                    until_unix_ms,
                    *limit,
                ),
            )
            .await?
        }
        Command::ServiceSimulate {
            node,
            address,
            port,
            protocol,
        } => {
            if *port == 0 {
                bail!("port must be between 1 and 65535");
            }
            get_json(
                &client,
                &node_port_simulation_url(&cli.controller_url, node, *address, *port, *protocol),
            )
            .await?
        }
        Command::ClusterIpSimulate {
            node,
            address,
            port,
            protocol,
        } => {
            if *port == 0 {
                bail!("port must be between 1 and 65535");
            }
            get_json(
                &client,
                &cluster_ip_simulation_url(&cli.controller_url, node, *address, *port, *protocol),
            )
            .await?
        }
        Command::LoadBalancerSimulate {
            node,
            address,
            source_address,
            port,
            protocol,
        } => {
            if *port == 0 {
                bail!("port must be between 1 and 65535");
            }
            get_json(
                &client,
                &load_balancer_simulation_url(
                    &cli.controller_url,
                    node,
                    *address,
                    *source_address,
                    *port,
                    *protocol,
                ),
            )
            .await?
        }
        Command::Explain {
            from,
            to,
            direction,
            ip_family,
            protocol,
            port,
        } => {
            explanation_value(
                &client,
                &cli.controller_url,
                from,
                to,
                *direction,
                *ip_family,
                *protocol,
                *port,
            )
            .await?
        }
        Command::Policy {
            command:
                PolicyCommand::Simulate {
                    policy_file,
                    last,
                    since_unix_ms,
                    until_unix_ms,
                    limit,
                },
        } => {
            policy_simulation_value(
                &client,
                &cli.controller_url,
                policy_file,
                *last,
                *since_unix_ms,
                *until_unix_ms,
                *limit,
            )
            .await?
        }
        Command::Policy {
            command:
                PolicyCommand::ShadowImpact {
                    flows_file,
                    last,
                    since_unix_ms,
                    until_unix_ms,
                    limit,
                },
        } => {
            shadow_impact_value(
                &client,
                &cli.controller_url,
                flows_file.as_ref(),
                *last,
                *since_unix_ms,
                *until_unix_ms,
                *limit,
            )
            .await?
        }
    };
    print_value(&value, cli.output)
}

async fn flow_history_value(
    client: &reqwest::Client,
    controller_url: &str,
    last: Option<u64>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
) -> Result<Value> {
    let (since_unix_ms, until_unix_ms) =
        resolve_time_window(last, since_unix_ms, until_unix_ms, unix_time_millis()?)?;
    get_json(
        client,
        &flow_history_url(controller_url, since_unix_ms, until_unix_ms, limit),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn explanation_value(
    client: &reqwest::Client,
    controller_url: &str,
    from: &str,
    to: &str,
    direction: Direction,
    ip_family: Option<IpFamily>,
    protocol: Protocol,
    port: u16,
) -> Result<Value> {
    if port == 0 {
        bail!("port must be between 1 and 65535");
    }
    post_json(
        client,
        &format!("{controller_url}/v1/explain"),
        &ExplainRequest {
            from,
            to,
            direction,
            ip_family,
            protocol,
            port,
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn topology_history_value(
    client: &reqwest::Client,
    controller_url: &str,
    last: Option<u64>,
    since_revision: Option<u64>,
    until_revision: Option<u64>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
) -> Result<Value> {
    let (since_unix_ms, until_unix_ms) =
        resolve_time_window(last, since_unix_ms, until_unix_ms, unix_time_millis()?)?;
    get_json(
        client,
        &topology_history_url(
            controller_url,
            since_revision,
            until_revision,
            since_unix_ms,
            until_unix_ms,
            limit,
        ),
    )
    .await
}

async fn policy_simulation_value(
    client: &reqwest::Client,
    controller_url: &str,
    policy_file: &PathBuf,
    last: Option<u64>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
) -> Result<Value> {
    let contents = std::fs::read_to_string(policy_file)
        .with_context(|| format!("read policy file {}", policy_file.display()))?;
    let policy: Value = serde_yaml::from_str(&contents)
        .with_context(|| format!("parse policy YAML {}", policy_file.display()))?;
    let flow_history = policy_simulation_flow_history(
        last,
        since_unix_ms,
        until_unix_ms,
        limit,
        unix_time_millis()?,
    )?;
    post_json(
        client,
        &format!("{controller_url}/v1/policy/simulate"),
        &PolicySimulationRequest {
            policy: &policy,
            flow_history,
        },
    )
    .await
}

async fn shadow_impact_value(
    client: &reqwest::Client,
    controller_url: &str,
    flows_file: Option<&PathBuf>,
    last: Option<u64>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
) -> Result<Value> {
    let (snapshot, analysis_source) = if let Some(path) = flows_file {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("read flow-history file {}", path.display()))?;
        let snapshot = serde_yaml::from_str::<FlowHistorySnapshot>(&contents)
            .with_context(|| format!("parse flow-history file {}", path.display()))?;
        (snapshot, format!("offline:{}", path.display()))
    } else {
        let (since_unix_ms, until_unix_ms) =
            resolve_time_window(last, since_unix_ms, until_unix_ms, unix_time_millis()?)?;
        let value = get_json(
            client,
            &flow_history_url(controller_url, since_unix_ms, until_unix_ms, limit),
        )
        .await?;
        let snapshot = serde_json::from_value::<FlowHistorySnapshot>(value)
            .context("decode live flow-history snapshot")?;
        (snapshot, format!("live:{controller_url}"))
    };
    serde_json::to_value(
        analyze_shadow_impact(&snapshot, analysis_source).context("analyze shadow impact")?,
    )
    .context("serialize shadow-impact report")
}

async fn get_json(client: &reqwest::Client, url: &str) -> Result<Value> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("connect to UNF controller at {url}"))?;
    decode_response(response).await
}

async fn post_json<T: Serialize>(client: &reqwest::Client, url: &str, body: &T) -> Result<Value> {
    let response = client
        .post(url)
        .json(body)
        .send()
        .await
        .with_context(|| format!("connect to UNF controller at {url}"))?;
    decode_response(response).await
}

async fn decode_response(response: reqwest::Response) -> Result<Value> {
    let status = response.status();
    let value: Value = response
        .json()
        .await
        .context("decode controller response")?;
    if status != StatusCode::OK {
        bail!(
            "controller returned {status}: {}",
            value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
        );
    }
    Ok(value)
}

fn print_value(value: &Value, output: Output) -> Result<()> {
    match output {
        Output::Json => println!("{}", serde_json::to_string_pretty(value)?),
        Output::Yaml => print!("{}", serde_yaml::to_string(value)?),
        Output::Table => print_table(value),
    }
    Ok(())
}

fn print_table(value: &Value) {
    if value.get("current_service").is_some() && value.get("outcomes").is_some() {
        print_service_explanation_table(value);
        return;
    }
    if value.get("component").and_then(Value::as_str) == Some("unf-controller")
        && value.get("agents").is_some()
    {
        print_controller_status_table(value);
        return;
    }
    if matches!(
        value.get("schema_version").and_then(Value::as_u64),
        Some(1..=6)
    ) && value.get("retained_flows").is_some()
        && value.get("entries").is_some()
    {
        print_flow_history_table(value);
        return;
    }
    if value.get("schema_version").and_then(Value::as_u64) == Some(1)
        && value.get("retained_snapshots").is_some()
        && value.get("entries").is_some()
    {
        print_topology_history_table(value);
        return;
    }
    if matches!(
        value.get("schema_version").and_then(Value::as_u64),
        Some(1..=3)
    ) && value.get("nodes").is_some()
        && value.get("workloads").is_some()
        && value.get("services").is_some()
    {
        print_topology_table(value);
        return;
    }
    if value.get("summary").is_some() && value.get("operation").is_some() {
        print_simulation_table(value);
        return;
    }
    if value.get("frontend_kind").is_some()
        && value.get("traffic_policy").is_some()
        && value.get("decision").is_some()
    {
        if value.get("source_address").is_some() {
            print_load_balancer_simulation_table(value);
        } else {
            print_node_port_simulation_table(value);
        }
        return;
    }
    if value.get("analysis").and_then(Value::as_str) == Some("shadow_impact") {
        print_shadow_impact_table(value);
        return;
    }
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            let rendered = match value {
                Value::String(text) => text.clone(),
                _ => value.to_string(),
            };
            println!("{key:24} {rendered}");
        }
    } else {
        println!("{value}");
    }
}

fn print_service_explanation_table(value: &Value) {
    println!("Service Explanation");
    println!(
        "service                  id={} backend={} current_revision={}",
        number_field(value, "service_id"),
        optional_number_field(value, "backend_id"),
        optional_number_field(value, "current_service_revision")
    );
    if let Some(service) = value
        .get("current_service")
        .filter(|value| !value.is_null())
    {
        println!(
            "intent                   {}/{} frontends={} backends={}",
            text_field(service, "namespace"),
            text_field(service, "name"),
            service["frontends"].as_array().map_or(0, Vec::len),
            service["backends"].as_array().map_or(0, Vec::len)
        );
    } else {
        println!("intent                   not present in current compiled revision");
    }
    if let Some(load_balancer) = value.get("load_balancer").filter(|value| !value.is_null()) {
        println!(
            "loadbalancer             allocation_revision={} reachability_revision={} provider={} reachable_nodes={} converged_nodes={}",
            optional_number_field(load_balancer, "allocation_revision"),
            optional_number_field(load_balancer, "reachability_revision"),
            load_balancer
                .get("provider")
                .map_or_else(|| "-".to_owned(), Value::to_string),
            load_balancer["reachable_nodes"]
                .as_array()
                .map_or(0, Vec::len),
            load_balancer["converged_nodes"]
                .as_array()
                .map_or(0, Vec::len)
        );
    }
    println!(
        "evidence                 outcomes={} observations={}",
        number_field(value, "matched_outcomes"),
        number_field(value, "matched_observations")
    );
    if let Some(outcomes) = value.get("outcomes").and_then(Value::as_array) {
        for entry in outcomes.iter().take(50) {
            let key = &entry["key"];
            let service = &entry["service"];
            println!(
                "outcome                  kind={} {} -> {} {}/{} action={} reason={} backend={} observations={} nodes={}",
                text_field(service, "frontend_kind"),
                flow_address(key, "source_ipv4", "source_ipv6"),
                flow_address(key, "destination_ipv4", "destination_ipv6"),
                protocol_label(number_field(key, "protocol")),
                number_field(key, "destination_port"),
                service_action_label(number_field(service, "action")),
                service_reason_label(number_field(service, "reason")),
                optional_number_field(service, "backend_id"),
                number_field(entry, "observed_events"),
                joined_strings(&entry["reporting_nodes"])
            );
        }
    }
}

fn print_node_port_simulation_table(value: &Value) {
    println!("NodePort Simulation");
    println!(
        "frontend                 node={} address={}:{} protocol={} kind={} policy={}",
        text_field(value, "node_name"),
        text_field(value, "address"),
        number_field(value, "port"),
        text_field(value, "protocol"),
        text_field(value, "frontend_kind"),
        text_field(value, "traffic_policy")
    );
    println!(
        "service                  {}/{} id={} revision={}",
        text_field(value, "namespace"),
        text_field(value, "name"),
        number_field(value, "service_id"),
        number_field(value, "service_revision")
    );
    println!(
        "prediction               decision={} source_preserved={} eligible_backends={}",
        text_field(value, "decision"),
        value
            .get("source_preserved")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        value["eligible_backend_ids"].as_array().map_or(0, Vec::len)
    );
}

fn print_load_balancer_simulation_table(value: &Value) {
    println!("LoadBalancer Simulation");
    println!(
        "frontend                 node={} vip={}:{} protocol={} kind={} policy={}",
        text_field(value, "node_name"),
        text_field(value, "address"),
        number_field(value, "port"),
        text_field(value, "protocol"),
        text_field(value, "frontend_kind"),
        text_field(value, "traffic_policy")
    );
    println!(
        "provenance               service_revision={} reachability_revision={} allocation_revision={} provider={}",
        number_field(value, "service_revision"),
        number_field(value, "reachability_revision"),
        number_field(value, "allocation_revision"),
        value
            .get("provider")
            .map_or_else(|| "-".to_owned(), Value::to_string)
    );
    println!(
        "prediction               source={} allowed={} decision={} source_preserved={} eligible_backends={}",
        text_field(value, "source_address"),
        value
            .get("source_allowed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        text_field(value, "decision"),
        value
            .get("source_preserved")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        value["eligible_backend_ids"].as_array().map_or(0, Vec::len)
    );
}

fn flow_address<'value>(value: &'value Value, ipv4: &str, ipv6: &str) -> &'value str {
    value
        .get(ipv4)
        .and_then(Value::as_str)
        .or_else(|| value.get(ipv6).and_then(Value::as_str))
        .unwrap_or("-")
}

const fn service_action_label(action: u64) -> &'static str {
    match action {
        1 => "translate",
        2 => "drop",
        3 => "expire",
        _ => "unknown",
    }
}

const fn service_reason_label(reason: u64) -> &'static str {
    match reason {
        1 => "forward-translated",
        2 => "reverse-translated",
        3 => "no-backend",
        4 => "invalid-frontend",
        5 => "missing-slot",
        6 => "invalid-slot",
        7 => "missing-backend",
        8 => "invalid-backend",
        9 => "pair-insert-failed",
        10 => "rewrite-failed",
        11 => "expired-or-corrupt",
        12 => "source-range-denied",
        _ => "unknown",
    }
}

fn print_shadow_impact_table(value: &Value) {
    let summary = &value["summary"];
    println!("Shadow Impact");
    println!(
        "source                   {} history_schema={} revision={} epoch={}",
        text_field(value, "analysis_source"),
        number_field(value, "flow_history_schema_version"),
        number_field(value, "flow_history_revision"),
        number_field(value, "source_epoch")
    );
    println!(
        "selected                 flows={} observations={}",
        number_field(summary, "selected_flows"),
        number_field(summary, "selected_observations")
    );
    println!(
        "shadowed                 flows={} observations={} policies={}",
        number_field(summary, "shadowed_flows"),
        number_field(summary, "shadowed_observations"),
        joined_numbers(&value["shadow_policy_ids"])
    );
    println!(
        "would deny              flows={} observations={}",
        number_field(summary, "would_deny_flows"),
        number_field(summary, "would_deny_observations")
    );
    println!(
        "would allow             flows={} observations={}",
        number_field(summary, "would_allow_flows"),
        number_field(summary, "would_allow_observations")
    );
    println!(
        "decision changes        flows={} observations={} workloads={}",
        number_field(summary, "decision_change_flows"),
        number_field(summary, "decision_change_observations"),
        number_field(summary, "affected_workloads")
    );
    if let Some(changes) = value.get("changes").and_then(Value::as_array) {
        for change in changes.iter().take(50) {
            let flow = &change["flow"];
            let key = &flow["key"];
            let sources = joined_strings(&flow["source_workloads"]);
            let destinations = joined_strings(&flow["destination_workloads"]);
            println!(
                "impact                   {} {} -> {} {}/{} actual={} shadow={} observations={}",
                text_field(change, "classification"),
                if sources.is_empty() {
                    identity_label(key, "source_identity")
                } else {
                    sources
                },
                if destinations.is_empty() {
                    identity_label(key, "destination_identity")
                } else {
                    destinations
                },
                protocol_label(number_field(key, "protocol")),
                number_field(key, "destination_port"),
                text_field(&flow["decision"], "verdict"),
                text_field(&flow["shadow"], "verdict"),
                number_field(flow, "observed_events")
            );
        }
        if changes.len() > 50 {
            println!("impacts omitted          {}", changes.len() - 50);
        }
    }
    println!("note                     {}", text_field(value, "note"));
}

fn print_controller_status_table(value: &Value) {
    println!("Controller Status");
    println!(
        "control plane            ready={} mode={} epoch={}",
        value.get("ready").and_then(Value::as_bool).unwrap_or(false),
        text_field(value, "mode"),
        number_field(value, "identity_epoch")
    );
    let revisions = &value["revisions"];
    println!(
        "revisions                identity={} policy={} routing={} topology={} telemetry={}",
        number_field(revisions, "identity"),
        number_field(revisions, "policy"),
        number_field(revisions, "routing"),
        number_field(revisions, "topology"),
        number_field(revisions, "telemetry")
    );
    println!(
        "objects                  nodes={} pods={} identities={} policies={}",
        number_field(value, "nodes"),
        number_field(value, "pods"),
        number_field(value, "identities"),
        number_field(value, "compiled_policies")
    );
    println!(
        "primary CNI              assigned_nodes={} invalid_blocks={} invalid_transports={}",
        number_field(value, "assigned_node_blocks"),
        number_field(value, "rejected_node_blocks"),
        number_field(value, "unroutable_node_transports")
    );
    let agents = &value["agents"];
    println!(
        "agents                   converged={}/{} reporting={} missing={} stale={} unexpected={} all_converged={}",
        number_field(agents, "converged_agents"),
        number_field(agents, "expected_agents"),
        number_field(agents, "reporting_agents"),
        number_field(agents, "missing_agents"),
        number_field(agents, "stale_agents"),
        number_field(agents, "unexpected_agents"),
        agents
            .get("all_converged")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    if let Some(nodes) = agents.get("nodes").and_then(Value::as_array) {
        for node in nodes {
            let report = &node["report"];
            println!(
                "agent                    {} fresh={} converged={} identity={}/{} policy={}/{} bank={} block={}/{} routes={}:{} / {}:{} entries={} errors={}",
                text_field(node, "node_name"),
                node.get("fresh").and_then(Value::as_bool).unwrap_or(false),
                node.get("converged")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                number_field(report, "applied_identity_revision"),
                number_field(report, "desired_identity_revision"),
                number_field(report, "applied_policy_revision"),
                number_field(report, "desired_policy_revision"),
                number_field(report, "active_policy_bank"),
                number_field(report, "applied_node_block_revision"),
                number_field(report, "desired_node_block_revision"),
                number_field(report, "applied_remote_route_epoch"),
                number_field(report, "applied_remote_route_revision"),
                number_field(report, "desired_remote_route_epoch"),
                number_field(report, "desired_remote_route_revision"),
                number_field(report, "remote_route_entries"),
                number_field(report, "remote_route_reconcile_errors")
            );
            println!(
                "  NodePort               desired={} applied={} cluster={} local={} translations={}/{} no_backend_drops={}",
                number_field(report, "desired_node_port_frontend_count"),
                number_field(report, "applied_node_port_frontend_count"),
                number_field(report, "node_port_cluster_frontend_count"),
                number_field(report, "node_port_local_frontend_count"),
                number_field(report, "node_port_cluster_translations"),
                number_field(report, "node_port_local_translations"),
                number_field(report, "node_port_no_backend_drops")
            );
            println!(
                "  LoadBalancer           revision={}/{} allocation={}/{} frontends={}:{}+{} ranges={} health={}/{} translations={}/{} no_backend_drops={} source_range_drops={} errors={}",
                number_field(report, "applied_load_balancer_revision"),
                number_field(report, "desired_load_balancer_revision"),
                number_field(report, "applied_load_balancer_allocation_revision"),
                number_field(report, "desired_load_balancer_allocation_revision"),
                number_field(report, "load_balancer_frontend_count"),
                number_field(report, "load_balancer_cluster_frontend_count"),
                number_field(report, "load_balancer_local_frontend_count"),
                number_field(report, "load_balancer_source_range_count"),
                number_field(report, "load_balancer_health_check_ready_count"),
                number_field(report, "load_balancer_health_check_count"),
                number_field(report, "load_balancer_cluster_translations"),
                number_field(report, "load_balancer_local_translations"),
                number_field(report, "load_balancer_no_backend_drops"),
                number_field(report, "load_balancer_source_range_drops"),
                number_field(report, "load_balancer_reconcile_errors")
            );
        }
    }
}

fn print_flow_history_table(value: &Value) {
    println!("Flow History");
    println!(
        "snapshot                 revision={} epoch={}",
        number_field(value, "revision"),
        number_field(value, "source_epoch")
    );
    println!(
        "retention                flows={}/{} observations={} evicted={} agent_dropped={}",
        number_field(value, "retained_flows"),
        number_field(value, "capacity"),
        number_field(value, "retained_observations"),
        number_field(value, "evicted_observations"),
        number_field(value, "agent_dropped_events")
    );
    println!(
        "durability               checkpointed={} omitted_flows={} omitted_observations={}",
        number_field(value, "durable_checkpointed_flows"),
        number_field(value, "durable_omitted_flows"),
        number_field(value, "durable_omitted_observations")
    );
    if let Some(query) = value.get("query") {
        println!(
            "query                    since={} until={} matched={} observations={} returned={} truncated={}",
            optional_number_field(query, "since_unix_ms"),
            optional_number_field(query, "until_unix_ms"),
            number_field(query, "matched_flows"),
            number_field(query, "matched_observations"),
            number_field(query, "returned_flows"),
            query
                .get("truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        );
    }
    if let Some(entries) = value.get("entries").and_then(Value::as_array) {
        for entry in entries.iter().take(50) {
            let key = &entry["key"];
            let sources = joined_strings(&entry["source_workloads"]);
            let destinations = joined_strings(&entry["destination_workloads"]);
            if let Some(service) = entry.get("service").filter(|value| !value.is_null()) {
                println!(
                    "service outcome          id={} kind={} {} -> {} {}/{} action={} reason={} backend={} observations={} nodes={}",
                    number_field(service, "service_id"),
                    text_field(service, "frontend_kind"),
                    flow_address(key, "source_ipv4", "source_ipv6"),
                    flow_address(key, "destination_ipv4", "destination_ipv6"),
                    protocol_label(number_field(key, "protocol")),
                    number_field(key, "destination_port"),
                    service_action_label(number_field(service, "action")),
                    service_reason_label(number_field(service, "reason")),
                    optional_number_field(service, "backend_id"),
                    number_field(entry, "observed_events"),
                    joined_strings(&entry["reporting_nodes"]),
                );
                continue;
            }
            println!(
                "flow                     {} -> {} {}/{} verdict={} observations={} nodes={}",
                if sources.is_empty() {
                    identity_label(key, "source_identity")
                } else {
                    sources
                },
                if destinations.is_empty() {
                    identity_label(key, "destination_identity")
                } else {
                    destinations
                },
                protocol_label(number_field(key, "protocol")),
                number_field(key, "destination_port"),
                text_field(&entry["decision"], "verdict"),
                number_field(entry, "observed_events"),
                joined_strings(&entry["reporting_nodes"]),
            );
        }
        if entries.len() > 50 {
            println!("flows omitted            {}", entries.len() - 50);
        }
    }
}

fn print_topology_history_table(value: &Value) {
    println!("Topology History");
    println!(
        "retention                snapshots={}/{} evicted={} checkpointed={} omitted={}",
        number_field(value, "retained_snapshots"),
        number_field(value, "capacity"),
        number_field(value, "evicted_snapshots"),
        number_field(value, "durable_checkpointed_snapshots"),
        number_field(value, "durable_omitted_snapshots")
    );
    let query = &value["query"];
    println!(
        "query                    revisions={}..{} time={}..{} matched={} returned={} truncated={}",
        optional_number_field(query, "since_revision"),
        optional_number_field(query, "until_revision"),
        optional_number_field(query, "since_unix_ms"),
        optional_number_field(query, "until_unix_ms"),
        number_field(query, "matched_snapshots"),
        number_field(query, "returned_snapshots"),
        query
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    if let Some(entries) = value.get("entries").and_then(Value::as_array) {
        for entry in entries.iter().take(50) {
            let snapshot = &entry["snapshot"];
            println!(
                "snapshot                 revision={} captured={} epoch={} identity={} nodes={} workloads={} services={}",
                number_field(snapshot, "revision"),
                number_field(entry, "captured_at_unix_ms"),
                number_field(snapshot, "source_epoch"),
                number_field(snapshot, "identity_revision"),
                snapshot["nodes"].as_array().map_or(0, Vec::len),
                snapshot["workloads"].as_array().map_or(0, Vec::len),
                snapshot["services"].as_array().map_or(0, Vec::len)
            );
        }
        if entries.len() > 50 {
            println!("snapshots omitted        {}", entries.len() - 50);
        }
    }
}

fn optional_number_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_u64)
        .map_or_else(|| "-".to_owned(), |number| number.to_string())
}

fn parse_duration_millis(value: &str) -> Result<u64, String> {
    let (digits, multiplier) = if let Some(digits) = value.strip_suffix("ms") {
        (digits, 1_u64)
    } else if let Some(digits) = value.strip_suffix('s') {
        (digits, 1_000)
    } else if let Some(digits) = value.strip_suffix('m') {
        (digits, 60_000)
    } else if let Some(digits) = value.strip_suffix('h') {
        (digits, 3_600_000)
    } else if let Some(digits) = value.strip_suffix('d') {
        (digits, 86_400_000)
    } else {
        return Err("duration must use ms, s, m, h, or d suffix".to_owned());
    };
    let amount = digits
        .parse::<u64>()
        .map_err(|_| "duration must start with a positive integer".to_owned())?;
    if amount == 0 {
        return Err("duration must be greater than zero".to_owned());
    }
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_owned())
}

fn unix_time_millis() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_millis(),
    )
    .context("Unix time does not fit in u64 milliseconds")
}

fn resolve_time_window(
    last_millis: Option<u64>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    now_unix_ms: u64,
) -> Result<(Option<u64>, Option<u64>)> {
    let until = until_unix_ms.or(last_millis.map(|_| now_unix_ms));
    let since = if let Some(duration) = last_millis {
        Some(
            until
                .unwrap_or(now_unix_ms)
                .checked_sub(duration)
                .context("flow-history duration starts before the Unix epoch")?,
        )
    } else {
        since_unix_ms
    };
    if since.zip(until).is_some_and(|(start, end)| start > end) {
        bail!("flow-history start must not exceed its end");
    }
    Ok((since, until))
}

fn policy_simulation_flow_history(
    last_millis: Option<u64>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
    now_unix_ms: u64,
) -> Result<Option<PolicySimulationFlowHistoryQuery>> {
    let (since_unix_ms, until_unix_ms) =
        resolve_time_window(last_millis, since_unix_ms, until_unix_ms, now_unix_ms)?;
    if since_unix_ms.is_none() && until_unix_ms.is_none() && limit.is_none() {
        return Ok(None);
    }
    Ok(Some(PolicySimulationFlowHistoryQuery {
        since_unix_ms,
        until_unix_ms,
        limit,
    }))
}

fn flow_history_url(
    controller_url: &str,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
) -> String {
    let mut parameters = Vec::new();
    if let Some(value) = since_unix_ms {
        parameters.push(format!("since_unix_ms={value}"));
    }
    if let Some(value) = until_unix_ms {
        parameters.push(format!("until_unix_ms={value}"));
    }
    if let Some(value) = limit {
        parameters.push(format!("limit={value}"));
    }
    let base = format!("{controller_url}/v1/flows");
    if parameters.is_empty() {
        base
    } else {
        format!("{base}?{}", parameters.join("&"))
    }
}

#[allow(clippy::too_many_arguments)]
fn service_explanation_url(
    controller_url: &str,
    service_id: u32,
    backend_id: Option<u32>,
    frontend_kind: Option<ServiceFrontend>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
) -> String {
    let mut parameters = vec![format!("service_id={service_id}")];
    if let Some(frontend_kind) = frontend_kind {
        parameters.push(format!("frontend_kind={}", frontend_kind.query_value()));
    }
    for (name, value) in [
        ("backend_id", backend_id.map(u64::from)),
        ("since_unix_ms", since_unix_ms),
        ("until_unix_ms", until_unix_ms),
        ("limit", limit.map(|value| value as u64)),
    ] {
        if let Some(value) = value {
            parameters.push(format!("{name}={value}"));
        }
    }
    format!(
        "{controller_url}/v1/services/explain?{}",
        parameters.join("&")
    )
}

fn node_port_simulation_url(
    controller_url: &str,
    node: &str,
    address: IpAddr,
    port: u16,
    protocol: NodePortProtocol,
) -> String {
    let protocol = match protocol {
        NodePortProtocol::Tcp => "tcp",
        NodePortProtocol::Udp => "udp",
    };
    format!(
        "{controller_url}/v1/services/nodeport/simulate?node_name={node}&address={address}&port={port}&protocol={protocol}"
    )
}

fn cluster_ip_simulation_url(
    controller_url: &str,
    node: &str,
    address: IpAddr,
    port: u16,
    protocol: NodePortProtocol,
) -> String {
    let protocol = match protocol {
        NodePortProtocol::Tcp => "tcp",
        NodePortProtocol::Udp => "udp",
    };
    format!(
        "{controller_url}/v1/services/clusterip/simulate?node_name={node}&address={address}&port={port}&protocol={protocol}"
    )
}

fn load_balancer_simulation_url(
    controller_url: &str,
    node: &str,
    address: IpAddr,
    source_address: IpAddr,
    port: u16,
    protocol: NodePortProtocol,
) -> String {
    let protocol = match protocol {
        NodePortProtocol::Tcp => "tcp",
        NodePortProtocol::Udp => "udp",
    };
    format!(
        "{controller_url}/v1/services/loadbalancer/simulate?node_name={node}&address={address}&source_address={source_address}&port={port}&protocol={protocol}"
    )
}

#[allow(clippy::too_many_arguments)]
fn topology_history_url(
    controller_url: &str,
    since_revision: Option<u64>,
    until_revision: Option<u64>,
    since_unix_ms: Option<u64>,
    until_unix_ms: Option<u64>,
    limit: Option<usize>,
) -> String {
    let mut parameters = Vec::new();
    for (name, value) in [
        ("since_revision", since_revision),
        ("until_revision", until_revision),
        ("since_unix_ms", since_unix_ms),
        ("until_unix_ms", until_unix_ms),
        ("limit", limit.map(|value| value as u64)),
    ] {
        if let Some(value) = value {
            parameters.push(format!("{name}={value}"));
        }
    }
    let base = format!("{controller_url}/v1/topology/history");
    if parameters.is_empty() {
        base
    } else {
        format!("{base}?{}", parameters.join("&"))
    }
}

fn joined_strings(value: &Value) -> String {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default()
}

fn joined_numbers(value: &Value) -> String {
    value
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_u64)
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| "-".to_owned())
}

fn identity_label(value: &Value, field: &str) -> String {
    format!("identity:{}", number_field(value, field))
}

const fn protocol_label(protocol: u64) -> &'static str {
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        132 => "sctp",
        _ => "unknown",
    }
}

fn print_topology_table(value: &Value) {
    let nodes = value["nodes"].as_array().map_or(&[][..], Vec::as_slice);
    let workloads = value["workloads"].as_array().map_or(&[][..], Vec::as_slice);
    let services = value["services"].as_array().map_or(&[][..], Vec::as_slice);
    println!("Topology");
    println!(
        "snapshot                 topology={} identity={} epoch={}",
        number_field(value, "revision"),
        number_field(value, "identity_revision"),
        number_field(value, "source_epoch")
    );
    println!(
        "objects                  nodes={} workloads={} services={}",
        nodes.len(),
        workloads.len(),
        services.len()
    );
    for node in nodes {
        println!(
            "node                     {} ready={}",
            text_field(node, "name"),
            node["ready"].as_bool().unwrap_or(false)
        );
    }
    for workload in workloads {
        let ipv4_addresses = joined_strings(&workload["ipv4_addresses"]);
        let ipv6_addresses = joined_strings(&workload["ipv6_addresses"]);
        println!(
            "workload                 {} node={} identity={} ipv4={} ipv6={}",
            text_field(workload, "reference"),
            workload["node_name"].as_str().unwrap_or("unassigned"),
            number_field(workload, "identity_id"),
            if ipv4_addresses.is_empty() {
                "-"
            } else {
                &ipv4_addresses
            },
            if ipv6_addresses.is_empty() {
                "-"
            } else {
                &ipv6_addresses
            }
        );
    }
    for service in services {
        let selected = service["selected_workloads"]
            .as_array()
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let backends = service["backends"]
            .as_array()
            .map_or(&[][..], Vec::as_slice);
        let ready_backends = backends
            .iter()
            .filter(|backend| {
                backend["ready"].as_bool().unwrap_or(false)
                    && !backend["terminating"].as_bool().unwrap_or(false)
            })
            .count();
        println!(
            "service                  {} type={} selected={} ready_backends={}/{}",
            text_field(service, "reference"),
            text_field(service, "service_type"),
            if selected.is_empty() { "-" } else { &selected },
            ready_backends,
            backends.len()
        );
        for backend in backends {
            println!(
                "backend                  service={} workload={} addresses={} ready={} serving={} terminating={} node={} zone={}",
                text_field(service, "reference"),
                backend["target_workload"].as_str().unwrap_or("-"),
                joined_strings(&backend["addresses"]),
                backend["ready"].as_bool().unwrap_or(false),
                backend["serving"].as_bool().unwrap_or(false),
                backend["terminating"].as_bool().unwrap_or(false),
                backend["node_name"].as_str().unwrap_or("-"),
                backend["zone"].as_str().unwrap_or("-")
            );
        }
    }
}

fn print_simulation_table(value: &Value) {
    let summary = &value["summary"];
    let snapshot = &value["snapshot"];
    println!("Policy Simulation");
    println!(
        "policy                   {} {} ({})",
        text_field(value, "resource_kind"),
        text_field(value, "policy"),
        text_field(value, "operation")
    );
    println!(
        "snapshot                 identity={} policy={} topology={} history={} epoch={}",
        number_field(snapshot, "identity_revision"),
        number_field(snapshot, "policy_revision"),
        number_field(snapshot, "topology_revision"),
        number_field(snapshot, "flow_history_revision"),
        number_field(snapshot, "identity_epoch")
    );
    println!(
        "flow source              {}",
        text_field(snapshot, "flow_source")
    );
    println!(
        "evaluated flows          {}",
        number_field(summary, "evaluated_flows")
    );
    println!(
        "remain allowed           {}",
        number_field(summary, "remain_allowed")
    );
    println!(
        "remain denied            {}",
        number_field(summary, "remain_denied")
    );
    println!(
        "would be allowed         {}",
        number_field(summary, "would_be_allowed")
    );
    println!(
        "would be denied          {}",
        number_field(summary, "would_be_denied")
    );
    println!(
        "decision changes         {}",
        number_field(summary, "decision_changes")
    );
    println!(
        "verdict changes          {}",
        number_field(summary, "verdict_changes")
    );
    println!(
        "affected workloads       {}",
        number_field(summary, "affected_workloads")
    );
    println!(
        "selected endpoints       sources={} destinations={}",
        number_field(value, "affected_sources"),
        number_field(value, "affected_destinations")
    );
    println!(
        "affected services        {}",
        joined_strings(&value["affected_services"])
    );
    print_historical_simulation_table(value);
    if let Some(changes) = value.get("changes").and_then(Value::as_array) {
        for change in changes.iter().take(20) {
            println!(
                "change                   {} {} -> {} {}/{} family={} addresses={}->{}: {} -> {}",
                change["direction"].as_str().unwrap_or("Ingress"),
                change["source"]["reference"].as_str().unwrap_or("?"),
                change["destination"]["reference"].as_str().unwrap_or("?"),
                change["protocol"].as_str().unwrap_or("?"),
                change["destination_port"],
                change["ip_family"].as_str().unwrap_or("-"),
                change["source_address"].as_str().unwrap_or("-"),
                change["destination_address"].as_str().unwrap_or("-"),
                change["current"]["verdict"].as_str().unwrap_or("?"),
                change["proposed"]["verdict"].as_str().unwrap_or("?"),
            );
        }
        if changes.len() > 20 {
            println!("changes omitted          {}", changes.len() - 20);
        }
    }
    println!("note                     {}", text_field(value, "note"));
}

fn print_historical_simulation_table(value: &Value) {
    let historical = &value["historical_summary"];
    let historical_query = &value["historical_query"];
    println!(
        "historical retained      flows={} observations={}",
        number_field(historical, "retained_flows"),
        number_field(historical, "retained_observations")
    );
    println!(
        "historical selection     since={} until={} matched={} observations={} returned={} truncated={}",
        optional_number_field(historical_query, "since_unix_ms"),
        optional_number_field(historical_query, "until_unix_ms"),
        number_field(historical_query, "matched_flows"),
        number_field(historical_query, "matched_observations"),
        number_field(historical_query, "returned_flows"),
        historical_query
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    );
    println!(
        "historical evaluation    flows={} observations={} skipped={}",
        number_field(historical, "evaluated_flows"),
        number_field(historical, "evaluated_observations"),
        number_field(historical, "skipped_unresolved_flows")
    );
    println!(
        "historical would deny    {} observations",
        number_field(historical, "would_be_denied_observations")
    );
}

fn text_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or("?")
}

fn number_field(value: &Value, field: &str) -> u64 {
    value.get(field).and_then(Value::as_u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_simulation_command_and_fixture_parse() {
        let cli = Cli::try_parse_from([
            "unfctl",
            "policy",
            "simulate",
            "deploy/examples/simulation-deny.yaml",
            "--last",
            "15m",
            "--limit",
            "25",
            "--output",
            "json",
        ])
        .expect("policy simulation command parses");
        assert!(matches!(
            cli.command,
            Command::Policy {
                command: PolicyCommand::Simulate {
                    last: Some(900_000),
                    since_unix_ms: None,
                    until_unix_ms: None,
                    limit: Some(25),
                    ..
                }
            }
        ));
        let policy: Value = serde_yaml::from_str(include_str!(
            "../../../deploy/examples/simulation-deny.yaml"
        ))
        .expect("checked-in simulation fixture is valid");
        assert_eq!(policy["metadata"]["name"], "frontend-to-backend");
        let network_policy: Value = serde_yaml::from_str(include_str!(
            "../../../deploy/examples/simulation-networkpolicy-egress-deny.yaml"
        ))
        .expect("checked-in NetworkPolicy simulation fixture is valid");
        assert_eq!(network_policy["kind"], "NetworkPolicy");
        assert_eq!(network_policy["spec"]["policyTypes"][0], "Egress");
        assert_eq!(
            policy_simulation_flow_history(Some(900_000), None, None, Some(25), 2_000_000)
                .expect("relative simulation window resolves"),
            Some(PolicySimulationFlowHistoryQuery {
                since_unix_ms: Some(1_100_000),
                until_unix_ms: Some(2_000_000),
                limit: Some(25),
            })
        );
        assert_eq!(
            policy_simulation_flow_history(None, None, None, None, 2_000_000)
                .expect("omitted simulation window remains backward compatible"),
            None
        );
    }

    #[test]
    fn shadow_impact_supports_live_and_offline_sources() {
        let offline = Cli::try_parse_from([
            "unfctl",
            "--controller-url",
            "http://127.0.0.1:1",
            "policy",
            "shadow-impact",
            "--flows-file",
            "flows.json",
            "--output",
            "json",
        ])
        .expect("offline shadow-impact command parses");
        assert!(matches!(
            offline.command,
            Command::Policy {
                command: PolicyCommand::ShadowImpact {
                    flows_file: Some(_),
                    last: None,
                    since_unix_ms: None,
                    until_unix_ms: None,
                    limit: None,
                }
            }
        ));

        let live = Cli::try_parse_from([
            "unfctl",
            "policy",
            "shadow-impact",
            "--last",
            "15m",
            "--limit",
            "25",
        ])
        .expect("live shadow-impact command parses");
        assert!(matches!(
            live.command,
            Command::Policy {
                command: PolicyCommand::ShadowImpact {
                    flows_file: None,
                    last: Some(900_000),
                    limit: Some(25),
                    ..
                }
            }
        ));

        assert!(
            Cli::try_parse_from([
                "unfctl",
                "policy",
                "shadow-impact",
                "--flows-file",
                "flows.json",
                "--last",
                "15m",
            ])
            .is_err()
        );
    }

    #[test]
    fn topology_command_parses() {
        let cli = Cli::try_parse_from(["unfctl", "topology", "--output", "yaml"])
            .expect("topology command parses");
        assert!(matches!(cli.command, Command::Topology));
        assert!(matches!(cli.output, Output::Yaml));
    }

    #[test]
    fn topology_history_command_builds_bounded_query() {
        let cli = Cli::try_parse_from([
            "unfctl",
            "topology-history",
            "--since-revision",
            "12",
            "--until-revision",
            "20",
            "--last",
            "15m",
            "--limit",
            "5",
            "--output",
            "json",
        ])
        .expect("topology-history command parses");
        assert!(matches!(
            cli.command,
            Command::TopologyHistory {
                last: Some(900_000),
                since_revision: Some(12),
                until_revision: Some(20),
                since_unix_ms: None,
                until_unix_ms: None,
                limit: Some(5),
            }
        ));
        assert_eq!(
            topology_history_url(
                "http://controller",
                Some(12),
                Some(20),
                Some(1_100_000),
                Some(2_000_000),
                Some(5),
            ),
            "http://controller/v1/topology/history?since_revision=12&until_revision=20&since_unix_ms=1100000&until_unix_ms=2000000&limit=5"
        );
    }

    #[test]
    fn flows_command_parses() {
        let cli = Cli::try_parse_from([
            "unfctl", "flows", "--last", "15m", "--limit", "25", "--output", "json",
        ])
        .expect("flows command parses");
        assert!(matches!(
            cli.command,
            Command::Flows {
                last: Some(900_000),
                since_unix_ms: None,
                until_unix_ms: None,
                limit: Some(25)
            }
        ));
        assert!(matches!(cli.output, Output::Json));
        assert_eq!(
            resolve_time_window(Some(900_000), None, None, 2_000_000)
                .expect("relative flow window resolves"),
            (Some(1_100_000), Some(2_000_000))
        );
        assert_eq!(
            flow_history_url(
                "http://controller",
                Some(1_100_000),
                Some(2_000_000),
                Some(25)
            ),
            "http://controller/v1/flows?since_unix_ms=1100000&until_unix_ms=2000000&limit=25"
        );
    }

    #[test]
    fn service_explanation_command_builds_bounded_query() {
        let cli = Cli::try_parse_from([
            "unfctl",
            "service-explain",
            "--service-id",
            "11",
            "--backend-id",
            "13",
            "--frontend-kind",
            "node-port-local",
            "--last",
            "15m",
            "--limit",
            "25",
        ])
        .expect("service explanation command parses");
        assert!(matches!(
            cli.command,
            Command::ServiceExplain {
                service_id: 11,
                backend_id: Some(13),
                frontend_kind: Some(ServiceFrontend::NodePortLocal),
                last: Some(900_000),
                limit: Some(25),
                ..
            }
        ));
        assert_eq!(
            service_explanation_url(
                "http://controller",
                11,
                Some(13),
                Some(ServiceFrontend::NodePortLocal),
                Some(1_100_000),
                Some(2_000_000),
                Some(25),
            ),
            "http://controller/v1/services/explain?service_id=11&frontend_kind=node_port_local&backend_id=13&since_unix_ms=1100000&until_unix_ms=2000000&limit=25"
        );
    }

    #[test]
    fn node_port_simulation_command_builds_exact_query() {
        let cli = Cli::try_parse_from([
            "unfctl",
            "service-simulate",
            "--node",
            "worker-a",
            "--address",
            "fdff::1",
            "--port",
            "30443",
            "--protocol",
            "udp",
        ])
        .expect("NodePort simulation command parses");
        assert!(matches!(
            cli.command,
            Command::ServiceSimulate {
                node,
                address,
                port: 30_443,
                protocol: NodePortProtocol::Udp,
            } if node == "worker-a" && address == "fdff::1".parse::<IpAddr>().unwrap()
        ));
        assert_eq!(
            node_port_simulation_url(
                "http://controller",
                "worker-a",
                "192.0.2.1".parse().unwrap(),
                30_443,
                NodePortProtocol::Tcp,
            ),
            "http://controller/v1/services/nodeport/simulate?node_name=worker-a&address=192.0.2.1&port=30443&protocol=tcp"
        );
    }

    #[test]
    fn cluster_ip_simulation_command_builds_exact_query() {
        let cli = Cli::try_parse_from([
            "unfctl",
            "cluster-ip-simulate",
            "--node",
            "worker-a",
            "--address",
            "fd00:96::80",
            "--port",
            "443",
            "--protocol",
            "udp",
        ])
        .expect("ClusterIP simulation command parses");
        assert!(matches!(
            cli.command,
            Command::ClusterIpSimulate {
                node,
                address,
                port: 443,
                protocol: NodePortProtocol::Udp,
            } if node == "worker-a" && address == "fd00:96::80".parse::<IpAddr>().unwrap()
        ));
        assert_eq!(
            cluster_ip_simulation_url(
                "http://controller",
                "worker-a",
                "10.96.0.80".parse().unwrap(),
                443,
                NodePortProtocol::Tcp,
            ),
            "http://controller/v1/services/clusterip/simulate?node_name=worker-a&address=10.96.0.80&port=443&protocol=tcp"
        );
    }

    #[test]
    fn load_balancer_simulation_and_explanation_build_exact_queries() {
        let cli = Cli::try_parse_from([
            "unfctl",
            "load-balancer-simulate",
            "--node",
            "worker-a",
            "--address",
            "192.0.2.60",
            "--source-address",
            "198.51.100.10",
            "--port",
            "443",
            "--protocol",
            "tcp",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::LoadBalancerSimulate {
                node,
                address,
                source_address,
                port: 443,
                protocol: NodePortProtocol::Tcp,
            } if node == "worker-a"
                && address == "192.0.2.60".parse::<IpAddr>().unwrap()
                && source_address == "198.51.100.10".parse::<IpAddr>().unwrap()
        ));
        assert_eq!(
            load_balancer_simulation_url(
                "http://controller",
                "worker-a",
                "2001:db8::60".parse().unwrap(),
                "2001:db8:100::10".parse().unwrap(),
                443,
                NodePortProtocol::Udp,
            ),
            "http://controller/v1/services/loadbalancer/simulate?node_name=worker-a&address=2001:db8::60&source_address=2001:db8:100::10&port=443&protocol=udp"
        );
        assert_eq!(
            ServiceFrontend::LoadBalancerLocal.query_value(),
            "load_balancer_local"
        );
        assert_eq!(
            ServiceFrontend::LoadBalancerCluster.query_value(),
            "load_balancer_cluster"
        );
    }

    #[test]
    fn sctp_explain_command_parses() {
        let cli = Cli::try_parse_from([
            "unfctl",
            "explain",
            "--from",
            "frontend/sctp-client",
            "--to",
            "backend/sctp-server",
            "--protocol",
            "sctp",
            "--port",
            "8086",
        ])
        .expect("SCTP explain command parses");
        assert!(matches!(
            cli.command,
            Command::Explain {
                protocol: Protocol::Sctp,
                direction: Direction::Ingress,
                ip_family: None,
                ..
            }
        ));
    }

    #[test]
    fn egress_ipv6_explain_command_parses() {
        let cli = Cli::try_parse_from([
            "unfctl",
            "explain",
            "--from",
            "frontend/client",
            "--to",
            "backend/server",
            "--direction",
            "egress",
            "--ip-family",
            "ipv6",
            "--port",
            "8080",
        ])
        .expect("egress IPv6 explain command parses");
        assert!(matches!(
            cli.command,
            Command::Explain {
                direction: Direction::Egress,
                ip_family: Some(IpFamily::Ipv6),
                ..
            }
        ));
    }
}
