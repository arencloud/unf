use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::Value;
use unf_api::SecurityPolicy;

#[derive(Debug, Parser)]
#[command(about = "Inspect, explain, and simulate the UNF network fabric")]
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
    /// Explain a policy decision using live controller state.
    Explain {
        /// Source pod as namespace/name.
        #[arg(long)]
        from: String,
        /// Destination pod as namespace/name.
        #[arg(long)]
        to: String,
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
    /// Compare a candidate `SecurityPolicy` with current topology and policy state.
    Simulate {
        /// `SecurityPolicy` YAML file to evaluate without applying.
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

#[derive(Debug, Serialize)]
struct ExplainRequest<'a> {
    from: &'a str,
    to: &'a str,
    protocol: Protocol,
    port: u16,
}

#[derive(Debug, Serialize)]
struct PolicySimulationRequest<'a> {
    policy: &'a SecurityPolicy,
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

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::new();
    let value = match &cli.command {
        Command::Status => get_json(&client, &format!("{}/v1/status", cli.controller_url)).await?,
        Command::Topology => {
            get_json(&client, &format!("{}/v1/topology", cli.controller_url)).await?
        }
        Command::Flows {
            last,
            since_unix_ms,
            until_unix_ms,
            limit,
        } => {
            let (since_unix_ms, until_unix_ms) =
                resolve_flow_window(*last, *since_unix_ms, *until_unix_ms, unix_time_millis()?)?;
            get_json(
                &client,
                &flow_history_url(&cli.controller_url, since_unix_ms, until_unix_ms, *limit),
            )
            .await?
        }
        Command::Explain {
            from,
            to,
            protocol,
            port,
        } => {
            if *port == 0 {
                bail!("port must be between 1 and 65535");
            }
            post_json(
                &client,
                &format!("{}/v1/explain", cli.controller_url),
                &ExplainRequest {
                    from,
                    to,
                    protocol: *protocol,
                    port: *port,
                },
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
            let contents = std::fs::read_to_string(policy_file)
                .with_context(|| format!("read policy file {}", policy_file.display()))?;
            let policy: SecurityPolicy = serde_yaml::from_str(&contents)
                .with_context(|| format!("parse SecurityPolicy YAML {}", policy_file.display()))?;
            let flow_history = policy_simulation_flow_history(
                *last,
                *since_unix_ms,
                *until_unix_ms,
                *limit,
                unix_time_millis()?,
            )?;
            post_json(
                &client,
                &format!("{}/v1/policy/simulate", cli.controller_url),
                &PolicySimulationRequest {
                    policy: &policy,
                    flow_history,
                },
            )
            .await?
        }
    };
    print_value(&value, cli.output)
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
    if value.get("component").and_then(Value::as_str) == Some("unf-controller")
        && value.get("agents").is_some()
    {
        print_controller_status_table(value);
        return;
    }
    if matches!(
        value.get("schema_version").and_then(Value::as_u64),
        Some(1..=3)
    ) && value.get("retained_flows").is_some()
        && value.get("entries").is_some()
    {
        print_flow_history_table(value);
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
        "revisions                identity={} policy={} topology={} telemetry={}",
        number_field(revisions, "identity"),
        number_field(revisions, "policy"),
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
                "agent                    {} fresh={} converged={} identity={}/{} policy={}/{} bank={}",
                text_field(node, "node_name"),
                node.get("fresh").and_then(Value::as_bool).unwrap_or(false),
                node.get("converged")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                number_field(report, "applied_identity_revision"),
                number_field(report, "desired_identity_revision"),
                number_field(report, "applied_policy_revision"),
                number_field(report, "desired_policy_revision"),
                number_field(report, "active_policy_bank")
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

fn resolve_flow_window(
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
        resolve_flow_window(last_millis, since_unix_ms, until_unix_ms, now_unix_ms)?;
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
        "policy                   {} ({})",
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
        "affected services        {}",
        joined_strings(&value["affected_services"])
    );
    print_historical_simulation_table(value);
    if let Some(changes) = value.get("changes").and_then(Value::as_array) {
        for change in changes.iter().take(20) {
            println!(
                "change                   {} -> {} {}/{}: {} -> {}",
                change["source"]["reference"].as_str().unwrap_or("?"),
                change["destination"]["reference"].as_str().unwrap_or("?"),
                change["protocol"].as_str().unwrap_or("?"),
                change["destination_port"],
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
        let policy: SecurityPolicy = serde_yaml::from_str(include_str!(
            "../../../deploy/examples/simulation-deny.yaml"
        ))
        .expect("checked-in simulation fixture is valid");
        assert_eq!(policy.metadata.name.as_deref(), Some("frontend-to-backend"));
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
    fn topology_command_parses() {
        let cli = Cli::try_parse_from(["unfctl", "topology", "--output", "yaml"])
            .expect("topology command parses");
        assert!(matches!(cli.command, Command::Topology));
        assert!(matches!(cli.output, Output::Yaml));
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
            resolve_flow_window(Some(900_000), None, None, 2_000_000)
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
                ..
            }
        ));
    }
}
