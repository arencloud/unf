use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Parser)]
#[command(about = "Inspect and explain the UNF network fabric")]
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
}

#[derive(Debug, Serialize)]
struct ExplainRequest<'a> {
    from: &'a str,
    to: &'a str,
    protocol: Protocol,
    port: u16,
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
