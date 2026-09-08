//! Seals a node-local BGP policy read from standard input.

use std::error::Error;
use std::io::{self, Read as _};

use unf_egress::{EgressBgpConfig, seal_egress_bgp_config};

fn main() -> Result<(), Box<dyn Error>> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let config: EgressBgpConfig = serde_json::from_slice(&input)?;
    let sealed = seal_egress_bgp_config(config)?;
    serde_json::to_writer_pretty(io::stdout().lock(), &sealed)?;
    println!();
    Ok(())
}
