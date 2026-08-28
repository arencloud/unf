use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use unf_link::{AssignedAddress, DeleteOutcome, VethPlan};

fn plan(host_name: String, netns: PathBuf) -> Result<VethPlan, unf_link::LinkError> {
    VethPlan::new(
        host_name,
        "eth0".to_string(),
        netns,
        1_400,
        [
            AssignedAddress {
                address: IpAddr::V4(Ipv4Addr::new(10, 244, 44, 2)),
                prefix_len: 24,
            },
            AssignedAddress {
                address: IpAddr::V6(Ipv6Addr::new(0xfd44, 0, 0, 0x44, 0, 0, 0, 2)),
                prefix_len: 64,
            },
        ],
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let operation = arguments.next().ok_or("missing operation")?;
    let host_name = arguments.next().ok_or("missing host interface name")?;
    let netns = PathBuf::from(arguments.next().ok_or("missing namespace path")?);
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    let plan = plan(host_name, netns)?;

    match operation.as_str() {
        "exercise" => {
            let first = plan.apply().await?;
            let replay = plan.apply().await?;
            let readback = plan.readback().await?;
            if first != replay || replay != readback {
                return Err("apply replay and readback differ".into());
            }
            if plan.delete().await? != DeleteOutcome::Deleted {
                return Err("first delete did not remove the owned veth".into());
            }
            if plan.delete().await? != DeleteOutcome::AlreadyAbsent {
                return Err("second delete was not idempotent".into());
            }
        }
        "apply" => {
            plan.apply().await?;
        }
        "readback" => {
            plan.readback().await?;
        }
        "delete" => {
            plan.delete().await?;
        }
        _ => return Err(format!("unsupported operation {operation:?}").into()),
    }
    Ok(())
}
