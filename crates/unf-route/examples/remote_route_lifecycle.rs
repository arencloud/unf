use std::env;

use unf_ipam::NodeBlockProvider;
use unf_route::{
    NativeIpv4NextHop, NativeIpv6NextHop, NativeRemoteNode, NativeRemoteRoutingProvider,
    RemoteNodeIntent, RouteDeleteOutcome,
};

fn plan(
    ipv4_output_interface: u32,
    ipv6_output_interface: u32,
) -> Result<unf_route::NativeRemoteRoutePlan, Box<dyn std::error::Error>> {
    let local_blocks = NodeBlockProvider::new("10.42.0.0/24".parse()?, "fd00:42::/64".parse()?);
    let remote = NativeRemoteNode {
        intent: RemoteNodeIntent {
            node_name: "worker-b".to_owned(),
            node_uid: "worker-b-uid".to_owned(),
            assignment_revision: 2,
            blocks: NodeBlockProvider::new("10.43.0.0/24".parse()?, "fd00:43::/64".parse()?),
        },
        ipv4_next_hop: NativeIpv4NextHop {
            gateway: "192.0.2.2".parse()?,
            output_interface: ipv4_output_interface,
            onlink: false,
        },
        ipv6_next_hop: NativeIpv6NextHop {
            gateway: "fdff::2".parse()?,
            output_interface: ipv6_output_interface,
            onlink: false,
        },
    };
    Ok(
        NativeRemoteRoutingProvider::new("worker-a", "worker-a-uid", local_blocks)?
            .plan(vec![remote])?,
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let operation = arguments.next().ok_or("missing operation")?;
    let output_interface = arguments
        .next()
        .ok_or("missing output interface index")?
        .parse::<u32>()?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    match operation.as_str() {
        "apply" => {
            let routes = plan(output_interface, output_interface)?;
            let first = routes.apply().await?;
            let replay = routes.apply().await?;
            let readback = routes.readback().await?;
            if first != replay || replay != readback {
                return Err("remote route replay and readback differ".into());
            }
        }
        "readback" => {
            plan(output_interface, output_interface)?.readback().await?;
        }
        "delete" => {
            plan(output_interface, output_interface)?.delete().await?;
        }
        "rollback" => {
            let routes = plan(output_interface, u32::MAX)?;
            if routes.apply().await.is_ok() {
                return Err("invalid IPv6 output interface unexpectedly applied".into());
            }
        }
        "exercise" => {
            let routes = plan(output_interface, output_interface)?;
            let first = routes.apply().await?;
            if first != routes.apply().await? || first != routes.readback().await? {
                return Err("remote route apply is not idempotent".into());
            }
            if routes.delete().await? != RouteDeleteOutcome::Deleted
                || routes.delete().await? != RouteDeleteOutcome::AlreadyAbsent
            {
                return Err("remote route deletion is not idempotent".into());
            }
        }
        _ => return Err(format!("unsupported operation {operation:?}").into()),
    }
    Ok(())
}
