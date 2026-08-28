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

fn replacement_plan(
    ipv4_output_interface: u32,
    ipv6_output_interface: u32,
) -> Result<unf_route::NativeRemoteRoutePlan, Box<dyn std::error::Error>> {
    let local_blocks = NodeBlockProvider::new("10.42.0.0/24".parse()?, "fd00:42::/64".parse()?);
    let remotes = [
        (
            "worker-b",
            "worker-b-uid",
            "10.43.0.0/24",
            "fd00:43::/64",
            "192.0.2.3",
            "fdff::3",
        ),
        (
            "worker-c",
            "worker-c-uid",
            "10.44.0.0/24",
            "fd00:44::/64",
            "192.0.2.2",
            "fdff::2",
        ),
    ]
    .into_iter()
    .map(|(name, uid, ipv4, ipv6, ipv4_gateway, ipv6_gateway)| {
        Ok(NativeRemoteNode {
            intent: RemoteNodeIntent {
                node_name: name.to_owned(),
                node_uid: uid.to_owned(),
                assignment_revision: 3,
                blocks: NodeBlockProvider::new(ipv4.parse()?, ipv6.parse()?),
            },
            ipv4_next_hop: NativeIpv4NextHop {
                gateway: ipv4_gateway.parse()?,
                output_interface: ipv4_output_interface,
                onlink: false,
            },
            ipv6_next_hop: NativeIpv6NextHop {
                gateway: ipv6_gateway.parse()?,
                output_interface: ipv6_output_interface,
                onlink: false,
            },
        })
    })
    .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    Ok(
        NativeRemoteRoutingProvider::new("worker-a", "worker-a-uid", local_blocks)?
            .plan(remotes)?,
    )
}

fn empty_plan() -> Result<unf_route::NativeRemoteRoutePlan, Box<dyn std::error::Error>> {
    let local_blocks = NodeBlockProvider::new("10.42.0.0/24".parse()?, "fd00:42::/64".parse()?);
    Ok(
        NativeRemoteRoutingProvider::new("worker-a", "worker-a-uid", local_blocks)?
            .plan(Vec::new())?,
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
        "reconcile" => {
            let previous = plan(output_interface, output_interface)?;
            previous.apply().await?;
            let desired = replacement_plan(output_interface, output_interface)?;
            desired.reconcile_from(&previous).await?;
            desired.readback().await?;
        }
        "retire" => {
            let previous = replacement_plan(output_interface, output_interface)?;
            let desired = empty_plan()?;
            desired.reconcile_from(&previous).await?;
            desired.readback().await?;
        }
        "reconcile-rollback" => {
            let previous = plan(output_interface, output_interface)?;
            previous.apply().await?;
            let desired = replacement_plan(output_interface, u32::MAX)?;
            if desired.reconcile_from(&previous).await.is_ok() {
                return Err("invalid replacement unexpectedly applied".into());
            }
            previous.readback().await?;
        }
        _ => return Err(format!("unsupported operation {operation:?}").into()),
    }
    Ok(())
}
