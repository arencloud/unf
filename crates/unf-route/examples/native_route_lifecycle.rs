use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};

use unf_cni_state::{AttachmentKey, AttachmentPhase, AttachmentRecord, AttachmentSpec};
use unf_ipam::{DualStackLease, Ipv4Lease, Ipv6Lease};
use unf_link::{DeleteOutcome, VethPlan};
use unf_route::{NativeRoutingProvider, RouteDeleteOutcome, RoutingProvider};

fn attachment(host_name: String, netns: String) -> AttachmentRecord {
    AttachmentRecord {
        spec: AttachmentSpec {
            key: AttachmentKey {
                network: "unf-route-test".to_string(),
                container_id: "route-container-1".to_string(),
                ifname: "eth0".to_string(),
            },
            netns,
            mtu: 1_400,
        },
        host_interface: host_name,
        lease: DualStackLease {
            ipv4: Ipv4Lease {
                address: Ipv4Addr::new(10, 244, 44, 2),
                gateway: Ipv4Addr::new(10, 244, 44, 1),
                prefix_len: 24,
            },
            ipv6: Ipv6Lease {
                address: Ipv6Addr::new(0xfd44, 0, 0, 0x44, 0, 0, 0, 2),
                gateway: Ipv6Addr::new(0xfd44, 0, 0, 0x44, 0, 0, 0, 1),
                prefix_len: 64,
            },
        },
        phase: AttachmentPhase::Preparing,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let operation = arguments.next().ok_or("missing operation")?;
    let host_name = arguments.next().ok_or("missing host interface name")?;
    let netns = arguments.next().ok_or("missing namespace path")?;
    if arguments.next().is_some() {
        return Err("unexpected extra argument".into());
    }

    let attachment = attachment(host_name, netns);
    let links = VethPlan::from_attachment(&attachment)?;
    match operation.as_str() {
        "setup" => {
            let link_state = links.apply().await?;
            let routes =
                NativeRoutingProvider::new(attachment.spec.mtu).plan(&attachment, &link_state)?;
            routes.apply().await?;
        }
        "route-apply" => {
            let link_state = links.readback().await?;
            let routes =
                NativeRoutingProvider::new(attachment.spec.mtu).plan(&attachment, &link_state)?;
            let first = routes.apply().await?;
            let replay = routes.apply().await?;
            let readback = routes.readback().await?;
            if first != replay || replay != readback {
                return Err("route apply replay and readback differ".into());
            }
        }
        "route-readback" => {
            let link_state = links.readback().await?;
            NativeRoutingProvider::new(attachment.spec.mtu)
                .plan(&attachment, &link_state)?
                .readback()
                .await?;
        }
        "route-delete" => {
            let link_state = links.readback().await?;
            NativeRoutingProvider::new(attachment.spec.mtu)
                .plan(&attachment, &link_state)?
                .delete()
                .await?;
        }
        "exercise" => {
            let link_state = links.apply().await?;
            let routes =
                NativeRoutingProvider::new(attachment.spec.mtu).plan(&attachment, &link_state)?;
            let first = routes.apply().await?;
            let replay = routes.apply().await?;
            if first != replay || replay != routes.readback().await? {
                return Err("route replay changed kernel state".into());
            }
            if routes.delete().await? != RouteDeleteOutcome::Deleted
                || routes.delete().await? != RouteDeleteOutcome::AlreadyAbsent
            {
                return Err("route deletion is not idempotent".into());
            }
            if links.delete().await? != DeleteOutcome::Deleted
                || links.delete().await? != DeleteOutcome::AlreadyAbsent
            {
                return Err("link deletion is not idempotent".into());
            }
        }
        "link-delete" => {
            links.delete().await?;
        }
        _ => return Err(format!("unsupported operation {operation:?}").into()),
    }
    Ok(())
}
