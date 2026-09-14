//! Disposable kernel qualifier, not a source of production CNI authority.
use std::future::Future;
use std::io::{self, BufRead, Write};
use std::task::Poll;

use unf_cni_state::{AttachmentKey, AttachmentPhase, AttachmentRecord, AttachmentSpec};
use unf_ipam::{DualStackLease, Ipv4Lease, Ipv6Lease};
use unf_link::VethPlan;
use unf_route::{NativeRoutingProvider, RoutingProvider};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("UNF_NATIVE_ATTACHMENT_ISOLATED_CONTAINER").as_deref() != Ok("yes") {
        return Err("isolated native attachment opt-in required".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("expected operation, host name and peer namespace".into());
    }
    let record = AttachmentRecord {
        spec: AttachmentSpec {
            key: AttachmentKey {
                network: "isolated-native-observation".into(),
                container_id: "fixture-sandbox".into(),
                ifname: "eth0".into(),
            },
            netns: args[2].clone(),
            mtu: 1400,
            workload_uid: Some("fixture-pod-uid".into()),
        },
        host_interface: args[1].clone(),
        phase: AttachmentPhase::Ready,
        creation_token: Some([17; 32]),
        lease: DualStackLease {
            ipv4: Ipv4Lease {
                address: "10.244.44.2".parse()?,
                gateway: "10.244.44.1".parse()?,
                prefix_len: 32,
            },
            ipv6: Ipv6Lease {
                address: "fd44::2".parse()?,
                gateway: "fd44::1".parse()?,
                prefix_len: 128,
            },
        },
    };
    let provider = NativeRoutingProvider::new(1400);
    match args[0].as_str() {
        "apply" => {
            let mut preparing = record.clone();
            preparing.phase = AttachmentPhase::Preparing;
            let links = VethPlan::from_attachment(&preparing)?.apply().await?;
            provider.plan(&record, &links)?.apply().await?;
        }
        "observe" => {
            let mut observation = provider.observe_bound_attachment(&record).await?;
            if observation.attachment() != &record
                || observation.readback().is_none()
                || observation.namespace_descriptors().is_none()
            {
                return Err("missing joint attachment observation".into());
            }
            println!("observation-ready");
            io::stdout().flush()?;
            for command in io::stdin().lock().lines() {
                match command?.as_str() {
                    "recheck" => match observation.recheck().await {
                        Ok(()) => {
                            if observation.readback().is_none()
                                || observation.namespace_descriptors().is_none()
                            {
                                return Err("successful recheck lost held observation".into());
                            }
                            println!("observation-current");
                        }
                        Err(error) => {
                            if observation.readback().is_some()
                                || observation.namespace_descriptors().is_some()
                            {
                                return Err("failed recheck retained active observation".into());
                            }
                            println!("observation-rejected: {error}");
                        }
                    },
                    "cancel" => {
                        let mut check = Box::pin(observation.recheck());
                        std::future::poll_fn(|cx| {
                            assert!(
                                check.as_mut().poll(cx).is_pending(),
                                "recheck did not suspend"
                            );
                            Poll::Ready(())
                        })
                        .await;
                        drop(check);
                        if observation.readback().is_some()
                            || observation.namespace_descriptors().is_some()
                        {
                            return Err("cancelled recheck retained active observation".into());
                        }
                        println!("observation-cancelled");
                    }
                    "finish" => break,
                    _ => return Err("unsupported observer command".into()),
                }
                io::stdout().flush()?;
            }
        }
        _ => return Err("unsupported native attachment operation".into()),
    }
    Ok(())
}
