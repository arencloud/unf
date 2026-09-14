//! Joint attachment/link/route snapshots, never packet-time locality authority.

use std::os::fd::BorrowedFd;

use unf_cni_state::{AttachmentPhase, AttachmentRecord};
use unf_link::{LinkReadback, VethObservation, VethPlan};

use crate::{NativeRoutePlan, NativeRoutingProvider, RouteError, RouteReadback, RoutingProvider};

/// A checked bound attachment retaining its exact namespace descriptors.
/// Construction is read-only. No deserialize/clone constructor, permission bit
/// or automatic rearm exists. The caller must obtain the record from the real
/// CNI journal and independently authenticate current placement before use.
pub struct NativeAttachmentObservation {
    attachment: AttachmentRecord,
    plan: NativeRoutePlan,
    routes: RouteReadback,
    links: Option<VethObservation>,
}

impl NativeRoutingProvider {
    /// Observe a Ready UID/creation-nonce-bound attachment and its exact routes.
    /// Both route connections use the descriptors retained by link observation.
    /// A second strict link check brackets the route reads. This does not make
    /// the reads atomic or protect subsequent packet delivery against drift.
    ///
    /// # Errors
    /// Rejects legacy/unbound or non-Ready records, missing/conflicting routes,
    /// neighbors, links, aliases, namespace identity, addresses or MTU.
    pub async fn observe_bound_attachment(
        &self,
        attachment: &AttachmentRecord,
    ) -> Result<NativeAttachmentObservation, RouteError> {
        let link_plan = bound_link_plan(attachment)?;
        let mut links = link_plan
            .observe()
            .await
            .map_err(|error| link_error(&error))?;
        let plan = self.plan(attachment, links.readback())?;
        let (host, peer) = links.namespace_descriptors().ok_or_else(retired)?;
        let routes = plan.readback_in_namespaces(host, peer).await?;
        links.recheck().await.map_err(|error| link_error(&error))?;
        Ok(NativeAttachmentObservation {
            attachment: attachment.clone(),
            plan,
            routes,
            links: Some(links),
        })
    }
}

impl NativeAttachmentObservation {
    /// Original caller-supplied record; not independent journal authentication.
    #[must_use]
    pub const fn attachment(&self) -> &AttachmentRecord {
        &self.attachment
    }

    /// Available only while the observation has not been explicitly retired.
    /// Even a non-retired snapshot is not a packet-time lease or route lock.
    #[must_use]
    pub fn readback(&self) -> Option<(&LinkReadback, &RouteReadback)> {
        self.links
            .as_ref()
            .map(|links| (links.readback(), &self.routes))
    }

    #[must_use]
    pub fn namespace_descriptors(&self) -> Option<(BorrowedFd<'_>, BorrowedFd<'_>)> {
        self.links.as_ref()?.namespace_descriptors()
    }

    /// Strictly recheck this same attachment and descriptor-bound route plan.
    /// A failed or cancelled recheck permanently retires the observation.
    /// Restoring a route/path cannot implicitly rearm it; construct a fresh
    /// observation after obtaining current authoritative attachment state.
    ///
    /// # Errors
    /// Rejects retired observations, any link/path drift or missing/conflicting
    /// route/neighbor state. No repair or other kernel mutation is performed.
    pub async fn recheck(&mut self) -> Result<(), RouteError> {
        let mut links = self.links.take().ok_or_else(retired)?;
        links.recheck().await.map_err(|error| link_error(&error))?;
        let (host, peer) = links.namespace_descriptors().ok_or_else(retired)?;
        let routes = self.plan.readback_in_namespaces(host, peer).await?;
        if routes != self.routes {
            return Err(RouteError::Readback(
                "observed route snapshot changed".into(),
            ));
        }
        links.recheck().await.map_err(|error| link_error(&error))?;
        self.links = Some(links);
        Ok(())
    }
}

fn bound_link_plan(attachment: &AttachmentRecord) -> Result<VethPlan, RouteError> {
    if attachment.phase != AttachmentPhase::Ready
        || attachment.spec.workload_uid.is_none()
        || attachment.creation_token.is_none()
    {
        return Err(RouteError::Readback(
            "attachment observation requires Ready UID/nonce binding".into(),
        ));
    }
    VethPlan::from_attachment(attachment).map_err(|error| link_error(&error))
}

fn link_error(error: &unf_link::LinkError) -> RouteError {
    RouteError::Readback(format!("attachment link observation: {error}"))
}

fn retired() -> RouteError {
    RouteError::Readback("native attachment observation has been retired".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use unf_cni_state::{AttachmentKey, AttachmentSpec};
    use unf_ipam::{DualStackLease, Ipv4Lease, Ipv6Lease};

    fn record() -> AttachmentRecord {
        AttachmentRecord {
            spec: AttachmentSpec {
                key: AttachmentKey {
                    network: "test".into(),
                    container_id: "sandbox".into(),
                    ifname: "eth0".into(),
                },
                netns: "/proc/unf-route-observation-not-a-process/ns/net".into(),
                mtu: 1400,
                workload_uid: Some("pod-uid".into()),
            },
            host_interface: "unfobs0".into(),
            phase: AttachmentPhase::Ready,
            creation_token: Some([7; 32]),
            lease: DualStackLease {
                ipv4: Ipv4Lease {
                    address: "192.0.2.2".parse().unwrap(),
                    gateway: "192.0.2.1".parse().unwrap(),
                    prefix_len: 32,
                },
                ipv6: Ipv6Lease {
                    address: "2001:db8::2".parse().unwrap(),
                    gateway: "2001:db8::1".parse().unwrap(),
                    prefix_len: 128,
                },
            },
        }
    }

    #[test]
    fn only_ready_nonzero_nonce_and_valid_uid_are_eligible() {
        assert!(bound_link_plan(&record()).is_ok());
        for mutation in 0..8 {
            let mut record = record();
            match mutation {
                0 => record.phase = AttachmentPhase::Preparing,
                1 => record.phase = AttachmentPhase::Deleting,
                2 => record.spec.workload_uid = None,
                3 => record.creation_token = None,
                4 => record.creation_token = Some([0; 32]),
                5 => record.spec.workload_uid = Some("".into()),
                6 => record.spec.workload_uid = Some("invalid/uid".into()),
                7 => record.phase = AttachmentPhase::Aborting,
                _ => unreachable!(),
            }
            assert!(bound_link_plan(&record).is_err(), "mutation {mutation}");
        }
    }

    #[tokio::test]
    async fn valid_metadata_cannot_construct_without_real_kernel_observation() {
        let result = NativeRoutingProvider::new(1400)
            .observe_bound_attachment(&record())
            .await;
        assert!(result.is_err());
    }
}
