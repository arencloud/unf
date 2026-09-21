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
    /// Observe a bounded inventory with one streaming host route/neighbor scan,
    /// rather than a full host-table dump for every attachment. Peer reads use
    /// each attachment's retained namespace descriptor. Strict link rechecks
    /// bracket the route work; the result remains a snapshot, not permission.
    ///
    /// At most 65,536 attachments and 1,048,576 host messages are inspected.
    /// Host and individual peer route workers have ten-second deadlines. Link
    /// workers use the existing observer semantics. Cancellation may outlive
    /// the awaiting future; a publisher must retain its work budget until actual
    /// namespace workers exit. No partial vector escapes on error/cancellation.
    ///
    /// # Errors
    /// Rejects over-budget, duplicate, legacy or non-Ready records, mismatching
    /// host namespaces, missing/conflicting routes or any link/ownership drift.
    pub async fn observe_bound_attachments(
        &self,
        attachments: &[AttachmentRecord],
    ) -> Result<Vec<NativeAttachmentObservation>, RouteError> {
        if attachments.len() > 65_536 {
            return Err(RouteError::Readback(
                "attachment observation count exceeds budget".into(),
            ));
        }
        // Validate all metadata/keys before opening any namespace descriptors.
        let mut keys = std::collections::BTreeSet::new();
        for record in attachments {
            bound_link_plan(record)?;
            if !keys.insert(&record.spec.key) {
                return Err(RouteError::Readback(
                    "duplicate attachment observation key".into(),
                ));
            }
        }
        let mut staged = Vec::with_capacity(attachments.len());
        let mut host_identity = None;
        for record in attachments {
            let links = bound_link_plan(record)?
                .observe()
                .await
                .map_err(|error| link_error(&error))?;
            let (host, _) = links.namespace_descriptors().ok_or_else(retired)?;
            let metadata = rustix::fs::fstat(host).map_err(|error| {
                RouteError::Readback(format!("batch host namespace metadata: {error}"))
            })?;
            let identity = (metadata.st_dev, metadata.st_ino);
            if host_identity.is_some_and(|expected| expected != identity) {
                return Err(RouteError::Readback(
                    "batch attachments use different host namespaces".into(),
                ));
            }
            host_identity = Some(identity);
            let plan = self.plan(record, links.readback())?;
            staged.push((record.clone(), plan, links));
        }
        if let Some((_, _, links)) = staged.first() {
            let (host, _) = links.namespace_descriptors().ok_or_else(retired)?;
            crate::kernel::batch::verify_host(host, staged.iter().map(|(_, plan, _)| plan)).await?;
        }
        let mut observations = Vec::with_capacity(staged.len());
        for (attachment, plan, mut links) in staged {
            let (_, peer) = links.namespace_descriptors().ok_or_else(retired)?;
            crate::kernel::batch::verify_peer(peer, &plan).await?;
            links.recheck().await.map_err(|error| link_error(&error))?;
            let routes = RouteReadback {
                routes: plan
                    .host_routes
                    .into_iter()
                    .chain(plan.container_routes)
                    .collect(),
                neighbors: plan
                    .host_neighbors
                    .into_iter()
                    .chain(plan.container_neighbors)
                    .collect(),
            };
            observations.push(NativeAttachmentObservation {
                attachment,
                plan,
                routes,
                links: Some(links),
            });
        }
        Ok(observations)
    }

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
    /// Recheck a whole prepared bank with one host route scan. Every member is
    /// retired before the first await, so any error/cancellation retires the
    /// complete cohort. Holding descriptors remains snapshot evidence only.
    ///
    /// # Errors
    /// Rejects over-budget/retired members, namespace/link drift or any missing,
    /// duplicate or conflicting planned route/neighbor in either namespace role.
    pub async fn recheck_batch(mut observations: Vec<&mut Self>) -> Result<(), RouteError> {
        let retained: Vec<_> = observations
            .iter_mut()
            .map(|observation| observation.links.take())
            .collect();
        if observations.len() > 65_536 {
            return Err(RouteError::Readback(
                "attachment recheck count exceeds budget".into(),
            ));
        }
        let mut links = retained
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(retired)?;
        for link in &mut links {
            link.recheck().await.map_err(|error| link_error(&error))?;
        }
        if let Some(link) = links.first() {
            let (host, _) = link.namespace_descriptors().ok_or_else(retired)?;
            crate::kernel::batch::verify_host(
                host,
                observations.iter().map(|observation| &observation.plan),
            )
            .await?;
        }
        for (link, observation) in links.iter_mut().zip(&observations) {
            let (_, peer) = link.namespace_descriptors().ok_or_else(retired)?;
            crate::kernel::batch::verify_peer(peer, &observation.plan).await?;
            link.recheck().await.map_err(|error| link_error(&error))?;
        }
        for (observation, link) in observations.into_iter().zip(links) {
            observation.links = Some(link);
        }
        Ok(())
    }

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

    /// Same-socket coordinates retained by the non-retired link observation.
    #[must_use]
    pub fn namespace_cookies(&self) -> Option<unf_link::NamespaceCookies> {
        self.links.as_ref()?.namespace_cookies()
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

    #[tokio::test]
    async fn batch_rejects_duplicates_and_unbound_records_before_kernel_work() {
        let provider = NativeRoutingProvider::new(1400);
        let duplicate = provider
            .observe_bound_attachments(&[record(), record()])
            .await;
        assert!(
            matches!(duplicate, Err(RouteError::Readback(message)) if message.contains("duplicate"))
        );
        let mut unbound = record();
        unbound.creation_token = None;
        assert!(
            provider
                .observe_bound_attachments(&[unbound])
                .await
                .is_err()
        );
        assert!(
            provider
                .observe_bound_attachments(&[record()])
                .await
                .is_err()
        );
        assert!(
            provider
                .observe_bound_attachments(&[])
                .await
                .unwrap()
                .is_empty()
        );
    }
}
