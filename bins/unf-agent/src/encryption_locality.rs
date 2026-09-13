//! Ephemeral placement candidate acquisition, not kernel admission. Fetches
//! only for Required demand and changed applied placement/desired-plan cuts.

use anyhow::{Context, Result, bail};
use unf_common::Revision;
use unf_encryption::{
    AdmittedNodeLocalPlan, AdmittedNodeLocalPlanDigest, EncryptionDisposition,
    EncryptionLocalityContext, EncryptionLocalityRequest, EncryptionLocalityResponse,
    MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES, VerifiedEncryptionLocality,
};

use super::{
    AgentState, EncryptionKeySynchronizer, EncryptionPlanSynchronizer, Ordering, read_agent_token,
};

pub(super) struct PlacementCache {
    candidate: Option<(AdmittedNodeLocalPlanDigest, VerifiedEncryptionLocality)>,
    pending: Option<PendingPlacement>,
    work_slot: std::sync::Arc<tokio::sync::Semaphore>,
}

struct PendingPlacement {
    context: EncryptionLocalityContext,
    plan_digest: AdmittedNodeLocalPlanDigest,
    task: tokio::task::JoinHandle<Result<VerifiedEncryptionLocality>>,
}

impl Drop for PendingPlacement {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Default for PlacementCache {
    fn default() -> Self {
        Self {
            candidate: None,
            pending: None,
            work_slot: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
}

impl PlacementCache {
    pub(super) fn clear(&mut self) {
        self.candidate = None;
        self.pending = None;
    }

    fn matches(&self, plan: &AdmittedNodeLocalPlan, context: &EncryptionLocalityContext) -> bool {
        self.candidate.as_ref().is_some_and(|(digest, evidence)| {
            *digest == plan.admitted_digest && evidence.certificate().context() == context
        })
    }
}

fn applied_context(
    plan: &AdmittedNodeLocalPlan,
    cluster_id: &str,
    state: &AgentState,
) -> Option<EncryptionLocalityContext> {
    if plan.snapshot.recipient.node_name != state.node_name
        || !plan
            .snapshot
            .decisions
            .iter()
            .any(|decision| decision.disposition == EncryptionDisposition::Required)
    {
        return None;
    }
    let identity_epoch = state.applied_identity_epoch.load(Ordering::Acquire);
    let identity_revision = state.applied_identity_revision.load(Ordering::Acquire);
    let route_epoch = state.applied_remote_route_epoch.load(Ordering::Acquire);
    let routing_revision = state.applied_remote_route_revision.load(Ordering::Acquire);
    if identity_epoch == 0
        || identity_revision == 0
        || routing_revision == 0
        || identity_epoch != plan.controller_epoch
        || route_epoch != identity_epoch
        || state.desired_identity_epoch.load(Ordering::Acquire) != identity_epoch
        || state.desired_identity_revision.load(Ordering::Acquire) != identity_revision
        || state.desired_remote_route_epoch.load(Ordering::Acquire) != route_epoch
        || state.desired_remote_route_revision.load(Ordering::Acquire) != routing_revision
    {
        return None;
    }
    Some(EncryptionLocalityContext {
        cluster_id: cluster_id.into(),
        recipient: plan.snapshot.recipient.clone(),
        membership_revision: plan.snapshot.membership_revision,
        identity_epoch,
        identity_revision: Revision::new(identity_revision),
        routing_revision: Revision::new(routing_revision),
    })
}

pub(super) async fn synchronize(
    plans: &mut EncryptionPlanSynchronizer,
    keys: &EncryptionKeySynchronizer,
    state: &AgentState,
) -> Result<()> {
    let Some(plan) = plans.current.as_ref() else {
        plans.locality.clear();
        return Ok(());
    };
    let Some(authority) = keys
        .authority
        .as_ref()
        .map(unf_encryption::DurableNodeKeyAuthority::authority)
    else {
        plans.locality.clear();
        return Ok(());
    };
    if authority.node_uid() != plan.snapshot.recipient.node_uid
        || authority.node_name() != state.node_name
    {
        plans.locality.clear();
        bail!("locality bootstrap recipient differs from current plan");
    }
    let Some(context) = applied_context(plan, authority.cluster_id(), state) else {
        plans.locality.clear();
        return Ok(());
    };
    if plans.locality.matches(plan, &context) {
        return Ok(());
    }
    if let Some(pending) = &plans.locality.pending {
        if pending.context != context || pending.plan_digest != plan.admitted_digest {
            plans.locality.clear();
        } else if !pending.task.is_finished() {
            return Ok(());
        } else {
            let mut pending = plans
                .locality
                .pending
                .take()
                .context("finished locality task disappeared")?;
            let evidence = (&mut pending.task)
                .await
                .context("locality worker failed")??;
            if applied_context(plan, authority.cluster_id(), state).as_ref() != Some(&context)
                || evidence.certificate().context() != &context
            {
                bail!("applied locality cut changed before candidate handoff");
            }
            tracing::debug!(
                generation = plan.snapshot.generation.get(),
                addresses = evidence.certificate().addresses().len(),
                "replayed locality placement candidate; kernel admission remains separate"
            );
            plans.locality.candidate = Some((plan.admitted_digest, evidence));
            return Ok(());
        }
    }
    // No last-known-good locality candidate survives a failed replacement. The
    // ordinary Required transport remains authoritative, entirely unchanged.
    plans.locality.clear();
    // A cancelled blocking replay retains this permit until it really exits.
    // Churn cannot build an unbounded queue of detached CPU jobs.
    let Ok(work_slot) = plans.locality.work_slot.clone().try_acquire_owned() else {
        return Ok(());
    };
    let controller_url = plans
        .controller_url
        .as_deref()
        .context("locality fetch has no controller URL")?;
    let endpoint = reqwest::Url::parse(&format!("{controller_url}/v1/state/encryption-locality"))?;
    if endpoint.scheme() != "https" {
        bail!("locality fetch requires authenticated HTTPS");
    }
    let request = EncryptionLocalityRequest::issue(context.clone())?;
    let builder = plans
        .client
        .current()
        .post(endpoint.clone())
        .bearer_auth(read_agent_token(&plans.agent_token_path)?)
        .json(&request);
    let task = tokio::spawn(async move {
        let response = builder
            .send()
            .await
            .context("request authenticated locality placement")?;
        if response.url() != &endpoint {
            bail!("locality response changed authenticated endpoint");
        }
        let bytes = collect_response(response).await?;
        tokio::task::spawn_blocking(move || {
            let _work_slot = work_slot;
            // Replay against the requested cut here; the event-loop handoff
            // separately checks that this is still the actual applied cut.
            EncryptionLocalityResponse::decode_authenticated(&bytes, &request, &request.context)
                .map_err(anyhow::Error::from)
        })
        .await
        .context("locality replay worker failed")?
    });
    plans.locality.pending = Some(PendingPlacement {
        context,
        plan_digest: plan.admitted_digest,
        task,
    });
    Ok(())
}

async fn collect_response(response: reqwest::Response) -> Result<Vec<u8>> {
    if response.status() != reqwest::StatusCode::OK {
        bail!(
            "controller rejected locality placement with status {}",
            response.status()
        );
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES as u64)
    {
        bail!("locality response Content-Length exceeds wire budget");
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read locality response stream")?
    {
        append_bounded(&mut bytes, &chunk)?;
    }
    Ok(bytes)
}

fn append_bounded(bytes: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    if bytes.len() > MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES
        || chunk.len() > MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES.saturating_sub(bytes.len())
    {
        bail!("locality response stream exceeds wire budget");
    }
    let needed = bytes.len() + chunk.len();
    if needed > bytes.capacity() {
        let capacity = bytes
            .capacity()
            .saturating_mul(2)
            .max(needed)
            .min(MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES);
        bytes.reserve_exact(capacity - bytes.len());
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests;
