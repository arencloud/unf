//! Authenticated placement acquisition, separate from transport/key churn.
//! A placement cut alone is never policy or packet-delivery permission.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use unf_common::Revision;
use unf_encryption::{
    AdmittedNodeLocalPlan, AdmittedNodeLocalPlanDigest, EncryptionLocalityContext,
    EncryptionLocalityRequest, EncryptionLocalityResponse, MAX_ENCRYPTION_LOCALITY_RESPONSE_BYTES,
    VerifiedEncryptionLocality,
};

mod checkpoint;

use super::{
    AgentState, EncryptionKeySynchronizer, EncryptionPlanSynchronizer, Ordering, read_agent_token,
};

pub(super) struct PlacementCache {
    candidate: Option<(AdmittedNodeLocalPlanDigest, VerifiedEncryptionLocality)>,
    pending: Option<PendingPlacement>,
    work_slot: std::sync::Arc<tokio::sync::Semaphore>,
    attachments: Option<super::cni_inventory::InventorySelection>,
    publisher: super::locality_publisher::BankPublisher,
    recovery_attempted: bool,
    source: Option<PlacementSource>,
    checkpoint_durable: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
enum PlacementSource {
    Controller,
    PrivateCheckpoint,
}

struct PlacementResult {
    evidence: VerifiedEncryptionLocality,
    source: PlacementSource,
    durable: bool,
}

struct PendingPlacement {
    context: EncryptionLocalityContext,
    plan_digest: AdmittedNodeLocalPlanDigest,
    source: PlacementSource,
    task: tokio::task::JoinHandle<Result<Option<PlacementResult>>>,
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
            attachments: None,
            publisher: super::locality_publisher::BankPublisher::default(),
            recovery_attempted: false,
            source: None,
            checkpoint_durable: false,
        }
    }
}

impl PlacementCache {
    pub(super) fn clear(&mut self) -> Result<()> {
        self.publisher.clear()?;
        self.candidate = None;
        self.pending = None;
        self.attachments = None;
        self.source = None;
        self.checkpoint_durable = false;
        // Recovery is a once-per-process bootstrap attempt. Clearing a failed
        // candidate must not resurrect the archive on the next polling tick.
        Ok(())
    }

    fn matches(&self, context: &EncryptionLocalityContext) -> bool {
        self.candidate
            .as_ref()
            .is_some_and(|(_, evidence)| evidence.certificate().context() == context)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum PlacementPhase {
    #[default]
    Absent,
    Fetching,
    Restoring,
    Replayed,
    Failed,
}

/// Last event-loop observation. Never a serialized admission capability.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PlacementObservation {
    phase: PlacementPhase,
    observed_at_unix_ms: u64,
    context: Option<EncryptionLocalityContext>,
    plan_digest: Option<AdmittedNodeLocalPlanDigest>,
    local_addresses: usize,
    journal_selected_attachments: usize,
    journal_selected_addresses: usize,
    journal_selected_payload_bytes: usize,
    source: Option<PlacementSource>,
    checkpoint_durable: bool,
}

pub(super) fn record_observation(cache: &PlacementCache, state: &AgentState, failed: bool) {
    let mut observation = PlacementObservation {
        observed_at_unix_ms: super::current_unix_time_milliseconds(),
        ..PlacementObservation::default()
    };
    if failed {
        observation.phase = PlacementPhase::Failed;
    } else if let Some((digest, evidence)) = &cache.candidate {
        observation.phase = PlacementPhase::Replayed;
        observation.context = Some(evidence.certificate().context().clone());
        observation.plan_digest = Some(*digest);
        observation.local_addresses = evidence.certificate().addresses().len();
        observation.source = cache.source;
        observation.checkpoint_durable = cache.checkpoint_durable;
        if let Some(selected) = &cache.attachments {
            (
                observation.journal_selected_attachments,
                observation.journal_selected_addresses,
                observation.journal_selected_payload_bytes,
            ) = selected.counts();
        }
    } else if let Some(pending) = &cache.pending {
        observation.phase = match pending.source {
            PlacementSource::Controller => PlacementPhase::Fetching,
            PlacementSource::PrivateCheckpoint => PlacementPhase::Restoring,
        };
        observation.context = Some(pending.context.clone());
        observation.plan_digest = Some(pending.plan_digest);
    }
    *state
        .locality_observation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = observation;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
// Independent observational claims, deliberately not mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub(super) struct PlacementStatus {
    schema_version: u16,
    scope: &'static str,
    acquisition: &'static str,
    observation: PlacementObservation,
    matches_reported_identity_and_routing: bool,
    dataplane_ready: bool,
    kernel_admitted: bool,
    observed_delivery: bool,
}

pub(super) async fn status(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<AgentState>>,
) -> axum::Json<PlacementStatus> {
    axum::Json(status_for(&state))
}

fn status_for(state: &AgentState) -> PlacementStatus {
    let observation = state
        .locality_observation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let matches_reported_identity_and_routing =
        observation.context.as_ref().is_some_and(|context| {
            context.recipient.node_name == state.node_name
                && context.identity_epoch != 0
                && state.applied_identity_epoch.load(Ordering::Acquire) == context.identity_epoch
                && state.desired_identity_epoch.load(Ordering::Acquire) == context.identity_epoch
                && state.applied_identity_revision.load(Ordering::Acquire)
                    == context.identity_revision.get()
                && state.desired_identity_revision.load(Ordering::Acquire)
                    == context.identity_revision.get()
                && state.applied_remote_route_epoch.load(Ordering::Acquire)
                    == context.identity_epoch
                && state.desired_remote_route_epoch.load(Ordering::Acquire)
                    == context.identity_epoch
                && state.applied_remote_route_revision.load(Ordering::Acquire)
                    == context.routing_revision.get()
                && state.desired_remote_route_revision.load(Ordering::Acquire)
                    == context.routing_revision.get()
        });
    PlacementStatus {
        schema_version: 1,
        scope: "localityPlacementCandidate",
        acquisition: "allAdmittedPlans",
        observation,
        matches_reported_identity_and_routing,
        dataplane_ready: state.ready.load(Ordering::Acquire),
        // These deliberately remain false until independent consuming and
        // delivery evidence exists. API reads cannot establish either fact.
        kernel_admitted: false,
        observed_delivery: false,
    }
}

pub(super) fn applied_context(
    plan: &AdmittedNodeLocalPlan,
    cluster_id: &str,
    state: &AgentState,
) -> Option<EncryptionLocalityContext> {
    // Pure-local Required demand need not create a remote Required transport
    // decision. Acquire topology for every exact admitted plan, including Native
    // and quiescent cuts; the policy-first packet path remains authoritative.
    if plan.snapshot.recipient.node_name != state.node_name {
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
    let result = synchronize_inner(plans, keys, state).await;
    if let Err(error) = result {
        plans.locality.clear().context(format!(
            "locality failed ({error:#}); withdrawal also failed"
        ))?;
        return Err(error);
    }
    Ok(())
}

async fn synchronize_inner(
    plans: &mut EncryptionPlanSynchronizer,
    keys: &EncryptionKeySynchronizer,
    state: &AgentState,
) -> Result<()> {
    let Some(plan) = plans.current.as_ref() else {
        plans.locality.clear()?;
        return Ok(());
    };
    let Some(authority) = keys
        .authority
        .as_ref()
        .map(unf_encryption::DurableNodeKeyAuthority::authority)
    else {
        plans.locality.clear()?;
        return Ok(());
    };
    if authority.node_uid() != plan.snapshot.recipient.node_uid
        || authority.node_name() != state.node_name
    {
        plans.locality.clear()?;
        bail!("locality bootstrap recipient differs from current plan");
    }
    let Some(context) = applied_context(plan, authority.cluster_id(), state) else {
        plans.locality.clear()?;
        return Ok(());
    };
    if plans.locality.matches(&context) {
        // Observational association only. Key rotation, policy or transport
        // generation changes do not invalidate independently replayed placement.
        if let Some((digest, _)) = &mut plans.locality.candidate {
            *digest = plan.admitted_digest;
        }
        refresh_attachments(&mut plans.locality, state, plan, &context).await?;
        return Ok(());
    }
    if let Some(pending) = &mut plans.locality.pending {
        pending.plan_digest = plan.admitted_digest;
        if pending.context != context {
            plans.locality.clear()?;
        } else if !pending.task.is_finished() {
            return Ok(());
        } else {
            let mut pending = plans
                .locality
                .pending
                .take()
                .context("finished locality task disappeared")?;
            let Some(result) = (&mut pending.task)
                .await
                .context("locality worker failed")??
            else {
                // No saved source: the next tick fetches with a fresh nonce.
                return Ok(());
            };
            let evidence = result.evidence;
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
            plans.locality.source = Some(result.source);
            plans.locality.checkpoint_durable = result.durable;
            refresh_attachments(&mut plans.locality, state, plan, &context).await?;
            return Ok(());
        }
    }
    // No last-known-good locality candidate survives a failed replacement. The
    // ordinary Required transport remains authoritative, entirely unchanged.
    plans.locality.clear()?;
    // A cancelled blocking replay retains this permit until it really exits.
    // Churn cannot build an unbounded queue of detached CPU jobs.
    let Ok(work_slot) = plans.locality.work_slot.clone().try_acquire_owned() else {
        return Ok(());
    };
    let digest = plan.admitted_digest;
    if !plans.locality.recovery_attempted {
        plans.locality.recovery_attempted = true;
        start_recovery(plans, context, digest, work_slot);
        return Ok(());
    }
    start_fetch(plans, context, digest, work_slot)
}

fn start_recovery(
    plans: &mut EncryptionPlanSynchronizer,
    context: EncryptionLocalityContext,
    plan_digest: AdmittedNodeLocalPlanDigest,
    work_slot: tokio::sync::OwnedSemaphorePermit,
) {
    let path = checkpoint::path(&plans.state_path);
    let expected = context.clone();
    let task = tokio::task::spawn_blocking(move || {
        let _work_slot = work_slot;
        let Some(bytes) = checkpoint::load(&path)? else {
            return Ok(None);
        };
        let evidence = unf_encryption::CapturedEncryptionLocality::replay_private_checkpoint(
            &bytes, &expected,
        )?;
        Ok(Some(PlacementResult {
            evidence,
            source: PlacementSource::PrivateCheckpoint,
            durable: true,
        }))
    });
    plans.locality.pending = Some(PendingPlacement {
        context,
        plan_digest,
        source: PlacementSource::PrivateCheckpoint,
        task: tokio::spawn(async move {
            task.await
                .context("locality checkpoint replay worker failed")?
        }),
    });
}

fn start_fetch(
    plans: &mut EncryptionPlanSynchronizer,
    context: EncryptionLocalityContext,
    plan_digest: AdmittedNodeLocalPlanDigest,
    work_slot: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
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
    let path = checkpoint::path(&plans.state_path);
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
            let (captured, evidence) = EncryptionLocalityResponse::capture_authenticated(&bytes, &request, &request.context)?;
            // The same bounded worker slot covers replay and durable I/O. A
            // cancelled write cannot race a new writer after releasing a slot.
            // A stale saved cut grants nothing: handoff and restart each require
            // the independently current full cut and fresh kernel observations.
            let durable = match checkpoint::save(&path, &captured, &request.context) {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(%error, "locality source checkpoint not durable; online candidate remains independently authenticated");
                    false
                }
            };
            Ok(Some(PlacementResult { evidence, source: PlacementSource::Controller, durable }))
        })
        .await
        .context("locality replay worker failed")?
    });
    plans.locality.pending = Some(PendingPlacement {
        context,
        plan_digest,
        source: PlacementSource::Controller,
        task,
    });
    Ok(())
}

async fn refresh_attachments(
    cache: &mut PlacementCache,
    state: &AgentState,
    plan: &AdmittedNodeLocalPlan,
    context: &EncryptionLocalityContext,
) -> Result<()> {
    let Some(inventory) = state.cni_inventory.get() else {
        cache.publisher.clear()?;
        cache.attachments = None;
        return Ok(());
    };
    let Some((_, evidence)) = &cache.candidate else {
        cache.publisher.clear()?;
        cache.attachments = None;
        return Ok(());
    };
    inventory
        .refresh(&mut cache.attachments, evidence, context)
        .await?;
    if applied_context(plan, &context.cluster_id, state).as_ref() != Some(context) {
        cache.attachments = None;
        bail!("applied locality cut changed during journal selection");
    }
    if let Some(selection) = &cache.attachments {
        cache
            .publisher
            .synchronize(state, plan, evidence, selection)
            .await?;
    }
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
