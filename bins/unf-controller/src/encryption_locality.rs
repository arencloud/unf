//! Read-only placement distribution. No generation publication or kernel
//! admission occurs here; current agent authentication is mandatory.

use super::{
    ApiError, Arc, AuthenticatedAgent, ControllerState, HeaderMap, Json, State,
    authenticate_internal_agent, encryption_generation_membership, encryption_nodes,
    encryption_workloads, mutex_lock, read_lock, require_current_encryption_agent,
};
use unf_encryption::{
    EncryptionLocalityContext, EncryptionLocalityRequest, EncryptionLocalityResponse,
};

pub(super) async fn snapshot(
    State(state): State<Arc<ControllerState>>,
    headers: HeaderMap,
    Json(request): Json<EncryptionLocalityRequest>,
) -> Result<Json<EncryptionLocalityResponse>, ApiError> {
    let agent = authenticate_internal_agent(&state, &headers).await?;
    snapshot_for(&state, &agent, &request).map(Json)
}

pub(super) fn snapshot_for(
    state: &ControllerState,
    agent: &AuthenticatedAgent,
    request: &EncryptionLocalityRequest,
) -> Result<EncryptionLocalityResponse, ApiError> {
    request
        .verify()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    // Watchers use the write side of this guard. Authentication freshness,
    // membership, revisions and replay facts must describe the same cut.
    let _cut = read_lock(&state.policy_state_guard);
    if !state.ready.load(std::sync::atomic::Ordering::Acquire) {
        return Err(ApiError::service_unavailable(
            "locality informer cut is not ready",
        ));
    }
    require_current_encryption_agent(state, agent)?;
    let (membership_revision, members) = encryption_generation_membership(state)?;
    let recipient = members
        .iter()
        .find(|member| member.node_name == agent.node_name)
        .ok_or_else(|| ApiError::forbidden("agent is outside locality membership"))?;
    if request.context.recipient != *recipient
        || request.context.cluster_id != state.encryption_cluster_id
    {
        return Err(ApiError::forbidden(
            "locality request targets a foreign cluster or Node incarnation",
        ));
    }
    // Unlike plan initialization, do not promote zero revisions into apparent
    // applied truth. An uninitialized cut must not issue locality evidence.
    let current = EncryptionLocalityContext {
        cluster_id: state.encryption_cluster_id.clone(),
        recipient: recipient.clone(),
        membership_revision,
        identity_epoch: state.identity_epoch,
        identity_revision: mutex_lock(&state.identities).revision(),
        routing_revision: mutex_lock(&state.revisions).routing,
    };
    if request.context != current {
        return Err(ApiError::service_unavailable(
            "locality request does not match the current placement cut",
        ));
    }
    EncryptionLocalityResponse::issue(
        request,
        &current,
        encryption_nodes(state, &members)?,
        encryption_workloads(state, &members),
    )
    .map_err(|error| ApiError::service_unavailable(error.to_string()))
}
