#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
artifact=${UNF_EGRESS_REACHABILITY_KIND_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-reachability-kind.json"}
plan_name=unf-dqr-lifecycle
observer_a_namespace=unf-dqr-observer-a
observer_b_namespace=unf-dqr-observer-b
started=$(date +%s)
stage=preflight
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

reachability_state() {
    "${kc[@]}" -n unf-system get configmap unf-egress-desired-state -o json \
        | jq -er '.data["reachability-evidence.json"] | fromjson'
}

collect_diagnostics() {
    local diagnostics="${project_root}/.artifacts/phase8-egress-reachability-kind-${started}"
    mkdir -p "${diagnostics}"
    "${kc[@]}" get egressreachabilityplans.network.unf.io -o yaml \
        >"${diagnostics}/plans.yaml" 2>&1 || true
    "${kc[@]}" get egressreachabilityobservations.network.unf.io -A -o yaml \
        >"${diagnostics}/observations.yaml" 2>&1 || true
    reachability_state >"${diagnostics}/store.json" 2>&1 || true
    "${kc[@]}" -n unf-system logs deployment/unf-controller --all-pods=true \
        >"${diagnostics}/controller.log" 2>&1 || true
    echo "diagnostics: ${diagnostics}" >&2
}

cleanup() {
    "${kc[@]}" delete egressreachabilityplan.network.unf.io "${plan_name}" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
    "${kc[@]}" delete namespace "${observer_a_namespace}" "${observer_b_namespace}" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

report_failure() {
    local status=$?
    if (( BASH_SUBSHELL > 0 )); then
        trap - ERR
        return "${status}"
    fi
    trap - ERR
    echo "Phase 8.8b Kind DQR lifecycle failed during ${stage}: ${BASH_COMMAND}" >&2
    collect_diagnostics
    exit "${status}"
}

trap report_failure ERR
trap cleanup EXIT

wait_for_state() {
    local expression=$1 state=
    for _ in $(seq 1 120); do
        state=$(reachability_state 2>/dev/null || true)
        if jq -e "${expression}" <<<"${state}" >/dev/null 2>&1; then
            printf '%s\n' "${state}"
            return 0
        fi
        sleep 1
    done
    return 1
}

apply_observer_identity() {
    local namespace=$1 observer=$2 domain=$3
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: network.unf.io/v1alpha1
kind: EgressReachabilityObservation
metadata:
  name: witness
  namespace: ${namespace}
spec:
  planName: ${plan_name}
  plan:
    revision: 1
    desiredRevision: 7
    allocationRevision: 6
    ownerName: qualification
    ownerUid: qualification-uid
    provider: {name: bgp, instance: qualification}
    leaseEpoch: 5
    action: Ensure
    addresses: [192.0.2.240, "2001:db8::240"]
    expectedPaths:
      - {gatewayUid: gateway-a, forwardingIdentity: edge-a}
      - {gatewayUid: gateway-b, forwardingIdentity: edge-b}
    minimumPathsPerAddress: 2
    maximumPathsPerAddress: 2
    vantages: [{name: outside, minimumFailureDomains: 2}]
    maxObservationAgeSeconds: 60
  observer: ${observer}
  failureDomain: ${domain}
  vantage: outside
EOF
}

publish_status() {
    local namespace=$1 epoch=$2 revision=$3 expires=$4 paths_mode=${5:-complete}
    local paths
    if [[ ${paths_mode} == complete ]]; then
        paths='[{"gatewayUid":"gateway-a","forwardingIdentity":"edge-a"},{"gatewayUid":"gateway-b","forwardingIdentity":"edge-b"}]'
    else
        paths='[{"gatewayUid":"foreign","forwardingIdentity":"foreign"}]'
    fi
    local patch
    patch=$(jq -nc \
        --arg digest "${plan_digest}" \
        --argjson epoch "${epoch}" \
        --argjson revision "${revision}" \
        --argjson observed "$(date +%s)" \
        --argjson expires "${expires}" \
        --argjson paths "${paths}" \
        '{status:{sourceEpoch:$epoch,revision:$revision,planDigest:$digest,
          observedAtUnixSeconds:$observed,validUntilUnixSeconds:$expires,
          routes:[{address:"192.0.2.240",paths:$paths},{address:"2001:db8::240",paths:$paths}]}}')
    "${kc[@]}" --as="system:serviceaccount:${namespace}:observer" -n "${namespace}" \
        patch egressreachabilityobservation.network.unf.io witness --subresource=status \
        --type=merge -p "${patch}" >/dev/null
}

for command in kubectl jq; do command -v "${command}" >/dev/null; done
[[ ${context} == kind-* ]]
[[ $("${kc[@]}" config current-context) == "${context}" ]]
! "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1
"${kc[@]}" get crd egressreachabilityplans.network.unf.io >/dev/null
"${kc[@]}" get crd egressreachabilityobservations.network.unf.io >/dev/null
"${kc[@]}" get clusterrole unf-reachability-observer >/dev/null
[[ $("${kc[@]}" get egressreachabilityplans.network.unf.io -o json | jq '.items | length') == 0 ]]
[[ $("${kc[@]}" get egressreachabilityobservations.network.unf.io -A -o json | jq '.items | length') == 0 ]]

stage=identity-rbac
for namespace in "${observer_a_namespace}" "${observer_b_namespace}"; do
    "${kc[@]}" create namespace "${namespace}" >/dev/null
    "${kc[@]}" -n "${namespace}" create serviceaccount observer >/dev/null
    "${kc[@]}" -n "${namespace}" create rolebinding dqr-observer \
        --clusterrole=unf-reachability-observer --serviceaccount="${namespace}:observer" >/dev/null
done
observer_a=("${kc[@]}" --as="system:serviceaccount:${observer_a_namespace}:observer" -n "${observer_a_namespace}")
[[ $("${observer_a[@]}" auth can-i patch egressreachabilityobservations.network.unf.io --subresource=status) == yes ]]
[[ $("${observer_a[@]}" auth can-i get egressreachabilityobservations.network.unf.io) == yes ]]
[[ $("${observer_a[@]}" auth can-i create egressreachabilityobservations.network.unf.io || true) == no ]]
[[ $("${observer_a[@]}" auth can-i patch egressreachabilityobservations.network.unf.io || true) == no ]]
[[ $("${kc[@]}" auth can-i patch egressreachabilityobservations.network.unf.io \
    --subresource=status --as=system:serviceaccount:unf-system:unf-agent \
    -n "${observer_a_namespace}" || true) == no ]]

stage=controller-plan
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: network.unf.io/v1alpha1
kind: EgressReachabilityPlan
metadata: {name: ${plan_name}}
spec:
  revision: 1
  desiredRevision: 7
  allocationRevision: 6
  ownerName: qualification
  ownerUid: qualification-uid
  provider: {name: bgp, instance: qualification}
  leaseEpoch: 5
  action: Ensure
  addresses: [192.0.2.240, "2001:db8::240"]
  expectedPaths:
    - {gatewayUid: gateway-a, forwardingIdentity: edge-a}
    - {gatewayUid: gateway-b, forwardingIdentity: edge-b}
  minimumPathsPerAddress: 2
  maximumPathsPerAddress: 2
  vantages: [{name: outside, minimumFailureDomains: 2}]
  maxObservationAgeSeconds: 60
EOF
plan_state=$(wait_for_state '.currentPlans | length == 1')
plan_digest=
while read -r byte; do printf -v plan_digest '%s%02x' "${plan_digest}" "${byte}"; done \
    < <(jq -r '.currentPlans[0].plan.digest[]' <<<"${plan_state}")
[[ ${#plan_digest} == 64 ]]

stage=observer-status-quorum
apply_observer_identity "${observer_a_namespace}" witness-a rack-a
apply_observer_identity "${observer_b_namespace}" witness-b rack-b
valid_until=$(( $(date +%s) + 60 ))
publish_status "${observer_a_namespace}" "${started}" 1 "${valid_until}"
publish_status "${observer_b_namespace}" "${started}" 1 "${valid_until}"
ready_state=$(wait_for_state '(.currentObservations | length) == 2 and .assessments[0].verdict == "ready"')
ready_revision=$(jq -er '.revision' <<<"${ready_state}")

stage=restart-recovery
"${kc[@]}" -n unf-system rollout restart deployment/unf-controller >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
restart_state=$(wait_for_state '(.currentObservations | length) == 2 and .assessments[0].verdict == "ready"')
(( $(jq -er '.revision' <<<"${restart_state}") >= ready_revision ))

stage=autonomous-expiry
short_until=$(( $(date +%s) + 8 ))
publish_status "${observer_a_namespace}" "${started}" 2 "${short_until}"
publish_status "${observer_b_namespace}" "${started}" 2 "${short_until}"
short_ready_state=$(wait_for_state '(.currentObservations | length) == 2 and .assessments[0].verdict == "ready"')
short_ready_revision=$(jq -er '.revision' <<<"${short_ready_state}")
expired_state=$(wait_for_state '(.currentObservations | length) == 2 and .assessments[0].verdict == "denyClosed"')
expired_revision=$(jq -er '.revision' <<<"${expired_state}")
(( expired_revision > short_ready_revision ))

stage=replay-and-recovery
publish_status "${observer_a_namespace}" "$((started - 1))" 99 "$(( $(date +%s) + 25 ))"
sleep 3
[[ $(reachability_state | jq -er '.currentObservations[] | select(.observation.observer.name == "witness-a") | .observation.revision') == 2 ]]
publish_status "${observer_a_namespace}" "${started}" 2 "$(( $(date +%s) + 25 ))" foreign
sleep 3
[[ $(reachability_state | jq -er '.currentObservations[] | select(.observation.observer.name == "witness-a") | .observation.revision') == 2 ]]
recovery_until=$(( $(date +%s) + 25 ))
publish_status "${observer_a_namespace}" "${started}" 3 "${recovery_until}"
publish_status "${observer_b_namespace}" "${started}" 3 "${recovery_until}"
recovered_state=$(wait_for_state '(.currentObservations | length) == 2 and .assessments[0].verdict == "ready"')

stage=exact-cleanup
"${kc[@]}" -n "${observer_a_namespace}" delete egressreachabilityobservation witness --wait=true >/dev/null
"${kc[@]}" -n "${observer_b_namespace}" delete egressreachabilityobservation witness --wait=true >/dev/null
"${kc[@]}" delete egressreachabilityplan "${plan_name}" --wait=true >/dev/null
clean_state=$(wait_for_state '(.currentPlans | length) == 0 and (.currentObservations | length) == 0 and (.assessments | length) == 0')
[[ $(jq '.latestPlans | length' <<<"${clean_state}") == 1 ]]
[[ $(jq '.latestObservations | length' <<<"${clean_state}") == 2 ]]

mkdir -p "$(dirname "${artifact}")"
jq -n \
    --argjson readyRevision "${ready_revision}" \
    --argjson expiredRevision "${expired_revision}" \
    --argjson recoveredRevision "$(jq -er '.revision' <<<"${recovered_state}")" \
    --arg planDigest "${plan_digest}" \
    '{schemaVersion:1,milestone:"8.8b",algorithm:"diversity-quorum-reachability-v1",
      rbac:{statusOnly:true,dedicatedObserverNamespaces:2,agentDenied:true},
      lifecycle:{readyRevision:$readyRevision,restartRecovered:true,
        autonomousExpiryRevision:$expiredRevision,replayRejected:true,
        samePositionMutationRejected:true,recoveredRevision:$recoveredRevision,
        currentCleanupExact:true,replayPositionsRetained:true},planDigest:$planDigest}' >"${artifact}"

echo "Phase 8.8b Kind DQR lifecycle passed; evidence: ${artifact}"
