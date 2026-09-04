#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
test_tools_image=${UNF_TEST_TOOLS_IMAGE:-localhost/unf-test-tools:ipv6-ext-v1}
artifact=${UNF_EGRESS_INTERNET_KIND_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-internet-kind.json"}
namespace=unf-egress-internet-qualification
pool=unf-egress-internet
policy=unf-egress-internet
classification=unf-egress-internet
publisher_binding=unf-egress-internet-publisher
external_container=unf-egress-internet-external
gateway_label=network.unf.io/egress-gateway
started_unix_seconds=$(date +%s)
diagnostics_dir=${UNF_EGRESS_INTERNET_KIND_DIAGNOSTICS:-"${project_root}/.artifacts/phase8-egress-internet-kind-${started_unix_seconds}"}
qualification_stage=preflight
resources_created=false
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
runtime=(sudo "${container_runtime}")
publisher=("${kc[@]}" --as="system:serviceaccount:${namespace}:classifier")

classification_state() {
    "${kc[@]}" -n unf-system get configmap unf-egress-desired-state -o json \
        | jq -er '.data["internet-classifications.json"] | fromjson'
}

controller_status() {
    local pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy/v1/status"
}

collect_diagnostics() {
    mkdir -p "${diagnostics_dir}"
    "${kc[@]}" get nodes -o json >"${diagnostics_dir}/nodes.json" 2>/dev/null || true
    "${kc[@]}" get egresspools.network.unf.io,egresspolicies.network.unf.io,egressinternetclassifications.network.unf.io -o yaml \
        >"${diagnostics_dir}/egress-resources.yaml" 2>/dev/null || true
    "${kc[@]}" -n unf-system get pods -o wide >"${diagnostics_dir}/unf-pods.txt" 2>/dev/null || true
    "${kc[@]}" -n unf-system logs deployment/unf-controller --all-pods=true \
        >"${diagnostics_dir}/controller.log" 2>&1 || true
    "${kc[@]}" -n unf-system logs daemonset/unf-agent --all-pods=true --prefix \
        >"${diagnostics_dir}/agents.log" 2>&1 || true
    classification_state >"${diagnostics_dir}/classification-store.json" 2>/dev/null || true
    "${runtime[@]}" inspect "${external_container}" \
        >"${diagnostics_dir}/external-container.json" 2>/dev/null || true
    "${runtime[@]}" logs "${external_container}" \
        >"${diagnostics_dir}/external-container.log" 2>&1 || true
}

cleanup() {
    if [[ ${resources_created} == true ]]; then
        "${kc[@]}" delete egressinternetclassification.network.unf.io "${classification}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete egresspool.network.unf.io "${pool}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete clusterrolebinding "${publisher_binding}" --ignore-not-found >/dev/null 2>&1 || true
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" label node "${gateway_node:-missing}" "${gateway_label}-" >/dev/null 2>&1 || true
    fi
    "${runtime[@]}" rm -f "${external_container}" >/dev/null 2>&1 || true
}

report_failure() {
    local status=$?
    trap - ERR
    collect_diagnostics
    echo "Phase 8.7f Kind internet lifecycle failed during ${qualification_stage}: ${BASH_COMMAND}" >&2
    echo "diagnostics: ${diagnostics_dir}" >&2
    exit "${status}"
}

trap report_failure ERR
trap cleanup EXIT

for command in kubectl jq sudo "${container_runtime}"; do
    command -v "${command}" >/dev/null
done
[[ ${context} == kind-* ]]
[[ $("${kc[@]}" config current-context) == "${context}" ]]
! "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1
"${kc[@]}" get crd egressinternetclassifications.network.unf.io >/dev/null
"${kc[@]}" get clusterrole unf-internet-classifier-publisher >/dev/null
[[ $("${kc[@]}" get egresspolicies.network.unf.io -o json | jq '.items | length') == 0 ]]
[[ $("${kc[@]}" get egresspools.network.unf.io -o json | jq '.items | length') == 0 ]]
[[ $("${kc[@]}" get egressinternetclassifications.network.unf.io -o json | jq '.items | length') == 0 ]]
! "${kc[@]}" get namespace "${namespace}" >/dev/null 2>&1
! "${kc[@]}" get clusterrolebinding "${publisher_binding}" >/dev/null 2>&1
! "${runtime[@]}" container exists "${external_container}"
"${runtime[@]}" image exists "${test_tools_image}"

mapfile -t nodes < <("${kc[@]}" get nodes -o name | sed 's|node/||' | sort)
(( ${#nodes[@]} == 3 ))
source_node=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].metadata.name}')
mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' -o name | sed 's|node/||' | sort)
(( ${#workers[@]} == 2 ))
gateway_node=${workers[1]}
nodes_json=$("${kc[@]}" get nodes -o json)
jq -e 'all(.items[]; any(.status.conditions[]; .type == "Ready" and .status == "True"))' <<<"${nodes_json}" >/dev/null
jq -e 'all(.items[]; .metadata.labels["network.unf.io/primary-cni"] == "enabled")' <<<"${nodes_json}" >/dev/null
source_json=$(jq -c --arg node "${source_node}" '.items[] | select(.metadata.name == $node)' <<<"${nodes_json}")
source_v4=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address' <<<"${source_json}")
source_v6=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")))][0].address' <<<"${source_json}")
ipv4_prefix=${source_v4%.*}
ipv6_prefix=${source_v6%::*}
allowed_v4=${ipv4_prefix}.223
allowed_v6=${ipv6_prefix}::df
exception_v4=${ipv4_prefix}.224
exception_v6=${ipv6_prefix}::e0
unknown_v4=${ipv4_prefix}.225
unknown_v6=${ipv6_prefix}::e1
private_v4=${ipv4_prefix}.226
private_v6=${ipv6_prefix}::e2
egress_v4=${ipv4_prefix}.240
egress_v6=${ipv6_prefix}::f0

qualification_stage=publisher-rbac
"${kc[@]}" create namespace "${namespace}" >/dev/null
resources_created=true
"${kc[@]}" -n "${namespace}" create serviceaccount classifier >/dev/null
"${kc[@]}" create clusterrolebinding "${publisher_binding}" \
    --clusterrole=unf-internet-classifier-publisher \
    --serviceaccount="${namespace}:classifier" >/dev/null
[[ $("${publisher[@]}" auth can-i create egressinternetclassifications.network.unf.io) == yes ]]
[[ $("${kc[@]}" auth can-i list egressinternetclassifications.network.unf.io \
    --as=system:serviceaccount:unf-system:unf-controller) == yes ]]
agent_publish_permission=$("${kc[@]}" auth can-i create egressinternetclassifications.network.unf.io \
    --as=system:serviceaccount:unf-system:unf-agent 2>/dev/null || true)
[[ ${agent_publish_permission} == no ]]

qualification_stage=dual-stack-fixture
"${runtime[@]}" run -d --name "${external_container}" --network kind \
    --ip "${allowed_v4}" --ip6 "${allowed_v6}" --mac-address 02:55:4e:46:08:08 \
    --cap-add NET_ADMIN --entrypoint /bin/sh "${test_tools_image}" -ec \
    "ip address add ${exception_v4}/24 dev eth0; ip -6 address add ${exception_v6}/64 dev eth0; \
     ip address add ${unknown_v4}/24 dev eth0; ip -6 address add ${unknown_v6}/64 dev eth0; \
     ip address add ${private_v4}/24 dev eth0; ip -6 address add ${private_v6}/64 dev eth0; \
     /usr/bin/socat UDP4-RECVFROM:18082,bind=${allowed_v4},reuseaddr,fork EXEC:/bin/cat & \
     /usr/bin/socat UDP4-RECVFROM:18082,bind=${exception_v4},reuseaddr,fork EXEC:/bin/cat & \
     /usr/bin/socat UDP4-RECVFROM:18082,bind=${unknown_v4},reuseaddr,fork EXEC:/bin/cat & \
     /usr/bin/socat UDP4-RECVFROM:18082,bind=${private_v4},reuseaddr,fork EXEC:/bin/cat & \
     /usr/bin/socat UDP6-RECVFROM:18082,bind=[${allowed_v6}],ipv6only=1,reuseaddr,fork EXEC:/bin/cat & \
     /usr/bin/socat UDP6-RECVFROM:18082,bind=[${exception_v6}],ipv6only=1,reuseaddr,fork EXEC:/bin/cat & \
     /usr/bin/socat UDP6-RECVFROM:18082,bind=[${unknown_v6}],ipv6only=1,reuseaddr,fork EXEC:/bin/cat & \
     exec /usr/bin/socat UDP6-RECVFROM:18082,bind=[${private_v6}],ipv6only=1,reuseaddr,fork EXEC:/bin/cat" >/dev/null
for node in "${nodes[@]}"; do
    for address in "${allowed_v4}" "${exception_v4}" "${unknown_v4}" "${private_v4}"; do
        "${runtime[@]}" exec "${node}" ip neigh del "${address}" dev eth0 >/dev/null 2>&1 || true
    done
    for address in "${allowed_v6}" "${exception_v6}" "${unknown_v6}" "${private_v6}"; do
        "${runtime[@]}" exec "${node}" ip -6 neigh del "${address}" dev eth0 >/dev/null 2>&1 || true
    done
done
while IFS=$'\t' read -r node_v4 node_v6 pod_v4 pod_v6; do
    "${runtime[@]}" exec "${external_container}" ip route replace "${pod_v4}" via "${node_v4}"
    "${runtime[@]}" exec "${external_container}" ip -6 route replace "${pod_v6}" via "${node_v6}"
done < <(jq -r '.items[] |
    ([.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address) as $v4 |
    ([.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")))][0].address) as $v6 |
    ([.spec.podCIDRs[] | select(contains("."))][0]) as $pod4 |
    ([.spec.podCIDRs[] | select(contains(":"))][0]) as $pod6 |
    [$v4,$v6,$pod4,$pod6] | @tsv' <<<"${nodes_json}")

qualification_stage=internet-intent
"${kc[@]}" label node "${gateway_node}" "${gateway_label}=enabled" --overwrite >/dev/null
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: managed
  namespace: ${namespace}
  labels: {app: managed}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_node}}
  tolerations: [{operator: Exists}]
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: network.unf.io/v1alpha1
kind: EgressPool
metadata: {name: ${pool}}
spec:
  provider: {name: static, instance: kind-internet}
  prefixes: [${egress_v4}/32, ${egress_v6}/128]
---
apiVersion: network.unf.io/v1alpha1
kind: EgressPolicy
metadata: {name: ${policy}}
spec:
  priority: 100
  target:
    namespaceSelector:
      matchLabels: {kubernetes.io/metadata.name: ${namespace}}
    workloadSelector:
      matchLabels: {app: managed}
    serviceAccounts: [default]
  destinations:
    internet:
      classifier: {name: route-authority, instance: kind-global}
      exceptions: [${exception_v4}/32, ${exception_v6}/128]
      fallback: LastKnownGood
      maxStalenessSeconds: 20
  egress:
    pool: ${pool}
    families: [IPv4, IPv6]
    addressesPerFamily: 1
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/managed --timeout=120s

publish_classification() {
    local revision=$1 validity=$2 provenance=$3 now valid_until
    now=$(date +%s)
    valid_until=$((now + validity))
    "${publisher[@]}" apply -f - >/dev/null <<EOF
apiVersion: network.unf.io/v1alpha1
kind: EgressInternetClassification
metadata: {name: ${classification}}
spec:
  classifier: {name: route-authority, instance: kind-global}
  sourceEpoch: ${started_unix_seconds}
  revision: ${revision}
  observedAtUnixSeconds: ${now}
  validUntilUnixSeconds: ${valid_until}
  rules:
    - {prefix: ${allowed_v4}/32, class: Internet, provenance: "${provenance}:allowed-v4"}
    - {prefix: ${allowed_v6}/128, class: Internet, provenance: "${provenance}:allowed-v6"}
    - {prefix: ${exception_v4}/32, class: Internet, provenance: "${provenance}:exception-v4"}
    - {prefix: ${exception_v6}/128, class: Internet, provenance: "${provenance}:exception-v6"}
    - {prefix: ${private_v4}/32, class: NonInternet, provenance: "${provenance}:private-v4"}
    - {prefix: ${private_v6}/128, class: NonInternet, provenance: "${provenance}:private-v6"}
EOF
}

wait_for_authority() {
    local authority=$1 current=$2 state
    for _ in $(seq 1 120); do
        state=$(classification_state 2>/dev/null || true)
        if jq -e --arg authority "${authority}" --argjson current "${current}" '
            (.current | length) == $current and (.snapshots | length) == 1
            and .snapshots[0].authority.state == $authority
        ' <<<"${state}" >/dev/null 2>&1; then
            printf '%s\n' "${state}"
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_activation() {
    local status=
    for _ in $(seq 1 180); do
        status=$(controller_status 2>/dev/null || true)
        if jq -e '.egress_source_applications == 1
            and .egress_gateway_applications >= 1
            and .egress_activation_ready_sources == 1' <<<"${status}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "internet intent did not reach bilateral activation" >&2
    jq . <<<"${status}" >&2 || true
    return 1
}

probe() {
    local address=$1 family=$2 expected=$3 marker=$4 output=
    local attempts=30 timeout=3 consecutive_denies=0
    if [[ ${expected} == deny ]]; then attempts=10; timeout=1; fi
    for _ in $(seq 1 "${attempts}"); do
        if [[ ${family} == 4 ]]; then
            output=$("${kc[@]}" -n "${namespace}" exec managed -- sh -ec \
                "printf '${marker}' | socat -T ${timeout} - UDP4:${address}:18082" 2>/dev/null || true)
        else
            output=$("${kc[@]}" -n "${namespace}" exec managed -- sh -ec \
                "printf '${marker}' | socat -T ${timeout} - UDP6:[${address}]:18082" 2>/dev/null || true)
        fi
        if [[ ${expected} == allow && ${output} == "${marker}" ]]; then return 0; fi
        if [[ ${expected} == deny ]]; then
            if [[ ${output} == "${marker}" ]]; then
                consecutive_denies=0
            else
                consecutive_denies=$((consecutive_denies + 1))
                if (( consecutive_denies == 2 )); then return 0; fi
            fi
        fi
        sleep 1
    done
    if [[ ${expected} == deny ]]; then
        echo "deny probe never converged: family=IPv${family} destination=${address}:18082 marker=${marker}" >&2
        return 1
    fi
    echo "allow probe failed: family=IPv${family} destination=${address}:18082 marker=${marker} output=${output@Q}" >&2
    return 1
}

assert_matrix() {
    local allowed=$1 suffix=$2 failed=false pid
    local pids=()
    (trap - ERR; probe "${allowed_v4}" 4 "${allowed}" "allowed-v4-${suffix}") & pids+=("$!")
    (trap - ERR; probe "${allowed_v6}" 6 "${allowed}" "allowed-v6-${suffix}") & pids+=("$!")
    (trap - ERR; probe "${exception_v4}" 4 deny "exception-v4-${suffix}") & pids+=("$!")
    (trap - ERR; probe "${exception_v6}" 6 deny "exception-v6-${suffix}") & pids+=("$!")
    (trap - ERR; probe "${unknown_v4}" 4 deny "unknown-v4-${suffix}") & pids+=("$!")
    (trap - ERR; probe "${unknown_v6}" 6 deny "unknown-v6-${suffix}") & pids+=("$!")
    (trap - ERR; probe "${private_v4}" 4 deny "private-v4-${suffix}") & pids+=("$!")
    (trap - ERR; probe "${private_v6}" 6 deny "private-v6-${suffix}") & pids+=("$!")
    for pid in "${pids[@]}"; do
        if ! wait "${pid}"; then failed=true; fi
    done
    [[ ${failed} == false ]]
}

qualification_stage=current-authority
publish_classification 1 100 fixture-v1
current_state=$(wait_for_authority current 1)
wait_for_activation
assert_matrix allow current
current_digest=$(jq -c '.snapshots[0].digest' <<<"${current_state}")

qualification_stage=durable-loss-and-fallback
"${publisher[@]}" delete egressinternetclassification.network.unf.io "${classification}" --wait=true >/dev/null
fallback_state=$(wait_for_authority lastKnownGood 0)
[[ $(jq -c '.snapshots[0].authority.previous_snapshot_digest' <<<"${fallback_state}") == "${current_digest}" ]]
assert_matrix allow fallback

qualification_stage=controller-restart-during-fallback
"${kc[@]}" -n unf-system rollout restart deployment/unf-controller >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s >/dev/null
restart_state=$(wait_for_authority lastKnownGood 0)
[[ $(jq -c '.snapshots[0].authority.previous_snapshot_digest' <<<"${restart_state}") == "${current_digest}" ]]
assert_matrix allow restart

qualification_stage=autonomous-expiry
deny_state=$(wait_for_authority denyClosed 0)
assert_matrix deny expired

qualification_stage=replay-and-mutation-rejection
publish_classification 1 90 replayed-v1
sleep 4
replay_state=$(classification_state)
[[ $(jq '.current | length' <<<"${replay_state}") == 0 ]]
"${publisher[@]}" delete egressinternetclassification.network.unf.io "${classification}" --wait=true >/dev/null

qualification_stage=authority-recovery
publish_classification 2 120 fixture-v2
recovered_state=$(wait_for_authority current 1)
assert_matrix allow recovered
recovered_digest=$(jq -c '.snapshots[0].digest' <<<"${recovered_state}")
publish_classification 2 120 mutated-v2
sleep 4
mutation_state=$(classification_state)
[[ $(jq -c '.snapshots[0].digest' <<<"${mutation_state}") == "${recovered_digest}" ]]

qualification_stage=evidence
collect_diagnostics
mkdir -p "$(dirname "${artifact}")"
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "$(git -C "${project_root}" rev-parse HEAD)" \
    --arg context "${context}" --arg source "${source_node}" --arg gateway "${gateway_node}" \
    --arg allowedV4 "${allowed_v4}" --arg allowedV6 "${allowed_v6}" \
    --arg exceptionV4 "${exception_v4}" --arg exceptionV6 "${exception_v6}" \
    --arg unknownV4 "${unknown_v4}" --arg unknownV6 "${unknown_v6}" \
    --arg privateV4 "${private_v4}" --arg privateV6 "${private_v6}" \
    --argjson current "${current_state}" --argjson fallback "${fallback_state}" \
    --argjson restart "${restart_state}" --argjson denied "${deny_state}" \
    --argjson recovered "${recovered_state}" \
    '{schemaVersion:1,generatedAt:$generatedAt,revision:$revision,context:$context,
      topology:{sourceNode:$source,gatewayNode:$gateway},
      destinations:{allowed:[$allowedV4,$allowedV6],exceptions:[$exceptionV4,$exceptionV6],
        unknown:[$unknownV4,$unknownV6],private:[$privateV4,$privateV6]},
      checkpoints:{current:$current,fallback:$fallback,restart:$restart,denyClosed:$denied,recovered:$recovered},
      verified:["Kubernetes-authenticated classifier publisher RBAC","agent publisher denial",
        "durable-before-distribution sealed checkpoint","dual-stack current Internet traffic",
        "absolute policy exceptions","provider NonInternet denial","unknown-space denial",
        "explicit digest-linked bounded LKG","controller restart during fallback",
        "autonomous packet deadline and deny-closed convergence","revision replay rejection",
        "same-position mutation rejection","higher-revision recovery","cross-Node gateway NAT"]}' \
    >"${artifact}.tmp"
mv "${artifact}.tmp" "${artifact}"

"${publisher[@]}" delete egressinternetclassification.network.unf.io "${classification}" --ignore-not-found --wait=true >/dev/null
"${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --wait=true >/dev/null
"${kc[@]}" delete egresspool.network.unf.io "${pool}" --wait=true >/dev/null
"${kc[@]}" delete clusterrolebinding "${publisher_binding}" >/dev/null
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=120s >/dev/null
"${kc[@]}" label node "${gateway_node}" "${gateway_label}-" >/dev/null
resources_created=false
"${runtime[@]}" rm -f "${external_container}" >/dev/null
trap - ERR EXIT
echo "Phase 8.7f dual-stack Kind internet lifecycle passed; evidence: ${artifact}; diagnostics: ${diagnostics_dir}"
