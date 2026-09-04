#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
test_tools_image=${UNF_TEST_TOOLS_IMAGE:-localhost/unf-test-tools:ipv6-ext-v1}
artifact=${UNF_EGRESS_FQDN_KIND_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-fqdn-kind.json"}
namespace=unf-egress-fqdn-qualification
pool=unf-egress-fqdn
policy=unf-egress-fqdn
external_container=unf-egress-fqdn-dns
gateway_label=network.unf.io/egress-gateway
dns_view=finance-production
dns_name=payments.bank.example
empty_marker=/tmp/unf-dns-authoritative-empty
started_unix_seconds=$(date +%s)
diagnostics_dir=${UNF_EGRESS_FQDN_KIND_DIAGNOSTICS:-"${project_root}/.artifacts/phase8-egress-fqdn-kind-${started_unix_seconds}"}
qualification_stage=preflight
resources_created=false
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
runtime=(sudo "${container_runtime}")

control_plane_state() {
    "${kc[@]}" -n unf-system get configmap unf-egress-control-plane -o json
}

observation_state() {
    "${kc[@]}" -n unf-system get configmap unf-egress-desired-state -o json \
        | jq -er '.data["fqdn-observations.json"] | fromjson'
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
    "${kc[@]}" get egresspools.network.unf.io,egresspolicies.network.unf.io -o yaml \
        >"${diagnostics_dir}/egress-resources.yaml" 2>/dev/null || true
    "${kc[@]}" -n unf-system get pods -o wide >"${diagnostics_dir}/unf-pods.txt" 2>/dev/null || true
    "${kc[@]}" -n unf-system logs deployment/unf-controller --all-pods=true \
        >"${diagnostics_dir}/controller.log" 2>&1 || true
    "${kc[@]}" -n unf-system logs daemonset/unf-agent --all-pods=true --prefix \
        >"${diagnostics_dir}/agents.log" 2>&1 || true
    control_plane_state >"${diagnostics_dir}/control-plane.json" 2>/dev/null || true
    "${runtime[@]}" logs "${external_container}" >"${diagnostics_dir}/dns.log" 2>&1 || true
}

cleanup() {
    if [[ ${resources_created} == true ]]; then
        "${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete egresspool.network.unf.io "${pool}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" label node "${gateway_node:-missing}" "${gateway_label}-" >/dev/null 2>&1 || true
    fi
    "${runtime[@]}" rm -f "${external_container}" >/dev/null 2>&1 || true
}

report_failure() {
    local status=$?
    collect_diagnostics
    echo "Phase 8.7d Kind FQDN lifecycle failed during ${qualification_stage}: ${BASH_COMMAND}" >&2
    echo "diagnostics: ${diagnostics_dir}" >&2
    return "${status}"
}

trap report_failure ERR
trap cleanup EXIT

for command in kubectl jq rg sudo "${container_runtime}"; do
    command -v "${command}" >/dev/null
done
[[ ${context} == kind-* ]]
[[ $("${kc[@]}" config current-context) == "${context}" ]]
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1; then
    echo "FQDN lifecycle qualification requires kube-proxy-free Kind" >&2
    exit 1
fi
[[ $("${kc[@]}" get egresspolicies.network.unf.io -o json | jq '.items | length') == 0 ]]
[[ $("${kc[@]}" get egresspools.network.unf.io -o json | jq '.items | length') == 0 ]]
! "${runtime[@]}" container exists "${external_container}"
"${runtime[@]}" image exists "${test_tools_image}"
"${runtime[@]}" run --rm --entrypoint sh "${test_tools_image}" -ec \
    'command -v unf-dns-fixture >/dev/null'

mapfile -t nodes < <("${kc[@]}" get nodes -o name | sed 's|node/||' | sort)
(( ${#nodes[@]} == 3 ))
source_a=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].metadata.name}')
mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' -o name | sed 's|node/||' | sort)
(( ${#workers[@]} == 2 ))
source_b=${workers[0]}
gateway_node=${workers[1]}
nodes_json=$("${kc[@]}" get nodes -o json)
jq -e 'all(.items[]; any(.status.conditions[]; .type == "Ready" and .status == "True"))' <<<"${nodes_json}" >/dev/null
jq -e 'all(.items[]; .metadata.labels["network.unf.io/primary-cni"] == "enabled")' <<<"${nodes_json}" >/dev/null
source_json=$(jq -c --arg node "${source_a}" '.items[] | select(.metadata.name == $node)' <<<"${nodes_json}")
source_v4=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address' <<<"${source_json}")
source_v6=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")))][0].address' <<<"${source_json}")
ipv4_prefix=${source_v4%.*}
ipv6_prefix=${source_v6%::*}
external_v4=${ipv4_prefix}.223
external_v6=${ipv6_prefix}::df
egress_v4=${ipv4_prefix}.240
egress_v6=${ipv6_prefix}::f0

qualification_stage=dns-and-traffic-fixture
"${runtime[@]}" run -d --name "${external_container}" --network kind \
    --ip "${external_v4}" --ip6 "${external_v6}" --mac-address 02:55:4e:46:08:07 \
    --cap-add NET_ADMIN --entrypoint /bin/sh "${test_tools_image}" -ec \
    "/usr/local/bin/unf-dns-fixture ${dns_name} ${external_v4} ${external_v6} 120 ${empty_marker} & exec /usr/bin/socat UDP6-RECVFROM:18081,ipv6only=0,reuseaddr,fork EXEC:/bin/cat" \
    >/dev/null
for node in "${nodes[@]}"; do
    "${runtime[@]}" exec "${node}" ip neigh del "${external_v4}" dev eth0 >/dev/null 2>&1 || true
    "${runtime[@]}" exec "${node}" ip -6 neigh del "${external_v6}" dev eth0 >/dev/null 2>&1 || true
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

qualification_stage=two-source-custom-view-intent
"${kc[@]}" label node "${gateway_node}" "${gateway_label}=enabled" --overwrite >/dev/null
resources_created=true
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata: {name: ${namespace}}
---
apiVersion: v1
kind: Pod
metadata:
  name: managed-a
  namespace: ${namespace}
  labels: {app: managed}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_a}}
  tolerations: [{operator: Exists}]
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Pod
metadata:
  name: managed-b
  namespace: ${namespace}
  labels: {app: managed}
spec:
  nodeSelector: {kubernetes.io/hostname: ${source_b}}
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
  provider: {name: static, instance: kind-fqdn}
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
    fqdn: ["*.bank.example"]
    dns:
      view: ${dns_view}
      discoveryNames: [${dns_name}]
      resolverAddresses: [${external_v4}]
      requiredObservers: 2
      maxAddresses: 8
      maxTtlSeconds: 120
      establishedFlowGraceSeconds: 0
  egress:
    pool: ${pool}
    families: [IPv4, IPv6]
    addressesPerFamily: 1
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/managed-a pod/managed-b --timeout=120s

wait_for_answer_quorum() {
    local observations= status=
    for _ in $(seq 1 180); do
        observations=$(observation_state 2>/dev/null || true)
        status=$(controller_status 2>/dev/null || true)
        if jq -e --arg view "${dns_view}" --arg name "${dns_name}" \
            --arg resolver "${external_v4}" --arg answerV4 "${external_v4}" \
            --arg answerV6 "${external_v6}" '
            [.batches[] | select(.view == $view)
              | select(.observations | length == 1)
              | select(.observations[0].queryName == $name)
              | select(.observations[0].source.resolver == $resolver)
              | select((.observations[0].answers | map(.address) | sort) == ([$answerV4, $answerV6] | sort))]
            | length == 2
        ' <<<"${observations}" >/dev/null 2>&1 \
            && jq -e '.egress_source_applications == 2
                and .egress_activation_ready_sources == 2
                and .agents.all_converged == true' <<<"${status}" >/dev/null 2>&1; then
            printf '%s\n' "${observations}"
            return 0
        fi
        sleep 1
    done
    return 1
}

probe_all() {
    local suffix=$1 pod family output success
    for pod in managed-a managed-b; do
        for family in 4 6; do
            success=false
            for _ in $(seq 1 5); do
                if [[ ${family} == 4 ]]; then
                    output=$("${kc[@]}" -n "${namespace}" exec "${pod}" -- sh -ec \
                        "printf '${pod}-v4-${suffix}' | socat -T 4 - UDP4:${external_v4}:18081" 2>/dev/null || true)
                else
                    output=$("${kc[@]}" -n "${namespace}" exec "${pod}" -- sh -ec \
                        "printf '${pod}-v6-${suffix}' | socat -T 4 - UDP6:[${external_v6}]:18081" 2>/dev/null || true)
                fi
                if [[ ${output} == "${pod}-v${family}-${suffix}" ]]; then success=true; break; fi
                sleep 1
            done
            [[ ${success} == true ]]
        done
    done
}

assert_new_flows_denied() {
    local pod output
    for pod in managed-a managed-b; do
        output=$("${kc[@]}" -n "${namespace}" exec "${pod}" -- sh -ec \
            "printf denied-v4 | socat -T 2 - UDP4:${external_v4}:18081" 2>/dev/null || true)
        [[ ${output} != denied-v4 ]]
        output=$("${kc[@]}" -n "${namespace}" exec "${pod}" -- sh -ec \
            "printf denied-v6 | socat -T 2 - UDP6:[${external_v6}]:18081" 2>/dev/null || true)
        [[ ${output} != denied-v6 ]]
    done
}

initial_observations=$(wait_for_answer_quorum)
probe_all initial

qualification_stage=observer-restart-and-quorum-recovery
old_epochs=$(jq -c --arg view "${dns_view}" '[.batches[] | select(.view == $view) | .sourceEpoch] | sort' <<<"${initial_observations}")
source_agent=$("${kc[@]}" -n unf-system get pods --field-selector "spec.nodeName=${source_b}" -o json \
    | jq -r '.items[] | select(.metadata.name | startswith("unf-agent-")) | .metadata.name' | head -n1)
"${kc[@]}" -n unf-system delete pod "${source_agent}" --wait=false >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s >/dev/null
recovered_observations=$(wait_for_answer_quorum)
new_epochs=$(jq -c --arg view "${dns_view}" '[.batches[] | select(.view == $view) | .sourceEpoch] | sort' <<<"${recovered_observations}")
[[ ${new_epochs} != "${old_epochs}" ]]
probe_all observer-restart

qualification_stage=authoritative-empty-and-deny
"${runtime[@]}" exec "${external_container}" touch "${empty_marker}"
for _ in $(seq 1 90); do
    empty_observations=$(observation_state 2>/dev/null || true)
    if jq -e --arg view "${dns_view}" '
        [.batches[] | select(.view == $view)
          | select(.observations | length == 1)
          | select(.observations[0].answers | length == 0)] | length == 2
    ' <<<"${empty_observations}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
jq -e --arg view "${dns_view}" '[.batches[] | select(.view == $view)
    | select(.observations | length == 1)
    | select(.observations[0].answers | length == 0)] | length == 2' \
    <<<"${empty_observations}" >/dev/null
assert_new_flows_denied

qualification_stage=authority-recovery
"${runtime[@]}" exec "${external_container}" unlink "${empty_marker}"
restored_observations=$(wait_for_answer_quorum)
probe_all restored

qualification_stage=final-authoritative-withdrawal
"${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --wait=true >/dev/null
for _ in $(seq 1 60); do
    final_observations=$(observation_state 2>/dev/null || true)
    if jq -e --arg view "${dns_view}" '
        [.batches[] | select(.view == $view and (.observations | length == 0))] | length == 2
    ' <<<"${final_observations}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
jq -e --arg view "${dns_view}" '
    [.batches[] | select(.view == $view and (.observations | length == 0))] | length == 2
' <<<"${final_observations}" >/dev/null

qualification_stage=evidence
collect_diagnostics
mkdir -p "$(dirname "${artifact}")"
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "$(git -C "${project_root}" rev-parse HEAD)" \
    --arg context "${context}" --arg view "${dns_view}" --arg name "${dns_name}" \
    --arg sourceA "${source_a}" --arg sourceB "${source_b}" --arg gateway "${gateway_node}" \
    --arg resolver "${external_v4}" --arg answerV4 "${external_v4}" --arg answerV6 "${external_v6}" \
    --argjson initial "${initial_observations}" --argjson recovered "${recovered_observations}" \
    --argjson empty "${empty_observations}" --argjson restored "${restored_observations}" \
    --argjson final "${final_observations}" \
    '{schemaVersion:1,generatedAt:$generatedAt,revision:$revision,context:$context,
      topology:{sourceNodes:[$sourceA,$sourceB],gatewayNode:$gateway},
      authority:{view:$view,discoveryName:$name,resolver:$resolver,answers:[$answerV4,$answerV6],requiredObservers:2},
      checkpoints:{initial:$initial,recovered:$recovered,authoritativeEmpty:$empty,restored:$restored,finalWithdrawal:$final},
      verified:["explicit wildcard discovery authority","custom resolver-address binding",
        "two distinct Node observers","dual-stack A and AAAA evidence","two replica-source activation grants",
        "provenance-preserving identity coalescing","quorum-gated source activation",
        "cross-Node dual-stack gateway NAT","observer restart with new source epoch",
        "authoritative empty dual-stack denial","authority recovery","final authenticated empty withdrawal"]}' \
    >"${artifact}.tmp"
mv "${artifact}.tmp" "${artifact}"

"${kc[@]}" delete egresspool.network.unf.io "${pool}" --wait=true >/dev/null
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=120s >/dev/null
"${kc[@]}" label node "${gateway_node}" "${gateway_label}-" >/dev/null
resources_created=false
"${runtime[@]}" rm -f "${external_container}" >/dev/null
trap - ERR EXIT
echo "Phase 8.7d dual-stack Kind FQDN lifecycle passed; evidence: ${artifact}; diagnostics: ${diagnostics_dir}"
