#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-service-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-service-dev}
container_runtime=${KIND_PROVIDER:-podman}
test_tools_image=${UNF_TEST_TOOLS_IMAGE:-localhost/unf-test-tools:ipv6-ext-v1}
artifact=${UNF_EGRESS_KIND_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-kind.json"}
namespace=unf-egress-lifecycle-qualification
pool=unf-egress-lifecycle
policy=unf-egress-lifecycle
external_container=unf-egress-lifecycle-external
provider_name=${UNF_EGRESS_PROVIDER_NAME:-static}
native_reachability=false
[[ ${provider_name} != native ]] || native_reachability=true
qualification_milestone=8.5
[[ ${native_reachability} != true ]] || qualification_milestone=8.8c
witness_a_container=unf-egress-native-witness-a
witness_b_container=unf-egress-native-witness-b
provider_observer_namespace=unf-native-provider-observer
fabric_a_observer_namespace=unf-native-fabric-observer-a
fabric_b_observer_namespace=unf-native-fabric-observer-b
native_observation_revision=0
gateway_label=network.unf.io/egress-gateway
started_unix_seconds=$(date +%s)
diagnostics_dir=${UNF_EGRESS_KIND_DIAGNOSTICS:-"${project_root}/.artifacts/phase8-egress-kind-${started_unix_seconds}"}
qualification_stage=preflight
resources_created=false
diagnostics_collected=false
controller_forward_pid=
controller_port=$((21000 + started_unix_seconds % 10000))
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
runtime=(sudo "${container_runtime}")

collect_diagnostics() {
    [[ ${diagnostics_collected} == false ]] || return 0
    diagnostics_collected=true
    mkdir -p "${diagnostics_dir}"
    "${kc[@]}" get nodes -o json >"${diagnostics_dir}/nodes.json" 2>/dev/null || true
    "${kc[@]}" get egresspools.network.unf.io,egresspolicies.network.unf.io -o yaml \
        >"${diagnostics_dir}/egress-resources.yaml" 2>/dev/null || true
    "${kc[@]}" -n unf-system get pods -o wide \
        >"${diagnostics_dir}/unf-pods.txt" 2>/dev/null || true
    "${kc[@]}" -n unf-system logs deployment/unf-controller --all-pods=true \
        >"${diagnostics_dir}/controller.log" 2>&1 || true
    "${kc[@]}" -n unf-system logs daemonset/unf-agent --all-pods=true --prefix \
        >"${diagnostics_dir}/agents.log" 2>&1 || true
    "${kc[@]}" -n unf-system get configmap unf-egress-control-plane \
        -o jsonpath='{.data.state\.json}' >"${diagnostics_dir}/control-plane.json" 2>/dev/null || true
    if [[ -n ${gateway_node:-} ]]; then
        "${runtime[@]}" exec "${gateway_node}" ip address show \
            >"${diagnostics_dir}/gateway-addresses.txt" 2>&1 || true
        "${runtime[@]}" exec "${gateway_node}" ip -6 neigh show proxy \
            >"${diagnostics_dir}/gateway-proxies.txt" 2>&1 || true
    fi
    "${runtime[@]}" inspect "${external_container}" \
        >"${diagnostics_dir}/external-container.json" 2>/dev/null || true
}

report_failure() {
    local status=$?
    local line=${BASH_LINENO[0]:-unknown}
    collect_diagnostics
    echo "Phase ${qualification_milestone} Kind egress lifecycle failed during ${qualification_stage} at line ${line}: ${BASH_COMMAND}" >&2
    echo "diagnostics: ${diagnostics_dir}" >&2
    return "${status}"
}

cleanup() {
    if [[ -n ${controller_forward_pid} ]]; then
        kill "${controller_forward_pid}" >/dev/null 2>&1 || true
        wait "${controller_forward_pid}" 2>/dev/null || true
    fi
    if [[ ${resources_created} == true ]]; then
        "${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --ignore-not-found \
            --wait=false >/dev/null 2>&1 || true
        if [[ ${native_reachability} == true ]]; then
            withdraw_native_reachability >/dev/null 2>&1 || true
            wait_for_release >/dev/null 2>&1 || true
        fi
        "${kc[@]}" delete egresspool.network.unf.io "${pool}" --ignore-not-found \
            --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found \
            --wait=false >/dev/null 2>&1 || true
        "${kc[@]}" label node "${gateway_node}" "${gateway_label}-" \
            >/dev/null 2>&1 || true
    fi
    "${runtime[@]}" rm -f "${external_container}" >/dev/null 2>&1 || true
    "${runtime[@]}" rm -f "${witness_a_container}" "${witness_b_container}" >/dev/null 2>&1 || true
    "${kc[@]}" delete namespace "${provider_observer_namespace}" \
        "${fabric_a_observer_namespace}" "${fabric_b_observer_namespace}" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

trap report_failure ERR
trap cleanup EXIT

for command in curl kubectl jq rg sha256sum sudo "${container_runtime}"; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "${command} is required for Phase 8.5 Kind egress qualification" >&2
        exit 1
    }
done
if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing egress qualification outside exact Kind context ${context}" >&2
    exit 1
fi
if "${kc[@]}" -n kube-system get daemonset kube-proxy >/dev/null 2>&1; then
    echo "egress qualification requires kube-proxy-free Kind" >&2
    exit 1
fi
if "${kc[@]}" get namespace "${namespace}" >/dev/null 2>&1 \
    || "${kc[@]}" get egresspool.network.unf.io "${pool}" >/dev/null 2>&1 \
    || "${kc[@]}" get egresspolicy.network.unf.io "${policy}" >/dev/null 2>&1 \
    || "${runtime[@]}" container exists "${external_container}" \
    || "${runtime[@]}" container exists "${witness_a_container}" \
    || "${runtime[@]}" container exists "${witness_b_container}"; then
    echo "dedicated egress qualification resources already exist; refusing to adopt them" >&2
    exit 1
fi
if [[ $("${kc[@]}" get egresspolicies.network.unf.io -o json | jq '.items | length') != 0 ]] \
    || [[ $("${kc[@]}" get egresspools.network.unf.io -o json | jq '.items | length') != 0 ]]; then
    echo "egress qualification requires a dedicated cluster with no existing egress intent" >&2
    exit 1
fi
if [[ -n $("${kc[@]}" get nodes -l "${gateway_label}" -o name) ]]; then
    echo "egress qualification requires no pre-existing explicit gateway labels" >&2
    exit 1
fi
"${runtime[@]}" image exists "${test_tools_image}" || {
    echo "test-tools image ${test_tools_image} is unavailable to ${container_runtime}" >&2
    exit 1
}

mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' \
    -o name | sed 's|node/||' | sort)
source_node=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{.items[0].metadata.name}')
if (( ${#workers[@]} != 2 )) || [[ -z ${source_node} ]]; then
    echo "egress qualification requires one control-plane and exactly two workers" >&2
    exit 1
fi
gateway_node=${workers[1]}
nodes_json=$("${kc[@]}" get nodes -o json)
if ! jq -e 'all(.items[]; any(.status.conditions[]; .type == "Ready" and .status == "True"))' \
    <<<"${nodes_json}" >/dev/null; then
    echo "every qualification Node must be Ready" >&2
    exit 1
fi
gateway_node_json=$(jq -c --arg node "${gateway_node}" \
    '.items[] | select(.metadata.name == $node)' <<<"${nodes_json}")
gateway_node_v4=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address' \
    <<<"${gateway_node_json}")
gateway_node_v6=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")))][0].address' \
    <<<"${gateway_node_json}")
if ! jq -e 'all(.items[]; .metadata.labels["network.unf.io/primary-cni"] == "enabled")' \
    <<<"${nodes_json}" >/dev/null; then
    echo "every qualification Node must run the exclusive UNF primary CNI" >&2
    exit 1
fi

source_node_json=$(jq -c --arg node "${source_node}" \
    '.items[] | select(.metadata.name == $node)' <<<"${nodes_json}")
source_node_v4=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address' \
    <<<"${source_node_json}")
source_node_v6=$(jq -er '[.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")))][0].address' \
    <<<"${source_node_json}")
[[ ${source_node_v6} == *::* ]] || {
    echo "Kind IPv6 InternalIP must use the expected compressed /64 form" >&2
    exit 1
}
ipv4_prefix=${source_node_v4%.*}
ipv6_prefix=${source_node_v6%::*}
external_v4=${ipv4_prefix}.223
egress_v4=${ipv4_prefix}.240
external_v6=${ipv6_prefix}::df
egress_v6=${ipv6_prefix}::f0
if [[ ${native_reachability} == true ]]; then
    egress_v4=192.0.2.240
    egress_v6=2001:db8:ffff::f0
fi

qualification_stage=external-fixture
"${runtime[@]}" run -d --name "${external_container}" --network kind \
    --ip "${external_v4}" --ip6 "${external_v6}" --mac-address 02:55:4e:46:08:05 \
    --cap-add NET_ADMIN \
    --entrypoint /bin/sh "${test_tools_image}" -ec \
    '/usr/local/bin/unf-flow-receiver 18080 & exec /usr/bin/socat UDP6-RECVFROM:18081,ipv6only=0,reuseaddr,fork EXEC:/bin/cat' \
    >/dev/null
while read -r node; do
    "${runtime[@]}" exec "${node}" ip neigh del "${external_v4}" dev eth0 \
        >/dev/null 2>&1 || true
    "${runtime[@]}" exec "${node}" ip -6 neigh del "${external_v6}" dev eth0 \
        >/dev/null 2>&1 || true
done < <(jq -r '.items[].metadata.name' <<<"${nodes_json}")
while IFS=$'\t' read -r node_v4 node_v6 pod_v4 pod_v6; do
    "${runtime[@]}" exec "${external_container}" ip route replace "${pod_v4}" via "${node_v4}"
    "${runtime[@]}" exec "${external_container}" ip -6 route replace "${pod_v6}" via "${node_v6}"
done < <(jq -r '.items[] |
    ([.status.addresses[] | select(.type == "InternalIP" and (.address | contains(".")))][0].address) as $v4 |
    ([.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":")) )][0].address) as $v6 |
    ([.spec.podCIDRs[] | select(contains("."))][0]) as $pod4 |
    ([.spec.podCIDRs[] | select(contains(":"))][0]) as $pod6 |
    [$v4,$v6,$pod4,$pod6] | @tsv' <<<"${nodes_json}")
"${runtime[@]}" exec "${external_container}" wget -T 2 -qO- \
    "http://127.0.0.1:18080/health" | grep -qx ok
if [[ ${native_reachability} == true ]]; then
    for witness in "${witness_a_container}" "${witness_b_container}"; do
        "${runtime[@]}" run -d --name "${witness}" --network kind --cap-add NET_ADMIN \
            --entrypoint /bin/sh "${test_tools_image}" -ec 'exec sleep infinity' >/dev/null
    done
fi

qualification_stage=watched-intent
"${kc[@]}" label node "${gateway_node}" "${gateway_label}=enabled" --overwrite >/dev/null
resources_created=true
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
---
apiVersion: v1
kind: Pod
metadata:
  name: managed
  namespace: ${namespace}
  labels:
    app: managed
spec:
  nodeSelector:
    kubernetes.io/hostname: ${source_node}
  tolerations:
    - operator: Exists
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: v1
kind: Pod
metadata:
  name: native
  namespace: ${namespace}
  labels:
    app: native
spec:
  nodeSelector:
    kubernetes.io/hostname: ${source_node}
  tolerations:
    - operator: Exists
  containers:
    - name: client
      image: ${test_tools_image}
      imagePullPolicy: Never
      command: [sh, -ec, "sleep infinity"]
---
apiVersion: network.unf.io/v1alpha1
kind: EgressPool
metadata:
  name: ${pool}
spec:
  provider:
    name: ${provider_name}
    instance: kind
  prefixes:
    - ${egress_v4}/32
    - ${egress_v6}/128
---
apiVersion: network.unf.io/v1alpha1
kind: EgressPolicy
metadata:
  name: ${policy}
spec:
  priority: 100
  target:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: ${namespace}
    workloadSelector:
      matchLabels:
        app: managed
    serviceAccounts: [default]
  destinations:
    networks:
      - ${external_v4}/32
      - ${external_v6}/128
  egress:
    pool: ${pool}
    families: [IPv4, IPv6]
    addressesPerFamily: 1
EOF
"${kc[@]}" -n "${namespace}" wait --for=condition=Ready pod/managed pod/native --timeout=120s
managed_v4=$("${kc[@]}" -n "${namespace}" get pod managed \
    -o json | jq -er '[.status.podIPs[].ip | select(contains("."))][0]')
managed_v6=$("${kc[@]}" -n "${namespace}" get pod managed \
    -o json | jq -er '[.status.podIPs[].ip | select(contains(":"))][0]')
native_v4=$("${kc[@]}" -n "${namespace}" get pod native \
    -o json | jq -er '[.status.podIPs[].ip | select(contains("."))][0]')
native_v6=$("${kc[@]}" -n "${namespace}" get pod native \
    -o json | jq -er '[.status.podIPs[].ip | select(contains(":"))][0]')

controller_raw() {
    local path=$1 pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller \
        -o json | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

controller_post() {
    local path=$1
    curl --fail --silent --show-error --max-time 10 \
        --request POST --header 'Content-Type: application/json' --data-binary @- \
        "http://127.0.0.1:${controller_port}${path}"
}

gateway_agent() {
    "${kc[@]}" -n unf-system get pods --field-selector "spec.nodeName=${gateway_node}" \
        -o json | jq -r '.items[] | select(.metadata.name | startswith("unf-agent-")) | .metadata.name' \
        | head -n 1
}

wait_for_activation() {
    local status=
    for _ in $(seq 1 180); do
        status=$(controller_raw /v1/status 2>/dev/null || true)
        if jq -e '
            .egress_source_applications == 1
            and .egress_gateway_applications >= 1
            and .egress_activation_ready_sources == 1
            and .agents.all_converged == true
        ' <<<"${status}" >/dev/null 2>&1; then
            printf '%s\n' "${status}"
            return 0
        fi
        sleep 1
    done
    echo "watched egress intent did not reach bilateral activation" >&2
    jq . <<<"${status}" >&2 || true
    return 1
}

assert_gateway_ownership() {
    "${runtime[@]}" exec "${gateway_node}" ip -o address show dev unf-egress0 \
        | rg --fixed-strings --quiet "${egress_v4}/32"
    "${runtime[@]}" exec "${gateway_node}" ip -o -6 address show dev unf-egress0 \
        | rg --fixed-strings --quiet "${egress_v6}/128"
    [[ $("${runtime[@]}" exec "${gateway_node}" \
        cat /proc/sys/net/ipv6/conf/eth0/proxy_ndp) == 1 ]]
    "${runtime[@]}" exec "${gateway_node}" ip -6 neigh show proxy \
        | rg --fixed-strings --quiet "${egress_v6} dev eth0 proxy"
}

native_peer_matrix() {
    local observed= success=false
    for _ in $(seq 1 5); do
        observed=$("${kc[@]}" -n "${namespace}" exec native -- \
            wget -T 4 -t 1 -qO- "http://${external_v4}:18080/peer" 2>/dev/null || true)
        if [[ ${observed} == "${native_v4}" ]]; then success=true; break; fi
        sleep 1
    done
    [[ ${success} == true ]]
    success=false
    for _ in $(seq 1 5); do
        observed=$("${kc[@]}" -n "${namespace}" exec native -- \
            wget -T 4 -t 1 -qO- "http://[${external_v6}]:18080/peer" 2>/dev/null || true)
        if [[ ${observed} == "${native_v6}" ]]; then success=true; break; fi
        sleep 1
    done
    [[ ${success} == true ]]
}

managed_udp_matrix() {
    local suffix=$1
    local observed= success=false
    for _ in $(seq 1 5); do
        observed=$("${kc[@]}" -n "${namespace}" exec managed -- sh -ec \
            "printf 'managed-v4-${suffix}' | socat -T 4 - UDP4:${external_v4}:18081" \
            2>/dev/null || true)
        if [[ ${observed} == "managed-v4-${suffix}" ]]; then success=true; break; fi
        sleep 1
    done
    [[ ${success} == true ]]
    success=false
    for _ in $(seq 1 5); do
        observed=$("${kc[@]}" -n "${namespace}" exec managed -- sh -ec \
            "printf 'managed-v6-${suffix}' | socat -T 4 - UDP6:[${external_v6}]:18081" \
            2>/dev/null || true)
        if [[ ${observed} == "managed-v6-${suffix}" ]]; then success=true; break; fi
        sleep 1
    done
    [[ ${success} == true ]]
}

control_plane_state() {
    "${kc[@]}" -n unf-system get configmap unf-egress-control-plane \
        -o json | jq -er '.data["state.json"] | fromjson'
}

reachability_state() {
    "${kc[@]}" -n unf-system get configmap unf-egress-desired-state -o json \
        | jq -er '.data["reachability-evidence.json"] | fromjson'
}

wait_for_native_plan() {
    local action=$1 resource=
    for _ in $(seq 1 120); do
        resource=$("${kc[@]}" get egressreachabilityplans.network.unf.io \
            -l network.unf.io/managed-native-reachability=true -o json 2>/dev/null || true)
        if jq -e --arg action "${action}" \
            '.items | length == 1 and .[0].spec.provider.name == "native" and .[0].spec.action == $action' \
            <<<"${resource}" >/dev/null 2>&1; then
            jq -c '.items[0]' <<<"${resource}"
            return 0
        fi
        sleep 1
    done
    return 1
}

native_plan_digest() {
    local owner_uid=$1 state= digest=
    for _ in $(seq 1 120); do
        state=$(reachability_state 2>/dev/null || true)
        digest=$(jq -c --arg uid "${owner_uid}" \
            '.currentPlans[]? | select(.plan.owner.uid == $uid) | .plan.digest' \
            <<<"${state}" 2>/dev/null || true)
        if [[ -n ${digest} && ${digest} != null ]]; then
            printf '%s\n' "${digest}"
            return 0
        fi
        sleep 1
    done
    return 1
}

digest_hex() {
    local digest_json=$1 encoded=
    while read -r byte; do printf -v encoded '%s%02x' "${encoded}" "${byte}"; done \
        < <(jq -r '.[]' <<<"${digest_json}")
    printf '%s\n' "${encoded}"
}

apply_native_observer_identity() {
    local namespace=$1 observer=$2 failure_domain=$3 vantage=$4 object=
    "${kc[@]}" create namespace "${namespace}" --dry-run=client -o yaml \
        | "${kc[@]}" apply -f - >/dev/null
    "${kc[@]}" -n "${namespace}" create serviceaccount observer --dry-run=client -o yaml \
        | "${kc[@]}" apply -f - >/dev/null
    "${kc[@]}" -n "${namespace}" create rolebinding native-observer \
        --clusterrole=unf-reachability-observer --serviceaccount="${namespace}:observer" \
        --dry-run=client -o yaml | "${kc[@]}" apply -f - >/dev/null
    object=$(jq -nc --argjson plan "${native_plan_json}" --arg namespace "${namespace}" \
        --arg observer "${observer}" --arg domain "${failure_domain}" --arg vantage "${vantage}" \
        '{apiVersion:"network.unf.io/v1alpha1",kind:"EgressReachabilityObservation",
          metadata:{name:"native-path",namespace:$namespace},
          spec:{planName:$plan.metadata.name,plan:$plan.spec,observer:$observer,
            failureDomain:$domain,vantage:$vantage}}')
    "${kc[@]}" apply -f - <<<"${object}" >/dev/null
}

publish_native_observation() {
    local namespace=$1 routes_mode=$2 valid_until=$3 routes patch
    if [[ ${routes_mode} == present ]]; then
        routes=$(jq -c --arg uid "${gateway_node_uid}" \
            '.spec.addresses | map({address:.,paths:[{gatewayUid:$uid,
              forwardingIdentity:("native-node/" + $uid)}]})' <<<"${native_plan_json}")
    else
        routes=$(jq -c '.spec.addresses | map({address:.,paths:[]})' <<<"${native_plan_json}")
    fi
    native_observation_revision=$((native_observation_revision + 1))
    patch=$(jq -nc --arg digest "${native_plan_digest_hex}" \
        --argjson epoch "${started_unix_seconds}" \
        --argjson revision "${native_observation_revision}" \
        --argjson observed "$(date +%s)" --argjson expires "${valid_until}" \
        --argjson routes "${routes}" \
        '{status:{sourceEpoch:$epoch,revision:$revision,planDigest:$digest,
          observedAtUnixSeconds:$observed,validUntilUnixSeconds:$expires,routes:$routes}}')
    "${kc[@]}" --as="system:serviceaccount:${namespace}:observer" -n "${namespace}" \
        patch egressreachabilityobservation.network.unf.io native-path \
        --subresource=status --type=merge -p "${patch}" >/dev/null
}

set_native_fixture_routes() {
    local operation=$1
    for fixture in "${external_container}" "${witness_a_container}" "${witness_b_container}"; do
        if [[ ${operation} == ensure ]]; then
            "${runtime[@]}" exec "${fixture}" ip route replace "${egress_v4}/32" via "${gateway_node_v4}"
            "${runtime[@]}" exec "${fixture}" ip -6 route replace "${egress_v6}/128" via "${gateway_node_v6}"
        else
            "${runtime[@]}" exec "${fixture}" ip route del "${egress_v4}/32" >/dev/null 2>&1 || true
            "${runtime[@]}" exec "${fixture}" ip -6 route del "${egress_v6}/128" >/dev/null 2>&1 || true
        fi
    done
}

probe_native_fixture() {
    local fixture=$1 nonce response url address
    nonce=$(printf '%s' "${fixture}-${native_plan_digest_hex}-${native_observation_revision}" \
        | sha256sum | cut -d' ' -f1)
    for address in "${egress_v4}" "${egress_v6}"; do
        if [[ ${address} == *:* ]]; then
            url="http://[${address}]:9963/v1/egress-reachability/probe"
        else
            url="http://${address}:9963/v1/egress-reachability/probe"
        fi
        response=$("${runtime[@]}" exec "${fixture}" wget -T 4 -t 1 -qO- \
            "${url}?planDigest=${native_plan_digest_hex}&desiredRevision=${native_desired_revision}&leaseEpoch=${native_lease_epoch}&address=${address}&nonce=${nonce}")
        jq -e --arg address "${address}" --arg uid "${gateway_node_uid}" \
            --argjson digest "${native_plan_digest_json}" \
            '.algorithm == "nonce-bound-kernel-ownership-v1"
              and .challenge.address == $address and .challenge.planDigest == $digest
              and .nodeUid == $uid and (.digest | length) == 32' <<<"${response}" >/dev/null
    done
}

wait_for_gateway_address_ownership() {
    for _ in $(seq 1 120); do
        if assert_gateway_ownership >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}

prepare_native_reachability() {
    local prove_conflict=${1:-false} valid_until state
    wait_for_gateway_address_ownership
    native_plan_json=$(wait_for_native_plan Ensure)
    gateway_node_uid=$(jq -er '.metadata.uid' <<<"${gateway_node_json}")
    native_desired_revision=$(jq -er '.spec.desiredRevision' <<<"${native_plan_json}")
    native_lease_epoch=$(jq -er '.spec.leaseEpoch' <<<"${native_plan_json}")
    native_plan_digest_json=$(native_plan_digest "$(jq -er '.spec.ownerUid' <<<"${native_plan_json}")")
    native_plan_digest_hex=$(digest_hex "${native_plan_digest_json}")
    apply_native_observer_identity "${provider_observer_namespace}" provider-receipt provider-edge provider
    apply_native_observer_identity "${fabric_a_observer_namespace}" fabric-a rack-a fabric
    apply_native_observer_identity "${fabric_b_observer_namespace}" fabric-b rack-b fabric
    set_native_fixture_routes ensure
    probe_native_fixture "${external_container}"
    probe_native_fixture "${witness_a_container}"
    probe_native_fixture "${witness_b_container}"
    valid_until=$(( $(date +%s) + 110 ))
    publish_native_observation "${provider_observer_namespace}" present "${valid_until}"
    publish_native_observation "${fabric_a_observer_namespace}" present "${valid_until}"
    if [[ ${prove_conflict} == true ]]; then
        publish_native_observation "${fabric_b_observer_namespace}" absent "${valid_until}"
        sleep 3
        state=$(reachability_state)
        jq -e '.assessments[0].verdict == "denyClosed"' <<<"${state}" >/dev/null
        jq -e '.egress_activation_ready_sources == 0' <<<"$(controller_raw /v1/status)" >/dev/null
    fi
    publish_native_observation "${fabric_b_observer_namespace}" present "${valid_until}"
}

withdraw_native_reachability() {
    native_plan_json=$(wait_for_native_plan Withdraw)
    native_desired_revision=$(jq -er '.spec.desiredRevision' <<<"${native_plan_json}")
    native_lease_epoch=$(jq -er '.spec.leaseEpoch' <<<"${native_plan_json}")
    native_plan_digest_json=$(native_plan_digest "$(jq -er '.spec.ownerUid' <<<"${native_plan_json}")")
    native_plan_digest_hex=$(digest_hex "${native_plan_digest_json}")
    apply_native_observer_identity "${provider_observer_namespace}" provider-receipt provider-edge provider
    apply_native_observer_identity "${fabric_a_observer_namespace}" fabric-a rack-a fabric
    apply_native_observer_identity "${fabric_b_observer_namespace}" fabric-b rack-b fabric
    set_native_fixture_routes withdraw
    for fixture in "${external_container}" "${witness_a_container}" "${witness_b_container}"; do
        if probe_native_fixture "${fixture}" >/dev/null 2>&1; then
            echo "native probe unexpectedly survived provider route withdrawal in ${fixture}" >&2
            return 1
        fi
    done
    local valid_until=$(( $(date +%s) + 110 ))
    publish_native_observation "${provider_observer_namespace}" absent "${valid_until}"
    publish_native_observation "${fabric_a_observer_namespace}" absent "${valid_until}"
    publish_native_observation "${fabric_b_observer_namespace}" absent "${valid_until}"
}

wait_for_release() {
    local state=
    for _ in $(seq 1 90); do
        native_peer_matrix
        state=$(control_plane_state)
        if jq -e '
            (.allocation.leases | length) == 0
            and (.gateways.records | length) == 0
            and (.retirements | length) == 0
        ' <<<"${state}" >/dev/null \
            && ! "${runtime[@]}" exec "${gateway_node}" ip -o address show dev unf-egress0 \
                | rg --fixed-strings --quiet "${egress_v4}" \
            && ! "${runtime[@]}" exec "${gateway_node}" ip -o -6 address show dev unf-egress0 \
                | rg --fixed-strings --quiet "${egress_v6}" \
            && ! "${runtime[@]}" exec "${gateway_node}" ip -6 neigh show proxy \
                | rg --fixed-strings --quiet "${egress_v6}"; then
            printf '%s\n' "${state}"
            return 0
        fi
        sleep 2
    done
    echo "egress retirement did not reach safe host release" >&2
    jq . <<<"${state}" >&2 || true
    return 1
}

qualification_stage=bilateral-traffic
if [[ ${native_reachability} == true ]]; then
    prepare_native_reachability true
fi
initial_status=$(wait_for_activation)
assert_gateway_ownership
initial_state=$(control_plane_state)
initial_epoch=$(jq -er '.allocation.leases[0].leaseEpoch' <<<"${initial_state}")
traffic_since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
native_peer_matrix
managed_udp_matrix initial
controller_pod=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-controller -o jsonpath='{.items[0].metadata.name}')
"${kc[@]}" -n unf-system port-forward "pod/${controller_pod}" \
    "${controller_port}:9962" >"${diagnostics_dir}-port-forward.log" 2>&1 &
controller_forward_pid=$!
for _ in $(seq 1 60); do
    if curl --fail --silent --show-error --max-time 2 \
        "http://127.0.0.1:${controller_port}/readyz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
kill -0 "${controller_forward_pid}"
operations_v4_request=$(jq -nc --arg from "${namespace}/managed" \
    --arg destination "${external_v4}" \
    '{from:$from,destination:$destination,protocol:"udp",port:18080}')
operations_v6_request=$(jq -nc --arg from "${namespace}/managed" \
    --arg destination "${external_v6}" \
    '{from:$from,destination:$destination,protocol:"udp",port:18080}')
operations_explain_v4=$(controller_post /v1/egress/explain <<<"${operations_v4_request}")
operations_explain_v6=$(controller_post /v1/egress/explain <<<"${operations_v6_request}")
operations_simulate_v4=$(controller_post /v1/egress/simulate <<<"${operations_v4_request}")
operations_simulate_v6=$(controller_post /v1/egress/simulate <<<"${operations_v6_request}")
kill "${controller_forward_pid}"
wait "${controller_forward_pid}" 2>/dev/null || true
controller_forward_pid=
for response in "${operations_explain_v4}" "${operations_explain_v6}" \
    "${operations_simulate_v4}" "${operations_simulate_v6}"; do
    jq -e --arg owner "${policy}" '
        .schema_version == 1 and .outcome == "eligible"
        and .selected_intent.name == $owner
        and (.candidate_egress_addresses | length) == 2
        and (.candidate_gateways | length) >= 1
        and .private_nat_state_inferred == false
        and ([.evidence[].layer] | unique | length) == (.evidence | length)
        and ([.evidence[].layer] | index("counterfactual")) != null
        and ([.evidence[].layer] | index("transport")) != null
    ' <<<"${response}" >/dev/null
done
gateway_pod=$(gateway_agent)
for _ in $(seq 1 30); do
    gateway_logs=$("${kc[@]}" -n unf-system logs "${gateway_pod}" --since-time="${traffic_since}" 2>/dev/null || true)
    if rg --fixed-strings --quiet '"message":"egress NAT lifecycle outcome"' <<<"${gateway_logs}" \
        && rg --fixed-strings --quiet "${egress_v4}" <<<"${gateway_logs}" \
        && rg --fixed-strings --quiet "${egress_v6}" <<<"${gateway_logs}"; then
        break
    fi
    sleep 1
done
rg --fixed-strings --quiet "${egress_v4}" <<<"${gateway_logs}"
rg --fixed-strings --quiet "${egress_v6}" <<<"${gateway_logs}"
for _ in $(seq 1 30); do
    operations_history=$(controller_raw '/v1/egress/history?limit=64' 2>/dev/null || true)
    if jq -e '.schema_version == 8 and .egress_evidence.retained_outcomes >= 2
        and .egress_evidence.private_nat_state_inferred == false' \
        <<<"${operations_history}" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
jq -e '.schema_version == 8 and .egress_evidence.retained_outcomes >= 2
    and .egress_evidence.private_nat_state_inferred == false' \
    <<<"${operations_history}" >/dev/null

qualification_stage=restart-recovery
if [[ ${native_reachability} == true ]]; then
    native_refresh_until=$(( $(date +%s) + 110 ))
    publish_native_observation "${provider_observer_namespace}" present "${native_refresh_until}"
    publish_native_observation "${fabric_a_observer_namespace}" present "${native_refresh_until}"
    publish_native_observation "${fabric_b_observer_namespace}" present "${native_refresh_until}"
fi
"${kc[@]}" -n unf-system rollout restart deployment/unf-controller >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=180s
restart_status=$(wait_for_activation)
assert_gateway_ownership
native_peer_matrix
managed_udp_matrix controller-restart
if [[ ${native_reachability} == true ]]; then
    qualification_stage=autonomous-reachability-expiry
    native_expiry=$(( $(date +%s) + 7 ))
    publish_native_observation "${provider_observer_namespace}" present "${native_expiry}"
    publish_native_observation "${fabric_a_observer_namespace}" present "${native_expiry}"
    publish_native_observation "${fabric_b_observer_namespace}" present "${native_expiry}"
    for _ in $(seq 1 30); do
        if jq -e '.assessments[0].verdict == "denyClosed"' <<<"$(reachability_state)" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    jq -e '.assessments[0].verdict == "denyClosed"' <<<"$(reachability_state)" >/dev/null
    native_peer_matrix
    expiry_fenced=false
    for _ in $(seq 1 30); do
        if [[ $("${kc[@]}" -n "${namespace}" exec managed -- sh -ec \
            "printf expired | socat -T 2 - UDP4:${external_v4}:18081" 2>/dev/null || true) != expired ]]; then
            expiry_fenced=true
            break
        fi
        sleep 1
    done
    [[ ${expiry_fenced} == true ]]
    native_recovery_until=$(( $(date +%s) + 110 ))
    publish_native_observation "${provider_observer_namespace}" present "${native_recovery_until}"
    publish_native_observation "${fabric_a_observer_namespace}" present "${native_recovery_until}"
    publish_native_observation "${fabric_b_observer_namespace}" present "${native_recovery_until}"
    wait_for_activation >/dev/null
fi
"${kc[@]}" -n unf-system rollout restart daemonset/unf-agent >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=180s
agent_restart_status=$(wait_for_activation)
assert_gateway_ownership
native_peer_matrix
managed_udp_matrix agent-restart

qualification_stage=withdrawal-and-safe-release
"${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --wait=true >/dev/null
if [[ ${native_reachability} == true ]]; then
    withdraw_native_reachability
fi
released_state=$(wait_for_release)

qualification_stage=safe-reuse
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: network.unf.io/v1alpha1
kind: EgressPolicy
metadata:
  name: ${policy}
spec:
  priority: 100
  target:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: ${namespace}
    workloadSelector:
      matchLabels:
        app: managed
    serviceAccounts: [default]
  destinations:
    networks: [${external_v4}/32, ${external_v6}/128]
  egress:
    pool: ${pool}
    families: [IPv4, IPv6]
    addressesPerFamily: 1
EOF
if [[ ${native_reachability} == true ]]; then
    prepare_native_reachability false
fi
reused_status=$(wait_for_activation)
assert_gateway_ownership
reused_state=$(control_plane_state)
reused_epoch=$(jq -er '.allocation.leases[0].leaseEpoch' <<<"${reused_state}")
(( reused_epoch > initial_epoch ))
jq -e --arg v4 "${egress_v4}" --arg v6 "${egress_v6}" '
    .allocation.leases[0].addresses == [$v4, $v6]
' <<<"${reused_state}" >/dev/null
native_peer_matrix
managed_udp_matrix safe-reuse

qualification_stage=final-release
"${kc[@]}" delete egresspolicy.network.unf.io "${policy}" --wait=true >/dev/null
if [[ ${native_reachability} == true ]]; then
    withdraw_native_reachability
fi
final_state=$(wait_for_release)
"${kc[@]}" delete egresspool.network.unf.io "${pool}" --wait=true >/dev/null
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=120s >/dev/null
"${kc[@]}" label node "${gateway_node}" "${gateway_label}-" >/dev/null
if [[ ${native_reachability} == true ]]; then
    "${kc[@]}" delete namespace "${provider_observer_namespace}" \
        "${fabric_a_observer_namespace}" "${fabric_b_observer_namespace}" \
        --wait=true --timeout=120s >/dev/null
    for _ in $(seq 1 60); do
        if [[ $("${kc[@]}" get egressreachabilityplans.network.unf.io \
            -l network.unf.io/managed-native-reachability=true -o json | jq '.items | length') == 0 ]] \
            && [[ $("${kc[@]}" get egressreachabilityobservations.network.unf.io -A -o json \
                | jq '.items | length') == 0 ]] \
            && jq -e '(.currentPlans | length) == 0 and (.currentObservations | length) == 0
                and (.assessments | length) == 0' <<<"$(reachability_state)" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    [[ $("${kc[@]}" get egressreachabilityplans.network.unf.io \
        -l network.unf.io/managed-native-reachability=true -o json | jq '.items | length') == 0 ]]
    jq -e '(.currentPlans | length) == 0 and (.currentObservations | length) == 0
        and (.assessments | length) == 0' <<<"$(reachability_state)" >/dev/null
fi
resources_created=false

qualification_stage=evidence
collect_diagnostics
mkdir -p "$(dirname "${artifact}")"
revision=$(git -C "${project_root}" rev-parse HEAD)
kubernetes_version=$("${kc[@]}" version -o json | jq -r '.serverVersion.gitVersion')
images=$("${kc[@]}" -n unf-system get pods \
    -l 'app.kubernetes.io/name in (unf-controller,unf-agent)' -o json | jq \
    '[.items[] | {name:.metadata.name,node:(.spec.nodeName // null),image:.spec.containers[0].image,imageID:(.status.containerStatuses[0].imageID // null)}]')
jq -n \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "${revision}" \
    --arg context "${context}" \
    --arg kubernetesVersion "${kubernetes_version}" \
    --arg sourceNode "${source_node}" \
    --arg gatewayNode "${gateway_node}" \
    --arg externalIPv4 "${external_v4}" \
    --arg externalIPv6 "${external_v6}" \
    --arg egressIPv4 "${egress_v4}" \
    --arg egressIPv6 "${egress_v6}" \
    --arg diagnostics "${diagnostics_dir}" \
    --arg milestone "${qualification_milestone}" \
    --arg providerName "${provider_name}" \
    --argjson nativeReachability "${native_reachability}" \
    --argjson initialEpoch "${initial_epoch}" \
    --argjson reusedEpoch "${reused_epoch}" \
    --argjson images "${images}" \
    --argjson initialStatus "${initial_status}" \
    --argjson controllerRestartStatus "${restart_status}" \
    --argjson agentRestartStatus "${agent_restart_status}" \
    --argjson reusedStatus "${reused_status}" \
    --argjson operationsExplainV4 "${operations_explain_v4}" \
    --argjson operationsExplainV6 "${operations_explain_v6}" \
    --argjson operationsSimulateV4 "${operations_simulate_v4}" \
    --argjson operationsSimulateV6 "${operations_simulate_v6}" \
    --argjson operationsHistory "${operations_history}" \
    '{schemaVersion:1,milestone:$milestone,generatedAt:$generatedAt,revision:$revision,context:$context,
      kubernetesVersion:$kubernetesVersion,kubeProxyPresent:false,
      topology:{sourceNode:$sourceNode,gatewayNode:$gatewayNode},
      reachability:{provider:$providerName,nativeReference:$nativeReachability,
        controllerOwnedPlan:$nativeReachability,providerReceipt:$nativeReachability,
        independentFabricFailureDomains:(if $nativeReachability then 2 else 0 end),
        conflictDenied:$nativeReachability,autonomousExpiryDenied:$nativeReachability,
        positiveWithdrawal:$nativeReachability},
      fixture:{externalIPv4:$externalIPv4,externalIPv6:$externalIPv6,
        egressIPv4:$egressIPv4,egressIPv6:$egressIPv6},
      lifecycle:{initialLeaseEpoch:$initialEpoch,reusedLeaseEpoch:$reusedEpoch,
        safeReuseMonotonic:($reusedEpoch > $initialEpoch),finalReleaseComplete:true},
      status:{initial:$initialStatus,controllerRestart:$controllerRestartStatus,
        agentRestart:$agentRestartStatus,reused:$reusedStatus},
      operations:{explain:{ipv4:$operationsExplainV4,ipv6:$operationsExplainV6},
        simulate:{ipv4:$operationsSimulateV4,ipv6:$operationsSimulateV6},
        chronicle:$operationsHistory},
      images:$images,diagnostics:$diagnostics,
      verified:(["exclusive UNF primary CNI","watched dual-stack EgressPool and EgressPolicy",
        "explicit Ready gateway selection","exact Node-UID-bound address ownership",
        "proxy-NDP IPv6 ownership","bilateral source and gateway activation",
        "policy-first dual-stack source steering","IPv4 and IPv6 UDP gateway NAT and reverse traffic",
        "exact sparse NAT witnesses","unrelated native egress source preservation",
        "dual-stack evidence-complete explanation and non-authoritative simulation",
        "loss-explicit Causal Egress Chronicle without private NAT inference",
        "controller restart recovery","agent restart and address readback recovery",
        "source fencing","lease-specific NAT drain","reachability withdrawal",
        "host address and proxy removal","Proof of Safe Forgetting release",
        "same-address reuse under a monotonic lease epoch","final clean release"]
        + (if $nativeReachability then ["controller-owned native DQR plan",
          "explicit provider route receipt","two independently authorized fabric failure domains",
          "nonce-bound IPv4 and IPv6 kernel ownership probes","conflicting observation denial",
          "autonomous finite-evidence source fencing","positive observed route withdrawal"] else [] end))}' \
    >"${artifact}.tmp"
mv "${artifact}.tmp" "${artifact}"

"${runtime[@]}" rm -f "${external_container}" "${witness_a_container}" \
    "${witness_b_container}" >/dev/null
trap - ERR EXIT
echo "Phase ${qualification_milestone} dual-stack Kind egress lifecycle passed; evidence: ${artifact}; diagnostics: ${diagnostics_dir}"
