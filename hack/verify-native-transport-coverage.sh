#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
project_root=$root
: "${KUBECONFIG:?exact disposable-cluster kubeconfig required}"
: "${UNF_NATIVE_COVERAGE_RUNTIME_REVISION:?exact runtime revision required}"
[[ $UNF_NATIVE_COVERAGE_RUNTIME_REVISION =~ ^[0-9a-f]{40}$ ]]
git -C "$root" diff --quiet
git -C "$root" diff --cached --quiet
context=${KUBE_CONTEXT:-$(kubectl --kubeconfig "$KUBECONFIG" config current-context)}
kc=(kubectl --kubeconfig "$KUBECONFIG" --context "$context" --request-timeout=15s)
namespace=unf-native-transport-qualification
test_tools_image=${UNF_TEST_TOOLS_IMAGE:?immutable test-tools image required}
[[ $test_tools_image =~ @sha256:[0-9a-f]{64}$ ]]
directory=${UNF_NATIVE_COVERAGE_DIAGNOSTICS:-"$root/.artifacts/native-coverage-$(date +%s)"}
install -d -m 0700 "$directory"
owned=false
stage=preflight
source "$root/hack/phase9-http-probe.sh"
cleanup() {
    if [[ $owned == true ]]; then
        "${kc[@]}" delete namespace "$namespace" --wait=false >/dev/null 2>&1 || true
    fi
}
failure() {
    local status=$?
    "${kc[@]}" -n "$namespace" get pods,services,networkpolicies -o json > "$directory/fixture-failure.json" 2>&1 || true
    printf 'Native coverage failed at %s; diagnostics: %s\n' "$stage" "$directory" >&2
    return "$status"
}
trap cleanup EXIT
trap failure ERR
if [[ $context != kind-* ]]; then
    : "${UNF_NATIVE_COVERAGE_INFRASTRUCTURE:?exact disposable OpenShift infrastructure required}"
    [[ $("${kc[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}') == "$UNF_NATIVE_COVERAGE_INFRASTRUCTURE" ]]
fi
"${kc[@]}" get namespaces -o json | jq -e --arg name "$namespace" 'all(.items[]; .metadata.name != $name)' >/dev/null
"${kc[@]}" -n unf-system get deployment unf-controller -o json | jq -e '
    any(.spec.template.spec.containers[] | select(.name=="controller") | .env[];
        .name=="UNF_ENCRYPTION_BASELINE" and .value=="native")' >/dev/null
"${kc[@]}" get encryptionpolicies.network.unf.io -A -o json | jq -e '.items|length==0' >/dev/null
controller_raw() {
    local pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json |
        jq -er '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")]|select(length==1)|.[0].metadata.name')
    timeout 20 "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/$pod:9962/proxy$1"
}
controller_raw /v1/version > "$directory/controller-version.json"
jq -e --arg revision "$UNF_NATIVE_COVERAGE_RUNTIME_REVISION" '.build_revision==$revision' "$directory/controller-version.json" >/dev/null
"${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-agent -o json > "$directory/agent-pods.json"
jq -e '.items|length>0 and all(.[]; .metadata.deletionTimestamp==null and any(.status.conditions[];.type=="Ready" and .status=="True"))' "$directory/agent-pods.json" >/dev/null
while IFS= read -r pod; do
    timeout 20 "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/$pod:9963/proxy/v1/version" > "$directory/$pod-version.json"
    jq -e --arg revision "$UNF_NATIVE_COVERAGE_RUNTIME_REVISION" '.component=="unf-agent" and .build_revision==$revision' "$directory/$pod-version.json" >/dev/null
done < <(jq -r '.items[].metadata.name' "$directory/agent-pods.json")
mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' -o json |
    jq -r '.items|sort_by(.metadata.name)|.[]|select(any(.status.conditions[];.type=="Ready" and .status=="True"))|.metadata.name')
(( ${#workers[@]} >= 2 ))
source_node=${workers[0]}
destination_node=${workers[1]}
"${kc[@]}" create namespace "$namespace" --save-config >/dev/null
owned=true
stage=fixture
for pod in client local-server remote-server; do
    node=$source_node
    role=server
    [[ $pod != remote-server ]] || node=$destination_node
    [[ $pod != client ]] || role=client
    jq -cn --arg namespace "$namespace" --arg pod "$pod" --arg node "$node" --arg role "$role" --arg image "$test_tools_image" '
      {apiVersion:"v1",kind:"Pod",metadata:{name:$pod,namespace:$namespace,labels:{app:$pod,role:$role}},spec:{
        nodeSelector:{"kubernetes.io/hostname":$node},containers:[{name:"probe",image:$image,imagePullPolicy:"IfNotPresent",
          command:["sh","-ec","/usr/local/bin/unf-udp-echo 4 5353 & /usr/local/bin/unf-udp-echo 6 5353 & exec /usr/local/bin/unf-flow-receiver 8080"]}]}}' |
      "${kc[@]}" apply -f - >/dev/null
    if [[ $role == server ]]; then
        jq -cn --arg namespace "$namespace" --arg pod "$pod" '
          {apiVersion:"v1",kind:"Service",metadata:{name:$pod,namespace:$namespace},spec:{ipFamilyPolicy:"RequireDualStack",
           selector:{app:$pod},ports:[{name:"tcp",port:8080,targetPort:8080,protocol:"TCP"},{name:"udp",port:5353,targetPort:5353,protocol:"UDP"}]}}' |
          "${kc[@]}" apply -f - >/dev/null
    fi
done
"${kc[@]}" -n "$namespace" wait --for=condition=Ready pods --all --timeout=180s >/dev/null
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: isolate-all, namespace: $namespace}
spec: {podSelector: {}, policyTypes: [Ingress, Egress]}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-request, namespace: $namespace}
spec:
  podSelector: {matchLabels: {role: client}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {role: server}}}]
      ports: [{protocol: TCP, port: 8080}, {protocol: UDP, port: 5353}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-server-ingress, namespace: $namespace}
spec:
  podSelector: {matchLabels: {role: server}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {role: client}}}]
      ports: [{protocol: TCP, port: 8080}, {protocol: UDP, port: 5353}]
EOF
udp_probe() {
    local pod=$1 address=$2 result
    result=$(timeout 10 "${kc[@]}" -n "$namespace" exec "$pod" -- sh -ec '
      case "$1" in *:*) target="UDP6-DATAGRAM:[$1]:5353";; *) target="UDP4-DATAGRAM:$1:5353";; esac
      result=$(printf native-coverage | socat -T 2 - "$target") || { printf probe-error; exit 0; }
      case "$result" in native-coverage) printf udp-ok;; "") printf network-denied;; *) printf probe-error;; esac
    ' native-coverage "$address") || return 2
    case "$result" in udp-ok) return 0;; network-denied) return 1;; *) return 2;; esac
}
probe() {
    case $1 in tcp) phase9_http_probe_once "$2" "$3" 8080;; udp) udp_probe "$2" "$3";; *) return 2;; esac
}
wait_probe() {
    local protocol=$1 pod=$2 address=$3
    for _ in $(seq 1 30); do
        if probe "$protocol" "$pod" "$address"; then return 0; fi
        sleep 1
    done
    return 1
}
# First prove all listeners independently of policy; an absent server cannot
# later masquerade as a successful denial assertion.
stage=listener-health
for pod in client local-server remote-server; do
    for address in 127.0.0.1 ::1; do
        for protocol in tcp udp; do wait_probe "$protocol" "$pod" "$address"; done
    done
done
stage=allowed-request-and-stateful-return
"${kc[@]}" -n "$namespace" get pods,services,networkpolicies -o json > "$directory/fixture.json"
allowed=0
for server in local-server remote-server; do
    for kind in pod service; do
        addresses=$("${kc[@]}" -n "$namespace" get "$kind" "$server" -o json |
            jq -ce 'if .kind=="Pod" then [.status.podIPs[].ip] else .spec.clusterIPs end
              | select(length==2 and any(.[];contains(":")) and any(.[];contains(".")))')
        while IFS= read -r address; do
            for protocol in tcp udp; do
                wait_probe "$protocol" client "$address"
                allowed=$((allowed+1))
            done
        done < <(jq -r '.[]' <<<"$addresses")
    done
done
stage=unsolicited-return-remains-denied
denied=0
addresses=$("${kc[@]}" -n "$namespace" get pod client -o json | jq -c '[.status.podIPs[].ip]')
for server in local-server remote-server; do
    while IFS= read -r address; do
        for protocol in tcp udp; do
            status=0
            probe "$protocol" "$server" "$address" || status=$?
            [[ $status == 1 ]] || { echo "expected real network denial, got status $status" >&2; false; }
            denied=$((denied+1))
        done
    done < <(jq -r '.[]' <<<"$addresses")
done
[[ $allowed == 16 && $denied == 8 ]]
stage=cleanup
"${kc[@]}" delete namespace "$namespace" --wait=true --timeout=180s >/dev/null
owned=false
"${kc[@]}" get namespaces -o json | jq -e --arg name "$namespace" 'all(.items[];.metadata.name!=$name)' >/dev/null
converged=false
deadline=$((SECONDS+180))
while (( SECONDS < deadline )); do
    if controller_raw /v1/state/agents > "$directory/final-agents.json" \
        && jq -e '.all_converged==true and .expected_agents>0 and .reporting_agents==.expected_agents' "$directory/final-agents.json" >/dev/null; then
        converged=true
        break
    fi
    sleep 2
done
[[ $converged == true ]]
jq -n --arg revision "$UNF_NATIVE_COVERAGE_RUNTIME_REVISION" --arg qualifier "$(git -C "$root" rev-parse HEAD)" \
    --arg context "$context" --arg source "$source_node" --arg destination "$destination_node" --argjson allowed "$allowed" --argjson denied "$denied" \
    '{schemaVersion:1,result:"passed",runtimeRevision:$revision,qualificationRevision:$qualifier,context:$context,
      sourceNode:$source,destinationNode:$destination,allowedRequests:$allowed,unsolicitedDenials:$denied,
      protocols:["TCP","UDP"],families:["IPv4","IPv6"],paths:["same-node","cross-node","PodIP","Service"],cleanup:"passed"}' > "$directory/evidence.json"
echo "Native local/return coverage passed: $directory/evidence.json"
