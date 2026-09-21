#!/usr/bin/env bash
# Bounded selective Required reply qualification; never flips cluster baseline.
set -Eeuo pipefail
umask 077
project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${KUBECONFIG:?exact disposable cluster required}"
: "${UNF_REQUIRED_REPLY_RUNTIME_REVISION:?committed runtime required}"
: "${UNF_TEST_TOOLS_IMAGE:?immutable test image required}"
: "${UNF_REQUIRED_REPLY_CAPTURE_INTERFACE:?exact physical underlay interface required}"
[[ $UNF_REQUIRED_REPLY_RUNTIME_REVISION =~ ^[0-9a-f]{40}$ ]]
[[ $UNF_TEST_TOOLS_IMAGE =~ @sha256:[0-9a-f]{64}$ ]]
[[ $UNF_REQUIRED_REPLY_CAPTURE_INTERFACE =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]
diagnostic_hold=${UNF_REQUIRED_REPLY_DIAGNOSTIC_HOLD_SECONDS:-0}
[[ $diagnostic_hold =~ ^(0|[1-9]|[1-5][0-9]|60)$ ]]
require_cni_ownership=${UNF_REQUIRED_REPLY_REQUIRE_CNI_OWNERSHIP:-false}
[[ $require_cni_ownership == true || $require_cni_ownership == false ]]
require_locality_candidate=${UNF_REQUIRED_REPLY_REQUIRE_LOCALITY_CANDIDATE:-false}
locality_acquisition=${UNF_REQUIRED_REPLY_LOCALITY_ACQUISITION:-required-only}
[[ $locality_acquisition == required-only || $locality_acquisition == all-plans ]]
[[ $require_locality_candidate == true || $require_locality_candidate == false ]]
require_locality_inventory=${UNF_REQUIRED_REPLY_REQUIRE_LOCALITY_INVENTORY:-false}
[[ $require_locality_inventory == true || $require_locality_inventory == false ]]
if [[ $require_locality_inventory == true ]]; then
    [[ $require_locality_candidate == true && $require_cni_ownership == true ]]
fi
[[ -z $(git -C "$project_root" status --porcelain) ]]
git -C "$project_root" merge-base --is-ancestor "$UNF_REQUIRED_REPLY_RUNTIME_REVISION" HEAD
context=${KUBE_CONTEXT:-$(kubectl --kubeconfig "$KUBECONFIG" config current-context)}
kc=(kubectl --kubeconfig "$KUBECONFIG" --context "$context")
read_api=("${kc[@]}" --request-timeout=15s)
namespace=unf-required-reply-qualification
directory=${UNF_REQUIRED_REPLY_DIAGNOSTICS:?new evidence directory required}
[[ ! -e $directory ]]
install -d -m 0700 "$directory"
owned=false
capture_started=false
capture_finished=false
forward_pid=
stage=preflight
source "$project_root/hack/phase9-http-probe.sh"
source "$project_root/hack/phase9-capture.sh"
source "$project_root/hack/required-reply-diagnostics.sh"
source "$project_root/hack/required-reply-cni-ownership.sh"
source "$project_root/hack/required-reply-locality.sh"
cleanup() {
    local status=$?
    trap - EXIT ERR
    if [[ -n $forward_pid ]]; then
        kill "$forward_pid" 2>/dev/null || true
        wait "$forward_pid" 2>/dev/null || true
    fi
    if [[ $owned == true ]]; then
        "${read_api[@]}" delete namespace "$namespace" --wait=false >/dev/null 2>&1 || true
    fi
    exit "$status"
}
failure() {
    local status=$?
    # Notify bounded external read-only observers immediately, independently
    # of API/capture readback. Preserve this original failure classification.
    jq -n --arg stage "$stage" --argjson status "$status" '{result:"failed",stage:$stage,exitCode:$status}' > "$directory/failure.json"
    if declare -F controller_raw >/dev/null; then
        required_reply_preserve_failure_status
    fi
    if [[ $capture_started == true && $capture_finished == false ]]; then
        # Retain failure evidence before deleting the owned Namespace. This
        # does not turn a failed traffic run into plaintext-absence evidence.
        if ! required_reply_preserve_failure_capture > "$directory/failed-capture-lifecycle.json" 2> "$directory/failed-capture-observer.log"; then
            echo 'Failure capture incomplete; do not infer plaintext absence' >&2
        fi
    fi
    "${read_api[@]}" -n "$namespace" get pods,services,networkpolicies,encryptionpolicies -o json > "$directory/failed-fixture.json" 2>&1 || true
    if (( diagnostic_hold > 0 )); then
        printf 'Holding only the failed fixture for %s seconds for read-only diagnostics\n' "$diagnostic_hold" >&2
        sleep "$diagnostic_hold"
    fi
    printf 'Required reply qualification failed at %s; retain %s\n' "$stage" "$directory" >&2
    return "$status"
}
trap cleanup EXIT
trap failure ERR
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ $context != kind-* ]]; then
    : "${UNF_REQUIRED_REPLY_INFRASTRUCTURE:?exact lab infrastructure required}"
    [[ $("${read_api[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}') == "$UNF_REQUIRED_REPLY_INFRASTRUCTURE" ]]
fi
"${read_api[@]}" get namespaces -o json | jq -e --arg ns "$namespace" 'all(.items[];.metadata.name!=$ns)' >/dev/null
"${read_api[@]}" get encryptionpolicies.network.unf.io -A -o json | jq -e '.items|length==0' >/dev/null
"${read_api[@]}" -n unf-system get deployment unf-controller -o json | jq -e '
  any(.spec.template.spec.containers[]|select(.name=="controller")|.env[];.name=="UNF_ENCRYPTION_BASELINE" and .value=="native")' >/dev/null
"${read_api[@]}" -n unf-system get pods -o json > "$directory/unf-before.json"
jq -e 'all(.items[]; .metadata.deletionTimestamp==null and .status.phase=="Running"
  and all(.status.containerStatuses[];.ready and .restartCount==0))' "$directory/unf-before.json" >/dev/null
controller=$(jq -er '[.items[]|select(.metadata.labels["app.kubernetes.io/name"]=="unf-controller")]|select(length==1)|.[0].metadata.name' "$directory/unf-before.json")
"${kc[@]}" -n unf-system port-forward --address=127.0.0.1 "pod/$controller" :9962 > "$directory/controller-forward.log" 2>&1 &
forward_pid=$!
controller_port=
for _ in $(seq 1 30); do
    kill -0 "$forward_pid"
    if [[ -f $directory/controller-forward.log ]]; then
        controller_port=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) -> 9962$/\1/p' "$directory/controller-forward.log")
    fi
    [[ -z $controller_port ]] || break
    sleep 1
done
[[ $controller_port =~ ^[0-9]+$ ]]
controller_raw() {
    kill -0 "$forward_pid"
    curl --fail --silent --show-error --max-time 15 "http://127.0.0.1:$controller_port$1"
}
controller_raw /v1/version > "$directory/controller-version.json"
jq -e --arg revision "$UNF_REQUIRED_REPLY_RUNTIME_REVISION" '.build_revision==$revision' "$directory/controller-version.json" >/dev/null
while read -r pod; do
    timeout 20 "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/$pod:9963/proxy/v1/version" > "$directory/$pod-version.json"
    jq -e --arg revision "$UNF_REQUIRED_REPLY_RUNTIME_REVISION" '.build_revision==$revision' "$directory/$pod-version.json" >/dev/null
done < <(jq -r '.items[]|select(.metadata.labels["app.kubernetes.io/name"]=="unf-agent")|.metadata.name' "$directory/unf-before.json")
mapfile -t workers < <("${read_api[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' -o json |
    jq -r '.items|sort_by(.metadata.name)|.[]|select(any(.status.conditions[];.type=="Ready" and .status=="True"))|.metadata.name')
(( ${#workers[@]} >= 2 ))
source_node=${workers[0]}
destination_node=${workers[1]}
source_agent=$(jq -er --arg node "$source_node" '.items[]|select(.spec.nodeName==$node and .metadata.labels["app.kubernetes.io/name"]=="unf-agent")|.metadata.name' "$directory/unf-before.json")
reply_agent=$(jq -er --arg node "$destination_node" '.items[]|select(.spec.nodeName==$node and .metadata.labels["app.kubernetes.io/name"]=="unf-agent")|.metadata.name' "$directory/unf-before.json")
if [[ $require_locality_candidate == true ]]; then
    locality_cluster_uid=$("${read_api[@]}" get namespace kube-system -o jsonpath='{.metadata.uid}')
    [[ -n $locality_cluster_uid ]]
    stage=locality-native-baseline
    required_reply_locality_wait native
fi
"${read_api[@]}" create namespace "$namespace" >/dev/null
owned=true
fixture_uid=65532
if [[ $context != kind-* ]]; then
    fixture_uid=$("${read_api[@]}" get namespace "$namespace" -o json | jq -er '.metadata.annotations["openshift.io/sa.scc.uid-range"]|split("/")[0]|tonumber')
fi
apply=("${read_api[@]}" apply --server-side --field-manager=unf-required-reply-qualification --validate=false -f -)
stage=fixture
for pod in required-client native-client server; do
    node=$source_node; role=client
    [[ $pod != server ]] || { node=$destination_node; role=server; }
    jq -cn --arg ns "$namespace" --arg pod "$pod" --arg node "$node" --arg role "$role" --arg image "$UNF_TEST_TOOLS_IMAGE" --argjson uid "$fixture_uid" '
      {apiVersion:"v1",kind:"Pod",metadata:{name:$pod,namespace:$ns,labels:{app:$pod,role:$role}},spec:{
        automountServiceAccountToken:false,nodeSelector:{"kubernetes.io/hostname":$node},
        securityContext:{runAsNonRoot:true,runAsUser:$uid,seccompProfile:{type:"RuntimeDefault"}},
        containers:[{name:"probe",image:$image,imagePullPolicy:"IfNotPresent",
          securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},
          resources:{requests:{cpu:"10m",memory:"16Mi"},limits:{cpu:"500m",memory:"128Mi"}},
          command:["sh","-ec","/usr/local/bin/unf-udp-echo 4 5353 & /usr/local/bin/unf-udp-echo 6 5353 & exec /usr/local/bin/unf-flow-receiver 8080"]}]}}' | "${apply[@]}" >/dev/null
done
"${apply[@]}" >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: server, namespace: $namespace}
spec:
  ipFamilyPolicy: RequireDualStack
  selector: {app: server}
  ports:
    - {name: tcp, protocol: TCP, port: 8080, targetPort: 8080}
    - {name: udp, protocol: UDP, port: 5353, targetPort: 5353}
    - {name: tcp-remap, protocol: TCP, port: 18080, targetPort: 8080}
    - {name: udp-remap, protocol: UDP, port: 53, targetPort: 5353}
---
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
"${kc[@]}" -n "$namespace" wait --for=condition=Ready pods --all --timeout=180s >/dev/null
if [[ $require_cni_ownership == true ]]; then
    stage=runtime-cni-ownership
    required_reply_cni_capture
fi
udp_probe() {
    local result
    result=$(timeout 10 "${kc[@]}" -n "$namespace" exec "$1" -- sh -ec '
      case "$1" in *:*) target="UDP6-DATAGRAM:[$1]:$2";; *) target="UDP4-DATAGRAM:$1:$2";; esac
      result=$(printf required-reply | socat -T 2 - "$target") || { printf probe-error; exit 0; }
      case "$result" in required-reply) printf udp-ok;; "") printf network-denied;; *) printf probe-error;; esac
    ' required-reply "$2" "$3") || return 2
    case $result in udp-ok) return 0;; network-denied) return 1;; *) return 2;; esac
}
probe() {
    local status=0
    printf 'Probe %s from %s to %s:%s\n' "$1" "$2" "$3" "$4"
    case $1 in
        tcp) phase9_http_probe_once "$2" "$3" "$4" || status=$?;;
        udp) udp_probe "$2" "$3" "$4" || status=$?;;
        *) status=2;;
    esac
    jq -cn --arg protocol "$1" --arg pod "$2" --arg address "$3" --argjson port "$4" --argjson status "$status" \
      --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{at:$at,protocol:$protocol,pod:$pod,address:$address,port:$port,exitCode:$status}' >> "$directory/probes.jsonl"
    return "$status"
}
listener_ready() {
    local deadline=$((SECONDS+30))
    while (( SECONDS < deadline )); do
        if probe "$@"; then return 0; fi
        sleep 1
    done
    return 1
}
for pod in required-client native-client server; do
    for address in 127.0.0.1 ::1; do
        listener_ready tcp "$pod" "$address" 8080
        listener_ready udp "$pod" "$address" 5353
    done
done
"${read_api[@]}" -n "$namespace" get pods,services,networkpolicies -o json > "$directory/fixture.json"
stage=capture-preparation
source "$project_root/hack/required-reply-capture.sh"
required_reply_capture_prepare
stage=policy-adoption
source "$project_root/hack/required-reply-adoption.sh"
required_reply_wait_policy
stage=selective-required-admission
"${apply[@]}" >/dev/null <<EOF
apiVersion: network.unf.io/v1alpha1
kind: EncryptionPolicy
metadata: {name: required-pair, namespace: $namespace}
spec:
  priority: 1000
  bidirectional: true
  sources: {matchLabels: {app: required-client}}
  destinations: {matchLabels: {app: server}}
EOF
required_reply_wait_generation required
if [[ $require_locality_candidate == true ]]; then
    stage=locality-required-candidate
    required_reply_locality_wait required
fi
stage=capture-and-traffic
required_reply_capture_start
capture_started=true
allowed=0
for client in required-client native-client; do
    for kind in Pod Service; do
        while read -r address; do
            for protocol in tcp udp; do
                port=8080; [[ $protocol != udp ]] || port=5353
                probe "$protocol" "$client" "$address" "$port"
                allowed=$((allowed+1))
                if [[ $kind == Service ]]; then
                    port=18080; [[ $protocol != udp ]] || port=53
                    probe "$protocol" "$client" "$address" "$port"
                    allowed=$((allowed+1))
                fi
            done
        done < <(jq -r --arg kind "$kind" '.items[]|select(.kind==$kind and .metadata.name=="server")|if .kind=="Pod" then .status.podIPs[].ip else .spec.clusterIPs[] end' "$directory/fixture.json")
    done
done
denied=0
for client in required-client native-client; do
    while read -r address; do
        for protocol in tcp udp; do
            port=8080; [[ $protocol != udp ]] || port=5353
            status=0
            probe "$protocol" server "$address" "$port" || status=$?
            [[ $status == 1 ]]
            denied=$((denied+1))
        done
    done < <(jq -r --arg pod "$client" '.items[]|select(.kind=="Pod" and .metadata.name==$pod)|.status.podIPs[].ip' "$directory/fixture.json")
done
[[ $allowed == 24 && $denied == 8 ]]
required_reply_capture_finish
capture_finished=true
stage=cleanup
"${kc[@]}" delete namespace "$namespace" --wait=true --timeout=180s >/dev/null
owned=false
"${read_api[@]}" get namespaces -o json | jq -e --arg ns "$namespace" 'all(.items[];.metadata.name!=$ns)' >/dev/null
required_reply_wait_generation native
if [[ $require_locality_candidate == true ]]; then
    stage=locality-native-convergence
    required_reply_locality_wait native
    jq -n --slurpfile candidate "$directory/locality-required.json" --slurpfile retired "$directory/locality-native.json" \
      --argjson inventory "$require_locality_inventory" \
      --arg acquisition "$locality_acquisition" \
      '{scope:"placement-candidate-only",acquisition:$acquisition,replayedAgents:($candidate[0]|length),journalInventoryCountsVerified:$inventory,kernelAdmitted:false,observedDelivery:false}
        + (if $acquisition=="all-plans" then {nativeConvergedAgents:($retired[0]|length)} else {retiredAgents:($retired[0]|length)} end)' > "$directory/locality-candidate.json"
else
    printf 'null\n' > "$directory/locality-candidate.json"
fi
if [[ $require_cni_ownership == true ]]; then
    stage=runtime-cni-retirement
    required_reply_cni_retirement
else
    printf 'null\n' > "$directory/cni-ownership.json"
fi
jq -n --arg runtime "$UNF_REQUIRED_REPLY_RUNTIME_REVISION" --arg qualifier "$(git -C "$project_root" rev-parse HEAD)" \
    --arg context "$context" --argjson allowed "$allowed" --argjson denied "$denied" --slurpfile capture "$directory/capture-summary.json" \
    --slurpfile cni "$directory/cni-ownership.json" \
    --slurpfile locality "$directory/locality-candidate.json" \
    '{schemaVersion:1,result:"passed",runtimeRevision:$runtime,qualificationRevision:$qualifier,context:$context,
      requiredRequests:12,nativeControls:12,allowedRequests:$allowed,unsolicitedDenials:$denied,
      families:["IPv4","IPv6"],protocols:["TCP","UDP"],paths:["cross-node PodIP","Service","translated Service port"],
      capture:$capture[0],replyContractSchema:2,cleanup:"namespace absent; fleet Native and converged"}
      + (if $cni[0] == null then {} else {cniOwnership:$cni[0]} end)
      + (if $locality[0] == null then {} else {localityCandidate:$locality[0]} end)' > "$directory/evidence.json"
echo "Required reply qualification passed: $directory/evidence.json"
