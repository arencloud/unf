#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${OPENSHIFT_KUBECONFIG:-${KUBECONFIG:-}}
node=${UNF_PRIMARY_CNI_REPROVISION_NODE:-}
ssh_target=${UNF_PRIMARY_CNI_SSH_TARGET:-}
known_hosts=${UNF_PRIMARY_CNI_SSH_KNOWN_HOSTS:-}
confirmation=${UNF_PRIMARY_CNI_REPROVISION_CONFIRM:-}
disposable_ack=${UNF_PRIMARY_CNI_REPROVISION_ACKNOWLEDGE_DISPOSABLE:-}
namespace=${UNF_PRIMARY_CNI_REPROVISION_NAMESPACE:-unf-primary-cni-reprovision}
image=${UNF_TEST_TOOLS_IMAGE:-quay.io/arencloud/unf-test-tools-dev@sha256:f57a7ee9668d6b87f4e00c4e8df9240b8889c6ee50f817ea1e884732b2f42b13}
artifact=${UNF_PRIMARY_CNI_REPROVISION_EVIDENCE:-${project_root}/.artifacts/phase3-openshift-primary-cni-node-reprovision.json}

for command in jq oc ssh; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift primary-CNI reprovision prerequisite is missing: ${command}" >&2
        exit 1
    }
done
[[ -n ${kubeconfig} && -f ${kubeconfig} && $(stat -c %a "${kubeconfig}") == 600 ]]
[[ ${node} =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]
[[ ${namespace} =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]
[[ ${ssh_target} =~ ^[a-z_][a-z0-9_-]*@[A-Za-z0-9:._-]+$ ]]
[[ -n ${known_hosts} && -f ${known_hosts} ]] || {
    echo "set UNF_PRIMARY_CNI_SSH_KNOWN_HOSTS to the target's pinned known-hosts file" >&2
    exit 1
}

kc=(oc --kubeconfig "${kubeconfig}")
ssh_node=(ssh -o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=${known_hosts}" "${ssh_target}")
context=$("${kc[@]}" config current-context)
infrastructure=$("${kc[@]}" get infrastructure cluster -o jsonpath='{.status.infrastructureName}')
expected_confirmation=${context}:${node}
[[ ${confirmation} == "${expected_confirmation}" ]] || {
    echo "refusing reprovision without UNF_PRIMARY_CNI_REPROVISION_CONFIRM=${expected_confirmation}" >&2
    exit 1
}
[[ -n ${infrastructure} && ${disposable_ack} == "${infrastructure}" ]] || {
    echo "refusing reprovision unless the disposable acknowledgement equals ${infrastructure}" >&2
    exit 1
}

node_cordoned=false
node_labeled=true
kubelet_stopped=false
namespace_created=false
artifact_tmp=
completed=false

cleanup() {
    set +e
    if [[ ${namespace_created} == true ]]; then
        "${kc[@]}" delete namespace "${namespace}" --ignore-not-found \
            --wait=false >/dev/null
    fi
    if [[ ${node_labeled} == false ]]; then
        "${kc[@]}" label node "${node}" network.unf.io/primary-cni=enabled \
            --overwrite >/dev/null
        node_labeled=true
    fi
    if [[ ${kubelet_stopped} == true ]]; then
        "${ssh_node[@]}" sudo systemctl start kubelet >/dev/null
        kubelet_stopped=false
    fi
    if [[ ${node_cordoned} == true ]]; then
        "${kc[@]}" adm uncordon "${node}" >/dev/null
        node_cordoned=false
    fi
    if [[ -n ${artifact_tmp} && -f ${artifact_tmp} ]]; then
        rm -f -- "${artifact_tmp}"
    fi
    if [[ ${completed} != true ]]; then
        echo "reprovision gate exited early; recovery actions were applied" >&2
    fi
}
trap cleanup EXIT

host_snapshot() {
    "${ssh_node[@]}" '
        attachments=$(sudo jq ".attachments | length" /var/lib/unf/cni/v1/attachments.json 2>/dev/null || echo 0)
        caches=$(sudo find /var/lib/cni/results -maxdepth 1 -type f -name "unf-primary-*-eth0" | wc -l)
        links=$(sudo ip -o link show | grep -Ec "^[0-9]+: unf[0-9a-f]+")
        pending=$(sudo find /var/lib/unf/cni/v1/pending-deletes -type f -name "*.json" 2>/dev/null | wc -l)
        maps=$(sudo find /sys/fs/bpf/unf/v15 -maxdepth 1 -type f 2>/dev/null | wc -l)
        routes4=$(sudo ip -4 route show proto 196 | wc -l)
        routes6=$(sudo ip -6 route show proto 196 | wc -l)
        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$attachments" "$caches" "$links" "$pending" "$maps" "$routes4" "$routes6"
    ' | tail -n 1
}

wait_for_convergence() {
    local expected=$1
    local controller snapshot=
    for _ in $(seq 1 180); do
        controller=$("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-controller -o json \
            | jq -r '.items[] | select(.metadata.deletionTimestamp == null and
                .status.phase == "Running") | .metadata.name' | head -n 1)
        if [[ -n ${controller} ]]; then
            snapshot=$("${kc[@]}" get --raw \
                "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/state/agents" \
                2>/dev/null || true)
        fi
        if jq -e --argjson expected "${expected}" '
            .expected_agents == $expected and .reporting_agents == $expected and
            .missing_agents == 0 and .stale_agents == 0 and
            .converged_agents == $expected and .unexpected_agents == 0 and
            .all_converged == true and
            all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded)
          ' <<<"${snapshot}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "agents did not converge to ${expected}/${expected}" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_for_target_maintenance() {
    local expected=$1
    local controller snapshot=
    for _ in $(seq 1 180); do
        controller=$("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-controller -o json \
            | jq -r '.items[] | select(.metadata.deletionTimestamp == null and
                .status.phase == "Running") | .metadata.name' | head -n 1)
        if [[ -n ${controller} ]]; then
            snapshot=$("${kc[@]}" get --raw \
                "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy/v1/state/agents" \
                2>/dev/null || true)
        fi
        if jq -e --argjson expected "${expected}" --arg target "${node}" '
            .expected_agents == $expected and
            ([.nodes[] | select(.node_name != $target and .fresh and .converged and
                .report.ready and .report.bpf_loaded)] | length) == ($expected - 1) and
            ([.nodes[] | select(.node_name == $target and
                ((.fresh | not) or (.converged | not)))] | length) == 1
          ' <<<"${snapshot}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "remaining agents did not converge around the maintained target" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

wait_target_agent() {
    local pod=
    for _ in $(seq 1 300); do
        pod=$("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-agent \
            --field-selector "spec.nodeName=${node}" -o json \
            | jq -r '.items[] | select(.metadata.deletionTimestamp == null and
                .status.phase == "Running" and
                all(.status.containerStatuses[]; .ready)) | .metadata.name' | head -n 1)
        [[ -n ${pod} ]] && {
            printf '%s\n' "${pod}"
            return 0
        }
        sleep 1
    done
    echo "target agent did not become Ready" >&2
    return 1
}

"${kc[@]}" get node "${node}" -o json | jq -e '
    (.metadata.labels["node-role.kubernetes.io/worker"] != null) and
    (.metadata.labels["node-role.kubernetes.io/control-plane"] == null) and
    .metadata.labels["network.unf.io/primary-cni"] == "enabled" and
    any(.status.conditions[]; .type == "Ready" and .status == "True")
  ' >/dev/null
[[ $("${kc[@]}" get nodes -o json | jq '[.items[] | select(any(.status.conditions[];
    .type == "Ready" and .status == "True"))] | length') -ge 3 ]]
[[ $("${kc[@]}" get network.config.openshift.io cluster -o jsonpath='{.spec.networkType}') == None ]]
[[ $("${kc[@]}" get co -o json | jq '[.items[] | select(.metadata.name != "insights") |
    select(any(.status.conditions[]; (.type == "Available" and .status != "True") or
        (.type == "Degraded" and .status == "True")))] | length') -eq 0 ]]
if "${kc[@]}" get namespace "${namespace}" >/dev/null 2>&1; then
    echo "refusing to reuse existing Namespace ${namespace}" >&2
    exit 1
fi
expected_agents=$("${kc[@]}" get nodes -l network.unf.io/primary-cni=enabled \
    -o json | jq '.items | length')
[[ ${expected_agents} -eq 5 ]]
wait_for_convergence "${expected_agents}"

baseline_pods=$("${kc[@]}" get pods -A \
    --field-selector "spec.nodeName=${node},status.phase=Running" -o json \
    | jq '[.items[] | select(.spec.hostNetwork != true)] | length')
baseline=$(host_snapshot)
IFS=$'\t' read -r baseline_attachments baseline_caches baseline_links \
    baseline_pending baseline_maps baseline_routes4 baseline_routes6 <<<"${baseline}"
[[ ${baseline_pods} -eq ${baseline_attachments} ]]
[[ ${baseline_attachments} -eq ${baseline_caches} ]]
[[ ${baseline_attachments} -eq ${baseline_links} ]]
[[ ${baseline_pending} -eq 0 && ${baseline_maps} -eq 18 ]]
[[ ${baseline_routes4} -eq $((baseline_attachments + expected_agents - 1)) ]]
[[ ${baseline_routes6} -eq ${baseline_routes4} ]]
"${ssh_node[@]}" '
    test "$(sudo systemctl is-active kubelet)" = active
    sudo test -S /run/unf/cni.sock
    test "$(sudo stat -c %a /run/unf/cni.sock)" = 600
    sudo test -f /var/lib/unf/cni/v1/install.env
    test "$(sudo find /etc/kubernetes/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)" = 1
'

"${kc[@]}" adm cordon "${node}" >/dev/null
node_cordoned=true
"${kc[@]}" adm drain "${node}" --ignore-daemonsets --delete-emptydir-data \
    --force --timeout=10m >/dev/null

"${ssh_node[@]}" sudo systemctl stop kubelet
kubelet_stopped=true
"${kc[@]}" label node "${node}" network.unf.io/primary-cni- >/dev/null
node_labeled=false

"${ssh_node[@]}" sudo bash -se <<'HOST_TEARDOWN'
test "$(systemctl is-active kubelet || true)" = inactive
mapfile -t sandboxes < <(find /var/lib/cni/results -maxdepth 1 -type f \
    -name 'unf-primary-*-eth0' -printf '%f\n' \
    | sed -E 's/^unf-primary-([0-9a-f]{64})-eth0$/\1/' | sort -u)
test "${#sandboxes[@]}" -gt 0
for sandbox in "${sandboxes[@]}"; do
    crictl stopp "${sandbox}" >/dev/null
    crictl rmp "${sandbox}" >/dev/null
done
for _ in $(seq 1 60); do
    attachments=$(jq '.attachments | length' /var/lib/unf/cni/v1/attachments.json)
    caches=$(find /var/lib/cni/results -maxdepth 1 -type f -name 'unf-primary-*-eth0' | wc -l)
    links=$(ip -o link show | grep -Ec '^[0-9]+: unf[0-9a-f]+' || true)
    pending=$(find /var/lib/unf/cni/v1/pending-deletes -type f -name '*.json' | wc -l)
    test "$attachments" -eq 0 && test "$caches" -eq 0 \
        && test "$links" -eq 0 && test "$pending" -eq 0 && break
    sleep 1
done
test "$attachments" -eq 0 && test "$caches" -eq 0 \
    && test "$links" -eq 0 && test "$pending" -eq 0

agent_container=$(crictl ps -o json | jq -r '[.containers[] |
    select(.labels["io.kubernetes.pod.namespace"] == "unf-system" and
        .metadata.name == "agent") | .id] | if length == 1 then .[0] else empty end')
agent_sandbox=$(crictl ps -o json | jq -r --arg id "$agent_container" '
    .containers[] | select(.id == $id) | .podSandboxId')
test -n "$agent_container" && test -n "$agent_sandbox"
crictl exec "$agent_container" /usr/local/bin/unf-component cleanup \
    --abi-version 13 --allow-current-abi --legacy-attachments --all-interfaces \
    --legacy-direction both --execute >/run/unf/node-reprovision-cleanup.log
grep -q 'UNF cleanup completed' /run/unf/node-reprovision-cleanup.log
test ! -e /sys/fs/bpf/unf/v15
crictl stopp "$agent_sandbox" >/dev/null
crictl rmp "$agent_sandbox" >/dev/null

state_dir=/var/lib/unf/cni/v1
routes=${state_dir}/remote-routes.json
marker=${state_dir}/install.env
binary=/var/lib/cni/bin/unf
config=/etc/kubernetes/cni/net.d/10-unf.conflist
test -f "$routes" && test ! -L "$routes"
test "$(jq -r .schemaVersion "$routes")" = 1
expected=$(jq '.remoteNodes | length' "$routes")
test "$(ip -j -4 route show proto 196 | jq length)" -eq "$expected"
test "$(ip -j -6 route show proto 196 | jq length)" -eq "$expected"
while IFS=$'\t' read -r block4 gateway4 block6 gateway6; do
    ip -j -details -4 route show exact "$block4" | jq -e --arg dst "$block4" \
        --arg gateway "$gateway4" 'length == 1 and .[0].dst == $dst and
        .[0].gateway == $gateway and .[0].dev == "br-ex" and .[0].protocol == "196"' >/dev/null
    ip -j -details -6 route show exact "$block6" | jq -e --arg dst "$block6" \
        --arg gateway "$gateway6" 'length == 1 and .[0].dst == $dst and
        .[0].gateway == $gateway and .[0].dev == "br-ex" and .[0].protocol == "196"' >/dev/null
    ip -4 route del "$block4" via "$gateway4" dev br-ex proto 196
    ip -6 route del "$block6" via "$gateway6" dev br-ex proto 196
done < <(jq -r '.remoteNodes[] | [.intent.blocks.ipv4Block, .ipv4Transport,
    .intent.blocks.ipv6Block, .ipv6Transport] | @tsv' "$routes")
test "$(ip -j -4 route show proto 196 | jq length)" -eq 0
test "$(ip -j -6 route show proto 196 | jq length)" -eq 0

test -f "$marker" && test ! -L "$marker" && test "$(wc -l <"$marker")" -eq 4
test "$(sed -n 's/^schema=//p' "$marker")" = 1
test "$(sed -n 's/^platform=//p' "$marker")" = openshift
binary_sha=$(sed -n 's/^binary_sha256=//p' "$marker")
config_sha=$(sed -n 's/^config_sha256=//p' "$marker")
test "$(sha256sum "$binary" | cut -d ' ' -f 1)" = "$binary_sha"
test "$(sha256sum "$config" | cut -d ' ' -f 1)" = "$config_sha"
test "$(find /etc/kubernetes/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 1

rm -f /run/unf/cni.sock /run/unf/node-reprovision-cleanup.log
rm -f "$binary" "$config"
rm -f "${state_dir}/attachments.json" "${state_dir}/node-block.json" "$routes" "$marker"
test -d "${state_dir}/pending-deletes" && test ! -L "${state_dir}/pending-deletes"
test -z "$(find "${state_dir}/pending-deletes" -mindepth 1 -maxdepth 1 \
    ! -name .unf-primary.lock -print -quit)"
rm -f "${state_dir}/pending-deletes/.unf-primary.lock"
rmdir "${state_dir}/pending-deletes" "$state_dir" /var/lib/unf/cni /run/unf
if test -d /sys/fs/bpf/unf; then
    test -z "$(find /sys/fs/bpf/unf -mindepth 1 -maxdepth 1 -print -quit)"
    rmdir /sys/fs/bpf/unf
fi
test ! -e "$binary" && test ! -e "$config" && test ! -e /var/lib/unf/cni
test ! -e /run/unf && test ! -e /sys/fs/bpf/unf
test "$(find /etc/kubernetes/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 0
test "$(ip -j -4 route show proto 196 | jq length)" -eq 0
test "$(ip -j -6 route show proto 196 | jq length)" -eq 0
systemctl start kubelet
test "$(systemctl is-active kubelet)" = active
HOST_TEARDOWN
kubelet_stopped=false

for _ in $(seq 1 120); do
    target_agents=$("${kc[@]}" -n unf-system get pods \
        -l app.kubernetes.io/name=unf-agent --field-selector "spec.nodeName=${node}" \
        -o json | jq '.items | length')
    [[ ${target_agents} -eq 0 ]] && break
    sleep 1
done
[[ ${target_agents} -eq 0 ]]
wait_for_target_maintenance "${expected_agents}"
"${ssh_node[@]}" '
    for directory in /var/lib/unf/cni /run/unf; do
        if sudo test -d "$directory"; then
            test -z "$(sudo find "$directory" -mindepth 1 -print -quit)"
            sudo rmdir "$directory"
        fi
    done
'

no_cni=$("${ssh_node[@]}" '
    test "$(systemctl is-active kubelet)" = active
    test ! -e /var/lib/cni/bin/unf
    test ! -e /etc/kubernetes/cni/net.d/10-unf.conflist
    test ! -e /var/lib/unf/cni
    test ! -e /run/unf
    test ! -e /sys/fs/bpf/unf
    routes4=$(sudo ip -4 route show proto 196 | wc -l)
    routes6=$(sudo ip -6 route show proto 196 | wc -l)
    configs=$(sudo find /etc/kubernetes/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)
    test "$configs" -eq 0
    printf "0\t0\t0\t0\t0\t%s\t%s\n" "$routes4" "$routes6"
' | tail -n 1)
[[ ${no_cni} == $'0\t0\t0\t0\t0\t0\t0' ]]

"${kc[@]}" create namespace "${namespace}" >/dev/null
namespace_created=true
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: no-cni-probe
  namespace: ${namespace}
spec:
  nodeName: ${node}
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: probe
      image: ${image}
      command: ["sh", "-c", "sleep infinity"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
EOF
sleep 20
probe=$("${kc[@]}" -n "${namespace}" get pod no-cni-probe -o json)
jq -e '.status.phase == "Pending" and
    all(.status.containerStatuses[]?; (.containerID // "") == "")' \
    <<<"${probe}" >/dev/null
events=$("${kc[@]}" -n "${namespace}" get events \
    --field-selector involvedObject.name=no-cni-probe -o json)
jq -e 'any(.items[]; .reason == "FailedCreatePodSandBox" and
    (.message | test("(?i)(cni|network plugin|network not ready)")))' \
    <<<"${events}" >/dev/null
"${kc[@]}" delete namespace "${namespace}" --wait=true --timeout=120s >/dev/null
namespace_created=false

"${kc[@]}" label node "${node}" network.unf.io/primary-cni=enabled --overwrite >/dev/null
node_labeled=true
agent_pod=$(wait_target_agent)
"${kc[@]}" adm uncordon "${node}" >/dev/null
node_cordoned=false
"${kc[@]}" wait --for=condition=Ready "node/${node}" --timeout=10m >/dev/null
wait_for_convergence "${expected_agents}"

for _ in $(seq 1 180); do
    recovered_pods=$("${kc[@]}" get pods -A \
        --field-selector "spec.nodeName=${node},status.phase=Running" -o json \
        | jq '[.items[] | select(.spec.hostNetwork != true)] | length')
    recovered=$(host_snapshot)
    IFS=$'\t' read -r recovered_attachments recovered_caches recovered_links \
        recovered_pending recovered_maps recovered_routes4 recovered_routes6 <<<"${recovered}"
    if [[ ${recovered_pods} -gt 0 && ${recovered_pods} -eq ${recovered_attachments} \
        && ${recovered_attachments} -eq ${recovered_caches} \
        && ${recovered_attachments} -eq ${recovered_links} \
        && ${recovered_pending} -eq 0 && ${recovered_maps} -eq 18 \
        && ${recovered_routes4} -eq $((recovered_attachments + expected_agents - 1)) \
        && ${recovered_routes6} -eq ${recovered_routes4} ]]; then
        break
    fi
    sleep 2
done
[[ ${recovered_pods} -gt 0 && ${recovered_pods} -eq ${recovered_attachments} ]]
[[ ${recovered_attachments} -eq ${recovered_caches} \
    && ${recovered_attachments} -eq ${recovered_links} ]]
[[ ${recovered_pending} -eq 0 && ${recovered_maps} -eq 18 ]]
[[ ${recovered_routes4} -eq $((recovered_attachments + expected_agents - 1)) \
    && ${recovered_routes6} -eq ${recovered_routes4} ]]

"${ssh_node[@]}" '
    test -S /run/unf/cni.sock && test "$(stat -c %a /run/unf/cni.sock)" = 600
    test -f /var/lib/unf/cni/v1/install.env
    test "$(find /etc/kubernetes/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)" = 1
    dig +short +time=2 +tries=1 @172.30.0.10 kubernetes.default.svc.cluster.local A \
        | grep -qx 172.30.0.1
'
[[ $("${kc[@]}" get --raw "/api/v1/nodes/${node}/proxy/healthz") == ok ]]
[[ $("${kc[@]}" get co -o json | jq '[.items[] | select(.metadata.name != "insights") |
    select(any(.status.conditions[]; (.type == "Available" and .status != "True") or
        (.type == "Degraded" and .status == "True")))] | length') -eq 0 ]]

canary=$("${kc[@]}" -n openshift-ingress-canary get pods \
    --field-selector "spec.nodeName=${node}" -o json \
    | jq -r '.items[] | select(.status.phase == "Running" and
        any(.status.conditions[]; .type == "Ready" and .status == "True")) |
        [.status.podIP, .status.podIPs[1].ip] | @tsv' | head -n 1)
IFS=$'\t' read -r canary4 canary6 <<<"${canary}"
[[ -n ${canary4} && -n ${canary6} ]]
source_node=$("${kc[@]}" get nodes -l node-role.kubernetes.io/worker \
    -o json | jq -r --arg target "${node}" '.items[] | select(.metadata.name != $target) |
        .metadata.name' | head -n 1)
traffic=$("${kc[@]}" debug "node/${source_node}" --quiet -- chroot /host sh -ec \
    "v4=\$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 8 https://${canary4}:8443/); \
     v6=\$(curl -g -k -sS -o /dev/null -w '%{http_code}' --max-time 8 'https://[${canary6}]:8443/'); \
     printf '%s/%s\\n' \"\$v4\" \"\$v6\"" | tail -n 1)
[[ ${traffic} == 200/200 ]]

mkdir -p "$(dirname "${artifact}")"
umask 077
artifact_tmp=$(mktemp "${artifact}.tmp.XXXXXX")
jq -n --arg context "${context}" --arg infrastructure "${infrastructure}" \
    --arg node "${node}" --arg agentPod "${agent_pod}" \
    --arg baseline "${baseline}" --arg noCni "${no_cni}" \
    --arg recovered "${recovered}" --arg traffic "${traffic}" '
    {
      schemaVersion: 1,
      scenario: "openshift-primary-cni-node-reprovision",
      context: $context,
      infrastructure: $infrastructure,
      node: $node,
      stateColumns: ["attachments", "crioCaches", "hostLinks", "pendingDeletes",
        "bpfMaps", "ipv4Routes", "ipv6Routes"],
      states: {baseline: $baseline, noCni: $noCni, recovered: $recovered},
      recoveredAgentPod: $agentPod,
      crossWorkerHttps: $traffic,
      checks: {
        guardedDrain: "passed",
        crioDeleteBeforeAgentStop: "passed",
        exactRoutesBpfAndArtifactsRemoved: "passed",
        noCniPodFailure: "passed",
        hostNetworkBootstrap: "passed",
        exactReprovisionState: "passed",
        controllerConvergence: "passed",
        platformHealth: "passed"
      }
    }
  ' >"${artifact_tmp}"
mv "${artifact_tmp}" "${artifact}"
artifact_tmp=
completed=true

echo "OpenShift primary-CNI node teardown and reprovision passed: ${artifact}"
