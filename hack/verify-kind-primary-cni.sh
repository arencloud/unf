#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-cni-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-cni-dev}
container_runtime=${KIND_PROVIDER:-podman}
artifact=${UNF_PRIMARY_CNI_EVIDENCE:-"${project_root}/.artifacts/phase3-primary-cni-kind.json"}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
qualification_namespace=unf-cni-qualification
foreign_node=
controller_scaled_down=false

cleanup_failure_injections() {
    if [[ -n ${foreign_node} ]]; then
        sudo "${container_runtime}" exec "${foreign_node}" \
            rm -f /etc/cni/net.d/99-foreign.conflist >/dev/null 2>&1 || true
    fi
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 \
            >/dev/null 2>&1 || true
    fi
}
trap cleanup_failure_injections EXIT

if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing primary-CNI qualification outside the exact Kind context ${context}" >&2
    exit 1
fi
if "${kc[@]}" -n kube-system get daemonset kindnet >/dev/null 2>&1; then
    echo "isolated fixture unexpectedly has kindnet installed" >&2
    exit 1
fi

mapfile -t workers < <("${kc[@]}" get nodes -l '!node-role.kubernetes.io/control-plane' \
    -o name | sed 's|node/||' | sort)
control_plane=$("${kc[@]}" get nodes -l node-role.kubernetes.io/control-plane \
    -o jsonpath='{.items[0].metadata.name}')
if (( ${#workers[@]} != 2 )) || [[ -z ${control_plane} ]]; then
    echo "qualification requires one control-plane and exactly two workers" >&2
    exit 1
fi
client_node=${workers[0]}
server_node=${workers[1]}
mapfile -t nodes < <(printf '%s\n' "${control_plane}" "${workers[@]}" | sort)

"${kc[@]}" wait --for=condition=Ready nodes --all --timeout=120s >/dev/null
for node in "${nodes[@]}"; do
    node_json=$("${kc[@]}" get node "${node}" -o json)
    [[ $(jq '.spec.podCIDRs | length' <<<"${node_json}") -eq 2 ]]
    [[ $(jq '[.status.addresses[] | select(.type == "InternalIP") | .address] | length' \
        <<<"${node_json}") -eq 2 ]]
    [[ $(jq -r '.metadata.labels["network.unf.io/primary-cni"]' <<<"${node_json}") == enabled ]]
    sudo "${container_runtime}" exec "${node}" sh -ec '
        test "$(find /etc/cni/net.d -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 1
        test -f /etc/cni/net.d/10-unf.conflist
        test -x /opt/cni/bin/unf
        test -S /run/unf/cni.sock
        test "$(stat -c %a /run/unf/cni.sock)" = 600
        marker=/var/lib/unf/cni/v1/install.env
        test -f "$marker" && test ! -L "$marker" && test "$(wc -l <"$marker")" -eq 3
        test "$(sed -n "s/^schema=//p" "$marker")" = 1
        test "$(sha256sum /opt/cni/bin/unf | cut -d " " -f 1)" = "$(sed -n "s/^binary_sha256=//p" "$marker")"
        test "$(sha256sum /etc/cni/net.d/10-unf.conflist | cut -d " " -f 1)" = "$(sed -n "s/^config_sha256=//p" "$marker")"
    '
done

attachment_count() {
    local node=$1
    sudo "${container_runtime}" exec "${node}" sh -ec '
        path=/var/lib/unf/cni/v1/attachments.json
        if [ -f "$path" ]; then jq ".attachments | length" "$path"; else echo 0; fi
    '
}

attachment_names() {
    local node=$1
    sudo "${container_runtime}" exec "${node}" sh -ec '
        path=/var/lib/unf/cni/v1/attachments.json
        if [ -f "$path" ]; then jq -r ".attachments[].hostInterface" "$path" | sort; fi
    '
}

controller_raw() {
    local path=$1
    local pod
    pod=$("${kc[@]}" -n unf-system get pods -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1)
    [[ -n ${pod} ]]
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${pod}:9962/proxy${path}"
}

wait_for_convergence() {
    local snapshot=
    for _ in $(seq 1 120); do
        snapshot=$(controller_raw /v1/state/agents 2>/dev/null || true)
        if jq -e --argjson expected "${#nodes[@]}" '
            .expected_agents == $expected
            and .reporting_agents == $expected
            and .missing_agents == 0
            and .stale_agents == 0
            and .converged_agents == $expected
            and .unexpected_agents == 0
            and .all_converged == true
            and all(.nodes[]; .fresh and .converged and .report.ready and .report.bpf_loaded)
        ' <<<"${snapshot}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "primary-CNI agents did not converge" >&2
    jq . <<<"${snapshot}" >&2 || true
    return 1
}

run_cached_checks() {
    local node=$1
    sudo "${container_runtime}" exec "${node}" sh -ec '
        found=false
        for cache in /var/lib/cni/results/unf-primary-*-eth0; do
            [ -f "$cache" ] || continue
            found=true
            container_id=$(jq -r .containerId "$cache")
            ifname=$(jq -r .ifName "$cache")
            netns=$(jq -r .netns "$cache")
            cni_args=$(jq -r '\''[.cniArgs[] | "\(.[0])=\(.[1])"] | join(";")'\'' "$cache")
            prev=$(jq -c .result "$cache")
            jq -r .config "$cache" | base64 -d \
                | jq -c --argjson prev "$prev" '\''.plugins[0] + {cniVersion: .cniVersion, name: .name, prevResult: $prev}'\'' \
                >/tmp/unf-check.json
            env CNI_COMMAND=CHECK CNI_CONTAINERID="$container_id" \
                CNI_NETNS="$netns" CNI_IFNAME="$ifname" CNI_ARGS="$cni_args" \
                CNI_PATH=/opt/cni/bin /opt/cni/bin/unf </tmp/unf-check.json
        done
        rm -f /tmp/unf-check.json
        [ "$found" = true ]
    '
}

"${kc[@]}" delete namespace "${qualification_namespace}" --ignore-not-found \
    --wait=true --timeout=120s >/dev/null
client_baseline=$(attachment_count "${client_node}")
server_baseline=$(attachment_count "${server_node}")
client_names_before=$(attachment_names "${client_node}")
server_names_before=$(attachment_names "${server_node}")

"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${qualification_namespace}
---
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: ${qualification_namespace}
  labels:
    app: server
spec:
  nodeSelector:
    kubernetes.io/hostname: ${server_node}
  containers:
    - name: server
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [/usr/local/bin/unf-flow-receiver]
      args: ["8080"]
      readinessProbe:
        httpGet:
          path: /health
          port: 8080
        periodSeconds: 2
        failureThreshold: 3
      livenessProbe:
        httpGet:
          path: /health
          port: 8080
        periodSeconds: 2
        failureThreshold: 3
---
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: ${qualification_namespace}
spec:
  nodeSelector:
    kubernetes.io/hostname: ${client_node}
  containers:
    - name: client
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [sh, -c, "sleep infinity"]
---
apiVersion: v1
kind: Service
metadata:
  name: server
  namespace: ${qualification_namespace}
spec:
  ipFamilyPolicy: RequireDualStack
  ipFamilies: [IPv4, IPv6]
  selector:
    app: server
  ports:
    - port: 8080
      targetPort: 8080
EOF
"${kc[@]}" -n "${qualification_namespace}" wait --for=condition=Ready \
    pod/client pod/server --timeout=120s >/dev/null
wait_for_convergence

server_json=$("${kc[@]}" -n "${qualification_namespace}" get pod server -o json)
client_json=$("${kc[@]}" -n "${qualification_namespace}" get pod client -o json)
[[ $(jq '.status.podIPs | length' <<<"${server_json}") -eq 2 ]]
[[ $(jq '.status.podIPs | length' <<<"${client_json}") -eq 2 ]]
server_v4=$(jq -r '.status.podIPs[].ip | select(contains("."))' <<<"${server_json}")
server_v6=$(jq -r '.status.podIPs[].ip | select(contains(":"))' <<<"${server_json}")

client_names_after=$(attachment_names "${client_node}")
server_names_after=$(attachment_names "${server_node}")
client_link=$(comm -13 <(printf '%s\n' "${client_names_before}") \
    <(printf '%s\n' "${client_names_after}"))
server_link=$(comm -13 <(printf '%s\n' "${server_names_before}") \
    <(printf '%s\n' "${server_names_after}"))
[[ -n ${client_link} && ${client_link} != *$'\n'* ]]
[[ -n ${server_link} && ${server_link} != *$'\n'* ]]

run_cached_checks "${client_node}"
run_cached_checks "${server_node}"

mapfile -t service_ips < <("${kc[@]}" -n "${qualification_namespace}" get service server \
    -o json | jq -r '.spec.clusterIPs[]')
for target in "http://${server_v4}:8080/health" "http://[${server_v6}]:8080/health"; do
    "${kc[@]}" -n "${qualification_namespace}" exec client -- \
        wget -T 5 -t 1 -qO- "${target}" | grep -qx ok
done
service_v4=${service_ips[0]}
service_v6=${service_ips[1]}
"${kc[@]}" -n "${qualification_namespace}" exec client -- \
    wget -T 5 -t 1 -qO- "http://${service_v4}:8080/health" | grep -qx ok
service_limitations='[]'
if sudo "${container_runtime}" exec "${client_node}" ip6tables -t nat -S >/dev/null 2>&1; then
    "${kc[@]}" -n "${qualification_namespace}" exec client -- \
        wget -T 5 -t 1 -qO- "http://[${service_v6}]:8080/health" | grep -qx ok
else
    kube_proxy=$("${kc[@]}" -n kube-system get pod -l k8s-app=kube-proxy \
        --field-selector spec.nodeName="${client_node}" -o jsonpath='{.items[0].metadata.name}')
    "${kc[@]}" -n kube-system logs "${kube_proxy}" \
        | grep -q 'No iptables support for family.*IPv6'
    service_limitations=$(jq -nc '["IPv6 ClusterIP forwarding excluded: the Kind node kernel exposes no ip6tables nat table and kube-proxy disables its IPv6 proxier"]')
fi
service_resolution=$("${kc[@]}" -n "${qualification_namespace}" exec client -- \
    getent ahosts server)
grep -q "${service_ips[0]}" <<<"${service_resolution}"
grep -q "${service_ips[1]}" <<<"${service_resolution}"

"${kc[@]}" -n "${qualification_namespace}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
wait_for_convergence
if "${kc[@]}" -n "${qualification_namespace}" exec client -- \
    wget -T 2 -t 1 -qO- "http://${server_v4}:8080/health" >/dev/null 2>&1; then
    echo "default-deny ingress unexpectedly allowed Pod-to-Pod traffic" >&2
    exit 1
fi
for _ in $(seq 1 5); do
    [[ $("${kc[@]}" -n "${qualification_namespace}" get pod server \
        -o jsonpath='{.status.containerStatuses[0].ready}') == true ]]
    [[ $("${kc[@]}" -n "${qualification_namespace}" get pod server \
        -o jsonpath='{.status.containerStatuses[0].restartCount}') -eq 0 ]]
    sleep 2
done
"${kc[@]}" -n "${qualification_namespace}" delete networkpolicy/default-deny-ingress \
    --wait=true >/dev/null
wait_for_convergence

control_plane_v4=$("${kc[@]}" get node "${control_plane}" -o json \
    | jq -r '.status.addresses[] | select(.type == "InternalIP" and (.address | contains("."))) | .address')
control_plane_v6=$("${kc[@]}" get node "${control_plane}" -o json \
    | jq -r '.status.addresses[] | select(.type == "InternalIP" and (.address | contains(":"))) | .address')
"${kc[@]}" -n "${qualification_namespace}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
spec:
  podSelector: {}
  policyTypes: [Egress]
EOF
wait_for_convergence
if "${kc[@]}" -n "${qualification_namespace}" exec client -- \
    wget -T 2 -t 1 -qO- "http://${server_v4}:8080/health" >/dev/null 2>&1; then
    echo "default-deny egress unexpectedly allowed Pod-to-Pod traffic" >&2
    exit 1
fi
"${kc[@]}" -n "${qualification_namespace}" exec client -- \
    sh -ec "socat -T 5 - TCP4:${control_plane_v4}:6443 </dev/null"
"${kc[@]}" -n "${qualification_namespace}" exec client -- \
    sh -ec "socat -T 5 - 'TCP6:[${control_plane_v6}]:6443' </dev/null"
"${kc[@]}" -n "${qualification_namespace}" delete networkpolicy/default-deny-egress \
    --wait=true >/dev/null
wait_for_convergence

client_active_count=$(attachment_count "${client_node}")
"${kc[@]}" -n "${qualification_namespace}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: terminal-retained
spec:
  restartPolicy: Never
  nodeSelector:
    kubernetes.io/hostname: ${client_node}
  containers:
    - name: terminal
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [/bin/true]
EOF
"${kc[@]}" -n "${qualification_namespace}" wait --for=jsonpath='{.status.phase}'=Succeeded \
    pod/terminal-retained --timeout=120s >/dev/null
terminal_ips=$("${kc[@]}" -n "${qualification_namespace}" get pod terminal-retained \
    -o json | jq -c '[.status.podIPs[].ip] | sort')
[[ $(jq 'length' <<<"${terminal_ips}") -eq 2 ]]
for _ in $(seq 1 120); do
    [[ $(attachment_count "${client_node}") -eq ${client_active_count} ]] && break
    sleep 1
done
[[ $(attachment_count "${client_node}") -eq ${client_active_count} ]]
"${kc[@]}" -n "${qualification_namespace}" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: terminal-replacement
spec:
  nodeSelector:
    kubernetes.io/hostname: ${client_node}
  containers:
    - name: replacement
      image: localhost/unf-test-tools:ipv6-ext-v1
      imagePullPolicy: Never
      command: [sh, -c, "sleep infinity"]
EOF
"${kc[@]}" -n "${qualification_namespace}" wait --for=condition=Ready \
    pod/terminal-replacement --timeout=120s >/dev/null
replacement_ips=$("${kc[@]}" -n "${qualification_namespace}" get pod terminal-replacement \
    -o json | jq -c '[.status.podIPs[].ip] | sort')
[[ ${replacement_ips} == "${terminal_ips}" ]]
wait_for_convergence

"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=60s >/dev/null
old_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
    --field-selector spec.nodeName="${server_node}" -o jsonpath='{.items[0].metadata.name}')
"${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=false >/dev/null
for _ in $(seq 1 10); do
    "${kc[@]}" -n "${qualification_namespace}" exec client -- \
        wget -T 2 -t 1 -qO- "http://${server_v4}:8080/health" | grep -qx ok
    "${kc[@]}" -n "${qualification_namespace}" exec client -- \
        wget -T 2 -t 1 -qO- "http://[${server_v6}]:8080/health" | grep -qx ok
done
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s >/dev/null
new_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
    --field-selector spec.nodeName="${server_node}" -o jsonpath='{.items[0].metadata.name}')
agent_logs=$("${kc[@]}" -n unf-system logs "${new_agent}" -c agent)
grep -q 'restored last-known-good node-block snapshot during controller outage' \
    <<<"${agent_logs}"
grep -q 'restored last-known-good remote routes' <<<"${agent_logs}"
"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=120s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s >/dev/null
wait_for_convergence
run_cached_checks "${server_node}"

foreign_node=${control_plane}
sudo "${container_runtime}" exec "${foreign_node}" \
    touch /etc/cni/net.d/99-foreign.conflist
old_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
    --field-selector spec.nodeName="${foreign_node}" -o jsonpath='{.items[0].metadata.name}')
"${kc[@]}" -n unf-system delete pod "${old_agent}" --wait=true >/dev/null
for _ in $(seq 1 30); do
    failed_agent=$("${kc[@]}" -n unf-system get pod -l app.kubernetes.io/name=unf-agent \
        --field-selector spec.nodeName="${foreign_node}" -o jsonpath='{.items[0].metadata.name}' \
        2>/dev/null || true)
    reason=$("${kc[@]}" -n unf-system get pod "${failed_agent}" \
        -o jsonpath='{.status.initContainerStatuses[0].state.terminated.reason}' 2>/dev/null || true)
    [[ ${reason} == Error ]] && break
    sleep 1
done
[[ ${reason} == Error ]]
installer_logs=$("${kc[@]}" -n unf-system logs "${failed_agent}" -c install-primary-cni)
grep -q 'refusing primary-CNI installation beside foreign CNI configuration' \
    <<<"${installer_logs}"
sudo "${container_runtime}" exec "${foreign_node}" \
    rm -f /etc/cni/net.d/99-foreign.conflist
foreign_node=
"${kc[@]}" -n unf-system delete pod "${failed_agent}" --wait=false >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s >/dev/null

"${kc[@]}" delete namespace "${qualification_namespace}" --wait=true \
    --timeout=120s >/dev/null
for _ in $(seq 1 30); do
    client_count=$(attachment_count "${client_node}")
    server_count=$(attachment_count "${server_node}")
    [[ ${client_count} -eq ${client_baseline} && ${server_count} -eq ${server_baseline} ]] && break
    sleep 1
done
[[ ${client_count} -eq ${client_baseline} && ${server_count} -eq ${server_baseline} ]]
sudo "${container_runtime}" exec "${client_node}" \
    sh -ec "! ip link show '${client_link}' >/dev/null 2>&1"
sudo "${container_runtime}" exec "${server_node}" \
    sh -ec "! ip link show '${server_link}' >/dev/null 2>&1"

mkdir -p "$(dirname "${artifact}")"
node_evidence=$("${kc[@]}" get nodes -o json | jq \
    '[.items[] | {name:.metadata.name,podCIDRs:.spec.podCIDRs,internalIPs:[.status.addresses[] | select(.type=="InternalIP") | .address]}]')
jq -n \
    --arg schemaVersion "1" \
    --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg revision "$(git -C "${project_root}" rev-parse HEAD)" \
    --arg context "${context}" \
    --arg kubernetesVersion "$("${kc[@]}" version -o json | jq -r .serverVersion.gitVersion)" \
    --argjson nodes "${node_evidence}" \
    --argjson limitations "${service_limitations}" \
    '{schemaVersion:($schemaVersion|tonumber),generatedAt:$generatedAt,revision:$revision,context:$context,kubernetesVersion:$kubernetesVersion,nodes:$nodes,verified:["exclusive fingerprinted installation","dual-stack cross-worker ADD","containerd-normalized CHECK","IPv4 and IPv6 direct forwarding","IPv4 Service forwarding and dual-stack Service DNS discovery","supplemental egress hook preserves kubelet probes","primary Node IPv4 and IPv6 traffic exception","terminal Pod dual-stack lease reuse without identity conflict","controller-outage agent restart","controller-epoch exact reconvergence","last-known-good route recovery","foreign-CNI refusal and recovery","DEL and lease release","exact veth cleanup"],limitations:$limitations}' \
    >"${artifact}"

if [[ ${UNF_PRIMARY_CNI_SKIP_ROLLBACK:-false} != true ]]; then
    KUBECONFIG="${kubeconfig}" KUBE_CONTEXT="${context}" KIND_PROVIDER="${container_runtime}" \
        "${project_root}/hack/rollback-kind-primary-cni.sh"
    jq '.verified += ["scoped BPF cleanup","exact remote-route deletion","fingerprinted artifact removal","CoreDNS bootstrap restoration","no-CNI baseline restoration"]' \
        "${artifact}" >"${artifact}.tmp"
    mv -f "${artifact}.tmp" "${artifact}"
fi

trap - EXIT
echo "isolated dual-stack primary-CNI qualification passed; evidence: ${artifact}"
