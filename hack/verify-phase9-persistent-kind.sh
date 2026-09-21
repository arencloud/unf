#!/usr/bin/env bash
# Read-only bootstrap checks; this is NOT Phase 9 traffic/lifecycle qualification.
set -Eeuo pipefail
umask 077
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
directory=${1:?new evidence directory}
[[ ! -e $directory ]]
install -d -m 0700 "$directory"
runtime=(sudo -n "$root/hack/phase9-kind-persistent-podman.sh")
kc=(kubectl --kubeconfig "$root/.tools/kind-unf-p9-20260921.kubeconfig"
    --context kind-unf-p9-20260921 --request-timeout=15s)
revision=${UNF_BOOTSTRAP_REVISION:-f984db9e8b041c014814958054a1908e9829233c}
cni_hash=${UNF_BOOTSTRAP_CNI_SHA256:-09129e9c91cc3434b0253bf7d4c811870f2e6e72ce6bf3e4b88eba7b03a4cd47}
[[ $revision =~ ^[0-9a-f]{40}$ && $cni_hash =~ ^[0-9a-f]{64}$ ]]
[[ $("${runtime[@]}" info --format '{{.Store.GraphRoot}}') == /var/lib/unf-kind/phase9-20260921/storage ]]
(( $(sysctl -n fs.inotify.max_user_instances) >= 512 ))
"${kc[@]}" get --raw=/readyz > "$directory/apiserver-ready.txt"
"${kc[@]}" get nodes -o json > "$directory/nodes.json"
jq -e '.items | length==3 and all(.[];
    any(.status.conditions[]; .type=="Ready" and .status=="True") and
    (.spec.podCIDRs | length==2 and any(.[]; contains(":")) and any(.[]; contains("."))))' \
    "$directory/nodes.json" >/dev/null
"${kc[@]}" -n kube-system get daemonsets -o json > "$directory/system-daemonsets.json"
jq -e 'all(.items[]; .metadata.name != "kube-proxy" and .metadata.name != "kindnet")' \
    "$directory/system-daemonsets.json" >/dev/null
"${kc[@]}" -n unf-system get pods -o json > "$directory/pods.json"
jq -e '.items | length==4 and all(.[];
    any(.status.conditions[]; .type=="Ready" and .status=="True") and
    all(((.status.containerStatuses // []) + (.status.initContainerStatuses // []))[];
        .restartCount==0))' "$directory/pods.json" >/dev/null
"${kc[@]}" -n unf-system get deployment unf-controller -o json > "$directory/controller.json"
jq -e 'any(.spec.template.spec.containers[] | select(.name=="controller") | .env[];
    .name=="UNF_ENCRYPTION_BASELINE" and .value=="native")' "$directory/controller.json" >/dev/null
while IFS=$'\t' read -r node address; do
    case $node in
        unf-p9-20260921-control-plane|unf-p9-20260921-worker|unf-p9-20260921-worker2) ;;
        *) exit 1 ;;
    esac
    [[ $address =~ ^10\.90\.91\.[0-9]+$ ]]
    "${runtime[@]}" inspect "$node" --format '{{json .Mounts}}' > "$directory/$node-mounts.json"
    jq -e 'any(.[]; .Destination=="/var" and .Type=="volume" and
        (.Source | startswith("/var/lib/unf-kind/phase9-20260921/storage/volumes/")))' \
        "$directory/$node-mounts.json" >/dev/null
    "${runtime[@]}" exec "$node" sha256sum /opt/cni/bin/unf > "$directory/$node-cni.sha256"
    [[ $(awk '{print $1}' "$directory/$node-cni.sha256") == "$cni_hash" ]]
    curl -fsS --max-time 15 "http://$address:9963/v1/version" > "$directory/$node-version.json"
    jq -e --arg revision "$revision" '.build_revision==$revision and
        .persistent_bpf_state_abi_version==15 and .encryption_map_abi_version==2' \
        "$directory/$node-version.json" >/dev/null
    curl -fsS --max-time 15 "http://$address:9963/v1/status" > "$directory/$node-status.json"
    jq -e --arg node "$node" '.node_name==$node and .ready and .healthy and .bpf_loaded' \
        "$directory/$node-status.json" >/dev/null
done < <(jq -r '.items[] | [.metadata.name,
    (.status.addresses[] | select(.type=="InternalIP" and (.address|contains("."))) | .address)] | @tsv' \
    "$directory/nodes.json")
control_plane=$(jq -r '.items[] | select(.metadata.name=="unf-p9-20260921-control-plane") |
    .status.addresses[] | select(.type=="InternalIP" and (.address|contains("."))) | .address' \
    "$directory/nodes.json")
for path in version state/agents; do
    curl -fsS --max-time 15 "http://$control_plane:9962/v1/$path" > "$directory/controller-${path//\//-}.json"
done
jq -e --arg revision "$revision" '.build_revision==$revision' "$directory/controller-version.json" >/dev/null
jq -e '.all_converged and .expected_agents==3 and .reporting_agents==3 and
    (.nodes | length==3 and all(.[]; .fresh and .converged))' \
    "$directory/controller-state-agents.json" >/dev/null
date --iso-8601=ns > "$directory/completed.time"
echo 'Persistent Kind bootstrap checks passed; no Phase 9 qualification claimed.'
