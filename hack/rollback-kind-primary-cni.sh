#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-cni-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-cni-dev}
container_runtime=${KIND_PROVIDER:-podman}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

if [[ ${context} != kind-* ]] || [[ $("${kc[@]}" config current-context) != "${context}" ]]; then
    echo "refusing primary-CNI rollback outside the exact Kind context ${context}" >&2
    exit 1
fi

mapfile -t nodes < <("${kc[@]}" get nodes -o name | sed 's|node/||' | sort)
if (( ${#nodes[@]} < 3 )); then
    echo "refusing rollback: expected the isolated three-node fixture" >&2
    exit 1
fi

# Drain every ordinary fixture workload first so kubelet invokes DEL while the
# local transaction socket is still available. Host-network bootstrap Pods are
# intentionally retained until owned routes and files are gone.
"${kc[@]}" delete namespace unf-cni-qualification unf-service-qualification \
    --ignore-not-found --wait=true --timeout=120s >/dev/null
"${kc[@]}" -n local-path-storage scale deployment/local-path-provisioner --replicas=0 \
    >/dev/null
"${kc[@]}" -n local-path-storage wait --for=delete pod \
    -l app=local-path-provisioner --timeout=120s >/dev/null 2>&1 || true

for node in "${nodes[@]}"; do
    sudo "${container_runtime}" exec "${node}" sh -ec '
        journal=/var/lib/unf/cni/v1/attachments.json
        if [ -f "$journal" ] && [ "$(jq ".attachments | length" "$journal")" -ne 0 ]; then
            echo "refusing rollback with live CNI attachments in $journal" >&2
            exit 1
        fi
    '
done

# Stop reconcilers before deleting their last-known-good route set.
"${kc[@]}" -n unf-system patch daemonset unf-agent --type=merge --patch \
    '{"spec":{"template":{"spec":{"nodeSelector":{"network.unf.io/rollback-hold":"true"}}}}}' \
    >/dev/null
for attempt in $(seq 1 60); do
    remaining=$("${kc[@]}" -n unf-system get pod \
        -l app.kubernetes.io/name=unf-agent --no-headers 2>/dev/null | wc -l)
    (( remaining == 0 )) && break
    sleep 1
done
if (( remaining != 0 )); then
    echo "agent shutdown did not converge before rollback" >&2
    exit 1
fi

# Use the product's existing scoped cleanup command after the long-running
# agents have stopped. One host-network Job per node removes only recognized
# current-ABI TCX/map pins and exact legacy UNF filters.
for node in "${nodes[@]}"; do
    job_name="unf-primary-cleanup-${node##*-}"
    "${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
  namespace: unf-system
spec:
  backoffLimit: 0
  template:
    spec:
      nodeName: ${node}
      hostNetwork: true
      hostPID: true
      restartPolicy: Never
      tolerations:
        - operator: Exists
      containers:
        - name: cleanup
          image: localhost/unf-agent:dev
          imagePullPolicy: Never
          command: [/usr/local/bin/unf-component]
          args:
            - cleanup
            - --abi-version
            - "7"
            - --allow-current-abi
            - --legacy-attachments
            - --all-interfaces
            - --legacy-direction
            - both
            - --execute
          securityContext:
            privileged: true
          volumeMounts:
            - name: bpffs
              mountPath: /sys/fs/bpf
      volumes:
        - name: bpffs
          hostPath:
            path: /sys/fs/bpf
            type: Directory
EOF
    "${kc[@]}" -n unf-system wait --for=condition=Complete "job/${job_name}" --timeout=120s
done

for node in "${nodes[@]}"; do
    echo "rolling back UNF primary-CNI state on ${node}"
    sudo "${container_runtime}" exec "${node}" sh -ec '
        state_dir=/var/lib/unf/cni/v1
        routes=${state_dir}/remote-routes.json
        services=${state_dir}/service-snapshot.json
        marker=${state_dir}/install.env
        binary=/opt/cni/bin/unf
        config=/etc/cni/net.d/10-unf.conflist

        for temporary_pattern in \
            "${marker}.tmp.*" \
            "${binary}.tmp.*" \
            "${config}.tmp.*"; do
            for temporary in $temporary_pattern; do
                [ -e "$temporary" ] || break
                test -f "$temporary" && test ! -L "$temporary"
                printf "%s\n" "${temporary##*/}" \
                    | grep -Eq "^(install.env|unf|10-unf.conflist)\\.tmp\\.[0-9]+$"
                rm -f "$temporary"
            done
        done

        cleanup_pending_deletes() {
            pending=${state_dir}/pending-deletes
            [ -e "$pending" ] || return 0
            test "$(ip -j -d link | jq '\''[.[] | select(.ifname | startswith("unf"))] | length'\'')" -eq 0
            test -d "$pending" && test ! -L "$pending"
            test "$(stat -c %a "$pending")" = 700
            pending_network=${pending}/unf-primary
            if [ -e "$pending_network" ]; then
                test -d "$pending_network" && test ! -L "$pending_network"
                test "$(stat -c %a "$pending_network")" = 700
                test -z "$(find "$pending_network" -mindepth 3 -print -quit)"
                test -z "$(find "$pending_network" -mindepth 1 -maxdepth 1 ! -type d -print -quit)"
                for container_directory in "$pending_network"/*; do
                    [ -e "$container_directory" ] || break
                    test -d "$container_directory" && test ! -L "$container_directory"
                    test "$(stat -c %a "$container_directory")" = 700
                    container_id=${container_directory##*/}
                    printf "%s\n" "$container_id" | grep -Eq "^[0-9a-f]{64}$"
                    for intent in "$container_directory"/*.json; do
                        [ -e "$intent" ] || break
                        test -f "$intent" && test ! -L "$intent"
                        test "$(stat -c %a "$intent")" = 600
                        jq -e --arg container_id "$container_id" \
                            '\''.schemaVersion == 1
                            and .key.network == "unf-primary"
                            and .key.containerId == $container_id
                            and (.key.ifname | test("^[A-Za-z0-9_.-]{1,15}$"))'\'' \
                            "$intent" >/dev/null
                        ifname=$(jq -r .key.ifname "$intent")
                        test "${intent##*/}" = "${ifname}.json"
                        rm -f "$intent"
                    done
                    rmdir "$container_directory"
                done
                rmdir "$pending_network"
            fi
            test -z "$(find "$pending" -mindepth 1 -maxdepth 1 ! -name .unf-primary.lock -print -quit)"
            if [ -e "$pending/.unf-primary.lock" ]; then
                test -f "$pending/.unf-primary.lock" && test ! -L "$pending/.unf-primary.lock"
                test "$(stat -c %a "$pending/.unf-primary.lock")" = 600
                rm -f "$pending/.unf-primary.lock"
            fi
            rmdir "$pending"
        }

        # A previous rollback attempt may already have removed the complete
        # owned transaction on this Node before another Node failed. Resume only
        # from an exact empty owned boundary; any partial combination remains
        # a hard error and follows the full validation path below.
        if [ ! -e "$routes" ] && [ ! -e "$services" ] && [ ! -e "$marker" ] \
            && [ ! -e "$binary" ] && [ ! -e "$config" ]; then
            test ! -e "${state_dir}/attachments.json"
            test ! -e "${state_dir}/node-block.json"
            cleanup_pending_deletes
            if [ -d "$state_dir" ]; then
                test -z "$(find "$state_dir" -mindepth 1 -print -quit)"
                rmdir "$state_dir"
            fi
            [ ! -d /var/lib/unf/cni ] || rmdir /var/lib/unf/cni
            rm -f /run/unf/cni.sock
            [ ! -d /run/unf ] || rmdir /run/unf
            if [ -d /sys/fs/bpf/unf ]; then
                test -z "$(find /sys/fs/bpf/unf -mindepth 1 -maxdepth 1 -print -quit)"
                rmdir /sys/fs/bpf/unf
            fi
            exit 0
        fi

        test -f "$routes" && test ! -L "$routes"
        test "$(jq -r .schemaVersion "$routes")" = 1
        expected=$(jq ".remoteNodes | length" "$routes")
        test "$(ip -j -4 route show proto 196 | jq length)" -eq "$expected"
        test "$(ip -j -6 route show proto 196 | jq length)" -eq "$expected"

        route_rows=$(jq -r '\''.remoteNodes[] | [.intent.blocks.ipv4Block, .ipv4Transport, .intent.blocks.ipv6Block, .ipv6Transport] | @tsv'\'' "$routes")
        old_ifs=$IFS
        IFS="
"
        for row in $route_rows; do
            IFS="	" read -r block4 gateway4 block6 gateway6 <<EOF
$row
EOF
            actual4=$(ip -j -4 route show exact "$block4")
            actual6=$(ip -j -6 route show exact "$block6")
            echo "$actual4" | jq -e --arg dst "$block4" --arg gateway "$gateway4" '\''length == 1 and .[0].dst == $dst and .[0].gateway == $gateway and .[0].dev == "eth0" and .[0].protocol == "196"'\'' >/dev/null
            echo "$actual6" | jq -e --arg dst "$block6" --arg gateway "$gateway6" '\''length == 1 and .[0].dst == $dst and .[0].gateway == $gateway and .[0].dev == "eth0" and .[0].protocol == "196"'\'' >/dev/null
            ip -4 route del "$block4" via "$gateway4" dev eth0 proto 196
            ip -6 route del "$block6" via "$gateway6" dev eth0 proto 196
        done
        IFS=$old_ifs
        test "$(ip -j -4 route show proto 196 | jq length)" -eq 0
        test "$(ip -j -6 route show proto 196 | jq length)" -eq 0

        test -f "$marker" && test ! -L "$marker" && test "$(wc -l <"$marker")" -eq 3
        test "$(sed -n "s/^schema=//p" "$marker")" = 1
        binary_sha=$(sed -n "s/^binary_sha256=//p" "$marker")
        config_sha=$(sed -n "s/^config_sha256=//p" "$marker")
        test -f "$binary" && test ! -L "$binary"
        test -f "$config" && test ! -L "$config"
        test "$(sha256sum "$binary" | cut -d " " -f 1)" = "$binary_sha"
        test "$(sha256sum "$config" | cut -d " " -f 1)" = "$config_sha"
        test "$(ip -j -d link | jq '\''[.[] | select(.ifname | startswith("unf"))] | length'\'')" -eq 0

        test -f "$services" && test ! -L "$services"
        test "$(stat -c %a "$services")" = 600
        jq -e "if has(\"service\") then .schemaVersion == 1 and .service.schemaVersion == 2 and .service.revision > 0 and (.service.services | length) > 0 and .nodePortNode.schemaVersion == 1 else .schemaVersion == 1 and .revision > 0 and (.services | length) > 0 end" "$services" >/dev/null

        for temporary in \
            "${state_dir}/attachments.json.tmp" \
            "${state_dir}/.node-block.json.tmp" \
            "${state_dir}/.remote-routes.json.tmp" \
            "${state_dir}/.service-snapshot.json.tmp"; do
            if [ -e "$temporary" ]; then
                test -f "$temporary" && test ! -L "$temporary"
                test "$(stat -c %a "$temporary")" = 600
                rm -f "$temporary"
            fi
        done

        rm -f /run/unf/cni.sock
        rm -f "$binary" "$config"
        rm -f "${state_dir}/attachments.json" "${state_dir}/node-block.json" \
            "$routes" "$services" "$marker"
        cleanup_pending_deletes
        rmdir "$state_dir"
        rmdir /var/lib/unf/cni
        rmdir /run/unf
        if [ -d /sys/fs/bpf/unf ]; then
            test -z "$(find /sys/fs/bpf/unf -mindepth 1 -maxdepth 1 -print -quit)"
            rmdir /sys/fs/bpf/unf
        fi
    '
done

"${kc[@]}" -n unf-system delete jobs -l batch.kubernetes.io/job-name \
    --ignore-not-found --wait=true >/dev/null 2>&1 || true
"${kc[@]}" delete -k "${project_root}/deploy/kind-primary-cni" \
    --ignore-not-found --wait=true --timeout=120s >/dev/null
"${kc[@]}" label nodes --all network.unf.io/primary-cni- >/dev/null

coredns_template_spec=$("${kc[@]}" -n kube-system get configmap \
    unf-primary-cni-bootstrap-backup -o jsonpath='{.data.coredns-template-spec}')
coredns_corefile=$("${kc[@]}" -n kube-system get configmap \
    unf-primary-cni-bootstrap-backup -o jsonpath='{.data.coredns-corefile}')
nodeport_sysctls=$("${kc[@]}" -n kube-system get configmap \
    unf-primary-cni-bootstrap-backup -o jsonpath='{.data.nodeport-sysctls}')
if ! jq -e --argjson node_count "${#nodes[@]}" \
    'type == "object" and length == $node_count' <<<"${nodeport_sysctls}" >/dev/null; then
    echo "primary-CNI rollback backup lacks exact NodePort sysctl state" >&2
    exit 1
fi
coredns_patch=$(jq -cn --argjson spec "${coredns_template_spec}" \
    '[{"op":"replace","path":"/spec/template/spec","value":$spec}]')
"${kc[@]}" -n kube-system patch deployment coredns --type=json --patch "${coredns_patch}" \
    >/dev/null
if [[ -n ${coredns_corefile} ]]; then
    corefile_patch=$(jq -cn --arg corefile "${coredns_corefile}" \
        '{data:{Corefile:$corefile}}')
    "${kc[@]}" -n kube-system patch configmap coredns --type=merge \
        --patch "${corefile_patch}" >/dev/null
fi

for node in "${nodes[@]}"; do
    sysctl_rows=$(jq -er --arg node "${node}" '
        .[$node] | to_entries[] | [.key, (.value | tostring)] | @tsv
    ' <<<"${nodeport_sysctls}")
    sudo "${container_runtime}" exec -i "${node}" sh -ec '
        tab=$(printf "\t")
        while IFS="$tab" read -r key value; do
            path=/proc/sys/net/ipv4/conf/${key}
            # Interfaces captured before CNI activation may have disappeared
            # after kubelet DEL. Every surviving captured key is exact.
            [ -e "$path" ] || continue
            printf "%s" "$value" >"$path"
            test "$(cat "$path")" = "$value"
        done
    ' <<<"${sysctl_rows}"
done
"${kc[@]}" -n kube-system delete configmap unf-primary-cni-bootstrap-backup >/dev/null
"${kc[@]}" -n local-path-storage scale deployment/local-path-provisioner --replicas=1 \
    >/dev/null

for node in "${nodes[@]}"; do
    sudo "${container_runtime}" exec "${node}" sh -ec '
        test ! -e /opt/cni/bin/unf
        test ! -e /etc/cni/net.d/10-unf.conflist
        test ! -e /var/lib/unf/cni
        test "$(ip -j -4 route show proto 196 | jq length)" -eq 0
        test "$(ip -j -6 route show proto 196 | jq length)" -eq 0
    '
done

echo "primary-CNI rollback restored the no-CNI fixture baseline for ${context}"
