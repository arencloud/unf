#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
temporary_dir=$(mktemp -d)
handoff_probe_pid=
controller_scaled_down=false
fault_helper_created=false
legacy_override_applied=false
tcx_restored=false
baseline_attachment_preference=
baseline_attachment_preference_present=false

agent_status() {
    "${kc[@]}" get --raw "/api/v1/namespaces/unf-system/pods/${1}/proxy/v1/status"
}

json_number() {
    local field=$1
    sed -nE "s/.*\"${field}\":([0-9]+).*/\1/p"
}

wait_for_agent_mode() {
    local expected_mode=$1 expected_agents=$2
    local pod status desired_identity applied_identity desired_policy applied_policy
    for _ in {1..60}; do
        mapfile -t current_agents < <("${kc[@]}" -n unf-system get pods \
            -l app.kubernetes.io/name=unf-agent \
            -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
        if [[ ${#current_agents[@]} -ne ${expected_agents} ]]; then
            sleep 1
            continue
        fi
        local converged=true
        for pod in "${current_agents[@]}"; do
            if ! "${kc[@]}" -n unf-system wait --for=condition=Ready "pod/${pod}" \
                --timeout=1s >/dev/null 2>&1; then
                converged=false
                break
            fi
            status=$(agent_status "${pod}" || true)
            desired_identity=$(json_number desired_identity_revision <<<"${status}")
            applied_identity=$(json_number applied_identity_revision <<<"${status}")
            desired_policy=$(json_number desired_policy_revision <<<"${status}")
            applied_policy=$(json_number applied_policy_revision <<<"${status}")
            if ! grep -q "\"tc_attachment_mode\":\"${expected_mode}\"" \
                <<<"${status}" \
                || [[ -z ${desired_identity} || ${desired_identity} -eq 0 \
                    || ${desired_identity} != "${applied_identity}" \
                    || -z ${desired_policy} || ${desired_policy} -eq 0 \
                    || ${desired_policy} != "${applied_policy}" ]]; then
                converged=false
                break
            fi
        done
        if [[ ${converged} == true ]]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

run_legacy_cleanup() {
    local helper=$1 node agent
    shift
    node=$("${kc[@]}" -n unf-system get pod "${helper}" \
        -o jsonpath='{.spec.nodeName}')
    agent=$("${kc[@]}" -n unf-system get pods \
        -l app.kubernetes.io/name=unf-agent \
        -o jsonpath="{range .items[?(@.spec.nodeName=='${node}')]}{.metadata.name}{'\n'}{end}" \
        | head -n 1)
    if [[ -z ${agent} ]]; then
        echo "could not identify the agent on helper node ${node}" >&2
        return 1
    fi
    "${kc[@]}" -n unf-system exec "${agent}" -- \
        /usr/local/bin/unf-component cleanup \
        --legacy-attachments --all-interfaces --legacy-direction ingress "$@"
}

remove_legacy_filters() {
    run_legacy_cleanup "$1" --execute
}

legacy_filter_exists() {
    local helper=$1
    "${kc[@]}" -n unf-system exec "${helper}" -- sh -eu -c '
        for path in /sys/class/net/*; do
            interface=${path##*/}
            if [ "${interface}" = lo ]; then
                continue
            fi
            if tc filter show dev "${interface}" ingress pref 21838 2>/dev/null \
                | grep -q "handle 0x554e0001 "; then
                exit 0
            fi
        done
        exit 1
    '
}

restore_attachment_preference() {
    if [[ ${baseline_attachment_preference_present} == true ]]; then
        "${kc[@]}" -n unf-system set env daemonset/unf-agent \
            "UNF_TC_ATTACHMENT_MODE=${baseline_attachment_preference}" >/dev/null
    else
        "${kc[@]}" -n unf-system set env daemonset/unf-agent \
            UNF_TC_ATTACHMENT_MODE- >/dev/null
    fi
}

cleanup() {
    local result=$?
    trap - EXIT
    set +e
    if [[ -n ${handoff_probe_pid} ]]; then
        "${kc[@]}" exec -n frontend client -- touch /tmp/unf-legacy-handoff-stop \
            >/dev/null 2>&1
        wait "${handoff_probe_pid}" 2>/dev/null
    fi
    if [[ ${controller_scaled_down} == true ]]; then
        "${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 \
            >/dev/null 2>&1
        "${kc[@]}" -n unf-system rollout status deployment/unf-controller \
            --timeout=120s >/dev/null 2>&1
    fi
    if [[ ${legacy_override_applied} == true ]]; then
        restore_attachment_preference >/dev/null 2>&1
        if "${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
            --timeout=120s >/dev/null 2>&1; then
            tcx_restored=true
        fi
    fi
    if [[ ${fault_helper_created} == true ]]; then
        if [[ ${legacy_override_applied} == true && ${tcx_restored} == true ]]; then
            while IFS= read -r helper; do
                [[ -n ${helper} ]] || continue
                remove_legacy_filters "${helper}" >/dev/null 2>&1
            done < <("${kc[@]}" -n unf-system get pods \
                -l app.kubernetes.io/name=unf-bpf-fault-helper \
                -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
                2>/dev/null)
        fi
        "${kc[@]}" delete -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" \
            >/dev/null 2>&1
    fi
    rm -rf "${temporary_dir}"
    exit "${result}"
}
trap cleanup EXIT

baseline_attachment_preference=$("${kc[@]}" -n unf-system get daemonset/unf-agent \
    -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="UNF_TC_ATTACHMENT_MODE")].value}')
if [[ -n ${baseline_attachment_preference} ]]; then
    baseline_attachment_preference_present=true
fi

mapfile -t initial_agents < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if [[ ${#initial_agents[@]} -eq 0 ]]; then
    echo "legacy netlink verification requires ready UNF agents" >&2
    exit 1
fi

baseline_mode=
for pod in "${initial_agents[@]}"; do
    status=$(agent_status "${pod}")
    mode=$(sed -nE 's/.*"tc_attachment_mode":"([^"]+)".*/\1/p' <<<"${status}")
    if [[ ${mode} != tcx_pinned && ${mode} != legacy_netlink ]]; then
        echo "agent ${pod} did not report an attachment mode suitable for handoff" >&2
        exit 1
    fi
    if [[ -n ${baseline_mode} && ${mode} != "${baseline_mode}" ]]; then
        echo "agents reported mixed baseline attachment modes" >&2
        exit 1
    fi
    baseline_mode=${mode}
done

"${kc[@]}" apply -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" >/dev/null
fault_helper_created=true
"${kc[@]}" -n unf-system rollout status daemonset/unf-bpf-fault-helper --timeout=120s
mapfile -t helper_pods < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-bpf-fault-helper \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if [[ ${#helper_pods[@]} -ne ${#initial_agents[@]} ]]; then
    echo "legacy netlink verification requires one helper per agent node" >&2
    exit 1
fi

if [[ ${baseline_mode} == tcx_pinned ]]; then
    "${kc[@]}" -n unf-system set env daemonset/unf-agent \
        UNF_TC_ATTACHMENT_MODE=legacy-netlink >/dev/null
    legacy_override_applied=true
    "${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s
    if ! wait_for_agent_mode legacy_netlink "${#initial_agents[@]}"; then
        echo "agents did not converge in explicitly selected legacy netlink mode" >&2
        exit 1
    fi
    for helper in "${helper_pods[@]}"; do
        "${kc[@]}" -n unf-system exec "${helper}" -- sh -eu -c '
            links=/sys/fs/bpf/unf/v4/links
            if [ -d "${links}" ]; then
                find "${links}" -maxdepth 1 -type f -name "tcx-ingress-*" -delete
                ! find "${links}" -maxdepth 1 -type f -name "tcx-ingress-*" | grep -q .
            fi
        '
    done
fi

server_node=$("${kc[@]}" -n backend get pod server -o jsonpath='{.spec.nodeName}')
restart_agent=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent \
    -o jsonpath="{range .items[?(@.spec.nodeName=='${server_node}')]}{.metadata.name}{'\n'}{end}" \
    | head -n 1)
server_helper=$("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-bpf-fault-helper \
    -o jsonpath="{range .items[?(@.spec.nodeName=='${server_node}')]}{.metadata.name}{'\n'}{end}" \
    | head -n 1)
if [[ -z ${restart_agent} || -z ${server_helper} ]]; then
    echo "could not identify the server-node agent and helper" >&2
    exit 1
fi
if ! legacy_filter_exists "${server_helper}"; then
    echo "server node does not expose UNF's reserved legacy netlink filter" >&2
    exit 1
fi

legacy_allow_response=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${legacy_allow_response} != "unf-demo-ok" ]]; then
    echo "legacy netlink mode lost the established allowed flow" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "legacy netlink mode lost established deny enforcement" >&2
    exit 1
fi

"${kc[@]}" exec -n frontend client -- sh -c '
    rm -f /tmp/unf-legacy-handoff-stop /tmp/unf-legacy-handoff-breach
    while [ ! -e /tmp/unf-legacy-handoff-stop ]; do
        attempt=0
        while [ "${attempt}" -lt 16 ]; do
            (
                if wget -T 1 -t 1 -qO- \
                    http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
                    echo policy-bypass >>/tmp/unf-legacy-handoff-breach
                fi
            ) &
            attempt=$((attempt + 1))
        done
        wait
    done
    test ! -s /tmp/unf-legacy-handoff-breach
' >"${temporary_dir}/handoff-probe.log" 2>&1 &
handoff_probe_pid=$!
sleep 1
if ! kill -0 "${handoff_probe_pid}" 2>/dev/null; then
    cat "${temporary_dir}/handoff-probe.log" >&2
    echo "continuous legacy deny probe did not start" >&2
    exit 1
fi

"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=0 >/dev/null
controller_scaled_down=true
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name=unf-controller --timeout=120s
"${kc[@]}" -n unf-system delete pod "${restart_agent}" --wait=true >/dev/null

recovered_agent=
for _ in {1..60}; do
    recovered_agent=$("${kc[@]}" -n unf-system get pods \
        -l app.kubernetes.io/name=unf-agent \
        -o jsonpath="{range .items[?(@.spec.nodeName=='${server_node}')]}{.metadata.name}{'\n'}{end}" \
        | grep -v "^${restart_agent}$" | head -n 1 || true)
    if [[ -n ${recovered_agent} ]] && "${kc[@]}" -n unf-system wait \
        --for=condition=Ready "pod/${recovered_agent}" --timeout=2s >/dev/null 2>&1; then
        break
    fi
    recovered_agent=
    sleep 1
done
if [[ -z ${recovered_agent} ]]; then
    echo "legacy replacement agent did not recover with the controller offline" >&2
    exit 1
fi
"${kc[@]}" exec -n frontend client -- touch /tmp/unf-legacy-handoff-stop >/dev/null
if ! wait "${handoff_probe_pid}"; then
    cat "${temporary_dir}/handoff-probe.log" >&2
    echo "deny enforcement opened during legacy netlink replacement" >&2
    exit 1
fi
handoff_probe_pid=

recovered_status=$(agent_status "${recovered_agent}")
if ! grep -q '"ready":true' <<<"${recovered_status}" \
    || ! grep -q '"tc_attachment_mode":"legacy_netlink"' <<<"${recovered_status}"; then
    echo "replacement agent did not report ready legacy netlink recovery" >&2
    exit 1
fi
recovered_logs=$("${kc[@]}" -n unf-system logs "${recovered_agent}")
if ! grep -q 'validated pinned last-known-good dataplane' <<<"${recovered_logs}" \
    || ! grep -q 'persistent netlink TC observation program installed' <<<"${recovered_logs}" \
    || ! grep -q '"replaced":true' <<<"${recovered_logs}"; then
    echo "replacement agent did not report in-place legacy filter replacement" >&2
    exit 1
fi
if ! legacy_filter_exists "${server_helper}"; then
    echo "reserved legacy filter disappeared during replacement" >&2
    exit 1
fi
legacy_recovered_allow=$("${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:8080)
if [[ ${legacy_recovered_allow} != "unf-demo-ok" ]]; then
    echo "legacy replacement lost the allowed flow" >&2
    exit 1
fi
if "${kc[@]}" exec -n frontend client -- \
    wget -T 2 -t 1 -qO- http://server.backend.svc.cluster.local:9090 >/dev/null 2>&1; then
    echo "legacy replacement lost deny enforcement" >&2
    exit 1
fi

"${kc[@]}" -n unf-system scale deployment/unf-controller --replicas=1 >/dev/null
controller_scaled_down=false
"${kc[@]}" -n unf-system rollout status deployment/unf-controller --timeout=120s
if ! wait_for_agent_mode legacy_netlink "${#initial_agents[@]}"; then
    echo "legacy agents did not reconverge after controller recovery" >&2
    exit 1
fi

if [[ ${legacy_override_applied} == true ]]; then
    restore_attachment_preference
    "${kc[@]}" -n unf-system rollout status daemonset/unf-agent --timeout=120s
    if ! wait_for_agent_mode tcx_pinned "${#initial_agents[@]}"; then
        echo "agents did not return to automatic TCX mode" >&2
        exit 1
    fi
    for helper in "${helper_pods[@]}"; do
        if ! "${kc[@]}" -n unf-system exec "${helper}" -- sh -eu -c '
            find /sys/fs/bpf/unf/v4/links -maxdepth 1 -type f \
                -name "tcx-ingress-*" | grep -q .
        '; then
            echo "TCX pins were not restored before legacy cleanup" >&2
            exit 1
        fi
        legacy_cleanup_dry_run=$(run_legacy_cleanup "${helper}")
        if ! grep -q 'UNF cleanup plan (dry-run)' <<<"${legacy_cleanup_dry_run}" \
            || ! grep -q 'dry run only' <<<"${legacy_cleanup_dry_run}"; then
            printf '%s\n' "${legacy_cleanup_dry_run}" >&2
            echo "legacy cleanup did not expose its dry-run contract" >&2
            exit 1
        fi
        if ! legacy_filter_exists "${helper}" >/dev/null 2>&1; then
            echo "legacy cleanup dry run mutated the reserved filter" >&2
            exit 1
        fi
        legacy_cleanup_execution=$(remove_legacy_filters "${helper}")
        if ! grep -q 'UNF cleanup completed' <<<"${legacy_cleanup_execution}"; then
            printf '%s\n' "${legacy_cleanup_execution}" >&2
            echo "legacy cleanup did not confirm reserved-filter removal" >&2
            exit 1
        fi
        if legacy_filter_exists "${helper}" >/dev/null 2>&1; then
            echo "reserved legacy filter remained after scoped cleanup" >&2
            exit 1
        fi
    done
    tcx_restored=true
    legacy_override_applied=false
fi

"${kc[@]}" delete -f "${project_root}/deploy/examples/bpf-fault-helper.yaml" >/dev/null
fault_helper_created=false

echo "legacy netlink verification passed: explicit selection, reserved filter installation, TCX-independent allow/deny, in-place offline-controller replacement with continuous deny enforcement, scoped TCX restoration, and dry-run-first production legacy cleanup"
