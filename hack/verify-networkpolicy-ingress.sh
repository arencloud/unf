#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
controller_url=${UNF_CONTROLLER_URL:-http://127.0.0.1:19962}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
fixture="${project_root}/deploy/examples/networkpolicy-upstream-ingress.yaml"
target_namespace=unf-np-target
source_a_namespace=unf-np-source-a
source_b_namespace=unf-np-source-b
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

cleanup() {
    "${kc[@]}" delete namespaces "${target_namespace}" "${source_a_namespace}" \
        "${source_b_namespace}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

status_field() {
    local field=$1
    sed -nE "s/.*\"${field}\": ([0-9]+).*/\1/p"
}

agent_field() {
    local field=$1
    sed -nE "s/.*\"${field}\":([0-9]+).*/\1/p"
}

controller_status() {
    "${unfctl}" --controller-url "${controller_url}" --output json status
}

agent_status() {
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${1}/proxy/v1/status"
}

wait_for_policy_state() {
    local expected_count=$1
    local expected_rejected=$2
    local floor_revision=$3
    local status revision accepted rejected pod agent desired applied all_converged
    for _ in {1..45}; do
        status=$(controller_status)
        revision=$(status_field policy <<<"${status}")
        accepted=$(status_field network_policies <<<"${status}")
        rejected=$(status_field rejected_network_policies <<<"${status}")
        all_converged=true
        if [[ -z ${revision} || ${revision} -le ${floor_revision} \
            || ${accepted} != "${expected_count}" \
            || ${rejected} != "${expected_rejected}" ]]; then
            all_converged=false
        else
            for pod in "${agent_pods[@]}"; do
                agent=$(agent_status "${pod}" || true)
                desired=$(agent_field desired_policy_revision <<<"${agent}")
                applied=$(agent_field applied_policy_revision <<<"${agent}")
                if [[ -z ${desired} || ${desired} != "${applied}" \
                    || ${applied} != "${revision}" ]]; then
                    all_converged=false
                    break
                fi
            done
        fi
        if [[ ${all_converged} == true ]]; then
            policy_revision=${revision}
            return 0
        fi
        sleep 1
    done
    return 1
}

require_policy_state() {
    local expected_count=$1
    local expected_rejected=$2
    local floor_revision=$3
    local description=$4
    if ! wait_for_policy_state "${expected_count}" "${expected_rejected}" \
        "${floor_revision}"; then
        echo "${description}" >&2
        exit 1
    fi
}

wait_for_current_policy_sync() {
    local status revision accepted rejected signature previous_signature=
    local pod agent desired applied all_converged
    for _ in {1..45}; do
        status=$(controller_status)
        revision=$(status_field policy <<<"${status}")
        accepted=$(status_field network_policies <<<"${status}")
        rejected=$(status_field rejected_network_policies <<<"${status}")
        signature="${accepted}:${rejected}:${revision}"
        all_converged=true
        for pod in "${agent_pods[@]}"; do
            agent=$(agent_status "${pod}" || true)
            desired=$(agent_field desired_policy_revision <<<"${agent}")
            applied=$(agent_field applied_policy_revision <<<"${agent}")
            if [[ -z ${desired} || ${desired} != "${applied}" \
                || ${applied} != "${revision}" ]]; then
                all_converged=false
                break
            fi
        done
        if [[ ${all_converged} == true && ${signature} == "${previous_signature}" ]]; then
            baseline_count=${accepted}
            baseline_rejected=${rejected}
            baseline_revision=${revision}
            return 0
        fi
        if [[ ${all_converged} == true ]]; then
            previous_signature=${signature}
        else
            previous_signature=
        fi
        sleep 1
    done
    return 1
}

expect_address_allow() {
    local namespace=$1
    local pod=$2
    local address=$3
    local port=$4
    local response
    response=$("${kc[@]}" exec -n "${namespace}" "${pod}" -- \
        wget -T 2 -t 1 -qO- "http://${address}:${port}")
    if [[ ${response} != "unf-upstream-ok" ]]; then
        echo "expected ${namespace}/${pod} to reach ${address} TCP/${port}" >&2
        exit 1
    fi
}

expect_address_deny() {
    local namespace=$1
    local pod=$2
    local address=$3
    local port=$4
    if "${kc[@]}" exec -n "${namespace}" "${pod}" -- \
        wget -T 2 -t 1 -qO- "http://${address}:${port}" >/dev/null 2>&1; then
        echo "expected ${namespace}/${pod} to be denied to ${address} TCP/${port}" >&2
        exit 1
    fi
}

expect_allow() {
    expect_address_allow "$1" "$2" "${server_ip}" "$3"
}

expect_deny() {
    expect_address_deny "$1" "$2" "${server_ip}" "$3"
}

expect_explanation_to() {
    local source=$1
    local destination=$2
    local port=$3
    local verdict=$4
    local reason=$5
    local explanation
    explanation=$("${unfctl}" --controller-url "${controller_url}" --output json \
        explain --from "${source}" --to "${target_namespace}/${destination}" \
        --protocol tcp --port "${port}")
    if ! grep -q "\"verdict\": \"${verdict}\"" <<<"${explanation}" \
        || ! grep -q "\"reason\": \"${reason}\"" <<<"${explanation}"; then
        echo "unexpected explanation for ${source} to ${destination} TCP/${port}" >&2
        exit 1
    fi
}

expect_explanation() {
    expect_explanation_to "$1" server "$2" "$3" "$4"
}

mapfile -t agent_pods < <("${kc[@]}" -n unf-system get pods \
    -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if [[ ${#agent_pods[@]} -eq 0 ]]; then
    echo "UNF agent DaemonSet has no pods" >&2
    exit 1
fi

cleanup
for namespace in "${target_namespace}" "${source_a_namespace}" "${source_b_namespace}"; do
    "${kc[@]}" wait --for=delete namespace/"${namespace}" --timeout=60s >/dev/null 2>&1 || true
done
if ! wait_for_current_policy_sync; then
    echo "existing policy state did not settle before upstream conformance" >&2
    exit 1
fi
"${kc[@]}" apply -f "${fixture}" >/dev/null
"${kc[@]}" wait --for=condition=Ready pod/server -n "${target_namespace}" --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/alternate-server -n "${target_namespace}" \
    --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/same-client -n "${target_namespace}" \
    --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/client -n "${source_a_namespace}" --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/client -n "${source_b_namespace}" --timeout=120s
server_ip=$("${kc[@]}" get pod -n "${target_namespace}" server \
    -o jsonpath='{.status.podIP}')
alternate_server_ip=$("${kc[@]}" get pod -n "${target_namespace}" alternate-server \
    -o jsonpath='{.status.podIP}')
if [[ ! ${server_ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "upstream conformance server has no IPv4 Pod address" >&2
    exit 1
fi
if [[ ! ${alternate_server_ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "upstream conformance alternate server has no IPv4 Pod address" >&2
    exit 1
fi
for port in 8087 8088; do
    response=$("${kc[@]}" exec -n "${target_namespace}" server -- \
        wget -T 2 -t 1 -qO- "http://127.0.0.1:${port}")
    if [[ ${response} != "unf-upstream-ok" ]]; then
        echo "upstream conformance server is not listening on TCP/${port}" >&2
        exit 1
    fi
    alternate_response=$("${kc[@]}" exec -n "${target_namespace}" alternate-server -- \
        wget -T 2 -t 1 -qO- "http://127.0.0.1:${port}")
    if [[ ${alternate_response} != "unf-upstream-ok" ]]; then
        echo "upstream conformance alternate server is not listening on TCP/${port}" >&2
        exit 1
    fi
done
if ! wait_for_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${baseline_revision}"; then
    echo "unselected target policy did not converge" >&2
    exit 1
fi

for source in \
    "${target_namespace} same-client" \
    "${source_a_namespace} client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    expect_allow "${namespace}" "${pod}" 8087
    expect_allow "${namespace}" "${pod}" 8088
done
expect_explanation "${source_a_namespace}/client" 8087 Allow NoApplicablePolicy

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server \
    conformance-target=isolated --overwrite >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "target Pod label selection did not converge"
for source in \
    "${target_namespace} same-client" \
    "${source_a_namespace} client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    expect_deny "${namespace}" "${pod}" 8087
done
expect_explanation "${source_a_namespace}/client" 8087 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" ingress-matrix --type=merge \
    -p '{"spec":{"ingress":[{"from":[{"podSelector":{"matchLabels":{"conformance-source":"same"}}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "same-Namespace PodSelector policy did not converge"
expect_allow "${target_namespace}" same-client 8087
expect_deny "${source_a_namespace}" client 8087
expect_deny "${source_b_namespace}" client 8087

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" ingress-matrix --type=merge \
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "empty NamespaceSelector policy did not converge"
expect_allow "${target_namespace}" same-client 8087
expect_allow "${source_a_namespace}" client 8087
expect_allow "${source_b_namespace}" client 8087
expect_deny "${source_a_namespace}" client 8088

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" ingress-matrix --type=merge \
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"conformance-group":"a"}},"podSelector":{"matchLabels":{"conformance-source":"selected"}}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "combined selector policy did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_deny "${target_namespace}" same-client 8087
expect_deny "${source_b_namespace}" client 8087
expect_explanation "${source_a_namespace}/client" 8087 Allow ExplicitRule

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" ingress-matrix --type=merge \
    -p '{"spec":{"ingress":[{"from":[{"podSelector":{"matchLabels":{"conformance-source":"same"}}},{"namespaceSelector":{"matchLabels":{"conformance-group":"b"}}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "alternative peer policy did not converge"
expect_allow "${target_namespace}" same-client 8087
expect_allow "${source_b_namespace}" client 8087
expect_deny "${source_a_namespace}" client 8087

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" ingress-matrix --type=merge \
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchExpressions":[{"key":"conformance-group","operator":"In","values":["a"]}]},"podSelector":{"matchExpressions":[{"key":"conformance-source","operator":"In","values":["selected"]},{"key":"blocked","operator":"DoesNotExist"}]}}],"ports":[{"protocol":"TCP","port":8087}]},{"from":[{"namespaceSelector":{"matchExpressions":[{"key":"conformance-group","operator":"In","values":["b"]}]},"podSelector":{"matchExpressions":[{"key":"conformance-source","operator":"Exists"},{"key":"blocked","operator":"DoesNotExist"}]}}],"ports":[{"protocol":"TCP","port":8088}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "expression-based multi-rule policy did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_deny "${source_a_namespace}" client 8088
expect_deny "${source_b_namespace}" client 8087
expect_allow "${source_b_namespace}" client 8088
expect_deny "${target_namespace}" same-client 8087
expect_deny "${target_namespace}" same-client 8088
expect_explanation "${source_a_namespace}/client" 8087 Allow ExplicitRule
expect_explanation "${source_b_namespace}/client" 8088 Allow ExplicitRule

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${source_b_namespace}" client blocked=true --overwrite >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "DoesNotExist source-label transition did not converge"
expect_deny "${source_b_namespace}" client 8088

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${source_b_namespace}" client blocked- >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "DoesNotExist source-label recovery did not converge"
expect_allow "${source_b_namespace}" client 8088

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" ingress-matrix --type=merge \
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"conformance-group":"a"}}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: stacked-port
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      conformance-target: isolated
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              conformance-group: b
      ports:
        - protocol: TCP
          port: 8088
EOF
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "stacked additive policies did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_deny "${source_a_namespace}" client 8088
expect_deny "${source_b_namespace}" client 8087
expect_allow "${source_b_namespace}" client 8088
expect_deny "${target_namespace}" same-client 8087
expect_explanation "${source_b_namespace}/client" 8088 Allow ExplicitRule

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      conformance-target: isolated
  policyTypes:
    - Ingress
  ingress:
    - {}
EOF
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "allow-all policy did not converge"
for source in \
    "${target_namespace} same-client" \
    "${source_a_namespace} client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    expect_allow "${namespace}" "${pod}" 8087
    expect_allow "${namespace}" "${pod}" 8088
done

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" allow-all >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "allow-all deletion did not reconverge"
expect_deny "${source_a_namespace}" client 8088
expect_deny "${source_b_namespace}" client 8087
expect_allow "${source_a_namespace}" client 8087
expect_allow "${source_b_namespace}" client 8088

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server conformance-target- >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "target Pod label removal did not reconverge"
for source in \
    "${target_namespace} same-client" \
    "${source_a_namespace} client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    expect_allow "${namespace}" "${pod}" 8087
    expect_allow "${namespace}" "${pod}" 8088
done
expect_explanation "${source_b_namespace}/client" 8087 Allow NoApplicablePolicy

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: named-port-destinations
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      named-port-target: "true"
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              conformance-group: a
      ports:
        - protocol: TCP
          port: web
EOF
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "multi-destination named-port policy did not converge"
expect_address_allow "${source_a_namespace}" client "${server_ip}" 8087
expect_address_deny "${source_a_namespace}" client "${server_ip}" 8088
expect_address_allow "${source_a_namespace}" client "${alternate_server_ip}" 8088
expect_address_deny "${source_a_namespace}" client "${alternate_server_ip}" 8087
expect_address_deny "${source_b_namespace}" client "${server_ip}" 8087
expect_address_deny "${source_b_namespace}" client "${alternate_server_ip}" 8088
expect_explanation_to "${source_a_namespace}/client" server 8087 Allow ExplicitRule
expect_explanation_to \
    "${source_a_namespace}/client" alternate-server 8088 Allow ExplicitRule
expect_explanation_to "${source_a_namespace}/client" server 8088 Deny DefaultAction
expect_explanation_to \
    "${source_a_namespace}/client" alternate-server 8087 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    named-port-destinations >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "multi-destination named-port deletion did not reconverge"
expect_address_allow "${source_a_namespace}" client "${server_ip}" 8088
expect_address_allow "${source_a_namespace}" client "${alternate_server_ip}" 8087

previous_revision=${policy_revision}
cleanup
for namespace in "${target_namespace}" "${source_a_namespace}" "${source_b_namespace}"; do
    if ! "${kc[@]}" wait --for=delete namespace/"${namespace}" --timeout=120s >/dev/null; then
        echo "upstream ingress conformance namespace ${namespace} did not terminate" >&2
        exit 1
    fi
done
if ! wait_for_policy_state "${baseline_count}" "${baseline_rejected}" "${previous_revision}"; then
    echo "upstream ingress conformance policies did not cleanly reconverge" >&2
    exit 1
fi

echo "upstream-aligned ingress conformance passed: destination-specific named ports, target Pod label isolation/recovery, default deny, same-namespace PodSelector, empty NamespaceSelector, selector AND, peer OR, matchExpressions with label recovery, multiple ingress rules, stacked additive policies, and allow-all precedence"
