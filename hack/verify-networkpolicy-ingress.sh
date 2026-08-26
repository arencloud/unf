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

pod_ipv4() {
    "${kc[@]}" get pod -n "$1" "$2" \
        -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' \
        | awk 'index($0, ".") > 0 && index($0, ":") == 0 { print; exit }'
}

pod_ipv6() {
    "${kc[@]}" get pod -n "$1" "$2" \
        -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' \
        | awk 'index($0, ":") > 0 { print; exit }'
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
    local response url_host=${address}
    [[ ${address} != *:* ]] || url_host="[${address}]"
    response=$("${kc[@]}" exec -n "${namespace}" "${pod}" -- \
        wget -T 2 -t 1 -qO- "http://${url_host}:${port}")
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
    local url_host=${address}
    [[ ${address} != *:* ]] || url_host="[${address}]"
    if "${kc[@]}" exec -n "${namespace}" "${pod}" -- \
        wget -T 2 -t 1 -qO- "http://${url_host}:${port}" >/dev/null 2>&1; then
        echo "expected ${namespace}/${pod} to be denied to ${address} TCP/${port}" >&2
        exit 1
    fi
}

expect_allow() {
    expect_address_allow "$1" "$2" "${server_ip}" "$3"
    expect_address_allow "$1" "$2" "${server_ipv6}" "$3"
}

expect_deny() {
    expect_address_deny "$1" "$2" "${server_ip}" "$3"
    expect_address_deny "$1" "$2" "${server_ipv6}" "$3"
}

protocol_exchange() {
    local namespace=$1
    local pod=$2
    local protocol=$3
    local address=$4
    local port=$5
    local endpoint
    case "${protocol}:$([[ ${address} == *:* ]] && echo 6 || echo 4)" in
        tcp:4) endpoint="TCP4:${address}:${port}" ;;
        udp:4) endpoint="UDP4-DATAGRAM:${address}:${port}" ;;
        tcp:6) endpoint="TCP6:[${address}]:${port}" ;;
        udp:6) endpoint="UDP6-DATAGRAM:[${address}]:${port}" ;;
        *) echo "unsupported echo protocol ${protocol}" >&2; return 2 ;;
    esac
    {
        printf 'unf-protocol-ok'
        sleep 0.2
    } | "${kc[@]}" exec -i -n "${namespace}" "${pod}" -- \
        timeout 3 socat -T 1 - "${endpoint}" 2>/dev/null
}

expect_protocol_allow() {
    local response
    response=$(protocol_exchange "$@" || true)
    if [[ ${response} != "unf-protocol-ok" ]]; then
        echo "expected $1/$2 $3 to reach $4 port $5" >&2
        exit 1
    fi
    if [[ $4 == "${protocol_server_ip:-}" && -n ${protocol_server_ipv6:-} ]]; then
        response=$(protocol_exchange "$1" "$2" "$3" "${protocol_server_ipv6}" "$5" || true)
        if [[ ${response} != "unf-protocol-ok" ]]; then
            echo "expected $1/$2 $3 to reach ${protocol_server_ipv6} port $5" >&2
            exit 1
        fi
    fi
}

expect_protocol_deny() {
    local response
    response=$(protocol_exchange "$@" || true)
    if [[ ${response} == "unf-protocol-ok" ]]; then
        echo "expected $1/$2 $3 to be denied to $4 port $5" >&2
        exit 1
    fi
    if [[ $4 == "${protocol_server_ip:-}" && -n ${protocol_server_ipv6:-} ]]; then
        response=$(protocol_exchange "$1" "$2" "$3" "${protocol_server_ipv6}" "$5" || true)
        if [[ ${response} == "unf-protocol-ok" ]]; then
            echo "expected $1/$2 $3 to be denied to ${protocol_server_ipv6} port $5" >&2
            exit 1
        fi
    fi
}

expect_protocol_explanation_to() {
    local source=$1
    local destination=$2
    local protocol=$3
    local port=$4
    local verdict=$5
    local reason=$6
    local explanation
    explanation=$("${unfctl}" --controller-url "${controller_url}" --output json \
        explain --from "${source}" --to "${target_namespace}/${destination}" \
        --protocol "${protocol}" --port "${port}")
    if ! grep -q "\"verdict\": \"${verdict}\"" <<<"${explanation}" \
        || ! grep -q "\"reason\": \"${reason}\"" <<<"${explanation}"; then
        echo "unexpected explanation for ${source} to ${destination} ${protocol}/${port}" >&2
        exit 1
    fi
}

expect_explanation_to() {
    expect_protocol_explanation_to "$1" "$2" tcp "$3" "$4" "$5"
}

expect_explanation() {
    expect_explanation_to "$1" server "$2" "$3" "$4"
}

expect_expression_target_selected() {
    expect_deny "${source_b_namespace}" client 8087
    expect_explanation "${source_b_namespace}/client" 8087 Deny DefaultAction
}

expect_expression_target_unselected() {
    expect_allow "${source_b_namespace}" client 8087
    expect_allow "${source_b_namespace}" client 8088
    expect_explanation "${source_b_namespace}/client" 8087 Allow NoApplicablePolicy
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
"${kc[@]}" wait --for=condition=Ready pod/protocol-server -n "${target_namespace}" \
    --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/same-client -n "${target_namespace}" \
    --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/client -n "${source_a_namespace}" --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/alternate-client \
    -n "${source_a_namespace}" --timeout=120s
"${kc[@]}" wait --for=condition=Ready pod/client -n "${source_b_namespace}" --timeout=120s
server_ip=$(pod_ipv4 "${target_namespace}" server)
server_ipv6=$(pod_ipv6 "${target_namespace}" server)
alternate_server_ip=$(pod_ipv4 "${target_namespace}" alternate-server)
alternate_server_ipv6=$(pod_ipv6 "${target_namespace}" alternate-server)
protocol_server_ip=$(pod_ipv4 "${target_namespace}" protocol-server)
protocol_server_ipv6=$(pod_ipv6 "${target_namespace}" protocol-server)
if [[ ! ${server_ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "upstream conformance server has no IPv4 Pod address" >&2
    exit 1
fi
if [[ ! ${alternate_server_ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "upstream conformance alternate server has no IPv4 Pod address" >&2
    exit 1
fi
if [[ ! ${protocol_server_ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "upstream conformance protocol server has no IPv4 Pod address" >&2
    exit 1
fi
for address_record in \
    "server ${server_ipv6}" \
    "alternate-server ${alternate_server_ipv6}" \
    "protocol-server ${protocol_server_ipv6}"; do
    read -r pod address <<<"${address_record}"
    if [[ ${address} != *:* ]]; then
        echo "upstream conformance ${pod} has no IPv6 Pod address" >&2
        exit 1
    fi
done
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
    "${source_a_namespace} alternate-client" \
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
    -p '{"spec":{"ingress":[{"from":[{"podSelector":{}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "empty same-Namespace PodSelector policy did not converge"
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
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"unf-np-source-a"}}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "exact Namespace name selector policy did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_deny "${source_b_namespace}" client 8087
expect_deny "${target_namespace}" same-client 8087
expect_explanation "${source_a_namespace}/client" 8087 Allow ExplicitRule
expect_explanation "${source_b_namespace}/client" 8087 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" ingress-matrix --type=merge \
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchExpressions":[{"key":"kubernetes.io/metadata.name","operator":"NotIn","values":["unf-np-target","unf-np-source-b"]}]}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "Namespace NotIn selector policy did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_deny "${source_b_namespace}" client 8087
expect_deny "${target_namespace}" same-client 8087
expect_explanation "${source_a_namespace}/client" 8087 Allow ExplicitRule
expect_explanation "${source_b_namespace}/client" 8087 Deny DefaultAction

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
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchExpressions":[{"key":"kubernetes.io/metadata.name","operator":"NotIn","values":["unf-np-target"]}]},"podSelector":{"matchExpressions":[{"key":"conformance-pod","operator":"In","values":["b","c"]}]}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "multi-value Pod and Namespace selector policy did not converge"
for pod in client alternate-client; do
    expect_allow "${source_a_namespace}" "${pod}" 8087
    expect_deny "${source_a_namespace}" "${pod}" 8088
done
expect_deny "${source_b_namespace}" client 8087
expect_deny "${target_namespace}" same-client 8087
expect_explanation "${source_a_namespace}/client" 8087 Allow ExplicitRule
expect_explanation "${source_a_namespace}/alternate-client" 8087 Allow ExplicitRule
expect_explanation "${source_b_namespace}/client" 8087 Deny DefaultAction
expect_explanation "${target_namespace}/same-client" 8087 Deny DefaultAction

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
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchExpressions":[{"key":"conformance-group","operator":"Exists"},{"key":"conformance-excluded","operator":"DoesNotExist"}]},"podSelector":{"matchExpressions":[{"key":"conformance-source","operator":"NotIn","values":["same"]}]}}],"ports":[{"protocol":"TCP","port":8087}]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "remaining selector operators did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_allow "${source_b_namespace}" client 8087
expect_deny "${target_namespace}" same-client 8087

previous_revision=${policy_revision}
"${kc[@]}" label namespace "${source_b_namespace}" \
    conformance-excluded=true --overwrite >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "Namespace DoesNotExist transition did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_deny "${source_b_namespace}" client 8087

previous_revision=${policy_revision}
"${kc[@]}" label namespace "${source_b_namespace}" conformance-excluded- >/dev/null
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${previous_revision}" "Namespace DoesNotExist recovery did not converge"
expect_allow "${source_b_namespace}" client 8087

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
expect_address_allow "${source_a_namespace}" client "${server_ipv6}" 8087
expect_address_deny "${source_a_namespace}" client "${server_ipv6}" 8088
expect_address_allow "${source_a_namespace}" client "${alternate_server_ipv6}" 8088
expect_address_deny "${source_a_namespace}" client "${alternate_server_ipv6}" 8087
expect_address_deny "${source_b_namespace}" client "${server_ipv6}" 8087
expect_address_deny "${source_b_namespace}" client "${alternate_server_ipv6}" 8088
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
expect_address_allow "${source_a_namespace}" client "${server_ipv6}" 8088
expect_address_allow "${source_a_namespace}" client "${alternate_server_ipv6}" 8087

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: nonexistent-named-port
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      named-port-target: "true"
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - protocol: TCP
          port: no-such-port
EOF
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "nonexistent named-port policy did not converge"
for destination in \
    "server ${server_ip} ${server_ipv6}" \
    "alternate-server ${alternate_server_ip} ${alternate_server_ipv6}"; do
    read -r pod ipv4 ipv6 <<<"${destination}"
    for port in 8087 8088; do
        expect_address_deny "${source_a_namespace}" client "${ipv4}" "${port}"
        expect_address_deny "${source_a_namespace}" client "${ipv6}" "${port}"
    done
    expect_explanation_to \
        "${source_a_namespace}/client" "${pod}" 8087 Deny DefaultAction
done

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    nonexistent-named-port >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "nonexistent named-port deletion did not reconverge"
for destination in \
    "${server_ip} ${server_ipv6}" \
    "${alternate_server_ip} ${alternate_server_ipv6}"; do
    read -r ipv4 ipv6 <<<"${destination}"
    for port in 8087 8088; do
        expect_address_allow "${source_a_namespace}" client "${ipv4}" "${port}"
        expect_address_allow "${source_a_namespace}" client "${ipv6}" "${port}"
    done
done

previous_revision=${policy_revision}
for protocol in tcp udp; do
    for port in 8090 8091; do
        expect_protocol_allow \
            "${source_a_namespace}" client "${protocol}" "${protocol_server_ip}" "${port}"
    done
done
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: udp-protocol
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      protocol-target: "true"
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              conformance-group: a
      ports:
        - protocol: UDP
          port: 8090
EOF
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "exact UDP policy did not converge"
expect_protocol_allow \
    "${source_a_namespace}" client udp "${protocol_server_ip}" 8090
expect_protocol_deny \
    "${source_a_namespace}" client udp "${protocol_server_ip}" 8091
expect_protocol_deny \
    "${source_a_namespace}" client tcp "${protocol_server_ip}" 8090
expect_protocol_deny \
    "${source_b_namespace}" client udp "${protocol_server_ip}" 8090
expect_protocol_explanation_to \
    "${source_a_namespace}/client" protocol-server udp 8090 Allow ExplicitRule
expect_protocol_explanation_to \
    "${source_a_namespace}/client" protocol-server udp 8091 Deny DefaultAction
expect_protocol_explanation_to \
    "${source_a_namespace}/client" protocol-server tcp 8090 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" udp-protocol --type=json \
    -p '[{"op":"remove","path":"/spec/ingress/0/ports/0/port"}]' >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "protocol-only UDP policy did not converge"
expect_protocol_allow \
    "${source_a_namespace}" client udp "${protocol_server_ip}" 8091
expect_protocol_deny \
    "${source_a_namespace}" client tcp "${protocol_server_ip}" 8091
expect_protocol_deny \
    "${source_b_namespace}" client udp "${protocol_server_ip}" 8091
expect_protocol_explanation_to \
    "${source_a_namespace}/client" protocol-server udp 8091 Allow ExplicitRule
expect_protocol_explanation_to \
    "${source_a_namespace}/client" protocol-server tcp 8091 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" udp-protocol >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "UDP policy deletion did not reconverge"
expect_protocol_allow \
    "${source_a_namespace}" client udp "${protocol_server_ip}" 8091
expect_protocol_allow \
    "${source_a_namespace}" client tcp "${protocol_server_ip}" 8090

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: empty-list-semantics
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      protocol-target: "true"
  policyTypes:
    - Ingress
  ingress:
    - from: []
      ports:
        - protocol: UDP
          port: 8090
        - protocol: TCP
          port: 8091
EOF
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "explicit empty source and multi-port policy did not converge"
for source in \
    "${target_namespace} same-client" \
    "${source_a_namespace} client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    expect_protocol_allow "${namespace}" "${pod}" udp "${protocol_server_ip}" 8090
    expect_protocol_allow "${namespace}" "${pod}" tcp "${protocol_server_ip}" 8091
    expect_protocol_deny "${namespace}" "${pod}" tcp "${protocol_server_ip}" 8090
    expect_protocol_deny "${namespace}" "${pod}" udp "${protocol_server_ip}" 8091
done
expect_protocol_explanation_to \
    "${source_b_namespace}/client" protocol-server udp 8090 Allow ExplicitRule
expect_protocol_explanation_to \
    "${source_b_namespace}/client" protocol-server tcp 8090 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" \
    empty-list-semantics --type=merge \
    -p '{"spec":{"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"conformance-group":"a"}}}],"ports":[]}]}}' \
    >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "explicit empty port policy did not converge"
for protocol in tcp udp; do
    for port in 8090 8091; do
        expect_protocol_allow \
            "${source_a_namespace}" client "${protocol}" "${protocol_server_ip}" "${port}"
        expect_protocol_deny \
            "${source_b_namespace}" client "${protocol}" "${protocol_server_ip}" "${port}"
    done
done
expect_protocol_explanation_to \
    "${source_a_namespace}/client" protocol-server udp 8091 Allow ExplicitRule
expect_protocol_explanation_to \
    "${source_b_namespace}/client" protocol-server tcp 8091 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    empty-list-semantics >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "empty-list policy deletion did not reconverge"
expect_protocol_allow \
    "${source_b_namespace}" client udp "${protocol_server_ip}" 8091
expect_protocol_allow \
    "${source_b_namespace}" client tcp "${protocol_server_ip}" 8090

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: target-match-expressions
  namespace: ${target_namespace}
spec:
  podSelector:
    matchExpressions:
      - key: expression-target
        operator: In
        values:
          - selected
      - key: expression-track
        operator: NotIn
        values:
          - excluded
      - key: expression-present
        operator: Exists
      - key: expression-blocked
        operator: DoesNotExist
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              conformance-group: a
      ports:
        - protocol: TCP
          port: 8087
EOF
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target match-expression policy did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_deny "${source_a_namespace}" client 8088
expect_expression_target_selected
for port in 8087 8088; do
    expect_address_allow \
        "${source_b_namespace}" client "${alternate_server_ip}" "${port}"
    expect_address_allow \
        "${source_b_namespace}" client "${alternate_server_ipv6}" "${port}"
done
expect_explanation_to \
    "${source_b_namespace}/client" alternate-server 8087 Allow NoApplicablePolicy

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server \
    expression-target=alternate --overwrite >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target In transition did not converge"
expect_expression_target_unselected

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server \
    expression-target=selected --overwrite >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target In recovery did not converge"
expect_expression_target_selected

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server \
    expression-track=excluded --overwrite >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target NotIn transition did not converge"
expect_expression_target_unselected

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server \
    expression-track=stable --overwrite >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target NotIn recovery did not converge"
expect_expression_target_selected

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server expression-present- >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target Exists transition did not converge"
expect_expression_target_unselected

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server \
    expression-present=true --overwrite >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target Exists recovery did not converge"
expect_expression_target_selected

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server \
    expression-blocked=true --overwrite >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target DoesNotExist transition did not converge"
expect_expression_target_unselected

previous_revision=${policy_revision}
"${kc[@]}" label pod -n "${target_namespace}" server expression-blocked- >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target DoesNotExist recovery did not converge"
expect_expression_target_selected

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    target-match-expressions >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "target match-expression deletion did not reconverge"
expect_expression_target_unselected

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: overlap-broad-target
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
          port: 8087
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: overlap-narrow-target
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      expression-target: selected
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
require_policy_state "$((baseline_count + 4))" "${baseline_rejected}" \
    "${previous_revision}" "overlapping target policies did not converge"
expect_allow "${source_a_namespace}" client 8087
expect_deny "${source_a_namespace}" client 8088
expect_deny "${source_b_namespace}" client 8087
expect_allow "${source_b_namespace}" client 8088
for address in "${alternate_server_ip}" "${alternate_server_ipv6}"; do
    expect_address_allow "${source_a_namespace}" client "${address}" 8087
    expect_address_deny "${source_a_namespace}" client "${address}" 8088
    expect_address_deny "${source_b_namespace}" client "${address}" 8087
    expect_address_deny "${source_b_namespace}" client "${address}" 8088
done
expect_explanation "${source_b_namespace}/client" 8088 Allow ExplicitRule
expect_explanation_to \
    "${source_b_namespace}/client" alternate-server 8088 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    overlap-narrow-target >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "narrow overlapping target policy deletion did not converge"
expect_deny "${source_b_namespace}" client 8088
expect_allow "${source_a_namespace}" client 8087
expect_address_allow \
    "${source_a_namespace}" client "${alternate_server_ip}" 8087
expect_address_allow \
    "${source_a_namespace}" client "${alternate_server_ipv6}" 8087

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    overlap-broad-target >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "broad overlapping target policy deletion did not converge"
for destination in \
    "${server_ip} ${server_ipv6}" \
    "${alternate_server_ip} ${alternate_server_ipv6}"; do
    read -r ipv4 ipv6 <<<"${destination}"
    for port in 8087 8088; do
        expect_address_allow "${source_b_namespace}" client "${ipv4}" "${port}"
        expect_address_allow "${source_b_namespace}" client "${ipv6}" "${port}"
    done
done

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-mutate-to-deny-all
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      named-port-target: "true"
  policyTypes:
    - Ingress
  ingress:
    - {}
EOF
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "mutable allow-all policy did not converge"
for source in \
    "${target_namespace} same-client" \
    "${source_a_namespace} client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    for destination in \
        "${server_ip} ${server_ipv6}" \
        "${alternate_server_ip} ${alternate_server_ipv6}"; do
        read -r ipv4 ipv6 <<<"${destination}"
        for port in 8087 8088; do
            expect_address_allow "${namespace}" "${pod}" "${ipv4}" "${port}"
            expect_address_allow "${namespace}" "${pod}" "${ipv6}" "${port}"
        done
    done
done
expect_explanation "${source_b_namespace}/client" 8087 Allow ExplicitRule

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" \
    allow-all-mutate-to-deny-all --type=json \
    -p '[{"op":"replace","path":"/spec/ingress","value":[]}]' >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "allow-all to default-deny policy update did not converge"
for source in \
    "${target_namespace} same-client" \
    "${source_a_namespace} client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    for destination in \
        "${server_ip} ${server_ipv6}" \
        "${alternate_server_ip} ${alternate_server_ipv6}"; do
        read -r ipv4 ipv6 <<<"${destination}"
        for port in 8087 8088; do
            expect_address_deny "${namespace}" "${pod}" "${ipv4}" "${port}"
            expect_address_deny "${namespace}" "${pod}" "${ipv6}" "${port}"
        done
    done
done
expect_explanation "${source_b_namespace}/client" 8087 Deny DefaultAction
expect_explanation_to \
    "${source_b_namespace}/client" alternate-server 8088 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" patch networkpolicy -n "${target_namespace}" \
    allow-all-mutate-to-deny-all --type=json \
    -p '[{"op":"replace","path":"/spec/ingress","value":[{}]}]' >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "default-deny to allow-all policy recovery did not converge"
for destination in \
    "${server_ip} ${server_ipv6}" \
    "${alternate_server_ip} ${alternate_server_ipv6}"; do
    read -r ipv4 ipv6 <<<"${destination}"
    for port in 8087 8088; do
        expect_address_allow "${source_b_namespace}" client "${ipv4}" "${port}"
        expect_address_allow "${source_b_namespace}" client "${ipv6}" "${port}"
    done
done
expect_explanation "${source_b_namespace}/client" 8087 Allow ExplicitRule

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    allow-all-mutate-to-deny-all >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "mutable policy deletion did not reconverge"
expect_allow "${source_b_namespace}" client 8087
expect_address_allow \
    "${source_b_namespace}" client "${alternate_server_ip}" 8088
expect_address_allow \
    "${source_b_namespace}" client "${alternate_server_ipv6}" 8088

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: broad-target-default-deny
  namespace: ${target_namespace}
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress: []
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: target-specific-allow-all
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      expression-target: selected
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector: {}
          namespaceSelector: {}
EOF
require_policy_state "$((baseline_count + 4))" "${baseline_rejected}" \
    "${previous_revision}" "target-specific exception policies did not converge"
for source in \
    "${source_a_namespace} client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    for port in 8087 8088; do
        expect_allow "${namespace}" "${pod}" "${port}"
        expect_address_deny \
            "${namespace}" "${pod}" "${alternate_server_ip}" "${port}"
        expect_address_deny \
            "${namespace}" "${pod}" "${alternate_server_ipv6}" "${port}"
    done
done
expect_explanation "${source_b_namespace}/client" 8087 Allow ExplicitRule
expect_explanation_to \
    "${source_b_namespace}/client" alternate-server 8087 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    target-specific-allow-all >/dev/null
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "target-specific allow deletion did not reconverge"
for destination in \
    "${server_ip} ${server_ipv6}" \
    "${alternate_server_ip} ${alternate_server_ipv6}"; do
    read -r ipv4 ipv6 <<<"${destination}"
    for port in 8087 8088; do
        expect_address_deny "${source_b_namespace}" client "${ipv4}" "${port}"
        expect_address_deny "${source_b_namespace}" client "${ipv6}" "${port}"
    done
done
expect_explanation "${source_b_namespace}/client" 8087 Deny DefaultAction

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    broad-target-default-deny >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "broad target default-deny deletion did not reconverge"
expect_allow "${source_b_namespace}" client 8087
expect_address_allow \
    "${source_b_namespace}" client "${alternate_server_ip}" 8088
expect_address_allow \
    "${source_b_namespace}" client "${alternate_server_ipv6}" 8088

previous_revision=${policy_revision}
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: multiple-local-pod-selector-peers
  namespace: ${target_namespace}
spec:
  podSelector:
    matchLabels:
      expression-target: selected
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              conformance-source: same
        - podSelector:
            matchLabels:
              app: upstream-alternate-server
      ports:
        - protocol: TCP
          port: 8087
EOF
require_policy_state "$((baseline_count + 3))" "${baseline_rejected}" \
    "${previous_revision}" "multiple local PodSelector peers did not converge"
for pod in same-client alternate-server; do
    expect_allow "${target_namespace}" "${pod}" 8087
    expect_deny "${target_namespace}" "${pod}" 8088
done
for namespace in "${source_a_namespace}" "${source_b_namespace}"; do
    expect_deny "${namespace}" client 8087
done
for port in 8087 8088; do
    expect_address_allow \
        "${source_b_namespace}" client "${alternate_server_ip}" "${port}"
    expect_address_allow \
        "${source_b_namespace}" client "${alternate_server_ipv6}" "${port}"
done
expect_explanation "${target_namespace}/same-client" 8087 Allow ExplicitRule
expect_explanation "${target_namespace}/alternate-server" 8087 Allow ExplicitRule
expect_explanation "${source_a_namespace}/client" 8087 Deny DefaultAction
expect_explanation_to \
    "${source_b_namespace}/client" alternate-server 8087 Allow NoApplicablePolicy

previous_revision=${policy_revision}
"${kc[@]}" delete networkpolicy -n "${target_namespace}" \
    multiple-local-pod-selector-peers >/dev/null
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${previous_revision}" "multiple local PodSelector peer deletion did not reconverge"
for source in \
    "${target_namespace} same-client" \
    "${target_namespace} alternate-server" \
    "${source_a_namespace} client" \
    "${source_a_namespace} alternate-client" \
    "${source_b_namespace} client"; do
    read -r namespace pod <<<"${source}"
    for port in 8087 8088; do
        expect_allow "${namespace}" "${pod}" "${port}"
    done
done
expect_explanation "${source_a_namespace}/client" 8087 Allow NoApplicablePolicy

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

echo "upstream-aligned dual-stack ingress conformance passed: IPv4/IPv6 explicit empty source/port wildcard semantics, multi-port OR, exact/protocol-only UDP isolation, destination-specific and nonexistent named ports, target Pod match-label/expression isolation and recovery, overlapping destination selectors, remote target-specific allow over namespace-wide default deny, same-object allow-all/default-deny update recovery, default deny, same-namespace empty/labeled PodSelector, multiple same-Namespace PodSelector peer OR, empty/exact-name NamespaceSelector, all peer selector operators with Pod/Namespace label recovery, selector AND including multi-value Pod In with Namespace NotIn, peer OR, multiple ingress rules, stacked additive policies, and allow-all precedence"
