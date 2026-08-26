#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
controller_url=${UNF_CONTROLLER_URL:-http://127.0.0.1:19962}
unfctl=${UNFCTL:-"${project_root}/target/debug/unfctl"}
fixture="${project_root}/deploy/examples/networkpolicy-egress.yaml"
simulation_fixture="${project_root}/deploy/examples/simulation-networkpolicy-egress-deny.yaml"
source_namespace=unf-egress-source
allowed_namespace=unf-egress-allowed
denied_namespace=unf-egress-denied
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")

cleanup() {
    "${kc[@]}" delete namespaces "${source_namespace}" "${allowed_namespace}" \
        "${denied_namespace}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
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

wait_for_policy_state() {
    local expected_count=$1 expected_rejected=$2 floor_revision=$3
    local status revision accepted rejected pod agent desired applied converged
    for _ in {1..45}; do
        status=$(controller_status)
        revision=$(status_field policy <<<"${status}")
        accepted=$(status_field network_policies <<<"${status}")
        rejected=$(status_field rejected_network_policies <<<"${status}")
        converged=true
        if [[ -z ${revision} || ${revision} -le ${floor_revision} \
            || ${accepted} != "${expected_count}" \
            || ${rejected} != "${expected_rejected}" ]]; then
            converged=false
        else
            for pod in "${agent_pods[@]}"; do
                agent=$(agent_status "${pod}" || true)
                desired=$(agent_field desired_policy_revision <<<"${agent}")
                applied=$(agent_field applied_policy_revision <<<"${agent}")
                if [[ -z ${desired} || ${desired} != "${applied}" \
                    || ${applied} != "${revision}" ]]; then
                    converged=false
                    break
                fi
            done
        fi
        if [[ ${converged} == true ]]; then
            policy_revision=${revision}
            return 0
        fi
        sleep 1
    done
    return 1
}

require_policy_state() {
    if ! wait_for_policy_state "$1" "$2" "$3"; then
        echo "$4" >&2
        exit 1
    fi
}

pod_address() {
    local namespace=$1 pod=$2 family=$3
    "${kc[@]}" get pod -n "${namespace}" "${pod}" \
        -o jsonpath='{range .status.podIPs[*]}{.ip}{"\n"}{end}' \
        | if [[ ${family} == 4 ]]; then
            awk 'index($0, ".") > 0 && index($0, ":") == 0 { print; exit }'
        else
            awk 'index($0, ":") > 0 { print; exit }'
        fi
}

tcp_exchange() {
    local pod=$1 address=$2 port=$3 host
    host=${address}
    [[ ${address} != *:* ]] || host="[${address}]"
    "${kc[@]}" exec -n "${source_namespace}" "${pod}" -- \
        wget -T 2 -t 1 -qO- "http://${host}:${port}"
}

expect_tcp_allow() {
    local response
    for _ in {1..10}; do
        response=$(tcp_exchange "$1" "$2" "$3" || true)
        if [[ ${response} == "$4" ]]; then
            return 0
        fi
        sleep 1
    done
    echo "expected ${source_namespace}/$1 to reach $2 TCP/$3" >&2
    exit 1
}

expect_tcp_deny() {
    if tcp_exchange "$1" "$2" "$3" >/dev/null 2>&1; then
        echo "expected ${source_namespace}/$1 to be denied to $2 TCP/$3" >&2
        exit 1
    fi
}

udp_exchange() {
    local address=$1 port=$2 endpoint response
    if [[ ${address} == *:* ]]; then
        endpoint="UDP6-DATAGRAM:[${address}]:${port}"
    else
        endpoint="UDP4-DATAGRAM:${address}:${port}"
    fi
    response=$({ printf 'unf-egress-protocol-ok'; sleep 0.2; } \
        | "${kc[@]}" exec -i -n "${source_namespace}" client -- \
            timeout 3 socat -T 1 - "${endpoint}" 2>/dev/null || true)
    printf '%s' "${response}"
}

expect_udp_allow() {
    local response
    response=$(udp_exchange "$1" "$2")
    if [[ ${response} != "unf-egress-protocol-ok" ]]; then
        echo "expected selected client to reach $1 UDP/$2" >&2
        exit 1
    fi
}

expect_udp_deny() {
    local response
    response=$(udp_exchange "$1" "$2")
    if [[ ${response} == "unf-egress-protocol-ok" ]]; then
        echo "expected selected client to be denied to $1 UDP/$2" >&2
        exit 1
    fi
}

sctp_exchange() {
    local port=$1 response
    response=$({ printf 'unf-egress-sctp-ok'; sleep 1; } \
        | "${kc[@]}" exec -i -n "${source_namespace}" client -- \
            timeout 5 socat -T 3 - "SCTP:${protocol_ipv4}:${port}" 2>/dev/null || true)
    printf '%s' "${response}"
}

expect_direction_provenance() {
    local revision=$1 port=$2 verdict=$3 reason=$4 require_rule=$5 logs line
    for _ in {1..20}; do
        logs=$("${kc[@]}" logs -n unf-system \
            -l app.kubernetes.io/name=unf-agent --all-containers=true \
            --prefix=true --since=2m --tail=-1)
        line=$(grep "\"destination_port\":${port}" <<<"${logs}" \
            | grep "\"policy_revision\":${revision}" \
            | grep "\"verdict\":\"${verdict}\"" \
            | grep "\"reason\":${reason}" | grep '"direction":2' \
            | tail -n 1 || true)
        if grep -Eq '"source_identity":[1-9][0-9]*' <<<"${line}" \
            && grep -Eq '"destination_identity":[1-9][0-9]*' <<<"${line}" \
            && grep -Eq '"policy_id":[1-9][0-9]*' <<<"${line}" \
            && { [[ ${require_rule} == false ]] \
                || grep -Eq '"rule_id":[0-9]+' <<<"${line}"; }; then
            return 0
        fi
        tcp_exchange client "${allowed_ipv4}" "${port}" >/dev/null 2>&1 || true
        sleep 1
    done
    return 1
}

expect_egress_explanation() {
    local destination=$1 family=$2 source_address=$3 destination_address=$4
    local port=$5 verdict=$6 reason=$7 explanation
    explanation=$("${unfctl}" --controller-url "${controller_url}" --output json \
        explain --from "${source_namespace}/client" --to "${destination}" \
        --direction egress --ip-family "${family}" --protocol tcp --port "${port}")
    if ! grep -q '"direction": "Egress"' <<<"${explanation}" \
        || ! grep -q "\"ip_family\": \"${family}\"" <<<"${explanation}" \
        || ! grep -q "\"source_address\": \"${source_address}\"" <<<"${explanation}" \
        || ! grep -q "\"destination_address\": \"${destination_address}\"" \
            <<<"${explanation}" \
        || ! grep -q "\"verdict\": \"${verdict}\"" <<<"${explanation}" \
        || ! grep -q "\"reason\": \"${reason}\"" <<<"${explanation}"; then
        echo "unexpected egress ${family} explanation to ${destination} TCP/${port}" >&2
        exit 1
    fi
}

expect_egress_history() {
    local family=$1 source_address=$2 destination_address=$3 port=$4 verdict=$5 revision=$6
    local history
    for _ in {1..30}; do
        history=$("${unfctl}" --controller-url "${controller_url}" --output json flows)
        if jq -e --arg family "${family}" --arg source "${source_address}" \
            --arg destination "${destination_address}" --arg verdict "${verdict}" \
            --argjson port "${port}" --argjson revision "${revision}" '
                .schema_version == 4
                and any(.entries[];
                    .key.direction == "Egress"
                    and .key.destination_port == $port
                    and .policy_revision == $revision
                    and .decision.verdict == $verdict
                    and (if $family == "ipv4" then
                        .key.source_ipv4 == $source and .key.destination_ipv4 == $destination
                    else
                        .key.source_ipv6 == $source and .key.destination_ipv6 == $destination
                    end))
            ' <<<"${history}" >/dev/null; then
            return 0
        fi
        tcp_exchange client "${destination_address}" "${port}" >/dev/null 2>&1 || true
        sleep 1
    done
    echo "egress ${family} ${verdict} flow was not retained with direction" >&2
    exit 1
}

expect_egress_simulation() {
    local revision=$1 simulation after_revision
    simulation=$("${unfctl}" --controller-url "${controller_url}" --output json \
        policy simulate "${simulation_fixture}")
    if ! jq -e --arg source4 "${source_ipv4}" --arg destination4 "${allowed_ipv4}" \
        --arg source6 "${source_ipv6}" --arg destination6 "${allowed_ipv6}" \
        --argjson revision "${revision}" '
        .schema_version == 4
        and .resource_kind == "NetworkPolicy"
        and .policy == "unf-egress-source/selected-egress"
        and .operation == "replace"
        and .snapshot.policy_revision == $revision
        and .affected_sources == 1
        and .affected_destinations == 0
        and .summary.would_be_denied >= 2
        and .summary.verdict_changes >= 2
        and .historical_summary.would_be_denied_observations > 0
        and any(.historical_changes[];
            .direction == "Egress"
            and .destination_port == 8080
            and .current.verdict == "Allow"
            and .proposed.verdict == "Deny")
        and any(.changes[];
            .direction == "Egress"
            and .ip_family == "ipv4"
            and .source_address == $source4
            and .destination_address == $destination4
            and .destination_port == 8080
            and .current.verdict == "Allow"
            and .proposed.verdict == "Deny")
        and any(.changes[];
            .direction == "Egress"
            and .ip_family == "ipv6"
            and .source_address == $source6
            and .destination_address == $destination6
            and .destination_port == 8080
            and .current.verdict == "Allow"
            and .proposed.verdict == "Deny")
    ' <<<"${simulation}" >/dev/null; then
        echo "direction-aware egress NetworkPolicy simulation was incomplete" >&2
        exit 1
    fi
    after_revision=$(status_field policy <<<"$(controller_status)")
    if [[ ${after_revision} != "${revision}" ]]; then
        echo "read-only NetworkPolicy simulation changed policy revision" >&2
        exit 1
    fi
}

cleanup
for namespace in "${source_namespace}" "${allowed_namespace}" "${denied_namespace}"; do
    "${kc[@]}" wait --for=delete namespace/"${namespace}" --timeout=60s \
        >/dev/null 2>&1 || true
done

mapfile -t agent_pods < <("${kc[@]}" get pods -n unf-system \
    -l app.kubernetes.io/name=unf-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
if [[ ${#agent_pods[@]} -ne 2 ]]; then
    echo "egress qualification requires exactly two UNF agents" >&2
    exit 1
fi
if ! wait_for_current_policy_sync; then
    echo "could not establish the egress policy baseline" >&2
    exit 1
fi

"${kc[@]}" apply -f "${fixture}" >/dev/null
for target in \
    "${source_namespace} client" \
    "${source_namespace} unselected-client" \
    "${allowed_namespace} server" \
    "${allowed_namespace} protocol-server" \
    "${denied_namespace} server"; do
    read -r namespace pod <<<"${target}"
    "${kc[@]}" wait --for=condition=Ready pod/"${pod}" -n "${namespace}" --timeout=120s
done

allowed_ipv4=$(pod_address "${allowed_namespace}" server 4)
allowed_ipv6=$(pod_address "${allowed_namespace}" server 6)
source_ipv4=$(pod_address "${source_namespace}" client 4)
source_ipv6=$(pod_address "${source_namespace}" client 6)
denied_ipv4=$(pod_address "${denied_namespace}" server 4)
denied_ipv6=$(pod_address "${denied_namespace}" server 6)
protocol_ipv4=$(pod_address "${allowed_namespace}" protocol-server 4)
protocol_ipv6=$(pod_address "${allowed_namespace}" protocol-server 6)
for address in "${source_ipv4}" "${source_ipv6}" "${allowed_ipv4}" \
    "${allowed_ipv6}" "${denied_ipv4}" \
    "${denied_ipv6}" "${protocol_ipv4}" "${protocol_ipv6}"; do
    if [[ -z ${address} ]]; then
        echo "egress qualification requires dual-stack Pod addresses" >&2
        exit 1
    fi
done

for pod in client unselected-client; do
    expect_tcp_allow "${pod}" "${allowed_ipv4}" 8080 unf-egress-ok
    expect_tcp_allow "${pod}" "${allowed_ipv6}" 8080 unf-egress-ok
    expect_tcp_allow "${pod}" "${denied_ipv4}" 8080 unf-egress-denied-ok
    expect_tcp_allow "${pod}" "${denied_ipv6}" 8080 unf-egress-denied-ok
done

"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: selected-egress
  namespace: ${source_namespace}
spec:
  podSelector:
    matchLabels:
      app: egress-client
  policyTypes: [Egress]
  egress: []
EOF
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${baseline_revision}" "egress default deny did not converge"
default_deny_revision=${policy_revision}
for address in "${allowed_ipv4}" "${allowed_ipv6}" "${denied_ipv4}" "${denied_ipv6}"; do
    expect_tcp_deny client "${address}" 8080
done
expect_tcp_allow unselected-client "${allowed_ipv4}" 8080 unf-egress-ok
expect_tcp_allow unselected-client "${allowed_ipv6}" 8080 unf-egress-ok

"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: selected-egress
  namespace: ${source_namespace}
spec:
  podSelector:
    matchLabels:
      app: egress-client
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              unf-egress-zone: allowed
          podSelector:
            matchLabels:
              app: egress-server
      ports:
        - protocol: TCP
          port: web
EOF
require_policy_state "$((baseline_count + 1))" "${baseline_rejected}" \
    "${default_deny_revision}" "selector/named-port egress allow did not converge"
selector_revision=${policy_revision}
selector_status=$(controller_status)
selector_egress_entries=$(status_field resolved_egress_policy_entries <<<"${selector_status}")
if [[ -z ${selector_egress_entries} || ${selector_egress_entries} -eq 0 ]]; then
    echo "controller status did not expose populated egress policy entries" >&2
    exit 1
fi
expect_tcp_allow client "${allowed_ipv4}" 8080 unf-egress-ok
expect_tcp_allow client "${allowed_ipv6}" 8080 unf-egress-ok
expect_tcp_deny client "${allowed_ipv4}" 8081
expect_tcp_deny client "${allowed_ipv6}" 8081
expect_tcp_deny client "${denied_ipv4}" 8080
expect_tcp_deny client "${denied_ipv6}" 8080
expect_egress_explanation "${allowed_namespace}/server" ipv4 \
    "${source_ipv4}" "${allowed_ipv4}" 8080 Allow ExplicitRule
expect_egress_explanation "${allowed_namespace}/server" ipv6 \
    "${source_ipv6}" "${allowed_ipv6}" 8080 Allow ExplicitRule
expect_egress_explanation "${allowed_namespace}/server" ipv4 \
    "${source_ipv4}" "${allowed_ipv4}" 8081 Deny DefaultAction
if ! expect_direction_provenance "${selector_revision}" 8080 Allow 1 true; then
    echo "egress explicit allow did not emit direction-correct provenance" >&2
    exit 1
fi
if ! expect_direction_provenance "${selector_revision}" 8081 Deny 3 false; then
    echo "egress default deny did not emit direction-correct provenance" >&2
    exit 1
fi
expect_egress_history ipv4 "${source_ipv4}" "${allowed_ipv4}" \
    8080 Allow "${selector_revision}"
expect_egress_history ipv6 "${source_ipv6}" "${allowed_ipv6}" \
    8080 Allow "${selector_revision}"
expect_egress_history ipv4 "${source_ipv4}" "${allowed_ipv4}" \
    8081 Deny "${selector_revision}"
expect_egress_simulation "${selector_revision}"
expect_tcp_allow client "${allowed_ipv4}" 8080 unf-egress-ok
expect_tcp_allow client "${allowed_ipv6}" 8080 unf-egress-ok

"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: selected-egress-protocols
  namespace: ${source_namespace}
spec:
  podSelector:
    matchLabels:
      app: egress-client
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              unf-egress-zone: allowed
          podSelector:
            matchLabels:
              app: egress-protocol-server
      ports:
        - protocol: UDP
          port: allowed-udp
        - protocol: SCTP
EOF
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${selector_revision}" "UDP/SCTP egress policy did not converge"
protocol_revision=${policy_revision}
for address in "${protocol_ipv4}" "${protocol_ipv6}"; do
    expect_udp_allow "${address}" 8090
    expect_udp_deny "${address}" 8091
done
for port in 8092 8093; do
    if [[ $(sctp_exchange "${port}") != "unf-egress-sctp-ok" ]]; then
        echo "protocol-only egress SCTP/${port} was not allowed" >&2
        exit 1
    fi
done

ipv4_prefix=$(awk -F. '{print $1 "." $2 "." $3 ".0/24"}' <<<"${allowed_ipv4}")
if [[ ${denied_ipv4%.*} != "${allowed_ipv4%.*}" ]]; then
    echo "IPv4 egress exception fixture Pods are not in one bounded /24" >&2
    exit 1
fi
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: selected-egress
  namespace: ${source_namespace}
spec:
  podSelector:
    matchLabels:
      app: egress-client
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: ${ipv4_prefix}
            except: [${denied_ipv4}/32]
      ports:
        - protocol: TCP
          port: 8080
    - to:
        - ipBlock:
            cidr: ::/0
            except: [${denied_ipv6}/128]
      ports:
        - protocol: TCP
          port: 8080
EOF
require_policy_state "$((baseline_count + 2))" "${baseline_rejected}" \
    "${protocol_revision}" "dual-stack egress ipBlock update did not converge"
ipblock_revision=${policy_revision}
expect_tcp_allow client "${allowed_ipv4}" 8080 unf-egress-ok
expect_tcp_allow client "${allowed_ipv6}" 8080 unf-egress-ok
expect_tcp_deny client "${denied_ipv4}" 8080
expect_tcp_deny client "${denied_ipv6}" 8080
expect_egress_explanation "${allowed_namespace}/server" ipv4 \
    "${source_ipv4}" "${allowed_ipv4}" 8080 Allow ExplicitRule
expect_egress_explanation "${allowed_namespace}/server" ipv6 \
    "${source_ipv6}" "${allowed_ipv6}" 8080 Allow ExplicitRule
expect_egress_explanation "${denied_namespace}/server" ipv4 \
    "${source_ipv4}" "${denied_ipv4}" 8080 Deny DefaultAction
expect_egress_explanation "${denied_namespace}/server" ipv6 \
    "${source_ipv6}" "${denied_ipv6}" 8080 Deny DefaultAction

"${kc[@]}" delete networkpolicy -n "${source_namespace}" \
    selected-egress selected-egress-protocols >/dev/null
require_policy_state "${baseline_count}" "${baseline_rejected}" \
    "${ipblock_revision}" "egress policy deletion did not reconverge"
for address in "${allowed_ipv4}" "${allowed_ipv6}"; do
    expect_tcp_allow client "${address}" 8080 unf-egress-ok
done
expect_tcp_allow client "${denied_ipv4}" 8080 unf-egress-denied-ok
expect_tcp_allow client "${denied_ipv6}" 8080 unf-egress-denied-ok

previous_revision=${policy_revision}
cleanup
for namespace in "${source_namespace}" "${allowed_namespace}" "${denied_namespace}"; do
    if ! "${kc[@]}" wait --for=delete namespace/"${namespace}" --timeout=120s >/dev/null; then
        echo "egress qualification namespace ${namespace} did not terminate" >&2
        exit 1
    fi
done
if ! wait_for_policy_state "${baseline_count}" "${baseline_rejected}" \
    "${previous_revision}"; then
    echo "egress fixture cleanup did not reconverge" >&2
    exit 1
fi

echo "dual-stack NetworkPolicy egress qualification passed: selected-source default isolation, non-selected pass-through, Namespace/Pod selector AND, named TCP and UDP ports, protocol-only SCTP, IPv4/IPv6 ipBlock exceptions, direction-correct explanation, retained history, read-only what-if simulation, allow/deny provenance, deletion recovery, and exact fixture cleanup"
