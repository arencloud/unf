#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kubeconfig=${KUBECONFIG:-"${project_root}/.tools/kind-unf-dev.kubeconfig"}
context=${KUBE_CONTEXT:-kind-unf-dev}
kc=(kubectl --kubeconfig "${kubeconfig}" --context "${context}")
receiver_name=unf-flow-export-receiver
token_secret=unf-flow-export-test-token
original_revision=
controller_configured=false

cleanup() {
    if [[ ${controller_configured} == true && -n ${original_revision} ]]; then
        "${kc[@]}" -n unf-system rollout undo deployment/unf-controller \
            --to-revision="${original_revision}" >/dev/null 2>&1 || true
        "${kc[@]}" -n unf-system rollout status deployment/unf-controller \
            --timeout=120s >/dev/null 2>&1 || true
    fi
    "${kc[@]}" -n unf-system delete deployment,service "${receiver_name}" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
    "${kc[@]}" -n unf-system delete secret "${token_secret}" \
        --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

for command in kubectl jq awk; do
    command -v "${command}" >/dev/null
done
[[ -s ${kubeconfig} ]]
"${kc[@]}" -n unf-system wait --for=condition=Available \
    deployment/unf-controller --timeout=120s >/dev/null
"${kc[@]}" -n unf-system rollout status daemonset/unf-agent \
    --timeout=120s >/dev/null
"${kc[@]}" -n frontend wait --for=condition=Ready pod/client --timeout=120s >/dev/null
"${kc[@]}" -n backend wait --for=condition=Ready pod/server --timeout=120s >/dev/null

active_controller() {
    "${kc[@]}" -n unf-system get pod \
        -l app.kubernetes.io/name=unf-controller -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name'
}

controller_raw() {
    local controller=$1
    local path=$2
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${controller}:9962/proxy${path}"
}

receiver_raw() {
    local path=$1
    local receiver
    receiver=$("${kc[@]}" -n unf-system get pod \
        -l app.kubernetes.io/name="${receiver_name}" -o json \
        | jq -r '.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running") | .metadata.name' \
        | head -n 1)
    [[ -n ${receiver} ]]
    "${kc[@]}" get --raw \
        "/api/v1/namespaces/unf-system/pods/${receiver}:8080/proxy${path}"
}

metric() {
    local controller=$1
    local name=$2
    controller_raw "${controller}" /metrics \
        | awk -v metric_name="${name}" '$1 == metric_name { print int($2); found=1 } END { if (!found) print 0 }'
}

wait_for_metric_equals() {
    local controller=$1
    local name=$2
    local expected=$3
    local value=0
    for _ in {1..60}; do
        value=$(metric "${controller}" "${name}" 2>/dev/null || true)
        if [[ ${value:-0} -eq ${expected} ]]; then
            printf '%s' "${value}"
            return 0
        fi
        sleep 1
    done
    echo "metric ${name} did not equal ${expected}; last value ${value:-unavailable}" >&2
    return 1
}

wait_for_metric_at_least() {
    local controller=$1
    local name=$2
    local expected=$3
    local value=0
    for _ in {1..60}; do
        value=$(metric "${controller}" "${name}" 2>/dev/null || true)
        if [[ ${value:-0} -ge ${expected} ]]; then
            printf '%s' "${value}"
            return 0
        fi
        sleep 1
    done
    echo "metric ${name} did not reach ${expected}; last value ${value:-unavailable}" >&2
    return 1
}

emit_flows() {
    for _ in {1..12}; do
        "${kc[@]}" -n frontend exec client -- \
            wget -qO- --timeout=2 "${server_url}" >/dev/null
    done
}


emit_pressure_flows() {
    for _ in {1..15}; do
        "${kc[@]}" -n frontend exec client -- sh -c \
            'for request in 1 2 3 4; do wget -qO- --timeout=2 "$1" >/dev/null; done' \
            sh "${server_url}"
        sleep 1
    done
}

server_ipv4=$("${kc[@]}" -n backend get pod server -o json \
    | jq -r '.status.podIPs[]?.ip | select(contains(":") | not)' \
    | head -n 1)
[[ -n ${server_ipv4} ]]
server_url="http://${server_ipv4}:8080"

"${kc[@]}" -n unf-system create secret generic "${token_secret}" \
    --from-literal=token=kind-flow-export-token >/dev/null
"${kc[@]}" apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${receiver_name}
  namespace: unf-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ${receiver_name}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${receiver_name}
    spec:
      containers:
        - name: receiver
          image: localhost/unf-test-tools:ipv6-ext-v1
          imagePullPolicy: Never
          command: [/usr/local/bin/unf-flow-receiver, "8080"]
          env:
            - name: UNF_FLOW_RECEIVER_TOKEN
              valueFrom:
                secretKeyRef:
                  name: ${token_secret}
                  key: token
            - name: UNF_FLOW_RECEIVER_FAIL_FIRST
              value: "1"
          ports:
            - name: http
              containerPort: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: http
            timeoutSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            capabilities:
              drop: [ALL]
---
apiVersion: v1
kind: Service
metadata:
  name: ${receiver_name}
  namespace: unf-system
spec:
  selector:
    app.kubernetes.io/name: ${receiver_name}
  ports:
    - name: http
      port: 8080
      targetPort: http
EOF
"${kc[@]}" -n unf-system rollout status deployment/"${receiver_name}" \
    --timeout=120s >/dev/null

original_revision=$("${kc[@]}" -n unf-system get deployment unf-controller \
    -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')
[[ -n ${original_revision} ]]
"${kc[@]}" -n unf-system patch deployment unf-controller --type=strategic -p "$(cat <<EOF
spec:
  template:
    spec:
      containers:
        - name: controller
          env:
            - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_URL
              value: http://${receiver_name}.unf-system.svc:8080/flows
            - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_ALLOW_PLAINTEXT
              value: "true"
            - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_BEARER_TOKEN_FILE
              value: /var/run/secrets/unf-flow-export/token
            - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_QUEUE_CAPACITY
              value: "1"
            - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_MAX_ATTEMPTS
              value: "3"
            - name: UNF_CONTROLLER_FLOW_EXPORT_HTTP_TIMEOUT_SECONDS
              value: "5"
          volumeMounts:
            - name: external-flow-export-token
              mountPath: /var/run/secrets/unf-flow-export
              readOnly: true
      volumes:
        - name: external-flow-export-token
          secret:
            secretName: ${token_secret}
            defaultMode: 292
EOF
)" >/dev/null
controller_configured=true
"${kc[@]}" -n unf-system rollout status deployment/unf-controller \
    --timeout=120s >/dev/null
controller=$(active_controller)
[[ $(wc -w <<<"${controller}") -eq 1 ]]
controller_uid=$("${kc[@]}" -n unf-system get pod "${controller}" -o jsonpath='{.metadata.uid}')
controller_restarts=$("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}')

emit_flows
wait_for_metric_at_least "${controller}" \
    unf_external_flow_export_delivered_batches_total 1 >/dev/null
wait_for_metric_at_least "${controller}" \
    unf_external_flow_export_delivery_errors_total 1 >/dev/null
wait_for_metric_at_least "${controller}" \
    unf_external_flow_export_delivery_attempts_total 2 >/dev/null

receiver_stats=$(receiver_raw /stats)
jq -e '
  .attempts >= 2
  and .accepted >= 1
  and .last_sequence > 0
  and .sequence_duplicates >= 1
  and .sequence_regressions == 0
  and .max_body_bytes > 0
  and .max_body_bytes <= 2097152
' <<<"${receiver_stats}" >/dev/null
last_envelope=$(receiver_raw /last)
jq -e '
  .schema_version == 1
  and (.controller_epoch | numbers) > 0
  and (.export_sequence | numbers) > 0
  and (.topology_revision | numbers) >= 0
  and (.received_unix_ms | numbers) > 0
  and .batch.schema_version == 3
  and (.batch.node_name | strings | length) > 0
  and (.batch.entries | length) > 0
  and all(.batch.entries[];
    .observed_events > 0
    and (.key.direction == "Ingress" or .key.direction == "Egress"))
' <<<"${last_envelope}" >/dev/null

baseline_telemetry=$(metric "${controller}" unf_telemetry_observations_total)
baseline_dropped=$(metric "${controller}" unf_external_flow_export_dropped_batches_total)
baseline_history=$(controller_raw "${controller}" /v1/flows | jq '.retained_observations')
"${kc[@]}" -n unf-system scale deployment/"${receiver_name}" --replicas=0 >/dev/null
"${kc[@]}" -n unf-system wait --for=delete pod \
    -l app.kubernetes.io/name="${receiver_name}" --timeout=120s >/dev/null
emit_flows
wait_for_metric_at_least "${controller}" unf_telemetry_observations_total \
    "$((baseline_telemetry + 1))" >/dev/null
wait_for_metric_at_least "${controller}" unf_external_flow_export_dropped_batches_total \
    "$((baseline_dropped + 1))" >/dev/null
for _ in {1..30}; do
    current_history=$(controller_raw "${controller}" /v1/flows | jq '.retained_observations')
    if [[ ${current_history} -gt ${baseline_history} ]]; then
        break
    fi
    sleep 1
done
[[ ${current_history:-0} -gt ${baseline_history} ]]
[[ $("${kc[@]}" -n unf-system get pod "${controller}" -o jsonpath='{.metadata.uid}') == "${controller_uid}" ]]
[[ $("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}') == "${controller_restarts}" ]]

baseline_delivered=$(metric "${controller}" unf_external_flow_export_delivered_batches_total)
"${kc[@]}" -n unf-system scale deployment/"${receiver_name}" --replicas=1 >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/"${receiver_name}" \
    --timeout=120s >/dev/null
emit_flows
wait_for_metric_at_least "${controller}" unf_external_flow_export_delivered_batches_total \
    "$((baseline_delivered + 1))" >/dev/null

"${kc[@]}" -n unf-system patch deployment "${receiver_name}" --type=strategic -p '
spec:
  template:
    spec:
      containers:
        - name: receiver
          env:
            - name: UNF_FLOW_RECEIVER_FAIL_FIRST
              value: "0"
            - name: UNF_FLOW_RECEIVER_DELAY_MILLIS
              value: "3000"
' >/dev/null
"${kc[@]}" -n unf-system rollout status deployment/"${receiver_name}" \
    --timeout=120s >/dev/null

baseline_telemetry=$(metric "${controller}" unf_telemetry_observations_total)
baseline_history=$(controller_raw "${controller}" /v1/flows | jq '.retained_observations')
baseline_enqueued=$(metric "${controller}" unf_external_flow_export_enqueued_batches_total)
baseline_delivered=$(metric "${controller}" unf_external_flow_export_delivered_batches_total)
baseline_dropped=$(metric "${controller}" unf_external_flow_export_dropped_batches_total)
baseline_dropped_observations=$(metric "${controller}" \
    unf_external_flow_export_dropped_observations_total)
emit_pressure_flows
wait_for_metric_at_least "${controller}" unf_telemetry_observations_total \
    "$((baseline_telemetry + 1))" >/dev/null
wait_for_metric_at_least "${controller}" unf_external_flow_export_enqueued_batches_total \
    "$((baseline_enqueued + 2))" >/dev/null
wait_for_metric_at_least "${controller}" unf_external_flow_export_delivered_batches_total \
    "$((baseline_delivered + 1))" >/dev/null
wait_for_metric_at_least "${controller}" unf_external_flow_export_dropped_batches_total \
    "$((baseline_dropped + 1))" >/dev/null
wait_for_metric_at_least "${controller}" unf_external_flow_export_dropped_observations_total \
    "$((baseline_dropped_observations + 1))" >/dev/null
wait_for_metric_equals "${controller}" unf_external_flow_export_queue_capacity 1 >/dev/null
wait_for_metric_equals "${controller}" unf_external_flow_export_queue_high_watermark 1 >/dev/null
[[ $(metric "${controller}" unf_external_flow_export_queue_depth) -le 1 ]]
for _ in {1..30}; do
    current_history=$(controller_raw "${controller}" /v1/flows | jq '.retained_observations')
    if [[ ${current_history} -gt ${baseline_history} ]]; then
        break
    fi
    sleep 1
done
[[ ${current_history:-0} -gt ${baseline_history} ]]

receiver_stats=$(receiver_raw /stats)
jq -e '
  .attempts >= 2
  and .accepted == .attempts
  and .last_sequence > 0
  and .sequence_duplicates == 0
  and .sequence_regressions == 0
  and .max_body_bytes > 0
  and .max_body_bytes <= 2097152
' <<<"${receiver_stats}" >/dev/null
[[ $("${kc[@]}" -n unf-system get pod "${controller}" -o jsonpath='{.metadata.uid}') == "${controller_uid}" ]]
[[ $("${kc[@]}" -n unf-system get pod "${controller}" \
    -o jsonpath='{.status.containerStatuses[0].restartCount}') == "${controller_restarts}" ]]

echo "external flow-export qualification passed: schema-v1 provenance envelope, bearer authentication, retry sequencing, exact queue bounds and high-water telemetry, sustained slow-receiver loss accounting, receiver-outage history continuity, recovery, and zero controller restarts"
