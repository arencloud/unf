#!/usr/bin/env bash
# Isolated PID-1 signal qualification; never signals a running fabric Pod.
set -Eeuo pipefail
umask 077
: "${KUBECONFIG:?explicit cluster configuration required}"
: "${UNF_SHUTDOWN_CONTROLLER_IMAGE:?immutable controller image required}"
: "${UNF_SHUTDOWN_AGENT_IMAGE:?immutable agent image required}"
: "${UNF_SHUTDOWN_REVISION:?embedded runtime revision required}"
: "${UNF_SHUTDOWN_DIAGNOSTICS:?new diagnostics directory required}"
[[ $UNF_SHUTDOWN_REVISION =~ ^[0-9a-f]{40}$ ]]
for image in "$UNF_SHUTDOWN_CONTROLLER_IMAGE" "$UNF_SHUTDOWN_AGENT_IMAGE"; do
    [[ $image =~ ^quay.io/arencloud/unf-(agent|controller)-dev@sha256:[0-9a-f]{64}$ ]]
done
directory=$UNF_SHUTDOWN_DIAGNOSTICS
[[ ! -e $directory ]]
install -d -m 0700 "$directory"
namespace=unf-service-shutdown-qualification
kc=(kubectl --request-timeout=15s)
"${kc[@]}" get nodes -o json > "$directory/nodes-before.json"
[[ -z $("${kc[@]}" get namespace "$namespace" --ignore-not-found -o name) ]]
namespace_uid=
forward_pid=
cleanup() {
    local result=$? current saved_pod
    trap - EXIT
    if [[ -n $forward_pid ]]; then
        kill "$forward_pid" 2>/dev/null || true
        wait "$forward_pid" || true
    fi
    if [[ -n $namespace_uid ]]; then
        "${kc[@]}" -n "$namespace" get pods -o json > "$directory/pods-final.json" || result=1
        current=$("${kc[@]}" get namespace "$namespace" -o jsonpath='{.metadata.uid}') || result=1
        if [[ $current == "$namespace_uid" ]]; then
            while read -r saved_pod; do
                [[ $saved_pod =~ ^(controller|agent)-(term|int)$ ]] || { result=1; continue; }
                "${kc[@]}" -n "$namespace" logs "$saved_pod" --timestamps \
                  > "$directory/$saved_pod-final.log" 2> "$directory/$saved_pod-final-observer.log" || result=1
            done < <(jq -r '.items[].metadata.name' "$directory/pods-final.json")
            "${kc[@]}" delete namespace "$namespace" --wait=true --timeout=120s > "$directory/cleanup.log" 2>&1 || result=1
        else
            echo 'Refusing cleanup of a replaced Namespace' >&2
            result=1
        fi
    fi
    if ((result==0)); then
        jq -n --arg revision "$UNF_SHUTDOWN_REVISION" '{schemaVersion:1,result:"passed",runtimeRevision:$revision,
          scope:"isolated offline controller and capability-only agent as PID 1",signals:["SIGTERM","SIGINT"],
          successfulExits:4,restarts:0,cleanup:"owned Namespace deleted",liveFabricShutdownQualified:false}' > "$directory/evidence.json"
    fi
    exit "$result"
}
trap cleanup EXIT
"${kc[@]}" create namespace "$namespace" -o json > "$directory/namespace.json"
namespace_uid=$(jq -er '.metadata.uid' "$directory/namespace.json")
"${kc[@]}" label namespace "$namespace" pod-security.kubernetes.io/enforce=restricted > "$directory/namespace-label.log"
# OpenShift allocates a namespace UID range; Kind has no range annotation.
"${kc[@]}" get namespace "$namespace" -o json > "$directory/namespace-admitted.json"
run_uid=$(jq -er '(.metadata.annotations["openshift.io/sa.scc.uid-range"] // "65532/1") | split("/")[0] | tonumber' "$directory/namespace-admitted.json")
[[ $run_uid =~ ^[1-9][0-9]*$ ]]
for component in controller agent; do
    image=$UNF_SHUTDOWN_CONTROLLER_IMAGE; port=9962; args='["--offline"]'
    if [[ $component == agent ]]; then image=$UNF_SHUTDOWN_AGENT_IMAGE; port=9963; args='[]'; fi
    for signal in TERM INT; do
        pod="$component-${signal,,}"
        jq -n --arg pod "$pod" --arg image "$image" --argjson args "$args" --argjson uid "$run_uid" '
          {apiVersion:"v1",kind:"Pod",metadata:{name:$pod},spec:{restartPolicy:"Never",
          terminationGracePeriodSeconds:10,automountServiceAccountToken:false,
          securityContext:{runAsNonRoot:true,runAsUser:$uid,seccompProfile:{type:"RuntimeDefault"}},
          containers:[{name:"probe",image:$image,args:$args,
            env:[{name:"RUST_LOG",value:"info"}],
            securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"]}},
            resources:{requests:{cpu:"25m",memory:"64Mi"},limits:{cpu:"1",memory:"512Mi"}}}]}}' \
          > "$directory/$pod-manifest.json"
        "${kc[@]}" -n "$namespace" create -f "$directory/$pod-manifest.json" > "$directory/$pod-create.log"
        "${kc[@]}" -n "$namespace" wait --for=condition=Ready "pod/$pod" --timeout=120s > "$directory/$pod-ready.log"
        "${kc[@]}" -n "$namespace" port-forward --address 127.0.0.1 "pod/$pod" ":$port" > "$directory/$pod-forward.log" 2>&1 &
        forward_pid=$!
        ready=false
        for attempt in $(seq 1 30); do
            endpoint=$(sed -n 's/^Forwarding from \(127\.0\.0\.1:[0-9]*\) ->.*/\1/p' "$directory/$pod-forward.log" | head -1)
            if [[ $endpoint =~ ^127\.0\.0\.1:[0-9]+$ ]] && curl -fsS --max-time 2 "http://$endpoint/v1/version" \
              > "$directory/$pod-version.json" 2> "$directory/$pod-version-observer.log"; then ready=true; break; fi
            sleep 1
        done
        [[ $ready == true ]]
        jq -e --arg component "unf-$component" --arg revision "$UNF_SHUTDOWN_REVISION" \
          '.component==$component and .build_revision==$revision' "$directory/$pod-version.json" >/dev/null
        kill "$forward_pid"
        wait "$forward_pid" || true
        forward_pid=
        "${kc[@]}" -n "$namespace" get pod "$pod" -o json > "$directory/$pod-before.json"
        jq -e '.status.containerStatuses|length==1 and all(.[];.restartCount==0 and .state.running!=null)' "$directory/$pod-before.json" >/dev/null
        "${kc[@]}" -n "$namespace" logs "$pod" -f --timestamps > "$directory/$pod.log" 2> "$directory/$pod-log-observer.log" &
        log_pid=$!
        # Exact new fixture process only; no kubectl delete or runtime stop hides exit status.
        "${kc[@]}" -n "$namespace" exec "$pod" -- sh -ec \
          'test "$(readlink /proc/1/exe)" = /usr/local/bin/unf-component; kill -"$1" 1' sh "$signal" \
          > "$directory/$pod-signal.log" 2>&1
        exited=false
        for attempt in $(seq 1 10); do
            "${kc[@]}" -n "$namespace" get pod "$pod" -o json > "$directory/$pod-after.json"
            if jq -e '.status.containerStatuses[0].state.terminated!=null' "$directory/$pod-after.json" >/dev/null; then exited=true; break; fi
            sleep 1
        done
        if [[ $exited != true ]]; then
            kill "$log_pid" 2>/dev/null || true
            wait "$log_pid" || true
            echo "$pod failed to terminate within ten observations" >&2
            exit 1
        fi
        wait "$log_pid"
        jq -e '.status.phase=="Succeeded" and (.status.containerStatuses|length==1 and all(.[];.restartCount==0 and .state.terminated.exitCode==0 and .state.terminated.reason=="Completed"))' \
          "$directory/$pod-after.json" >/dev/null
        rg -q "$component shutdown requested; draining service tasks" "$directory/$pod.log"
        rg -q "$component shutdown complete" "$directory/$pod.log"
        if rg -q '"level":"ERROR"' "$directory/$pod.log"; then exit 1; fi
    done
done
"${kc[@]}" get nodes -o json > "$directory/nodes-after.json"
