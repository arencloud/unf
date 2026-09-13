#!/usr/bin/env bash
# Caller supplies kc, namespace and capture_pod. Call only after the last
# outage probe and exact owned-link restoration, never as failure cleanup.
phase9_capture_finish() {
    local stopped_at snapshot logs dropped exit_code deadline=$((SECONDS + 60))
    stopped_at=$(date +%s)
    # PID 1 is GNU timeout, which forwards INT to tcpdump for a clean flush.
    # An already expired/crashed capture cannot accept this exec: fail closed.
    timeout 20 "${kc[@]}" -n "${namespace}" exec "${capture_pod}" -c tcpdump \
        -- /bin/sh -ec 'kill -INT 1' || return
    while (( SECONDS < deadline )); do
        snapshot=$(timeout 20 "${kc[@]}" -n "${namespace}" get pod "${capture_pod}" -o json) || return
        exit_code=$(jq -er '[.status.containerStatuses[] | select(.name=="tcpdump")
            | .state.terminated.exitCode] | .[0] | select(. != null)' <<<"${snapshot}" 2>/dev/null) || exit_code=
        [[ -z ${exit_code} ]] || break
        sleep 1
    done
    [[ ${exit_code:-} == 0 ]] || {
        echo "capture did not flush successfully after explicit stop (exit ${exit_code:-unavailable})" >&2
        return 1
    }
    logs=$(timeout 20 "${kc[@]}" -n "${namespace}" logs "${capture_pod}" -c tcpdump) || return
    dropped=$(jq -en --arg logs "${logs}" '
        [$logs | split("\n")[] | capture("^(?<count>[0-9]+) packets dropped by kernel$").count | tonumber]
        | select(length == 1 and .[0] == 0) | .[0]') || {
        echo "capture loss is nonzero or unavailable; refusing plaintext-absence evidence" >&2
        return 1
    }
    jq -cn --argjson snapshot "${snapshot}" --argjson stoppedAt "${stopped_at}" --argjson dropped "${dropped}" '
        [$snapshot.status.containerStatuses[] | select(.name=="tcpdump")][0].state.terminated as $state |
        {explicitStopAfterFault:true,watchdogSeconds:300,stopRequestedUnixSeconds:$stoppedAt,
         startedAt:$state.startedAt,finishedAt:$state.finishedAt,exitCode:$state.exitCode,
         packetsDroppedByKernel:$dropped}'
}
