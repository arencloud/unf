#!/usr/bin/env bash
# Shared by the platform gates. controller_raw and project_root are supplied
# by the caller. Captures contain public diagnostic history, never authority.

phase9_operations_capture() {
    local label=$1 directory=$2 attempt status=1 attempts='[]' received
    mkdir -p "${directory}" || return
    for attempt in 1 2 3; do
        received="${directory}/${label}-attempt-${attempt}-received.json"
        if controller_raw /v1/encryption/history >"${received}"; then status=0; else status=$?; fi
        attempts=$(jq -cn --argjson attempts "${attempts}" --argjson attempt "${attempt}" \
            --argjson status "${status}" --argjson bytes "$(wc -c <"${received}")" \
            '$attempts + [{attempt:$attempt,transferExitCode:$status,receivedBytes:$bytes}]') || return
        [[ ${status} != 0 ]] || break
        echo "encryption history read ${label} attempt ${attempt} unavailable (exit ${status}); raw attempt retained" >&2
        [[ ${attempt} == 3 ]] || sleep 1
    done
    jq -n --argjson attempts "${attempts}" \
        '{schemaVersion:1,attempts:$attempts,verificationExitCode:null}' \
        >"${directory}/${label}-read.json" || return
    [[ ${status} == 0 ]] || return "${status}"
    cp "${received}" "${directory}/${label}-received.json" || return
    # A successful transfer with invalid content is a verification failure,
    # never grounds to retry until a different checkpoint happens to pass.
    if cargo run --quiet --locked --offline --manifest-path "${project_root}/Cargo.toml" \
        -p unfctl -- --controller-url http://127.0.0.1:1 --output json \
        encryption-history --file "${directory}/${label}-received.json" \
        >"${directory}/${label}-verified.json"; then status=0; else status=$?; fi
    jq -n --argjson attempts "${attempts}" --argjson status "${status}" \
        '{schemaVersion:1,attempts:$attempts,verificationExitCode:$status}' \
        >"${directory}/${label}-read.json" || return
    [[ ${status} == 0 ]] || return "${status}"
    printf '%s\n' "${directory}/${label}-verified.json"
}

phase9_operations_continuity() {
    local before=$1 after=$2
    jq -L "${project_root}/hack" -n -e --slurpfile before "${before}" --slurpfile after "${after}" '
        include "phase9-qualification";
        {before:$before[0],after:$after[0]} | phase9_operations_continuity_valid
    ' >/dev/null
}

phase9_operations_evidence() {
    local before=$1 after=$2
    jq -n --slurpfile before "${before}" --slurpfile after "${after}" \
        --slurpfile beforeRead "${before%-verified.json}-read.json" \
        --slurpfile afterRead "${after%-verified.json}-read.json" \
        --arg beforeSha256 "$(sha256sum "${before}" | awk '{print $1}')" \
        --arg afterSha256 "$(sha256sum "${after}" | awk '{print $1}')" '
        $before[0] as $before | $after[0] as $after |
        {independentCheckpointReplay:true,retentionBound:512,
         reads:{before:$beforeRead[0],after:$afterRead[0]},
         beforeCheckpointSha256:$beforeSha256,afterCheckpointSha256:$afterSha256,
         verifiedFromRevision:$before.revision,verifiedThroughRevision:$after.revision,
         evictedRecords:$after.evictedRecords,evictedObservations:$after.evictedObservations,
         retentionEvictedObservationsDelta:($after.evictedObservations-$before.evictedObservations),
         reportedLostObservations:$after.reportedLostObservations,
         lossAffected:($after.evictedObservations > 0 or $after.reportedLostObservations > 0),
         completenessClaim:"retained-window-only"}
    '
}
