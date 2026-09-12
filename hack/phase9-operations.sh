#!/usr/bin/env bash
# Shared by the platform gates. controller_raw and project_root are supplied
# by the caller. Captures contain public diagnostic history, never authority.

phase9_operations_capture() {
    local label=$1 directory=$2
    mkdir -p "${directory}" || return
    controller_raw /v1/encryption/history >"${directory}/${label}-received.json" || return
    cargo run --quiet --locked --offline --manifest-path "${project_root}/Cargo.toml" \
        -p unfctl -- --controller-url http://127.0.0.1:1 --output json \
        encryption-history --file "${directory}/${label}-received.json" \
        >"${directory}/${label}-verified.json" || return
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
        --arg beforeSha256 "$(sha256sum "${before}" | awk '{print $1}')" \
        --arg afterSha256 "$(sha256sum "${after}" | awk '{print $1}')" '
        $before[0] as $before | $after[0] as $after |
        {independentCheckpointReplay:true,retentionBound:512,
         beforeCheckpointSha256:$beforeSha256,afterCheckpointSha256:$afterSha256,
         verifiedFromRevision:$before.revision,verifiedThroughRevision:$after.revision,
         evictedRecords:$after.evictedRecords,evictedObservations:$after.evictedObservations,
         retentionEvictedObservationsDelta:($after.evictedObservations-$before.evictedObservations),
         reportedLostObservations:$after.reportedLostObservations,
         lossAffected:($after.evictedObservations > 0 or $after.reportedLostObservations > 0),
         completenessClaim:"retained-window-only"}
    '
}
