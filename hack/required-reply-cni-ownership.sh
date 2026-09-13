#!/usr/bin/env bash
# Read-only runtime incarnation evidence for this qualifier's three owned Pods.
required_reply_cni_journal() {
    local agent=$1 output=$2
    timeout 30 "${kc[@]}" -n unf-system exec "$agent" -c agent -- sh -ec '
      test "$(stat -c %s /var/lib/unf/cni/v1/attachments.json)" -le 4194304
      test "$(stat -c %u /var/lib/unf/cni/v1/attachments.json)" -eq 0
      test "$(stat -c %a /var/lib/unf/cni/v1/attachments.json)" = 600
      cat /var/lib/unf/cni/v1/attachments.json' > "$output"
    jq -e '.schemaVersion>=2 and .schemaVersion<=4 and (.attachments|type)=="array"' "$output" >/dev/null
}

required_reply_cni_capture() {
    local pod node agent
    for pod in required-client native-client server; do
        node=$source_node; agent=$source_agent
        [[ $pod != server ]] || { node=$destination_node; agent=$reply_agent; }
        "${read_api[@]}" -n "$namespace" get pod "$pod" -o json > "$directory/cni-pod-$pod.json"
        required_reply_cni_journal "$agent" "$directory/cni-before-$pod.json"
        jq -L "$project_root/hack" -e --slurpfile pod "$directory/cni-pod-$pod.json" --arg node "$node" '
          include "required-reply-cni-ownership"; required_reply_cni_owner_valid($pod[0];$node)
        ' "$directory/cni-before-$pod.json" >/dev/null
    done
    jq -s 'map(.metadata.uid)|unique|select(length==3)' "$directory/"cni-pod-*.json > "$directory/cni-fixture-uids.json"
    [[ -s $directory/cni-fixture-uids.json ]]
}

required_reply_cni_retirement() {
    local attempt agent absent
    for attempt in $(seq 1 30); do
        absent=true
        for agent in "$source_agent" "$reply_agent"; do
            required_reply_cni_journal "$agent" "$directory/cni-retired-$attempt-$agent.json"
            if ! jq -e --slurpfile uids "$directory/cni-fixture-uids.json" '
              all(.attachments[]; .spec.workloadUid as $uid | $uids[0] | index($uid) == null)
            ' "$directory/cni-retired-$attempt-$agent.json" >/dev/null; then absent=false; fi
        done
        if [[ $absent == true ]]; then
            jq -n '{scope:"live-cni-runtime-incarnation",runtimeUIDsVerified:3,
              creationNoncesVerified:3,retiredUIDsVerified:3,localityAdmission:false}' > "$directory/cni-ownership.json"
            return 0
        fi
        sleep 2
    done
    echo 'CNI fixture ownership did not retire; preserve journals and report incomplete cleanup' >&2
    return 1
}
