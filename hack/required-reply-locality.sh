#!/usr/bin/env bash
# Sourced by the reply gate. Read-only candidate observation, not packet proof.
required_reply_locality_wait() {
    local mode=$1 deadline=$((SECONDS+120)) attempt=0 attempt_dir node pod uid minimum valid
    local -a records
    while (( SECONDS < deadline )); do
        attempt=$((attempt+1))
        attempt_dir=$directory/locality-$mode-$attempt
        install -d -m 0700 "$attempt_dir"
        controller_raw /v1/state/agents > "$attempt_dir/agents.json"
        records=(); valid=true
        for node in "$source_node" "$destination_node"; do
            pod=$(jq -er --arg node "$node" '.items[]|select(.spec.nodeName==$node and .metadata.labels["app.kubernetes.io/name"]=="unf-agent")|.metadata.name' "$directory/unf-before.json")
            "${read_api[@]}" get --raw "/api/v1/namespaces/unf-system/pods/$pod:9963/proxy/v1/encryption/locality" > "$attempt_dir/$node-status.json"
            if [[ $mode == required ]]; then
                uid=$("${read_api[@]}" get node "$node" -o jsonpath='{.metadata.uid}')
                "${read_api[@]}" -n unf-system exec "$pod" -c agent -- gzip -c /var/lib/unf/cni/v1/encryption-plan.json |
                    gzip -dc > "$attempt_dir/$node-plan.json"
                minimum=2; [[ $node != "$source_node" ]] || minimum=4
                if ! jq -L "$project_root/hack" -e --arg node "$node" --arg uid "$uid" --arg cluster "$locality_cluster_uid" \
                    --argjson minimum "$minimum" --slurpfile plan "$attempt_dir/$node-plan.json" --slurpfile agents "$attempt_dir/agents.json" '
                    include "required-reply-locality";
                    ($agents[0].nodes|map(select(.node_name==$node))|select(length==1)|.[0]) as $agent
                    | $agent.fresh and $agent.converged and locality_candidate_valid($node;$uid;$cluster;$agent.report;$plan[0];$minimum)
                ' "$attempt_dir/$node-status.json" > "$attempt_dir/$node-check.json"; then valid=false; fi
            else
                if ! jq -L "$project_root/hack" -e 'include "required-reply-locality"; locality_absent_valid' \
                    "$attempt_dir/$node-status.json" > "$attempt_dir/$node-check.json"; then valid=false; fi
            fi
            records+=("$attempt_dir/$node-status.json")
        done
        if [[ $valid == true ]]; then
            jq -s '.' "${records[@]}" > "$directory/locality-$mode.json"
            return 0
        fi
        sleep 2
    done
    return 1
}
