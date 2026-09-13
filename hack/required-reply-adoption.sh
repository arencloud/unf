#!/usr/bin/env bash
# Sourced by the scoped reply gate. No private key files are read.
required_reply_wait_policy() {
    local deadline=$((SECONDS+180)) attempt=0 valid client direction family protocol reverse from to verdict port request policy
    local attempt_dir
    while (( SECONDS < deadline )); do
        attempt=$((attempt+1)); attempt_dir=$directory/policy-$attempt
        install -d -m 0700 "$attempt_dir"
        controller_raw /v1/topology > "$attempt_dir/topology.json"
        valid=true
        if ! jq -e --arg ns "$namespace" --slurpfile fixture "$directory/fixture.json" '
          . as $t | [$fixture[0].items[]|select(.kind=="Pod")] as $pods
          | ($pods|length)==3 and all($pods[];. as $p|any($t.workloads[];
             .namespace==$ns and .name==$p.metadata.name and .node_name==$p.spec.nodeName and .identity_id>0
             and (.ipv4_addresses+.ipv6_addresses|sort)==([$p.status.podIPs[].ip]|sort)))
          and all($pods[];(.status.podIPs|length)==2)
          and any(.services[];.namespace==$ns and .name=="server" and (.cluster_ips|length)==2 and any(.backends[];.ready))
        ' "$attempt_dir/topology.json" >/dev/null; then sleep 2; continue; fi
        for client in required-client native-client; do
            for direction in ingress egress; do
                for family in ipv4 ipv6; do
                    for protocol in tcp udp; do
                        port=8080; [[ $protocol != udp ]] || port=5353
                        for reverse in false true; do
                            (( SECONDS < deadline )) || return 1
                            from=$client; to=server; verdict=Allow
                            [[ $reverse == false ]] || { from=server; to=$client; verdict=Deny; }
                            request=$(jq -cn --arg from "$namespace/$from" --arg to "$namespace/$to" --arg direction "$direction" \
                              --arg family "$family" --arg protocol "$protocol" --argjson port "$port" \
                              '{from:$from,to:$to,direction:$direction,ip_family:$family,protocol:$protocol,port:$port}')
                            curl --fail --silent --show-error --max-time 15 -H 'Content-Type: application/json' --data-binary "$request" \
                              "http://127.0.0.1:$controller_port/v1/explain" > "$attempt_dir/$client-$direction-$family-$protocol-$reverse.json"
                            if ! jq -L "$project_root/hack" -e --arg verdict "$verdict" --arg direction "${direction^}" --arg family "$family" \
                              'include "native-transport-adoption"; native_policy_observed($verdict;$direction;$family)' \
                              "$attempt_dir/$client-$direction-$family-$protocol-$reverse.json" >/dev/null; then valid=false; break 5; fi
                        done
                    done
                done
            done
        done
        if [[ $valid == true ]]; then
            policy=$(jq -se '[.[].policy_revision]|unique|select(length==1)|.[0]' "$attempt_dir"/*client-*.json) || valid=false
            controller_raw /v1/state/agents > "$attempt_dir/agents.json"
            if [[ $valid == true ]] && jq -L "$project_root/hack" -e --argjson policy "$policy" --slurpfile topology "$attempt_dir/topology.json" \
              'include "native-transport-adoption"; native_agent_cut_applied($policy;$topology[0])' "$attempt_dir/agents.json" >/dev/null; then
                required_identity=$(jq -er --arg ns "$namespace" '.workloads[]|select(.namespace==$ns and .name=="required-client")|.identity_id' "$attempt_dir/topology.json")
                server_identity=$(jq -er --arg ns "$namespace" '.workloads[]|select(.namespace==$ns and .name=="server")|.identity_id' "$attempt_dir/topology.json")
                echo "All 32 policy outcomes adopted at revision $policy"
                return 0
            fi
        fi
        sleep 2
    done
    return 1
}

required_reply_wait_generation() {
    local mode=$1 deadline=$((SECONDS+360)) attempt=0 attempt_dir pod node valid policy service egress generation
    local -a records
    while (( SECONDS < deadline )); do
        attempt=$((attempt+1)); attempt_dir=$directory/$mode-generation-$attempt
        install -d -m 0700 "$attempt_dir"
        controller_raw /v1/state/agents > "$attempt_dir/agents.json"
        if ! jq -e '.all_converged and .expected_agents>0 and .reporting_agents==.expected_agents
          and all(.nodes[];.fresh and .converged and .report.ready and .report.bpf_loaded)' "$attempt_dir/agents.json" >/dev/null; then sleep 2; continue; fi
        policy=$(jq -er '[.nodes[].report.applied_policy_revision]|unique|select(length==1)|.[0]' "$attempt_dir/agents.json")
        service=$(jq -er '[.nodes[].report.applied_service_revision]|unique|select(length==1)|.[0]' "$attempt_dir/agents.json")
        egress=$("${read_api[@]}" -n unf-system get configmap unf-egress-control-plane -o json | jq -er '.data["state.json"]|fromjson|.desiredRevision')
        # Public recovery plans only; gzip avoids requiring jq in the agent.
        records=()
        while IFS=$'\t' read -r pod node; do
            timeout 30 "${kc[@]}" -n unf-system exec "$pod" -c agent -- gzip -c /var/lib/unf/cni/v1/encryption-generation.json.recovery-plan |
              gzip -dc | jq -e --arg node "$node" '{node:$node,pending:(.pending!=null),
                generation:.active.fact.checkpoint.transaction.desired.published.generation,
                policyRevision:.active.fact.checkpoint.transaction.desired.published.policyRevision,
                serviceRevision:.active.fact.checkpoint.transaction.desired.published.serviceRevision,
                egressRevision:.active.fact.checkpoint.transaction.desired.published.egressRevision,
                epochs:[.active.plans[].epoch]}' > "$attempt_dir/$node.json"
            records+=("$attempt_dir/$node.json")
        done < <(jq -r '.items[]|select(.metadata.labels["app.kubernetes.io/name"]=="unf-agent")|[.metadata.name,.spec.nodeName]|@tsv' "$directory/unf-before.json")
        valid=false
        if jq -L "$project_root/hack" -se --arg mode "$mode" --arg source "$source_node" --arg destination "$destination_node" \
          --argjson policy "$policy" --argjson service "$service" --argjson egress "$egress" \
          --slurpfile agents "$attempt_dir/agents.json" '
          include "required-reply-adoption";
          reply_generation_cut_valid($mode;$source;$destination;$agents[0].expected_agents;$policy;$service;$egress)
        ' "${records[@]}" > "$attempt_dir/check.json" 2> "$attempt_dir/check.log"; then valid=true; fi
        if [[ $valid == true && $mode == required ]]; then
            generation=$(jq -er .generation "${records[0]}")
            timeout 30 "${kc[@]}" -n unf-system exec "$reply_agent" -c agent -- gzip -c /var/lib/unf/cni/v1/encryption-plan.json |
              gzip -dc > "$attempt_dir/reply-public-plan.json"
            jq -L "$project_root/hack" -e --argjson source "$required_identity" --argjson destination "$server_identity" \
              --arg source_node "$source_node" --arg destination_node "$destination_node" \
              --argjson policy "$policy" --argjson generation "$generation" '
              include "required-reply-adoption";
              reply_provenance_valid($source;$destination;$source_node;$destination_node;$policy;$generation)' \
              "$attempt_dir/reply-public-plan.json" >/dev/null || valid=false
        fi
        if [[ $valid == true ]]; then echo "$mode transport generation converged: $attempt_dir"; return 0; fi
        sleep 2
    done
    return 1
}
