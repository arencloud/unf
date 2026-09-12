#!/usr/bin/env bash
# Caller supplies phase9_link_exec, project_root and source_node.
lowered_source_targets=()

phase9_link_targets() {
    local selector
    selector=$(<"${project_root}/hack/phase9-link-targets.jq")
    phase9_link_exec sh -euc '
        journal=$(jq -c "{
          nodeName:.active.fact.recipient.nodeName,nodeUid:.active.fact.recipient.nodeUid,
          clusterId:.active.plans[0].clusterId,
          activeEpoch:.active.fact.checkpoint.transaction.desired.activeEpoch,
          plans:[(.active.plans[]?,.pending.plans[]?) |
            {epoch,interfaceName,ownerAlias,clusterId,localNodeUid}],
          transports:[(.active.fact.checkpoint.transportAuthority[]?,
            .pending.fact.checkpoint.transportAuthority[]?) |
            {keyEpoch,state,interfaceName,interfaceIndex}]}
          " /var/lib/unf/cni/v1/encryption-generation.json.recovery-plan)
        links=$(ip -j -details link show type wireguard)
        jq -cen --arg node "$1" --argjson journal "$journal" --argjson links "$links" \
          "{journal:\$journal,links:\$links} | $2"
    ' phase9-link-targets "${source_node}" "${selector}"
}

phase9_change_owned_link() {
    local target=$1 mode=$2 guard
    guard=$(<"${project_root}/hack/phase9-link-guard.sh")
    phase9_link_exec sh -euc "${guard}" phase9-link-guard "${target}" "${mode}"
}

lower_owned_encryption_links() {
    local targets= target previous seen deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if targets=$(phase9_link_targets); then break; fi
        targets=
        sleep 1
    done
    [[ -n ${targets} ]] || return 1
    local -a current_targets=()
    mapfile -t current_targets < <(jq -c '.[]' <<<"${targets}")
    (( ${#current_targets[@]} > 0 && ${#current_targets[@]} <= 2 )) || return 1
    for target in "${current_targets[@]}"; do
        seen=false
        for previous in "${lowered_source_targets[@]}"; do
            [[ ${previous} != "${target}" ]] || seen=true
        done
        [[ ${seen} == true ]] || lowered_source_targets+=("${target}")
        # Register cleanup before mutation: a lost acknowledgement must not
        # strand a lowered interface outside the trap's owned target list.
        link_lowered=true
        phase9_change_owned_link "${target}" down || return 1
    done
}

restore_owned_encryption_links() {
    local target status=0
    for target in "${lowered_source_targets[@]}"; do
        phase9_change_owned_link "${target}" up || status=1
    done
    return "${status}"
}
