#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Invoke the real function in a conditional, as its rollout callers do. Bash
# disables errexit throughout such functions; every failed check must return.
eval "$(sed -n '/^assert_version()/,/^}/p' "${UNF_VERSION_CHECK_SOURCE:-$root/hack/deploy-openshift-service-fabric.sh}")"
source_revision=0123456789012345678901234567890123456789
compatibility_schema=2 persistent_abi=15 identity_schema=2 policy_schema=4
service_schema=4 agent_status_schema=8 flow_export_schema=7 selection_schema=1
egress_distribution_schema=2 egress_host_schema=2 egress_ha_schema=1
egress_map_schema=4 egress_event_schema=1 encryption_model_schema=1
encryption_plan_schema=2 encryption_path_schema=2 encryption_operations_schema=1 encryption_map_abi=2
valid=$(jq -n --arg revision "$source_revision" '{
    schema_version:2,component:"unf-controller",build_revision:$revision,
    persistent_bpf_state_abi_version:15,identity_snapshot_schema_version:2,
    policy_snapshot_schema_version:4,service_snapshot_schema_version:4,
    agent_status_schema_version:8,flow_export_schema_version:7,selection_contract_schema_version:1,
    egress_distribution_schema_version:2,egress_host_state_schema_version:2,
    egress_ha_promotion_schema_version:1,egress_map_schema_version:4,egress_event_schema_version:1,
    encryption_model_schema_version:1,encryption_plan_schema_version:2,
    encryption_path_proof_schema_version:2,encryption_operations_schema_version:1,encryption_map_abi_version:2
}')
if ! assert_version "$valid" unf-controller; then
    echo 'valid deployment version rejected' >&2; exit 1
fi
for field in $(jq -r 'keys[]' <<<"$valid"); do
    for mutation in ".${field}=null" "del(.${field})" ".${field}=999"; do
        if assert_version "$(jq "$mutation" <<<"$valid")" unf-controller; then
            echo "deployment version accepted $mutation" >&2; exit 1
        fi
    done
done
for invalid in '' '{}' 'not-json' 'null'; do
    if assert_version "$invalid" unf-controller 2>/dev/null; then
        echo 'deployment version accepted missing/malformed evidence' >&2; exit 1
    fi
done
agent=$(jq '.component="unf-agent"' <<<"$valid")
if ! assert_version "$agent" unf-agent; then exit 1; fi
egress_distribution_schema=0 encryption_model_schema=0
if assert_version "$(jq '.build_revision="old"' <<<"$valid")" unf-controller; then exit 1; fi
if ! assert_version "$valid" unf-controller; then exit 1; fi
echo 'Deployment version gate rejects every mismatched contract in conditional callers'
