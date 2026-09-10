#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
agent_file="${project_root}/bins/unf-agent/src/main.rs"

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.7g check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

identity_line=$(rg -n 'preflight_encryption_node_identity\(' "${agent_file}" | head -1 | cut -d: -f1)
bpf_line=$(rg -n 'load_persistent_ebpf\(&config\)' "${agent_file}" | head -1 | cut -d: -f1)
[[ -n ${identity_line} && -n ${bpf_line} && ${identity_line} -lt ${bpf_line} ]] || {
    echo 'Phase 9.7g check failed: Node replacement fence must precede persistent BPF access' >&2
    exit 1
}

require_text 'retaining offline-start recovery' bins/unf-agent/src/main.rs \
    'controller outage must preserve independently recoverable last-known-good state'
require_text 'durable encryption plan belongs to replaced Node UID' bins/unf-agent/src/main.rs \
    'reachable authority must fence stale plan ownership before BPF access'
require_text 'durable encryption generation belongs to replaced Node UID' bins/unf-agent/src/main.rs \
    'reachable authority must fence stale generation/recovery ownership before BPF access'
require_text 'fn plan_encryption_abi_cleanup' bins/unf-agent/src/main.rs \
    'current cleanup must independently plan the encryption ABI island'
require_text 'unrecognized encryption ABI state; refusing cleanup' bins/unf-agent/src/main.rs \
    'foreign pin ownership must reject before deletion'
require_text 'execute_encryption_abi_cleanup(plan)?;' bins/unf-agent/src/main.rs \
    'encryption packet authority must be removed before the shared map island'
require_text 'Survivable Authority Envelope' \
    docs/adr/0206-survivable-authority-envelope.md \
    'outage, replacement, and cleanup behavior must have an accepted design record'

echo 'Phase 9.7g recovery and cleanup passed: outages retain proven state, reachable Node-UID replacement fences stale authority before BPF access, and cleanup removes only the exact encryption ABI island while preserving foreign and adjacent state'
