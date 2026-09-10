#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
adjacent_ref=${UNF_ENCRYPTION_ADJACENT_REF:-372cdec7be4318659502fd0c2fd28d8cab58e283}

require_text() {
    local expected=$1 relative_file=$2 description=$3
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9.7f check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

git -C "${project_root}" cat-file -e "${adjacent_ref}^{commit}" || {
    echo "Phase 9.7f check failed: adjacent baseline ${adjacent_ref} is unavailable" >&2
    exit 1
}
if git -C "${project_root}" show "${adjacent_ref}:crates/unf-state/src/lib.rs" |
    rg --quiet 'encryption_model_schema_version'; then
    echo 'Phase 9.7f check failed: fixed N baseline unexpectedly advertises the N+1 encryption tuple' >&2
    exit 1
fi

require_text 'pub encryption_model_schema_version: u16,' crates/unf-state/src/lib.rs \
    'N+1 must advertise its encryption model schema'
require_text 'pub encryption_map_abi_version: u16,' crates/unf-state/src/lib.rs \
    'N+1 must advertise its separately versioned encryption map ABI'
require_text 'if remote.iter().all(|version| *version == 0)' bins/unf-agent/src/main.rs \
    'the exact all-zero adjacent tuple must retain last-known-good state'
require_text 'if remote.contains(&0)' bins/unf-agent/src/main.rs \
    'partial encryption capability advertisement must fail closed'
require_text 'encryption compatibility tuple is partial' bins/unf-agent/src/main.rs \
    'operators need a stable partial-transition diagnosis'
require_text 'adjacent legacy checkpoint' bins/unf-controller/src/main.rs \
    'operations recovery must preserve the pre-wrapper checkpoint migration'
require_text 'Bidirectional Compatibility Sextant' \
    docs/adr/0205-bidirectional-compatibility-sextant.md \
    'the two-way transition boundary must have an accepted design record'

echo "Phase 9.7f adjacent compatibility passed: baseline ${adjacent_ref} and N+1 interoperate through an additive all-or-zero encryption tuple; partial or foreign authority fails before persistent BPF access"
