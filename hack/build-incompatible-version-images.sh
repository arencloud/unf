#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
controller_image=${UNF_INCOMPATIBLE_CONTROLLER_IMAGE:-localhost/unf-controller:incompatible-tuple}
agent_image=${UNF_INCOMPATIBLE_AGENT_IMAGE:-localhost/unf-agent:incompatible-tuple}

for command in git podman sed tar; do
    command -v "${command}" >/dev/null
done

if ! git -C "${project_root}" diff --quiet --ignore-submodules HEAD -- \
    || ! git -C "${project_root}" diff --cached --quiet --ignore-submodules HEAD --; then
    echo "incompatible-version images require a clean committed worktree" >&2
    exit 2
fi
[[ -s ${project_root}/.artifacts/unf-ebpf-tc ]]

revision=$(git -C "${project_root}" rev-parse --verify HEAD^{commit})
temporary_root=$(mktemp -d)
cleanup() {
    rm -rf -- "${temporary_root}"
}
trap cleanup EXIT

git -C "${project_root}" archive --format=tar "${revision}" \
    | tar -xf - -C "${temporary_root}"
mkdir -p "${temporary_root}/.artifacts"
cp "${project_root}/.artifacts/unf-ebpf-tc" "${temporary_root}/.artifacts/unf-ebpf-tc"

state_source=${temporary_root}/crates/unf-state/src/lib.rs
current_policy_schema=$(sed -nE \
    's/^pub const POLICY_SNAPSHOT_SCHEMA_VERSION: u16 = ([0-9]+);$/\1/p' \
    "${state_source}")
current_persistent_abi=$(sed -nE \
    's/^pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = ([0-9]+);$/\1/p' \
    "${state_source}")
[[ ${current_policy_schema} =~ ^[0-9]+$ ]]
[[ ${current_persistent_abi} =~ ^[0-9]+$ ]]
incompatible_policy_schema=$((current_policy_schema + 1))
incompatible_persistent_abi=$((current_persistent_abi + 1))

sed -i \
    "s/^pub const POLICY_SNAPSHOT_SCHEMA_VERSION: u16 = ${current_policy_schema};$/pub const POLICY_SNAPSHOT_SCHEMA_VERSION: u16 = ${incompatible_policy_schema};/" \
    "${state_source}"
sed -i \
    "s/^pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = ${current_persistent_abi};$/pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = ${incompatible_persistent_abi};/" \
    "${state_source}"
grep -Fxq \
    "pub const POLICY_SNAPSHOT_SCHEMA_VERSION: u16 = ${incompatible_policy_schema};" \
    "${state_source}"
grep -Fxq \
    "pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = ${incompatible_persistent_abi};" \
    "${state_source}"

build_revision=${revision}-incompatible-policy-${incompatible_policy_schema}-abi-${incompatible_persistent_abi}
for package in unf-controller unf-agent; do
    if [[ ${package} == unf-controller ]]; then
        image=${controller_image}
    else
        image=${agent_image}
    fi
    podman build \
        --build-arg "UNF_BUILD_REVISION=${build_revision}" \
        --build-arg "UNF_PACKAGE=${package}" \
        --label "org.opencontainers.image.revision=${revision}" \
        --label "io.unf.test.policy-snapshot-schema=${incompatible_policy_schema}" \
        --label "io.unf.test.persistent-bpf-state-abi=${incompatible_persistent_abi}" \
        --tag "${image}" \
        --file "${temporary_root}/images/Containerfile" \
        "${temporary_root}"
done

echo "built deliberately incompatible images from ${revision}: policy schema ${current_policy_schema}->${incompatible_policy_schema}, persistent ABI ${current_persistent_abi}->${incompatible_persistent_abi}; ${controller_image}, ${agent_image}"
