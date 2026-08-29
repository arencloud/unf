#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
controller_image=${UNF_CLEAN_REBUILD_CONTROLLER_IMAGE:-localhost/unf-controller:clean-rebuild-abi5}
agent_image=${UNF_CLEAN_REBUILD_AGENT_IMAGE:-localhost/unf-agent:clean-rebuild-abi5}

for command in git podman sed tar; do
    command -v "${command}" >/dev/null
done

if ! git -C "${project_root}" diff --quiet --ignore-submodules HEAD -- \
    || ! git -C "${project_root}" diff --cached --quiet --ignore-submodules HEAD --; then
    echo "clean-rebuild images require a clean committed worktree" >&2
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
current_abi=$(sed -nE \
    's/^pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = ([0-9]+);$/\1/p' \
    "${state_source}")
[[ ${current_abi} =~ ^[0-9]+$ ]]
clean_rebuild_abi=$((current_abi + 1))

sed -i \
    "s/^pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = ${current_abi};$/pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = ${clean_rebuild_abi};/" \
    "${state_source}"
grep -Fxq \
    "pub const PERSISTENT_BPF_STATE_ABI_VERSION: u16 = ${clean_rebuild_abi};" \
    "${state_source}"

build_revision=${revision}-clean-rebuild-abi-${clean_rebuild_abi}
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
        --label "io.unf.test.clean-rebuild-from-abi=${current_abi}" \
        --label "io.unf.test.clean-rebuild-to-abi=${clean_rebuild_abi}" \
        --tag "${image}" \
        --file "${temporary_root}/images/Containerfile" \
        "${temporary_root}"
done

echo "built clean-rebuild boundary images from ${revision}: persistent ABI ${current_abi}->${clean_rebuild_abi}; ${controller_image}, ${agent_image}"
