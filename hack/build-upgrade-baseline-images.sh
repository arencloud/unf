#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline_ref=${UNF_UPGRADE_BASELINE_REF:-HEAD^}
controller_image=${UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE:-localhost/unf-controller:upgrade-n}
agent_image=${UNF_UPGRADE_BASELINE_AGENT_IMAGE:-localhost/unf-agent:upgrade-n}

for command in git make podman rg tar; do
    command -v "${command}" >/dev/null
done

baseline_commit=$(git -C "${project_root}" rev-parse --verify "${baseline_ref}^{commit}")
current_commit=$(git -C "${project_root}" rev-parse --verify HEAD^{commit})
[[ ${baseline_commit} != "${current_commit}" ]]
git -C "${project_root}" merge-base --is-ancestor "${baseline_commit}" "${current_commit}"

temporary_root=$(mktemp -d)
cleanup() {
    rm -rf -- "${temporary_root}"
}
trap cleanup EXIT

git -C "${project_root}" archive --format=tar "${baseline_commit}" \
    | tar -xf - -C "${temporary_root}"
make -C "${temporary_root}" artifacts
revision_build_arg=()
if rg -q '^ARG UNF_BUILD_REVISION' "${temporary_root}/images/Containerfile"; then
    revision_build_arg=(--build-arg "UNF_BUILD_REVISION=${baseline_commit}")
fi
podman build \
    "${revision_build_arg[@]}" \
    --build-arg UNF_PACKAGE=unf-controller \
    --label "org.opencontainers.image.revision=${baseline_commit}" \
    --tag "${controller_image}" \
    --file "${temporary_root}/images/Containerfile" \
    "${temporary_root}"
podman build \
    "${revision_build_arg[@]}" \
    --build-arg UNF_PACKAGE=unf-agent \
    --label "org.opencontainers.image.revision=${baseline_commit}" \
    --tag "${agent_image}" \
    --file "${temporary_root}/images/Containerfile" \
    "${temporary_root}"

echo "built upgrade baseline images from ${baseline_commit}: ${controller_image}, ${agent_image}"
