#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline_ref=${UNF_OPENSHIFT_UPGRADE_BASELINE_REF:-HEAD^}
auth_file=${QUAY_AUTH_FILE:-"${project_root}/.tools/quay-auth.json"}
record=${UNF_OPENSHIFT_UPGRADE_IMAGE_RECORD:-"${project_root}/.artifacts/phase3-openshift-upgrade-images.json"}
controller_repository=${UNF_CONTROLLER_DEV_REPOSITORY:-quay.io/arencloud/unf-controller-dev}
agent_repository=${UNF_AGENT_DEV_REPOSITORY:-quay.io/arencloud/unf-agent-dev}
test_tools_repository=${UNF_TEST_TOOLS_DEV_REPOSITORY:-quay.io/arencloud/unf-test-tools-dev}

for command in git jq make podman rg sha256sum tar; do
    command -v "${command}" >/dev/null
done
[[ -s ${auth_file} ]]
[[ -z $(git -C "${project_root}" status --porcelain) ]] || {
    echo "OpenShift upgrade images require a clean committed tree" >&2
    exit 2
}

baseline_commit=$(git -C "${project_root}" rev-parse --verify "${baseline_ref}^{commit}")
current_commit=$(git -C "${project_root}" rev-parse --verify HEAD^{commit})
[[ ${baseline_commit} != "${current_commit}" ]]
git -C "${project_root}" merge-base --is-ancestor "${baseline_commit}" "${current_commit}"
commit_distance=$(git -C "${project_root}" rev-list --count "${baseline_commit}..${current_commit}")
((commit_distance >= 1))
baseline_short=${baseline_commit:0:12}
current_short=${current_commit:0:12}
baseline_tag=phase3-n-${baseline_short}
current_tag=phase3-n1-${current_short}
temporary_root=$(mktemp -d)
cleanup() {
    rm -rf -- "${temporary_root}"
}
trap cleanup EXIT

git -C "${project_root}" archive --format=tar "${baseline_commit}" \
    | tar -xf - -C "${temporary_root}"
make -C "${temporary_root}" artifacts
make -C "${project_root}" artifacts

build_generation() {
    local source_root=$1 revision=$2 generation=$3
    local controller_local="localhost/unf-controller:${generation}"
    local agent_local="localhost/unf-agent:${generation}"
    local tools_local="localhost/unf-test-tools:${generation}"
    podman build --build-arg "UNF_BUILD_REVISION=${revision}" \
        --build-arg UNF_PACKAGE=unf-controller \
        --label "org.opencontainers.image.revision=${revision}" \
        --tag "${controller_local}" --file "${source_root}/images/Containerfile" "${source_root}"
    podman build --build-arg "UNF_BUILD_REVISION=${revision}" \
        --build-arg UNF_PACKAGE=unf-agent \
        --label "org.opencontainers.image.revision=${revision}" \
        --tag "${agent_local}" --file "${source_root}/images/Containerfile" "${source_root}"
    podman build --label "org.opencontainers.image.revision=${revision}" \
        --tag "${tools_local}" --file "${source_root}/images/SctpTestContainerfile" "${source_root}"
}

build_generation "${temporary_root}" "${baseline_commit}" "${baseline_tag}"
build_generation "${project_root}" "${current_commit}" "${current_tag}"

push_image() {
    local local_image=$1 remote_image=$2 digest_file=$3
    podman push --authfile "${auth_file}" --digestfile "${digest_file}" \
        "${local_image}" "docker://${remote_image}" >&2
    local digest
    digest=$(<"${digest_file}")
    [[ ${digest} =~ ^sha256:[0-9a-f]{64}$ ]]
    printf '%s@%s\n' "${remote_image%%:*}" "${digest}"
}

baseline_controller=$(push_image "localhost/unf-controller:${baseline_tag}" \
    "${controller_repository}:${baseline_tag}" "${temporary_root}/n-controller.digest")
baseline_agent=$(push_image "localhost/unf-agent:${baseline_tag}" \
    "${agent_repository}:${baseline_tag}" "${temporary_root}/n-agent.digest")
baseline_tools=$(push_image "localhost/unf-test-tools:${baseline_tag}" \
    "${test_tools_repository}:${baseline_tag}" "${temporary_root}/n-tools.digest")
current_controller=$(push_image "localhost/unf-controller:${current_tag}" \
    "${controller_repository}:${current_tag}" "${temporary_root}/n1-controller.digest")
current_agent=$(push_image "localhost/unf-agent:${current_tag}" \
    "${agent_repository}:${current_tag}" "${temporary_root}/n1-agent.digest")
current_tools=$(push_image "localhost/unf-test-tools:${current_tag}" \
    "${test_tools_repository}:${current_tag}" "${temporary_root}/n1-tools.digest")

install -d -m 0700 "$(dirname "${record}")"
jq -n \
    --arg created_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg baseline_commit "${baseline_commit}" --arg current_commit "${current_commit}" \
    --argjson commit_distance "${commit_distance}" \
    --arg baseline_controller "${baseline_controller}" \
    --arg baseline_agent "${baseline_agent}" --arg baseline_test_tools "${baseline_tools}" \
    --arg current_controller "${current_controller}" \
    --arg current_agent "${current_agent}" --arg current_test_tools "${current_tools}" '
    {
        schema_version: 1,
        created_at: $created_at,
        baseline: {
            revision: $baseline_commit,
            controller: $baseline_controller,
            agent: $baseline_agent,
            test_tools: $baseline_test_tools
        },
        current: {
            revision: $current_commit,
            controller: $current_controller,
            agent: $current_agent,
            test_tools: $current_test_tools
        },
        commit_distance: $commit_distance
    }
' >"${record}"
chmod 0600 "${record}"
jq -e '
    .schema_version == 1
    and .commit_distance >= 1
    and all(.baseline.controller, .baseline.agent, .baseline.test_tools,
            .current.controller, .current.agent, .current.test_tools;
        test("@sha256:[0-9a-f]{64}$"))
' "${record}" >/dev/null

echo "published immutable OpenShift upgrade images for N=${baseline_commit} and N+1=${current_commit}; record: ${record}"
