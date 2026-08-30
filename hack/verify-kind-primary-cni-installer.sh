#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
agent_image=${UNF_KIND_PRIMARY_AGENT_IMAGE:-quay.io/arencloud/unf-agent-dev@sha256:34a85f5af5cb5cc465b1d1dbea67d8c9c9809218a4bce719c411f46fb4c1b48b}
fixture=$(mktemp -d /tmp/unf-kind-installer.XXXXXX)
anonymous_auth=${fixture}/anonymous-auth.json
cleanup() {
    find "${fixture}" -depth -delete
}
trap cleanup EXIT

for command in podman skopeo; do
    command -v "${command}" >/dev/null || {
        echo "Kind primary-CNI installer test prerequisite is missing: ${command}" >&2
        exit 1
    }
done
bash -n "${project_root}/hack/configure-kind-primary-cni.sh"
bash -n "${project_root}/hack/rollback-kind-primary-cni.sh"
grep -q 'nodeport-sysctls' "${project_root}/hack/configure-kind-primary-cni.sh"
grep -q 'nodeport-sysctls' "${project_root}/hack/rollback-kind-primary-cni.sh"
for setting in rp_filter accept_local; do
    grep -q "/proc/sys/net/ipv4/conf/\*/${setting}" \
        "${project_root}/hack/configure-kind-primary-cni.sh"
done
grep -q 'conf/${key}' "${project_root}/hack/rollback-kind-primary-cni.sh"
printf '%s\n' '{"auths":{}}' >"${anonymous_auth}"
chmod 0600 "${anonymous_auth}"
skopeo inspect --authfile "${anonymous_auth}" "docker://${agent_image}" >/dev/null
podman pull --authfile "${anonymous_auth}" "${agent_image}" >/dev/null

mkdir -p \
    "${fixture}/host/opt/cni/bin" \
    "${fixture}/host/etc/cni/net.d" \
    "${fixture}/host/var/lib/unf/cni" \
    "${fixture}/host/run/unf" \
    "${fixture}/install"
install -m 0555 \
    "${project_root}/deploy/kind-primary-cni/install.sh" \
    "${fixture}/install/install.sh"
install -m 0444 \
    "${project_root}/deploy/kind-primary-cni/10-unf.conflist" \
    "${fixture}/install/10-unf.conflist"

run_installer() {
    podman run --rm --entrypoint /bin/sh \
        -v "${fixture}/host:/host:Z" \
        -v "${fixture}/install:/opt/unf/install:ro,Z" \
        "${agent_image}" /opt/unf/install/install.sh
}

run_installer
run_installer
marker=${fixture}/host/var/lib/unf/cni/v1/install.env
[[ $(stat -c '%a' "${marker}") == 600 ]]
grep -q '^schema=1$' "${marker}"

# Recover the exact interruption observed in a rolling Kind redeployment:
# desired artifacts were moved, but the atomic ownership marker was not.
unlink "${marker}"
run_installer
[[ $(wc -l <"${marker}") -eq 3 ]]

# Also finish an upgrade interrupted after only the desired binary moved.
desired_binary_sha256=$(sha256sum "${fixture}/host/opt/cni/bin/unf" | cut -d ' ' -f 1)
desired_config_sha256=$(sha256sum "${fixture}/host/etc/cni/net.d/10-unf.conflist" | cut -d ' ' -f 1)
{
    echo 'schema=1'
    printf '%064d\n' 0 | sed 's/^/binary_sha256=/'
    echo "config_sha256=${desired_config_sha256}"
} >"${marker}"
chmod 0600 "${marker}"
run_installer
grep -q "^binary_sha256=${desired_binary_sha256}$" "${marker}"

touch "${fixture}/host/etc/cni/net.d/20-foreign.conf"
set +e
foreign_output=$(run_installer 2>&1)
foreign_rc=$?
set -e
[[ ${foreign_rc} -ne 0 ]]
grep -q 'refusing primary-CNI installation beside foreign CNI configuration' \
    <<<"${foreign_output}"
unlink "${fixture}/host/etc/cni/net.d/20-foreign.conf"

printf x >>"${fixture}/host/opt/cni/bin/unf"
set +e
drift_output=$(run_installer 2>&1)
drift_rc=$?
set -e
[[ ${drift_rc} -ne 0 ]]
grep -q 'refusing to replace drifted owned CNI binary' <<<"${drift_output}"

unlink "${marker}"
set +e
unowned_output=$(run_installer 2>&1)
unowned_rc=$?
set -e
[[ ${unowned_rc} -ne 0 ]]
grep -q 'refusing to replace unowned CNI binary' <<<"${unowned_output}"

echo "Kind primary-CNI installer interruption fixture passed"
