#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
agent_image=${UNF_OPENSHIFT_PRIMARY_AGENT_IMAGE:-quay.io/arencloud/unf-agent-dev@sha256:17efacea6d20d2bf26cef5f0b5adfbf03c99c05f694d793de931a0f036329c86}
fixture=$(mktemp -d /tmp/unf-primary-installer.XXXXXX)
anonymous_auth=${fixture}/anonymous-auth.json
socket_pid=
cleanup() {
    if [[ -n ${socket_pid} ]]; then
        kill "${socket_pid}" 2>/dev/null || true
    fi
    find "${fixture}" -depth -delete
}
trap cleanup EXIT

for command in podman skopeo socat; do
    command -v "${command}" >/dev/null || {
        echo "OpenShift primary-CNI installer test prerequisite is missing: ${command}" >&2
        exit 1
    }
done
printf '%s\n' '{"auths":{}}' >"${anonymous_auth}"
chmod 0600 "${anonymous_auth}"
skopeo inspect --authfile "${anonymous_auth}" "docker://${agent_image}" >/dev/null
podman pull --authfile "${anonymous_auth}" "${agent_image}" >/dev/null

mkdir -p \
    "${fixture}/host/var/lib/cni/bin" \
    "${fixture}/host/etc/kubernetes/cni/net.d" \
    "${fixture}/host/var/lib/unf/cni" \
    "${fixture}/host/run/unf" \
    "${fixture}/install"
install -m 0555 \
    "${project_root}/deploy/openshift-primary-cni/runtime/install.sh" \
    "${fixture}/install/install.sh"
install -m 0444 \
    "${project_root}/deploy/openshift-primary-cni/runtime/10-unf.conflist" \
    "${fixture}/install/10-unf.conflist"

socat "UNIX-LISTEN:${fixture}/host/run/unf/cni.sock,fork" EXEC:/bin/true &
socket_pid=$!
for _ in $(seq 1 50); do
    [[ -S ${fixture}/host/run/unf/cni.sock ]] && break
    sleep 0.1
done
[[ -S ${fixture}/host/run/unf/cni.sock ]]

run_installer() {
    podman run --rm --entrypoint /bin/sh -e UNF_INSTALL_ONESHOT=true \
        -v "${fixture}/host:/host:Z" \
        -v "${fixture}/install:/opt/unf/install:ro,Z" \
        "${agent_image}" /opt/unf/install/install.sh
}

run_installer
run_installer
marker=${fixture}/host/var/lib/unf/cni/v1/install.env
pending=${fixture}/host/var/lib/unf/cni/v1/pending-deletes
[[ $(stat -c '%a' "${marker}") == 600 ]]
[[ -d ${pending} && ! -L ${pending} && $(stat -c '%a' "${pending}") == 700 ]]
grep -q '^schema=1$' "${marker}"
grep -q '^platform=openshift$' "${marker}"

touch "${fixture}/host/etc/kubernetes/cni/net.d/20-foreign.conf"
set +e
foreign_output=$(run_installer 2>&1)
foreign_rc=$?
set -e
[[ ${foreign_rc} -ne 0 ]]
grep -q 'refusing primary-CNI installation beside foreign CNI configuration' \
    <<<"${foreign_output}"
unlink "${fixture}/host/etc/kubernetes/cni/net.d/20-foreign.conf"

printf x >>"${fixture}/host/var/lib/cni/bin/unf"
set +e
drift_output=$(run_installer 2>&1)
drift_rc=$?
set -e
[[ ${drift_rc} -ne 0 ]]
grep -q 'refusing to replace drifted owned CNI binary' <<<"${drift_output}"

echo "OpenShift primary-CNI installer transaction fixture passed"
