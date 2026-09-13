#!/bin/sh
set -eu
umask 077

binary_source=/opt/unf/cni/unf-cni
binary_target=/host/var/lib/cni/bin/unf
config_source=/opt/unf/install/10-unf.conflist
config_target=/host/etc/kubernetes/cni/net.d/10-unf.conflist
state_dir=/host/var/lib/unf/cni/v1
marker=${state_dir}/install.env
socket=/host/run/unf/cni.sock

desired_binary_sha256=$(sha256sum "${binary_source}" | cut -d ' ' -f 1)
desired_config_sha256=$(sha256sum "${config_source}" | cut -d ' ' -f 1)

for directory in /host/var/lib/cni/bin /host/etc/kubernetes/cni/net.d; do
    if [ ! -d "${directory}" ] || [ -L "${directory}" ]; then
        echo "refusing missing or symbolic-link OpenShift CNI directory ${directory}" >&2
        exit 1
    fi
done
mkdir -p "${state_dir}" "${state_dir}/pending-deletes"

foreign_configs=$(find /host/etc/kubernetes/cni/net.d -mindepth 1 -maxdepth 1 \
    -type f ! -name 10-unf.conflist -print)
if [ -n "${foreign_configs}" ]; then
    echo "refusing primary-CNI installation beside foreign CNI configuration: ${foreign_configs}" >&2
    exit 1
fi
if [ -e "${marker}" ] || [ -L "${marker}" ]; then
    if [ -L "${marker}" ] || [ ! -f "${marker}" ] || [ "$(wc -l <"${marker}")" -ne 4 ]; then
        echo "refusing malformed or non-regular ownership marker ${marker}" >&2
        exit 1
    fi
    schema=$(sed -n 's/^schema=//p' "${marker}")
    platform=$(sed -n 's/^platform=//p' "${marker}")
    owned_binary_sha256=$(sed -n 's/^binary_sha256=//p' "${marker}")
    owned_config_sha256=$(sed -n 's/^config_sha256=//p' "${marker}")
    if [ "${schema}" != 1 ] || [ "${platform}" != openshift ] \
        || ! printf '%s\n' "${owned_binary_sha256}" | grep -Eq '^[0-9a-f]{64}$' \
        || ! printf '%s\n' "${owned_config_sha256}" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "refusing invalid ownership marker ${marker}" >&2
        exit 1
    fi
    if [ -L "${binary_target}" ] || [ ! -f "${binary_target}" ]; then
        echo "refusing to replace drifted owned CNI binary ${binary_target}" >&2
        exit 1
    fi
    actual_binary_sha256=$(sha256sum "${binary_target}" | cut -d ' ' -f 1)
    if [ "${actual_binary_sha256}" != "${owned_binary_sha256}" ] \
        && [ "${actual_binary_sha256}" != "${desired_binary_sha256}" ]; then
        echo "refusing to replace drifted owned CNI binary ${binary_target}" >&2
        exit 1
    fi
    if [ -L "${config_target}" ] || [ ! -f "${config_target}" ]; then
        echo "refusing to replace drifted owned CNI configuration ${config_target}" >&2
        exit 1
    fi
    actual_config_sha256=$(sha256sum "${config_target}" | cut -d ' ' -f 1)
    if [ "${actual_config_sha256}" != "${owned_config_sha256}" ] \
        && [ "${actual_config_sha256}" != "${desired_config_sha256}" ]; then
        echo "refusing to replace drifted owned CNI configuration ${config_target}" >&2
        exit 1
    fi
else
    if [ -e "${binary_target}" ] || [ -L "${binary_target}" ]; then
        if [ -L "${binary_target}" ] || [ ! -f "${binary_target}" ] \
            || [ "$(sha256sum "${binary_target}" | cut -d ' ' -f 1)" != "${desired_binary_sha256}" ]; then
            echo "refusing to replace unowned CNI binary ${binary_target}" >&2
            exit 1
        fi
    fi
    if [ -e "${config_target}" ] || [ -L "${config_target}" ]; then
        if [ -L "${config_target}" ] || [ ! -f "${config_target}" ] \
            || [ "$(sha256sum "${config_target}" | cut -d ' ' -f 1)" != "${desired_config_sha256}" ]; then
            echo "refusing to replace unowned CNI configuration ${config_target}" >&2
            exit 1
        fi
    fi
fi

# A socket pathname can outlive the old agent. Probe with the candidate CNI
# client before replacing any owned artifact; a cached readiness lease must
# never admit an incompatible or unavailable transaction server.
probe_wait=${UNF_INSTALL_AGENT_WAIT_SECONDS:-180}
case ${probe_wait} in
    [1-9]|[1-9][0-9]|1[0-7][0-9]|180) ;;
    *) echo 'CNI installer protocol wait must be between 1 and 180 seconds' >&2; exit 1 ;;
esac
probe_deadline=$(( $(date +%s) + probe_wait ))
probe_attempt=0
while :; do
    probe_attempt=$(( probe_attempt + 1 ))
    if [ -S "${socket}" ] && probe_result=$(timeout 5 env CNI_COMMAND=STATUS "${binary_source}" <<'JSON'
{"cniVersion":"1.1.0","name":"unf-primary-install-probe","type":"unf","agentSocket":"/host/run/unf/cni.sock","statusLeasePath":"/host/run/unf/cni-status.lease","statusGracePeriodSeconds":0,"ipam":{"type":"unf"}}
JSON
    ); then
        break
    fi
    if [ "$(date +%s)" -ge "${probe_deadline}" ] || [ "${probe_attempt}" -ge "${probe_wait}" ]; then
        echo 'refusing primary-CNI installation before a protocol-compatible local agent responds' >&2
        printf '%s\n' "${probe_result:-local agent socket is absent}" >&2
        exit 1
    fi
    sleep 1
done

binary_tmp=${binary_target}.tmp.$$
config_tmp=${config_target}.tmp.$$
marker_tmp=${marker}.tmp.$$
trap 'rm -f "${binary_tmp}" "${config_tmp}" "${marker_tmp}"' EXIT
install -m 0755 "${binary_source}" "${binary_tmp}"
install -m 0644 "${config_source}" "${config_tmp}"
mv -f "${binary_tmp}" "${binary_target}"
mv -f "${config_tmp}" "${config_target}"

{
    echo 'schema=1'
    echo 'platform=openshift'
    echo "binary_sha256=$(sha256sum "${binary_target}" | cut -d ' ' -f 1)"
    echo "config_sha256=$(sha256sum "${config_target}" | cut -d ' ' -f 1)"
} >"${marker_tmp}"
chmod 0600 "${marker_tmp}"
mv -f "${marker_tmp}" "${marker}"
trap - EXIT

[ "${UNF_INSTALL_ONESHOT:-false}" = true ] && exit 0
exec sleep infinity
