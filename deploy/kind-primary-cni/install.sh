#!/bin/sh
set -eu
umask 077

binary_source=/opt/unf/cni/unf-cni
binary_target=/host/opt/cni/bin/unf
config_source=/opt/unf/install/10-unf.conflist
config_target=/host/etc/cni/net.d/10-unf.conflist
state_dir=/host/var/lib/unf/cni/v1
marker=${state_dir}/install.env

mkdir -p /host/opt/cni/bin /host/etc/cni/net.d "${state_dir}" /host/run/unf

foreign_configs=$(find /host/etc/cni/net.d -mindepth 1 -maxdepth 1 -type f ! -name 10-unf.conflist -print)
if [ -n "${foreign_configs}" ]; then
    echo "refusing primary-CNI installation beside foreign CNI configuration: ${foreign_configs}" >&2
    exit 1
fi
if [ -e "${binary_target}" ] && [ ! -f "${marker}" ]; then
    echo "refusing to replace unowned CNI binary ${binary_target}" >&2
    exit 1
fi
if [ -e "${config_target}" ] && [ ! -f "${marker}" ]; then
    echo "refusing to replace unowned CNI configuration ${config_target}" >&2
    exit 1
fi
if [ -e "${marker}" ]; then
    if [ -L "${marker}" ] || [ ! -f "${marker}" ] || [ "$(wc -l <"${marker}")" -ne 3 ]; then
        echo "refusing malformed or non-regular ownership marker ${marker}" >&2
        exit 1
    fi
    schema=$(sed -n 's/^schema=//p' "${marker}")
    owned_binary_sha256=$(sed -n 's/^binary_sha256=//p' "${marker}")
    owned_config_sha256=$(sed -n 's/^config_sha256=//p' "${marker}")
    if [ "${schema}" != 1 ] \
        || ! printf '%s\n' "${owned_binary_sha256}" | grep -Eq '^[0-9a-f]{64}$' \
        || ! printf '%s\n' "${owned_config_sha256}" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "refusing invalid ownership marker ${marker}" >&2
        exit 1
    fi
    if [ -L "${binary_target}" ] || [ ! -f "${binary_target}" ] \
        || [ "$(sha256sum "${binary_target}" | cut -d ' ' -f 1)" != "${owned_binary_sha256}" ]; then
        echo "refusing to replace drifted owned CNI binary ${binary_target}" >&2
        exit 1
    fi
    if [ -L "${config_target}" ] || [ ! -f "${config_target}" ] \
        || [ "$(sha256sum "${config_target}" | cut -d ' ' -f 1)" != "${owned_config_sha256}" ]; then
        echo "refusing to replace drifted owned CNI configuration ${config_target}" >&2
        exit 1
    fi
fi

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
    echo "binary_sha256=$(sha256sum "${binary_target}" | cut -d ' ' -f 1)"
    echo "config_sha256=$(sha256sum "${config_target}" | cut -d ' ' -f 1)"
} >"${marker_tmp}"
chmod 0600 "${marker_tmp}"
mv -f "${marker_tmp}" "${marker}"
trap - EXIT
