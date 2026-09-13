#!/usr/bin/env bash
# Remote probes emit only an explicit result. A failed exec never constitutes
# proof of network denial. Caller supplies kc, namespace and project_root.
phase9_http_probe_once() {
    local pod=$1 address=$2 port=$3 target result
    if [[ ${address} == *:* ]]; then target="http://[${address}]:${port}/health"; else target="http://${address}:${port}/health"; fi
    result=$(timeout 15 "${kc[@]}" -n "${namespace}" exec "${pod}" -- sh -euc \
        "$(<"${project_root}/hack/phase9-http-probe-remote.sh")" phase9-http-probe "${target}") || return 2
    case ${result} in
        http-ok) return 0 ;;
        network-denied) return 1 ;;
        *) echo "HTTP probe result unavailable or invalid" >&2; return 2 ;;
    esac
}

phase9_http_probe_denied() {
    local status=0
    phase9_http_probe_once "$@" || status=$?
    case ${status} in
        1) return 0 ;;
        0) return 1 ;;
        *) return 2 ;;
    esac
}
