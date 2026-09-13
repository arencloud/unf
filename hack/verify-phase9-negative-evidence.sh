#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
project_root=${root}
source "${root}/hack/phase9-http-probe.sh"
kc=(mock_oc) namespace=fixture
mock_exec_status=0 mock_wget_status=0 mock_body=ok mock_version='GNU Wget 1.21.3'
export mock_wget_status mock_body mock_version
wget() {
    if [[ $1 == --version ]]; then printf '%s\n' "${mock_version}"; return 0; fi
    printf '%s\n' "${mock_body}"
    return "${mock_wget_status}"
}
export -f wget
timeout() {
    [[ $1 == 15 && $2 == mock_oc && $3 == -n && $4 == fixture && $5 == exec ]] || return 99
    (( mock_exec_status == 0 )) || return "${mock_exec_status}"
    shift 7
    [[ $1 == sh && $2 == -euc ]] || return 99
    shift
    bash "$@"
}
phase9_http_probe_once client 192.0.2.1 8080
phase9_http_probe_once client 2001:db8::1 8080
mock_wget_status=4
status=0
phase9_http_probe_once client 192.0.2.1 8080 || status=$?
[[ ${status} == 1 ]]
phase9_http_probe_denied client 192.0.2.1 8080
for failure in exec deadline http-error wrong-body non-gnu; do
    mock_exec_status=0 mock_wget_status=0 mock_body=ok mock_version='GNU Wget 1.21.3'
    case ${failure} in
        exec) mock_exec_status=1 ;;
        deadline) mock_exec_status=124 ;;
        http-error) mock_wget_status=8 ;;
        wrong-body) mock_body=broken ;;
        non-gnu) mock_version=BusyBox ;;
    esac
    status=0
    phase9_http_probe_denied client 192.0.2.1 8080 2>/dev/null || status=$?
    [[ ${status} == 2 ]] || { echo "accepted ${failure} as network evidence" >&2; exit 1; }
done

mock_links='[{"ifname":"lo"}]' mock_rules4='[]' mock_rules6='[]' mock_routes4='[]' mock_routes6='[]'
mock_ip_failure=none mock_ip_empty=none
export mock_links mock_rules4 mock_rules6 mock_routes4 mock_routes6 mock_ip_failure mock_ip_empty
ip() {
    local kind
    case $* in
        '-j -details link show') kind=links ;;
        '-j -4 rule show') kind=rules4 ;;
        '-j -6 rule show') kind=rules6 ;;
        '-j -4 route show table all') kind=routes4 ;;
        '-j -6 route show table all') kind=routes6 ;;
        *) return 99 ;;
    esac
    [[ ${mock_ip_failure} != "${kind}" ]] || return 1
    [[ ${mock_ip_empty} != "${kind}" ]] || return 0
    local variable=mock_${kind}
    printf '%s\n' "${!variable}"
}
export -f ip
snapshot() { bash "${root}/hack/phase9-cleanup-snapshot.sh" worker; }
snapshot | jq -e '.absent and .node == "worker" and .schemaVersion == 1' >/dev/null
for kind in links rules4 rules6 routes4 routes6; do
    if mock_ip_failure=${kind} snapshot >/dev/null 2>&1; then exit 1; fi
    if mock_ip_empty=${kind} snapshot >/dev/null 2>&1; then exit 1; fi
done
for links in '[]' null '{}'; do
    if mock_links=${links} snapshot >/dev/null 2>&1; then exit 1; fi
done
mock_links='[{"ifname":"unfwg00000000bg"}]' snapshot | jq -e '(.absent | not) and .links == 1' >/dev/null
mock_links='[{"ifname":"renamed","ifalias":"unf:encryption:v2:cluster:uid:412"}]' snapshot |
    jq -e '(.absent | not) and .links == 1' >/dev/null
mock_rules4='[{"table":20001}]' snapshot | jq -e '(.absent | not) and .rules4 == 1' >/dev/null
mock_rules6='[{"table":"20002"}]' snapshot | jq -e '(.absent | not) and .rules6 == 1' >/dev/null
mock_routes4='[{"table":20002}]' snapshot | jq -e '(.absent | not) and .routes4 == 1' >/dev/null
mock_routes6='[{"table":20001}]' snapshot | jq -e '(.absent | not) and .routes6 == 1' >/dev/null
mock_rules4='[{"table":"20450","protocol":"85"}]' snapshot | jq -e '(.absent | not) and .rules4 == 1' >/dev/null
mock_rules6='[{"action":"unreachable","protocol":"85"}]' snapshot | jq -e '(.absent | not) and .rules6 == 1' >/dev/null
mock_routes6='[{"table":"main","protocol":"85"}]' snapshot | jq -e '(.absent | not) and .routes6 == 1' >/dev/null
mock_rules4='[{"table":30000,"protocol":"86"}]' snapshot | jq -e '.absent' >/dev/null

mock_firewall_failure=none mock_firewall4=':KUBE-FIREWALL - [0:0]' mock_firewall6=''
export mock_firewall_failure mock_firewall4 mock_firewall6
iptables-save() { [[ ${mock_firewall_failure} != 4 ]] || return 2; printf '%s\n' "${mock_firewall4}"; }
ip6tables-save() { [[ ${mock_firewall_failure} != 6 ]] || return 2; printf '%s\n' "${mock_firewall6}"; }
export -f iptables-save ip6tables-save
firewall() { bash "${root}/hack/phase9-host-firewall-check.sh"; }
[[ $(firewall) == host-firewall-clean ]]
for family in 4 6; do
    if mock_firewall_failure=${family} firewall >/dev/null 2>&1; then exit 1; fi
done
if mock_firewall4=':KUBE-SVC-LEFTOVER - [0:0]' firewall >/dev/null 2>&1; then exit 1; fi
if mock_firewall6='-A KUBE-SERVICES -j KUBE-SVC-LEFTOVER' firewall >/dev/null 2>&1; then exit 1; fi

# Fail on drift of the runtime's reserved protocol/table coordinates.
[[ $(<"${root}/crates/unf-encryption/src/kernel_provider.rs") == *'pub const UNF_WIREGUARD_ROUTE_PROTOCOL: u8 = 0x55;'* ]]
[[ $(<"${root}/bins/unf-controller/src/main.rs") == *'let route_table = 20_000 + u32::try_from(epoch % 10_000)'* ]]
for platform in openshift kind; do
    gate=$(<"${root}/hack/verify-${platform}-encryption-phase9.sh")
    [[ ${gate} == *'phase9_http_probe_denied'* && ${gate} == *'cleanupKernelState:'* ]]
    [[ ${gate} == *'phase9-cleanup-snapshot.sh'* && ${gate} == *'phase9-host-firewall-check.sh'* ]]
    [[ ${gate} != *'lookup 2000[12]'* && ${gate} != *'! http_probe_once'* ]]
done
echo "Phase 9 denial and cleanup evidence reject observation failures and distinguish both IP families"
