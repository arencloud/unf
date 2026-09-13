#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Extract only the real read function; never execute platform setup or faults.
source <(sed -n '/^controller_raw()/,/^}/p' "${root}/hack/verify-openshift-encryption-phase9.sh")
kc=(mock_oc)
host_probe_namespace=test-witness
host_probe_created=true
controller_status=0 probe_status=0 transfer_status=0 calls=0
controller_pod_and_node() {
    (( controller_status == 0 )) || return "${controller_status}"
    printf 'controller\tnode\n'
}
host_probe_pod_on_node() {
    [[ $1 == node ]] || return 99
    (( probe_status == 0 )) || return "${probe_status}"
    printf 'witness\n'
}
timeout() {
    [[ $1 == 20 && $2 == mock_oc ]] || return 99
    calls=$((calls + 1))
    shift 2
    if [[ ${host_probe_created} == true ]]; then
        [[ $* == '-n test-witness exec witness -c host-probe -- wget -T 10 -t 1 -qO- http://127.0.0.1:9962/v1/encryption/history' ]] || return 99
    else
        [[ $* == 'get --raw /api/v1/namespaces/unf-system/pods/controller:9962/proxy/v1/encryption/history' ]] || return 99
    fi
    return "${transfer_status}"
}
controller_raw /v1/encryption/history
[[ ${calls} == 1 ]]
probe_status=124 calls=0 status=0
controller_raw /v1/encryption/history || status=$?
[[ ${status} == 1 && ${calls} == 0 ]]
host_probe_created=false
controller_raw /v1/encryption/history
[[ ${calls} == 1 ]]
host_probe_created=true probe_status=0 transfer_status=124 calls=0 status=0
controller_raw /v1/encryption/history || status=$?
[[ ${status} == 124 && ${calls} == 1 ]]
controller_status=124 calls=0 status=0
controller_raw /v1/encryption/history || status=$?
[[ ${status} == 124 && ${calls} == 0 ]]
for helper in host_probe_pod_on_node controller_pod_and_node; do
    body=$(sed -n "/^${helper}()/,/^}/p" "${root}/hack/verify-openshift-encryption-phase9.sh")
    [[ ${body} == *'timeout 20 '* && ${body} != *'oc_read '* ]]
done
echo "Phase 9 active witness cannot fall back to Pod proxy; lookup and transfer failures propagate"
