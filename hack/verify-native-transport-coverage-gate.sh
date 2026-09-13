#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
gate=$root/hack/verify-native-transport-coverage.sh
bash -n "$gate"
bash "$root/hack/verify-phase9-negative-evidence.sh"
# Exercise the actual orchestration boundary: only an explicit successful
# remote network-denial observation may count as denial, never failed exec.
eval "$(sed -n '/^udp_probe()/,/^}/p' "$gate")"
timeout() { shift; "$@"; }
probe_kc() { printf '%s' "$response"; return "$transport_status"; }
kc=(probe_kc)
namespace=fixture
project_root=$root
source "$root/hack/phase9-http-probe.sh"
transport_status=0
response=http-ok
phase9_http_probe_once fixture 192.0.2.1 8080
check() {
    local expected=$1 actual=0
    udp_probe fixture 192.0.2.1 || actual=$?
    [[ $actual == "$expected" ]] || { echo "unexpected UDP observation outcome: $actual" >&2; exit 1; }
}
transport_status=0
response=udp-ok; check 0
response=network-denied; check 1
response=probe-error; check 2
response=; check 2
response=$'udp-ok\nnetwork-denied'; check 2
response=network-denied; transport_status=124; check 2
response=udp-ok; transport_status=1; check 2
for invariant in 'policyTypes: \[Ingress, Egress\]' 'same-node' 'cross-node' \
    'allowed == 24 && \$denied == 8' 'port:53,targetPort:5353' 'port:18080,targetPort:8080' 'status == 1' 'UNF_NATIVE_COVERAGE_RUNTIME_REVISION' \
    'UNF_NATIVE_COVERAGE_INFRASTRUCTURE' 'all_converged==true' 'project_root=\$root'; do
    rg -q "$invariant" "$gate"
done
echo 'Native coverage gate preserves observation-safe TCP/UDP denial and both locality/family boundaries'
