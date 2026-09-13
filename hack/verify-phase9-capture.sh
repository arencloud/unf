#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "${root}/hack/phase9-capture.sh"
filter=$(phase9_capture_filter 192.0.2.1 2001:db8::1 192.0.2.2 2001:db8::2)
[[ ${filter} == '(udp and (port 51820 or port 51821)) or ((host 192.0.2.1 or host 2001:db8::1) and tcp port 8080) or ((host 192.0.2.2 or host 2001:db8::2) and tcp port 8081)' ]]
tcpdump -ddd -y EN10MB "${filter}" >/dev/null
kc=(mock_oc) namespace=fixture capture_pod=capture
capture_container_path=/capture/test.pcap
scratch=$(mktemp -d)
trap 'rm -r -- "${scratch}"' EXIT
stop_status=0 capture_status=0 mock_dropped=0 missing_stats=false duplicate_stats=false
timeout() {
    [[ $1 == 20 && $2 == mock_oc && $3 == -n && $4 == fixture ]] || return 99
    shift 4
    case $1 in
        exec)
            [[ $* == "exec capture -c tcpdump -- /bin/sh -ec kill -INT 1" ]] || return 99
            return "${stop_status}" ;;
        get)
            jq -cn --argjson status "${capture_status}" '{status:{containerStatuses:[{name:"tcpdump",
                state:{terminated:{exitCode:$status,startedAt:"start",finishedAt:"finish"}}}]}}' ;;
        logs)
            if [[ ${missing_stats} == false ]]; then printf '%s packets dropped by kernel\n' "${mock_dropped}"; fi
            if [[ ${duplicate_stats} == true ]]; then printf '0 packets dropped by kernel\n'; fi ;;
        cp) printf 'mock-pcap\n' >"${!#}"; printf 'copy diagnostic, not JSON\n' ;;
        *) return 99 ;;
    esac
}
phase9_capture_finish "${scratch}/success" | jq -e '.explicitStopAfterFault and .exitCode == 0
    and .packetsDroppedByKernel == 0 and .watchdogSeconds == 300' >/dev/null
for failure in stop timeout crash dropped missing duplicate; do
    stop_status=0 capture_status=0 mock_dropped=0 missing_stats=false duplicate_stats=false
    case ${failure} in
        stop) stop_status=255 ;;
        timeout) capture_status=124 ;;
        crash) capture_status=1 ;;
        dropped) mock_dropped=1 ;;
        missing) missing_stats=true ;;
        duplicate) duplicate_stats=true ;;
    esac
    if phase9_capture_finish "${scratch}/${failure}" >/dev/null 2>&1; then
        echo "capture accepted ${failure} failure" >&2
        exit 1
    fi
    if [[ ${failure} == dropped || ${failure} == missing || ${failure} == duplicate ]]; then
        [[ -e ${scratch}/${failure}/tcpdump.log && -s ${scratch}/${failure}/received.pcap ]]
    fi
done
for platform in openshift kind; do
    gate=${root}/hack/verify-${platform}-encryption-phase9.sh
    restore_line=$(rg -n '^restore_owned_encryption_links$' "${gate}" | cut -d: -f1)
    stop_line=$(rg -n '^capture_lifecycle=\$\(phase9_capture_finish ' "${gate}" | cut -d: -f1)
    (( restore_line < stop_line ))
    rg -q 'args: \["--signal=INT", "300", "/usr/bin/tcpdump"' "${gate}"
    rg -q 'lifecycle:\$captureLifecycle' "${gate}"
    rg -q '^capture_filter=\$\(phase9_capture_filter ' "${gate}"
    rg -q '"\$\{capture_container_path\}", "\$\{capture_filter\}"' "${gate}"
done
echo "Phase 9 capture requires explicit post-fault stop, clean flush and zero reported kernel loss"
