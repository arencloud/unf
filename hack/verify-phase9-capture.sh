#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "${root}/hack/phase9-capture.sh"
kc=(mock_oc) namespace=fixture capture_pod=capture
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
        *) return 99 ;;
    esac
}
phase9_capture_finish | jq -e '.explicitStopAfterFault and .exitCode == 0
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
    if phase9_capture_finish >/dev/null 2>&1; then
        echo "capture accepted ${failure} failure" >&2
        exit 1
    fi
done
for platform in openshift kind; do
    gate=${root}/hack/verify-${platform}-encryption-phase9.sh
    restore_line=$(rg -n '^restore_owned_encryption_links$' "${gate}" | cut -d: -f1)
    stop_line=$(rg -n '^capture_lifecycle=\$\(phase9_capture_finish\)$' "${gate}" | cut -d: -f1)
    (( restore_line < stop_line ))
    rg -q 'args: \["--signal=INT", "300", "/usr/bin/tcpdump"' "${gate}"
    rg -q 'lifecycle:\$captureLifecycle' "${gate}"
done
echo "Phase 9 capture requires explicit post-fault stop, clean flush and zero reported kernel loss"
