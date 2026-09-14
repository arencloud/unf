#!/usr/bin/env bash
# Read-only joint snapshot qualification in disposable owned namespaces.
set -Eeuo pipefail
umask 077
[[ ${UNF_NATIVE_ATTACHMENT_ISOLATED_CONTAINER:-} == yes && $EUID == 0 ]]
for command in ip jq mount umount native-attachment-observation; do command -v "$command" >/dev/null; done
directory=$(mktemp -d /tmp/unf-native-attachment.XXXXXX)
suffix=${directory##*.}
fabric=unf-na-f-$suffix
peer=unf-na-p-$suffix
foreign=unf-na-x-$suffix
namespaces=()
observer_pid=
overmounted=false
sequence=0
stage=setup
stop_observer() {
    if [[ -n $observer_pid ]]; then
        printf 'finish\n' >&"$observer_input"
        exec {observer_input}>&-
        exec {observer_output}<&-
        wait "$observer_pid"
        observer_pid=
    fi
}
cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n $observer_pid ]]; then kill "$observer_pid" 2>/dev/null || true; wait "$observer_pid" 2>/dev/null || true; fi
    if [[ $overmounted == true ]]; then umount "/var/run/netns/$peer" || result=1; fi
    for namespace in "${namespaces[@]}"; do
        ip -n "$namespace" -j -details link show > "$directory/final-$namespace-links.json" || result=1
        ip -n "$namespace" -j address show > "$directory/final-$namespace-addresses.json" || result=1
        ip -n "$namespace" -j route show > "$directory/final-$namespace-routes4.json" || result=1
        ip -n "$namespace" -j -6 route show > "$directory/final-$namespace-routes6.json" || result=1
    done
    for namespace in "${namespaces[@]}"; do ip netns del "$namespace" || result=1; done
    printf 'Native attachment qualification exit=%s stage=%s evidence=%s\n' "$result" "$stage" "$directory"
    exit "$result"
}
trap cleanup EXIT
for namespace in "$fabric" "$peer" "$foreign"; do ip netns add "$namespace"; namespaces+=("$namespace"); ip -n "$namespace" link set lo up; done
apply() { ip netns exec "$fabric" native-attachment-observation apply unfobs0 "/var/run/netns/$peer"; }
start_observer() {
    stop_observer
    sequence=$((sequence+1))
    coproc OBSERVER { exec ip netns exec "$fabric" native-attachment-observation observe unfobs0 "/var/run/netns/$peer" 2> "$directory/observer-$sequence.stderr"; }
    observer_pid=$OBSERVER_PID
    exec {observer_input}>&"${OBSERVER[1]}"
    exec {observer_output}<&"${OBSERVER[0]}"
    local response
    read -r -t 20 response <&"$observer_output"
    [[ $response == observation-ready ]]
}
check() {
    local name=$1 expected=$2 response command=${3:-recheck}
    printf '%s\n' "$command" >&"$observer_input"
    read -r -t 20 response <&"$observer_output"
    jq -cn --arg name "$name" --arg response "$response" --arg expected "$expected" '{name:$name,response:$response,expected:$expected}' >> "$directory/checks.jsonl"
    case $expected in
        current) [[ $response == observation-current ]];;
        cancelled) [[ $response == observation-cancelled ]];;
        retired) [[ $response == 'observation-rejected: native route readback failed: native attachment observation has been retired' ]];;
        host-route) [[ $response == 'observation-rejected: native route readback failed: Host state is incomplete: 1 of 2 routes and 2 of 2 neighbors exist' ]];;
        peer-route) [[ $response == 'observation-rejected: native route readback failed: Container state is incomplete: 3 of 4 routes and 2 of 2 neighbors exist' ]];;
        host-neighbor) [[ $response == 'observation-rejected: native route readback failed: Host state is incomplete: 2 of 2 routes and 1 of 2 neighbors exist' ]];;
        peer-neighbor) [[ $response == 'observation-rejected: native route readback failed: Container state is incomplete: 4 of 4 routes and 1 of 2 neighbors exist' ]];;
        namespace) [[ $response == observation-rejected:* && $response == *'observed namespace descriptor identity changed'* ]];;
        mtu) [[ $response == observation-rejected:* && $response == *'expected MTU'* ]];;
        *) return 1;;
    esac
}
apply
stage=route-and-neighbor-drift
start_observer
check initial current
for fault in host4 host6 peer4 peer6 neighbor4 neighbor6; do
    case $fault in
        host4) ip -n "$fabric" route del 10.244.44.2/32 dev unfobs0; expected=host-route;;
        host6) ip -n "$fabric" -6 route del fd44::2/128 dev unfobs0; expected=host-route;;
        peer4) ip -n "$peer" route del default via 10.244.44.1 dev eth0; expected=peer-route;;
        peer6) ip -n "$peer" -6 route del default via fd44::1 dev eth0; expected=peer-route;;
        neighbor4) ip -n "$fabric" neigh del 10.244.44.2 dev unfobs0; expected=host-neighbor;;
        neighbor6) ip -n "$peer" -6 neigh del fd44::1 dev eth0; expected=peer-neighbor;;
    esac
    check "$fault-missing" "$expected"
    apply
    check "$fault-restored-stays-retired" retired
    start_observer
    check "$fault-explicit-reobserved" current
done
stage=namespace-path-replacement
mount --bind "/var/run/netns/$foreign" "/var/run/netns/$peer"
overmounted=true
check replaced-path namespace
umount "/var/run/netns/$peer"
overmounted=false
check restored-path-stays-retired retired
start_observer
check path-explicit-reobserved current
stage=link-drift
ip -n "$peer" link set eth0 mtu 1399
check mtu-drift mtu
ip -n "$peer" link set eth0 mtu 1400
check restored-mtu-stays-retired retired
start_observer
check link-explicit-reobserved current
stage=cancellation
check cancelled cancelled cancel
check cancelled-stays-retired retired
start_observer
check cancellation-explicit-reobserved current
stop_observer
stage=verified
jq -s -e 'length==28 and ([.[]|select(.expected=="current")]|length)==10 and ([.[]|select(.expected=="retired")]|length)==9 and ([.[]|select(.expected|test("^(host|peer)-(route|neighbor)$"))]|length)==6' "$directory/checks.jsonl" >/dev/null
jq -n '{schemaVersion:1,result:"passed",scope:"isolated-joint-native-attachment-observation",positiveChecks:10,routeOrNeighborDrift:6,linkOrPathDrift:2,cancellations:1,stickyRetirements:9,packetTimeLifetime:false,kernelAdmitted:false,productionAuthority:false}'
