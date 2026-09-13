#!/usr/bin/env bash
# Isolated held-descriptor snapshot tests; not packet-time locality permission.
set -Eeuo pipefail
umask 077
[[ ${UNF_VETH_OBSERVATION_ISOLATED_CONTAINER:-} == yes && $EUID == 0 ]]
for command in ip jq mount umount mktemp veth-lifecycle; do command -v "$command" >/dev/null; done
directory=$(mktemp -d /tmp/unf-veth-observation.XXXXXX)
suffix=${directory##*.}
fabric=unf-vo-f-$suffix
peer=unf-vo-p-$suffix
foreign=unf-vo-x-$suffix
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
    if [[ -n $observer_pid ]]; then
        kill "$observer_pid" 2>/dev/null || true
        wait "$observer_pid" 2>/dev/null || true
    fi
    if [[ $overmounted == true ]]; then umount "/var/run/netns/$peer" || result=1; fi
    for namespace in "${namespaces[@]}"; do
        ip -n "$namespace" -j -details link show > "$directory/final-$namespace-links.json" || result=1
        ip -n "$namespace" -j address show > "$directory/final-$namespace-addresses.json" || result=1
    done
    for namespace in "${namespaces[@]}"; do ip netns del "$namespace" || result=1; done
    printf 'Veth observation qualification exit=%s stage=%s evidence=%s\n' "$result" "$stage" "$directory"
    exit "$result"
}
trap cleanup EXIT
for namespace in "$fabric" "$peer" "$foreign"; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
    ip -n "$namespace" link set lo up
done
apply() { ip netns exec "$fabric" veth-lifecycle apply unfobs0 "/var/run/netns/$peer"; }
start_observer() {
    stop_observer
    sequence=$((sequence + 1))
    coproc OBSERVER { exec ip netns exec "$fabric" veth-lifecycle observe unfobs0 "/var/run/netns/$peer" 2> "$directory/observer-$sequence.stderr"; }
    observer_pid=$OBSERVER_PID
    exec {observer_input}>&"${OBSERVER[1]}"
    exec {observer_output}<&"${OBSERVER[0]}"
    local response
    read -r -t 20 response <&"$observer_output"
    [[ $response == observation-ready ]]
}
check() {
    local name=$1 expected=$2 response
    printf 'recheck\n' >&"$observer_input"
    read -r -t 20 response <&"$observer_output"
    jq -n --arg name "$name" --arg response "$response" --arg expected "$expected" \
        '{name:$name,response:$response,expected:$expected}' >> "$directory/checks.jsonl"
    case $expected in
        current) [[ $response == observation-current ]];;
        retired) [[ $response == 'observation-rejected: veth lifecycle readback failed: veth observation has been retired' ]];;
        namespace) [[ $response == *'observed namespace descriptor identity changed'* ]];;
        mtu) [[ $response == observation-rejected:* && $response == *'expected MTU'* ]];;
        missing) [[ $response == observation-rejected:* && $response == *'required interface '* && $response == *' is absent' ]];;
        *) return 1;;
    esac
}
apply
stage=mtu-drift
start_observer
check initial current
ip -n "$peer" link set eth0 mtu 1399
check mtu-drift mtu
ip -n "$peer" link set eth0 mtu 1400
check restored-mtu-stays-retired retired
start_observer
check explicit-new-observation current
stage=namespace-path-replacement
mount --bind "/var/run/netns/$foreign" "/var/run/netns/$peer"
overmounted=true
check replaced-namespace-path namespace
umount "/var/run/netns/$peer"
overmounted=false
check restored-path-stays-retired retired
start_observer
check original-namespace-restored current
stage=peer-move
ip -n "$peer" link set eth0 netns "$foreign"
check moved-peer missing
ip -n "$foreign" link set eth0 netns "$peer"
apply
check restored-peer-stays-retired retired
start_observer
check peer-explicit-reobserved current
stage=target-deletion
ip -n "$fabric" link del unfobs0
check deleted-target missing
apply
check recreated-target-stays-retired retired
start_observer
check replacement-explicit-reobserved current
stop_observer
stage=verified
jq -s -e 'length==13 and ([.[]|select(.expected=="current")]|length)==5 and ([.[]|select(.expected=="retired")]|length)==4' "$directory/checks.jsonl" >/dev/null
jq -n '{schemaVersion:1,result:"passed",scope:"isolated-held-namespace-observation",positiveChecks:5,driftRejections:4,stickyRetirements:4,packetTimeLifetime:false,kernelAdmitted:false}'
