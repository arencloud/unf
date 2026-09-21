#!/usr/bin/env bash
# Disposable private fabric only; no host paths or production TC attachment.
set -Eeuo pipefail
umask 077
[[ ${UNF_MAIN_COMPOSITION_ISOLATED:-} == yes && $EUID == 0 ]]
[[ ${UNF_EXPECT_BUILD_REVISION:-} =~ ^[0-9a-f]{40}$ ]]
export UNF_EBPF_OBJECT=/usr/local/lib/unf/main-locality-test
directory=$(mktemp -d /tmp/unf-main-composition.XXXXXX)
export UNF_MAIN_COMPOSITION_ROOT=$directory
suffix=${directory##*.}
fabric=unf-main-f-$suffix
peer_a=unf-main-p-a-$suffix
peer_b=unf-main-p-b-$suffix
export UNF_MAIN_PEER_0=/var/run/netns/$peer_a UNF_MAIN_PEER_1=/var/run/netns/$peer_b
namespaces=()
declare -A inodes=()
mounted=false
cleanup() {
    local result=$?
    trap - EXIT
    if [[ $mounted == true ]]; then umount "$directory/bpffs" || result=1; fi
    for namespace in "${namespaces[@]}"; do
        if [[ $(stat -Lc '%d:%i' "/var/run/netns/$namespace") == "${inodes[$namespace]}" ]]; then
            ip netns del "$namespace" || result=1
        else result=1; fi
    done
    printf 'main-composition-cleanup: exit=%s namespaces=%s\n' "$result" "${#namespaces[@]}"
    exit "$result"
}
trap cleanup EXIT
for namespace in "$fabric" "$peer_a" "$peer_b"; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
    inodes[$namespace]=$(stat -Lc '%d:%i' "/var/run/netns/$namespace")
    ip -n "$namespace" link set lo up
done
mkdir "$directory/bpffs"
mount -t bpf bpf "$directory/bpffs"
mounted=true
LC_ALL=C find "$directory/bpffs" -mindepth 1 -printf '%y %D:%i %P\n' | LC_ALL=C sort > "$directory/before"
ip netns exec "$fabric" bash -ec '
    printf "1\n" > /proc/sys/net/ipv4/ip_forward
    printf "1\n" > /proc/sys/net/ipv6/conf/all/forwarding
    [[ $(< /proc/sys/net/ipv4/ip_forward) == 1 && $(< /proc/sys/net/ipv6/conf/all/forwarding) == 1 ]]
'
for test in tests::diagnostic_build_revision_matches_source encryption_locality::tests::checkpoint::privileged_private_checkpoint_replay_is_bounded_and_offline tests::locality_delivery::privileged_publisher_main_hook_delivers_and_revokes_dual_stack; do
    ip netns exec "$fabric" /usr/local/bin/unf-main-tests --ignored --exact "$test" --nocapture --test-threads=1 | tee "$directory/test.log"
    grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$directory/test.log"
done
for namespace in "${namespaces[@]}"; do
    ip -n "$namespace" -j link show | jq -e 'length==1 and .[0].ifname=="lo"' >/dev/null
done
LC_ALL=C find "$directory/bpffs" -mindepth 1 -printf '%y %D:%i %P\n' | LC_ALL=C sort > "$directory/after"
diff -u "$directory/before" "$directory/after"
umount "$directory/bpffs"
mounted=false
printf 'main-composition-suite: PASS tests=3 allowed=24 denied=24 checkpoint-replay=true dsr-sockets=true exact-cleanup=true controller-admission=false\n'
