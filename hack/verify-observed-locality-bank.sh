#!/usr/bin/env bash
# Run only inside the disposable privileged platform diagnostic Pod.
set -Eeuo pipefail
umask 077
[[ ${UNF_OBSERVED_BANK_ISOLATED_CONTAINER:-} == yes && $EUID == 0 ]]
for command in ip jq stat kernel-netns-cookie kernel-observed-bank; do command -v "$command" >/dev/null; done

# Regress the complete existing 28-case snapshot/retirement suite first. Include
# all exact case observations in the Pod log before its private filesystem goes.
native_log=$(mktemp /tmp/unf-ob-native.XXXXXX)
UNF_NATIVE_ATTACHMENT_ISOLATED_CONTAINER=yes bash /usr/local/bin/verify-native-attachment-observation | tee "$native_log"
native_directory=$(sed -n 's/^Native attachment qualification exit=0 stage=verified evidence=\(\/tmp\/unf-native-attachment\.[[:alnum:]]\{6\}\)$/\1/p' "$native_log")
[[ $native_directory =~ ^/tmp/unf-native-attachment\.[a-zA-Z0-9]{6}$ ]]
jq -s -e 'length==28' "$native_directory/checks.jsonl" >/dev/null
while IFS= read -r check; do printf 'native-check: %s\n' "$check"; done < "$native_directory/checks.jsonl"

directory=$(mktemp -d /tmp/unf-observed-bank.XXXXXX)
suffix=${directory##*.}
fabric=unf-ob-f-$suffix
peer_a=unf-ob-p-a-$suffix
peer_b=unf-ob-p-b-$suffix
namespaces=()
declare -A namespace_inodes=()
stage=create-namespaces
cleanup() {
    local result=$?
    trap - EXIT
    for namespace in "${namespaces[@]}"; do
        if [[ $(stat -Lc '%d:%i' "/var/run/netns/$namespace") == "${namespace_inodes[$namespace]}" ]]; then
            ip netns del "$namespace" || result=1
        else result=1; fi
    done
    if [[ $result == 0 ]]; then
        printf 'observed-locality-suite: PASS native-checks=28 bank-checks=true namespace-cleanup=true packet-delivery-tested=false\n'
    else
        printf 'observed-locality-suite: FAIL exit=%s stage=%s\n' "$result" "$stage"
    fi
    exit "$result"
}
trap cleanup EXIT
for namespace in "$fabric" "$peer_a" "$peer_b"; do
    ip netns add "$namespace"
    namespaces+=("$namespace")
    namespace_inodes[$namespace]=$(stat -Lc '%d:%i' "/var/run/netns/$namespace")
    ip -n "$namespace" link set lo up
done
if [[ ${UNF_KERNEL_BANK_ISOLATED_CONTAINER:-} == yes ]]; then
    # Dedicated mount inside this disposable Pod; no host bpffs bind mount.
    export UNF_KERNEL_BANK_BPFFS=$directory/bpffs
    mkdir "$UNF_KERNEL_BANK_BPFFS"
    mount -t bpf bpf "$UNF_KERNEL_BANK_BPFFS"
    # Some kernels populate fresh bpffs with built-in iterator debug files.
    # Preserve their exact identities; do not exclude names from the leak check.
    LC_ALL=C find "$UNF_KERNEL_BANK_BPFFS" -mindepth 1 -printf '%y %D:%i %P\n' |
        LC_ALL=C sort > "$directory/bpffs-before"
    printf 'kernel-locality-bpffs-before:\n'
    sed 's/^/  /' "$directory/bpffs-before"
    # Only the private fabric namespace changes forwarding, never host sysctls.
    ip netns exec "$fabric" bash -ec '
        printf "1\n" > /proc/sys/net/ipv4/ip_forward
        printf "1\n" > /proc/sys/net/ipv6/conf/all/forwarding
        [[ $(< /proc/sys/net/ipv4/ip_forward) == 1 && $(< /proc/sys/net/ipv6/conf/all/forwarding) == 1 ]]
    '
fi
host_cookie=$(ip netns exec "$fabric" kernel-netns-cookie)
peer_a_cookie=$(ip netns exec "$peer_a" kernel-netns-cookie)
peer_b_cookie=$(ip netns exec "$peer_b" kernel-netns-cookie)
stage=bank-checks
ip netns exec "$fabric" kernel-observed-bank "/var/run/netns/$peer_a" "/var/run/netns/$peer_b" "$host_cookie" "$peer_a_cookie" "$peer_b_cookie"
for namespace in "${namespaces[@]}"; do
    stage=check-links-$namespace
    ip -n "$namespace" -j link show > "$directory/$namespace-links.json"
    jq -c '{links:map({ifname,ifindex,link_index})}' "$directory/$namespace-links.json"
    jq -e 'length==1 and .[0].ifname=="lo"' "$directory/$namespace-links.json" >/dev/null
done
if [[ ${UNF_KERNEL_BANK_ISOLATED_CONTAINER:-} == yes ]]; then
    stage=check-bpffs-inventory
    LC_ALL=C find "$UNF_KERNEL_BANK_BPFFS" -mindepth 1 -printf '%y %D:%i %P\n' |
        LC_ALL=C sort > "$directory/bpffs-after"
    printf 'kernel-locality-bpffs-after:\n'
    sed 's/^/  /' "$directory/bpffs-after"
    diff -u "$directory/bpffs-before" "$directory/bpffs-after"
    stage=unmount-bpffs
    umount "$UNF_KERNEL_BANK_BPFFS"
    rmdir "$UNF_KERNEL_BANK_BPFFS"
    printf 'kernel-locality-suite: PASS bank-checks=true namespace-cleanup=true packet-delivery-tested=false\n'
fi
stage=delete-namespaces
