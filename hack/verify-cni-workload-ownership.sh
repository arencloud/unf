#!/usr/bin/env bash
# Run inside an isolated privileged qualification container, never a node shell.
set -Eeuo pipefail
umask 077
[[ ${UNF_CNI_OWNERSHIP_ISOLATED_CONTAINER:-} == yes && $EUID == 0 ]]
binary=${UNF_CNI_OWNERSHIP_BINARY:-/usr/local/bin/disposable-lifecycle}
[[ -x $binary ]]
for command in ip jq sha256sum mktemp; do command -v "$command" >/dev/null; done
directory=$(mktemp -d /tmp/unf-cni-ownership.XXXXXX)
suffix=${directory##*.}
host_namespace=unf-own-h-$suffix
pod_namespace=unf-own-p-$suffix
host_created=false
pod_created=false
stage=namespace-setup
cleanup() {
    local result=$?
    trap - EXIT
    if [[ $pod_created == true ]]; then ip netns del "$pod_namespace" || result=1; fi
    if [[ $host_created == true ]]; then ip netns del "$host_namespace" || result=1; fi
    printf 'CNI ownership qualification exit=%s stage=%s evidence=%s\n' "$result" "$stage" "$directory"
    exit "$result"
}
trap cleanup EXIT
trap 'printf "CNI ownership failure: stage=%s line=%s\n" "$stage" "$LINENO" >&2' ERR
ip netns add "$host_namespace"
host_created=true
ip netns add "$pod_namespace"
pod_created=true
state=$directory/attachments.json
config='{"cniVersion":"1.1.0","name":"unf-lifecycle-test","type":"unf","mtu":1400,"ipam":{"type":"unf"}}'
run_cni() {
    local command=$1 input=$2 args=$3
    printf '%s' "$input" | ip netns exec "$host_namespace" env \
        UNF_CNI_TEST_STATE_PATH="$state" \
        UNF_CNI_TEST_IPV4_BLOCK=10.244.44.0/24 \
        UNF_CNI_TEST_IPV6_BLOCK=fd44:0:0:44::/120 \
        CNI_COMMAND="$command" CNI_CONTAINERID=ownership-sandbox \
        CNI_IFNAME=eth0 CNI_NETNS="/run/netns/$pod_namespace" \
        CNI_ARGS="$args" "$binary"
}
expect_denied() {
    local name=$1
    shift
    if "$@" > "$directory/$name.json" 2> "$directory/$name.stderr"; then
        printf 'Expected rejection unexpectedly passed: %s\n' "$name" >&2
        return 1
    fi
    jq -e '.code == 11 or .code == 4' "$directory/$name.json" >/dev/null
}
check_config() { jq -c --argjson previous "$1" '. + {prevResult:$previous}' <<< "$config"; }
alias_for() { ip -n "$host_namespace" -j link show dev "$interface" | jq -er '.[0].ifalias'; }
assert_no_resources() {
    jq -e '.schemaVersion==2 and (.attachments|length)==0' "$state" >/dev/null
    if ip -n "$host_namespace" link show dev "$interface" >/dev/null 2>&1; then return 1; fi
    if ip -n "$pod_namespace" link show dev eth0 >/dev/null 2>&1; then return 1; fi
    ip -n "$host_namespace" -j -4 route show protocol 196 | jq -e 'length==0' >/dev/null
    ip -n "$host_namespace" -j -6 route show protocol 196 | jq -e 'length==0' >/dev/null
}

stage=legacy-replay
legacy=$(run_cni ADD "$config" '')
interface=$(jq -er '.interfaces[0].name|select(test("^unf[0-9a-f]{11}$"))' <<< "$legacy")
legacy_alias=$(alias_for)
[[ $legacy_alias == unf:cni:v1:* ]]
before=$(sha256sum "$state")
replay=$(run_cni ADD "$config" 'K8S_POD_UID=pod-new-runtime')
[[ $(jq -cS . <<< "$legacy") == "$(jq -cS . <<< "$replay")" ]]
run_cni CHECK "$(check_config "$legacy")" 'K8S_POD_UID=pod-new-runtime'
[[ $(sha256sum "$state") == "$before" && $(alias_for) == "$legacy_alias" ]]
jq -e '.schemaVersion==2 and all(.attachments[];.spec.workloadUid==null)' "$state" >/dev/null
run_cni DEL "$config" ''
assert_no_resources

stage=bound-add-and-restart
bound=$(run_cni ADD "$config" 'IgnoreUnknown=1;K8S_POD_UID=pod-uid-a')
interface=$(jq -er '.interfaces[0].name|select(test("^unf[0-9a-f]{11}$"))' <<< "$bound")
bound_check=$(check_config "$bound")
bound_alias=$(alias_for)
[[ $bound_alias == unf:cni:v2:* && $bound_alias != "$legacy_alias" ]]
jq -e '.schemaVersion==3 and (.attachments|length)==1 and .attachments[0].phase=="ready" and .attachments[0].spec.workloadUid=="pod-uid-a"' "$state" >/dev/null
before=$(sha256sum "$state")
replay=$(run_cni ADD "$config" 'K8S_POD_UID=pod-uid-a')
[[ $(jq -cS . <<< "$bound") == "$(jq -cS . <<< "$replay")" ]]
run_cni CHECK "$bound_check" 'K8S_POD_UID=pod-uid-a'
[[ $(sha256sum "$state") == "$before" ]]

stage=incarnation-rejection
expect_denied changed-uid-add run_cni ADD "$config" 'K8S_POD_UID=pod-uid-b'
expect_denied changed-uid-check run_cni CHECK "$bound_check" 'K8S_POD_UID=pod-uid-b'
expect_denied omitted-uid-add run_cni ADD "$config" ''
expect_denied omitted-uid-check run_cni CHECK "$bound_check" ''
expect_denied duplicate-uid run_cni ADD "$config" 'K8S_POD_UID=pod-uid-a;K8S_POD_UID=pod-uid-a'
[[ $(sha256sum "$state") == "$before" && $(alias_for) == "$bound_alias" ]]

stage=kernel-alias-drift
ip -n "$host_namespace" link set dev "$interface" alias ''
expect_denied missing-alias-check run_cni CHECK "$bound_check" 'K8S_POD_UID=pod-uid-a'
expect_denied missing-alias-add run_cni ADD "$config" 'K8S_POD_UID=pod-uid-a'
ip -n "$host_namespace" link set dev "$interface" alias "$legacy_alias"
expect_denied legacy-alias-check run_cni CHECK "$bound_check" 'K8S_POD_UID=pod-uid-a'
[[ $(sha256sum "$state") == "$before" ]]
ip -n "$host_namespace" link set dev "$interface" alias "$bound_alias"
run_cni CHECK "$bound_check" 'K8S_POD_UID=pod-uid-a'

stage=route-drift
ip -n "$host_namespace" -4 route del 10.244.44.2/32 dev "$interface" proto 196
expect_denied missing-v4-route run_cni CHECK "$bound_check" 'K8S_POD_UID=pod-uid-a'
ip -n "$host_namespace" -4 route add 10.244.44.2/32 dev "$interface" proto 196 scope link
ip -n "$host_namespace" -6 route del fd44:0:0:44::2/128 dev "$interface" proto 196
expect_denied missing-v6-route run_cni CHECK "$bound_check" 'K8S_POD_UID=pod-uid-a'
ip -n "$host_namespace" -6 route add fd44:0:0:44::2/128 dev "$interface" proto 196
run_cni CHECK "$bound_check" 'K8S_POD_UID=pod-uid-a'
[[ $(sha256sum "$state") == "$before" ]]

stage=normal-delete-and-address-reuse
run_cni DEL "$config" ''
assert_no_resources
replacement=$(run_cni ADD "$config" 'K8S_POD_UID=pod-uid-b')
replacement_alias=$(alias_for)
[[ $replacement_alias != "$bound_alias" ]]
[[ $(jq -cS '.ips' <<< "$replacement") == "$(jq -cS '.ips' <<< "$bound")" ]]
run_cni CHECK "$(check_config "$replacement")" 'K8S_POD_UID=pod-uid-b'
expect_denied prior-incarnation run_cni CHECK "$(check_config "$replacement")" 'K8S_POD_UID=pod-uid-a'
run_cni DEL "$config" ''
assert_no_resources
stage=verified
jq -n --arg binarySha256 "$(sha256sum "$binary" | cut -d ' ' -f1)" \
    '{schemaVersion:1,result:"passed",scope:"isolated-cni-workload-ownership",binarySha256:$binarySha256,
      legacyReplay:true,uidBinding:true,restart:true,aliasDrift:true,dualStackRouteDrift:true,
      addressReuse:true,negativeCases:11,normalCleanup:true,liveLocalityAdmission:false}'
