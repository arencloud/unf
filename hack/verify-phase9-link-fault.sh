#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "${root}/hack/phase9-link-fault.sh"
sh -n "${root}/hack/phase9-link-guard.sh"
sh "${root}/hack/phase9-link-selector-preflight.sh" "$(<"${root}/hack/phase9-link-targets.jq")"
fixture=$(jq -cn '
  def plan($epoch;$name): {epoch:$epoch,interfaceName:$name,
    ownerAlias:("unf:encryption:v2:cluster:uid:"+($epoch|tostring)),clusterId:"cluster",localNodeUid:"uid"};
  [plan(411;"unfwg00000000bf"),plan(412;"unfwg00000000bg")] as $plans |
  {journal:{nodeName:"worker",nodeUid:"uid",clusterId:"cluster",activeEpoch:412,plans:$plans,
    transports:[$plans[] | {keyEpoch:.epoch,state:(if .epoch==412 then "active" else "draining" end),
      interfaceName,interfaceIndex:.epoch}]},
   links:[$plans[] | {ifname:.interfaceName,ifindex:.epoch,ifalias:.ownerAlias,
     linkinfo:{info_kind:"wireguard"}}]}')
targets() { jq -ce --arg node worker -f "${root}/hack/phase9-link-targets.jq"; }
[[ $(targets <<<"${fixture}" | jq length) == 2 ]]
retired=$(jq '.links |= map(select(.ifindex==412))' <<<"${fixture}")
target=$(targets <<<"${retired}" | jq -ce 'select(length==1) | .[0] | select(.epoch==412)')
# The old first-plan selector still names 411; the new selector chooses the
# actually present active transport, including base-36 alphabetic names.
[[ $(jq -r '.journal.plans[0].interfaceName' <<<"${retired}") == unfwg00000000bf ]]
for mutation in \
    '.journal.nodeName="foreign"' '.journal.nodeUid="foreign"' \
    '.journal.activeEpoch=411' '.journal.activeEpoch=0' \
    '.journal.plans[1].ownerAlias="foreign"' '.journal.plans[1].localNodeUid="foreign"' \
    '.links[0].ifindex=999' '.links[0].linkinfo.info_kind="dummy"' \
    '.links[0].ifname="foreign"' '.links=[]'; do
    if jq "${mutation}" <<<"${retired}" | targets >/dev/null 2>&1; then
        echo "link-target selector accepted invalid input: ${mutation}" >&2
        exit 1
    fi
done
foreign=$(jq '.links += [{ifname:"foreign",ifindex:99,ifalias:"unf:encryption:v2:other:other:412",
    linkinfo:{info_kind:"wireguard"}}]' <<<"${retired}")
[[ $(targets <<<"${foreign}" | jq length) == 1 ]]

# Mock only netlink commands: no host or cluster links are changed by this test.
calls=$(mktemp)
journal_file=$(mktemp)
trap 'unlink "${calls}"; unlink "${journal_file}"' EXIT
export PHASE9_TEST_CALLS=${calls}
export PHASE9_TEST_LINKS
PHASE9_TEST_LINKS=$(jq -c .links <<<"${retired}")
ip() {
    case "$*" in
        '-j -details link show dev '*)
            [[ ${PHASE9_TEST_NETLINK_FAILURE:-false} == false ]] || return 1
            [[ ${PHASE9_TEST_EMPTY_NETLINK:-false} == false ]] || return 0
            jq -ce --arg name "$6" '[.[]|select(.ifname==$name)]|select(length>0)' <<<"${PHASE9_TEST_LINKS}" ;;
        '-j link show')
            [[ ${PHASE9_TEST_NETLINK_FAILURE:-false} == false ]] || return 1
            printf '%s\n' "${PHASE9_TEST_LINKS}" ;;
        '-j -details link show type wireguard')
            printf '%s\n' "${PHASE9_TEST_LINKS}" ;;
        'link set dev '*) printf '%s\n' "$*" >>"${PHASE9_TEST_CALLS}" ;;
        *) return 99 ;;
    esac
}
export -f ip
bash "${root}/hack/phase9-link-guard.sh" "${target}" down
[[ $(<"${calls}") == 'link set dev unfwg00000000bg down' ]]
truncate -s 0 "${calls}"
for mode in down up; do
    for mutation in '.[0].ifalias="foreign"' '.[0].linkinfo.info_kind="dummy"'; do
        if PHASE9_TEST_LINKS=$(jq -c "${mutation}" <<<"${PHASE9_TEST_LINKS}") \
            bash "${root}/hack/phase9-link-guard.sh" "${target}" "${mode}" >/dev/null 2>&1; then
            echo "link mutation guard accepted ${mutation} for ${mode}" >&2
            exit 1
        fi
        [[ ! -s ${calls} ]]
    done
done
if PHASE9_TEST_LINKS='[]' bash "${root}/hack/phase9-link-guard.sh" "${target}" down >/dev/null 2>&1; then exit 1; fi
PHASE9_TEST_LINKS='[]' bash "${root}/hack/phase9-link-guard.sh" "${target}" up
if PHASE9_TEST_LINKS=$(jq -c '.[0].ifindex=999' <<<"${PHASE9_TEST_LINKS}") \
    bash "${root}/hack/phase9-link-guard.sh" "${target}" down >/dev/null 2>&1; then exit 1; fi
PHASE9_TEST_LINKS=$(jq -c '.[0].ifindex=999' <<<"${PHASE9_TEST_LINKS}") \
    bash "${root}/hack/phase9-link-guard.sh" "${target}" up
[[ ! -s ${calls} ]]
if PHASE9_TEST_NETLINK_FAILURE=true bash "${root}/hack/phase9-link-guard.sh" "${target}" up >/dev/null 2>&1; then exit 1; fi
for mode in down up; do
    if PHASE9_TEST_EMPTY_NETLINK=true bash "${root}/hack/phase9-link-guard.sh" "${target}" "${mode}" >/dev/null 2>&1; then exit 1; fi
    if bash "${root}/hack/phase9-link-guard.sh" '' "${mode}" >/dev/null 2>&1; then exit 1; fi
done
[[ ! -s ${calls} ]]
# Exercise the actual host-side projection and command quoting, not just the
# isolated jq predicate. Exported mocks run only in this test's Bash children.
jq '.journal as $j | {active:{fact:{recipient:{nodeName:$j.nodeName,nodeUid:$j.nodeUid},
    checkpoint:{transaction:{desired:{activeEpoch:$j.activeEpoch}},transportAuthority:$j.transports}},
    plans:$j.plans},pending:null}' <<<"${retired}" >"${journal_file}"
export PHASE9_TEST_JOURNAL=${journal_file}
jq() {
    local -a arguments=("$@")
    local i
    for i in "${!arguments[@]}"; do
        if [[ ${arguments[$i]} == /var/lib/unf/cni/v1/encryption-generation.json.recovery-plan ]]; then
            arguments[$i]=${PHASE9_TEST_JOURNAL}
        fi
    done
    command jq "${arguments[@]}"
}
export -f jq
source "${root}/hack/phase9-link-fault.sh"
project_root=${root}
source_node=worker
link_lowered=false
phase9_link_exec() {
    [[ $1 == sh ]] || return 1
    shift
    bash "$@"
}
[[ $(phase9_link_targets | jq -c '.[0]') == "${target}" ]]
lower_owned_encryption_links
lower_owned_encryption_links
[[ ${link_lowered} == true && ${#lowered_source_targets[@]} == 1 ]]
restore_owned_encryption_links
[[ $(wc -l <"${calls}") == 3 ]]
[[ $(tail -1 "${calls}") == 'link set dev unfwg00000000bg up' ]]
echo "Phase 9 link fault selects live admitted epochs and preserves foreign/replaced devices"
