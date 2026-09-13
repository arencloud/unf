#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -f "$temporary/wget" "$temporary/calls" "$temporary/records" "$temporary/cleanup-error"; rmdir "$temporary/continuity" 2>/dev/null || true; rmdir "$temporary"' EXIT
ln -s "$root/hack/testdata/native-continuity-wget.sh" "$temporary/wget"
targets=$(jq -cn '[range(8)|{label:("target/"+tostring),address:"192.0.2.1",port:8080}]')
export UNF_CONTINUITY_WGET_CALLS=$temporary/calls
for scenario in ok wrong-status malformed timeout failed; do
    export UNF_CONTINUITY_WGET_SCENARIO=$scenario
    : > "$temporary/calls"
    PATH="$temporary:$PATH" sh "$root/hack/native-continuity-probe-remote.sh" "$targets" 1 > "$temporary/records"
    calls=$(wc -l < "$temporary/calls")
    expected=false
    [[ $scenario != ok ]] || expected=true
    jq -se --argjson expected "$expected" --argjson calls "$calls" '
        .[0].type=="started" and .[-1].type=="complete" and .[-1].samples>0
        and .[-1].samples==$calls
        and all(.[]|select(.type=="sample");.ok==$expected)
        and (if $expected then .[-1].failures==0 else .[-1].failures==.[-1].samples end)' "$temporary/records" >/dev/null
done
if PATH="$temporary:$PATH" sh "$root/hack/native-continuity-probe-remote.sh" '[]' 1 > "$temporary/records" 2>/dev/null; then
    echo 'invalid targets accepted' >&2; exit 1
fi
# EXIT cleanup must also work after its parent function returns early.
if bash -c 'set -Eeuo pipefail; source "$1"; directory=$2; kc=(false); native_transport_continuity' \
    continuity-test "$root/hack/native-transport-continuity.sh" "$temporary" 2> "$temporary/cleanup-error"; then
    echo 'observer failure was accepted' >&2; exit 1
fi
if grep -q 'unbound variable' "$temporary/cleanup-error"; then
    echo 'continuity EXIT cleanup lost its scope' >&2; exit 1
fi
bash -n "$root/hack/native-transport-continuity.sh"
sh -n "$root/hack/native-continuity-probe-remote.sh"
echo 'Native continuity probe retains failures and uses exactly one wget attempt per sample'
