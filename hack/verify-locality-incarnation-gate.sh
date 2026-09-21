#!/usr/bin/env bash
# Disposable kernel/journal gate. No production maps, pins, links or CNI leases.
set -Eeuo pipefail
umask 077
: "${KUBECONFIG:?explicit kubeconfig}"
: "${KUBE_CONTEXT:?explicit context}"
: "${UNF_LOCALITY_GATE_NODE:?exact node}"
: "${UNF_LOCALITY_GATE_NODE_UID:?exact Node UID}"
: "${UNF_LOCALITY_GATE_IMAGE:?immutable diagnostic image}"
: "${UNF_LOCALITY_GATE_DIAGNOSTICS:?new evidence directory}"
: "${UNF_LOCALITY_GATE_PLATFORM:?cl02 or kind}"
image=$UNF_LOCALITY_GATE_IMAGE
directory=$UNF_LOCALITY_GATE_DIAGNOSTICS
suite=${UNF_LOCALITY_GATE_SUITE:-incarnation}
case $suite in
    incarnation)
        test_command='["/usr/local/bin/kernel-incarnation-gate"]'
        marker='kernel-incarnation-gate: PASS schema=1 exact-revocation=true unrelated-preserved=true stale-serial-denied=true foreign-journal-denied=true cleanup=true packet-delivery-tested=false$'
        ;;
    observed-bank)
        test_command='["bash","/usr/local/bin/verify-observed-locality-bank"]'
        marker='observed-locality-suite: PASS native-checks=28 bank-checks=true namespace-cleanup=true packet-delivery-tested=false$'
        ;;
    kernel-journal-floor)
        test_command='["env","UNF_KERNEL_BANK_ISOLATED_CONTAINER=yes","UNF_KERNEL_BANK_PACKET_DELIVERY=yes","UNF_LOCALITY_JOURNAL_FLOOR_TEST=yes","bash","/usr/local/bin/verify-observed-locality-bank"]'
        marker='kernel-locality-suite: PASS bank-checks=true namespace-cleanup=true packet-delivery-tested=true$'
        ;;
    kernel-runtime-owner)
        test_command='["env","UNF_KERNEL_BANK_ISOLATED_CONTAINER=yes","UNF_KERNEL_BANK_PACKET_DELIVERY=yes","UNF_LOCALITY_JOURNAL_FLOOR_TEST=yes","UNF_LOCALITY_RUNTIME_OWNER_TEST=yes","bash","/usr/local/bin/verify-observed-locality-bank"]'
        marker='kernel-locality-suite: PASS bank-checks=true namespace-cleanup=true packet-delivery-tested=true$'
        ;;
    kernel-delivery|kernel-admission)
        test_command='["env","UNF_KERNEL_BANK_ISOLATED_CONTAINER=yes","UNF_KERNEL_BANK_PACKET_DELIVERY=yes","bash","/usr/local/bin/verify-observed-locality-bank"]'
        marker='kernel-locality-suite: PASS bank-checks=true namespace-cleanup=true packet-delivery-tested=true$'
        ;;
    kernel-bank)
        test_command='["env","UNF_KERNEL_BANK_ISOLATED_CONTAINER=yes","bash","/usr/local/bin/verify-observed-locality-bank"]'
        marker='kernel-locality-suite: PASS bank-checks=true namespace-cleanup=true packet-delivery-tested=false$'
        ;;
    *) exit 2;;
esac
[[ $image =~ ^quay.io/arencloud/unf-test-tools-dev@sha256:[0-9a-f]{64}$ ]]
[[ ! -e $directory && -z $(git status --porcelain) ]]
install -d -m 0700 "$directory"
kc=(kubectl --kubeconfig "$KUBECONFIG" --context "$KUBE_CONTEXT" --request-timeout=20s)
"${kc[@]}" get node "$UNF_LOCALITY_GATE_NODE" -o json > "$directory/node-before.json"
jq -e --arg uid "$UNF_LOCALITY_GATE_NODE_UID" '.metadata.uid==$uid and any(.status.conditions[];.type=="Ready" and .status=="True")' "$directory/node-before.json" >/dev/null
case $UNF_LOCALITY_GATE_PLATFORM in
    cl02)
        "${kc[@]}" get infrastructure cluster -o json | jq -e '.status.infrastructureName=="cl02-st7gq"' >/dev/null
        ;;
    kind)
        : "${UNF_LOCALITY_GATE_CL02_EVIDENCE:?matching successful cl02 evidence required}"
        jq -e --arg image "$image" --arg suite "$suite" '.result=="passed" and .platform=="cl02" and .image==$image and (.suite // "incarnation")==$suite and .cleanup==true' "$UNF_LOCALITY_GATE_CL02_EVIDENCE" >/dev/null
        [[ $KUBE_CONTEXT == kind-unf-p9-20260921 ]]
        ;;
    *) exit 2;;
esac
namespace=
namespace_uid=
cleanup() {
    local result=$?
    local removed=false delivery=false
    trap - EXIT
    if [[ -n $namespace && -n $namespace_uid ]]; then
        "${kc[@]}" -n "$namespace" get pods -o json > "$directory/pods-after.json" || result=1
        "${kc[@]}" -n "$namespace" logs gate --timestamps --limit-bytes=1048577 > "$directory/test.log" 2> "$directory/log-observer.log" || result=1
        [[ $(wc -c < "$directory/test.log") -le 1048576 ]] || result=1
        "${kc[@]}" -n "$namespace" get events -o json > "$directory/events.json" || result=1
        if [[ $("${kc[@]}" get namespace "$namespace" -o jsonpath='{.metadata.uid}') == "$namespace_uid" ]]; then
            if "${kc[@]}" delete namespace "$namespace" --wait=true --timeout=90s > "$directory/cleanup.log" &&
                "${kc[@]}" get namespace "$namespace" --ignore-not-found -o name > "$directory/namespace-after.txt" &&
                [[ ! -s $directory/namespace-after.txt ]]; then removed=true; else result=1; fi
        else
            result=1
        fi
    fi
    if [[ $result == 0 ]]; then
        rg -q "$marker" "$directory/test.log" || result=1
    fi
    if [[ $suite == kernel-delivery || $suite == kernel-admission || $suite == kernel-journal-floor || $suite == kernel-runtime-owner ]]; then
        if rg -q 'kernel-locality-delivery: PASS allowed=8 denied=16 protocols=tcp,udp families=4,6 request-bank=true reply-native=true production-policy=false$' "$directory/test.log" &&
            [[ $(rg -c 'kernel-locality-delivery: name=.* delivered=true ' "$directory/test.log") == 8 &&
               $(rg -c 'kernel-locality-delivery: name=.* delivered=false ' "$directory/test.log") == 16 ]]; then
            delivery=true
        else result=1; fi
    fi
    if [[ $suite == kernel-admission || $suite == kernel-journal-floor || $suite == kernel-runtime-owner ]]; then
        rg -q 'kernel-locality-admission: PASS decisions=8 pending-writer-denied=true cancelled-writer-denied=true rollback-not-rearmed=true production-integration=false$' "$directory/test.log" || result=1
        [[ $(rg -c 'kernel-locality-check: name=coordinator-' "$directory/test.log") == 8 ]] || result=1
    fi
    if [[ $suite == kernel-journal-floor || $suite == kernel-runtime-owner ]]; then
        rg -q 'kernel-locality-journal-floor: PASS schema=5 reopen-fenced=true legacy-agent-rejected=true socket-absent=true readiness-absent=true bytes-preserved=true$' "$directory/test.log" || result=1
    fi
    if [[ $suite == kernel-runtime-owner ]]; then
        rg -q 'kernel-locality-runtime-owner: PASS atomic-create=true exclusive-owner=true reopen-withdrawn=true exact-bindings=true partial-rejected=true foreign-preserved=true cleanup=true$' "$directory/test.log" || result=1
    fi
    jq -n --argjson code "$result" --argjson removed "$removed" --argjson delivery "$delivery" --arg platform "$UNF_LOCALITY_GATE_PLATFORM" --arg suite "$suite" --arg image "$image" --arg node "$UNF_LOCALITY_GATE_NODE" --arg uid "$UNF_LOCALITY_GATE_NODE_UID" --arg ns "$namespace" --arg nsuid "$namespace_uid" \
        '{schemaVersion:2,result:(if $code==0 then "passed" else "failed" end),platform:$platform,suite:$suite,image:$image,node:$node,nodeUid:$uid,namespace:$ns,namespaceUid:$nsuid,cleanup:$removed,packetDeliveryTested:$delivery}' > "$directory/evidence.json"
    printf 'Incarnation gate result=%s evidence=%s\n' "$result" "$directory"
    exit "$result"
}
trap cleanup EXIT
jq -n '{apiVersion:"v1",kind:"Namespace",metadata:{generateName:"unf-locality-gate-",labels:{"pod-security.kubernetes.io/enforce":"privileged","pod-security.kubernetes.io/audit":"privileged","pod-security.kubernetes.io/warn":"privileged"}}}' | "${kc[@]}" create -f - -o json > "$directory/namespace.json"
namespace=$(jq -er '.metadata.name' "$directory/namespace.json")
namespace_uid=$(jq -er '.metadata.uid' "$directory/namespace.json")
if [[ $UNF_LOCALITY_GATE_PLATFORM == cl02 ]]; then
    "${kc[@]}" -n "$namespace" create rolebinding gate-privileged --clusterrole=system:openshift:scc:privileged --serviceaccount="$namespace:default" >/dev/null
fi
jq -n --arg ns "$namespace" --arg node "$UNF_LOCALITY_GATE_NODE" --arg image "$image" --argjson command "$test_command" '{apiVersion:"v1",kind:"Pod",metadata:{name:"gate",namespace:$ns},spec:{nodeName:$node,hostNetwork:true,automountServiceAccountToken:false,restartPolicy:"Never",activeDeadlineSeconds:180,containers:[{name:"gate",image:$image,imagePullPolicy:"IfNotPresent",securityContext:{privileged:true,runAsUser:0},resources:{requests:{cpu:"100m",memory:"64Mi"},limits:{cpu:"1",memory:"256Mi"}},env:[{name:"UNF_LOCALITY_GATE_ISOLATED_CONTAINER",value:"yes"},{name:"UNF_OBSERVED_BANK_ISOLATED_CONTAINER",value:"yes"}],command:$command}]}}' > "$directory/pod.json"
"${kc[@]}" create -f "$directory/pod.json" >/dev/null
finished=false
for _ in $(seq 1 100); do
    "${kc[@]}" -n "$namespace" get pod gate -o json > "$directory/pod-observation.json"
    phase=$(jq -r '.status.phase' "$directory/pod-observation.json")
    if [[ $phase == Succeeded ]]; then finished=true; break; fi
    [[ $phase != Failed ]]
    sleep 2
done
[[ $finished == true ]]
jq -e --arg image "$image" '.spec.containers[0].image==$image and (.status.containerStatuses|length)==1 and .status.containerStatuses[0].state.terminated.exitCode==0 and .status.containerStatuses[0].restartCount==0' "$directory/pod-observation.json" >/dev/null
"${kc[@]}" get node "$UNF_LOCALITY_GATE_NODE" -o json > "$directory/node-after.json"
jq -e --arg uid "$UNF_LOCALITY_GATE_NODE_UID" '.metadata.uid==$uid and any(.status.conditions[];.type=="Ready" and .status=="True")' "$directory/node-after.json" >/dev/null
