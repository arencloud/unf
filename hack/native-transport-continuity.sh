#!/usr/bin/env bash
# Sourced only by the already preflighted, adopted Native coverage fixture.
native_transport_continuity() (
    set -Eeuo pipefail
    local churn_namespace=unf-native-continuity-churn churn_owned=false probe_pid= targets ready=false
    local evidence=$directory/continuity
    install -d -m 0700 "$evidence"
    cleanup_continuity() {
        if [[ -n $probe_pid ]]; then kill "$probe_pid" 2>/dev/null || true; wait "$probe_pid" 2>/dev/null || true; fi
        if [[ $churn_owned == true ]]; then "${kc[@]}" delete namespace "$churn_namespace" --wait=false >/dev/null 2>&1 || true; fi
    }
    trap cleanup_continuity EXIT
    "${kc[@]}" get namespaces -o json | jq -e --arg ns "$churn_namespace" 'all(.items[];.metadata.name!=$ns)' >/dev/null
    targets=$(jq -ce '[.items[] | select((.kind=="Pod" or .kind=="Service") and .metadata.name!="client")
        | . as $item | (if .kind=="Pod" then [.status.podIPs[].ip] else .spec.clusterIPs end)[]
        | {label:($item.metadata.name+"/"+$item.kind+"/"+(if contains(":") then "ipv6" else "ipv4" end)),
           address:.,port:(if $item.kind=="Pod" then 8080 else 18080 end)}] | select(length==8)' "$directory/fixture.json")
    controller_raw /v1/status > "$evidence/before-status.json"
    # Bound the complete streaming observation externally; do not give the
    # 45-second remote probe the ordinary 15-second API request deadline.
    timeout 75 kubectl --kubeconfig "$KUBECONFIG" --context "$context" -n "$namespace" exec -i client -- python3 - --targets "$targets" --seconds 45 \
        < "$root/hack/native_continuity_probe.py" > "$evidence/probes.jsonl" 2> "$evidence/probe-observer.log" &
    probe_pid=$!
    for _ in $(seq 1 10); do
        kill -0 "$probe_pid"
        if jq -se '[.[]|select(.type=="sample")]|group_by(.label)|length==8 and all(.[];length>=2 and all(.[];.ok==true))' "$evidence/probes.jsonl" >/dev/null 2>&1; then ready=true; break; fi
        sleep 1
    done
    [[ $ready == true ]]
    sleep 3
    record_event() { jq -cn --arg action "$1" --argjson at "$(date +%s%3N)" '{action:$action,unixMs:$at}' >> "$evidence/events.jsonl"; }
    record_event create-start
    "${kc[@]}" create namespace "$churn_namespace" > "$evidence/create.log"
    churn_owned=true
    record_event create-complete
    sleep 3
    record_event relabel-start
    "${kc[@]}" label namespace "$churn_namespace" unf-continuity=changed > "$evidence/relabel.log"
    record_event relabel-complete
    sleep 3
    record_event delete-start
    "${kc[@]}" delete namespace "$churn_namespace" --wait=true --timeout=30s > "$evidence/delete.log"
    churn_owned=false
    record_event delete-complete
    wait "$probe_pid"
    probe_pid=
    controller_raw /v1/status > "$evidence/after-status.json"
    "${kc[@]}" get namespaces -o json | jq -e --arg ns "$churn_namespace" 'all(.items[];.metadata.name!=$ns)' >/dev/null
    jq -s --slurpfile events "$evidence/events.jsonl" '
        . as $records | [.[]|select(.type=="sample")] as $samples
        | {samples:($samples|length),failures:([$samples[]|select(.ok!=true)]|length),
           targets:($samples|group_by(.label)|map({label:.[0].label,samples:length,failures:([.[]|select(.ok!=true)]|length)})),
           complete:([$records[]|select(.type=="complete")]|length==1),events:$events}' "$evidence/probes.jsonl" > "$evidence/summary.json"
    jq -e '.complete==true and .failures==0 and (.targets|length)==8 and all(.targets[];.samples>=3)' "$evidence/summary.json" >/dev/null
    jq -se '.[0].type=="started" and .[-1].type=="complete"
        and .[-1].failures==0 and .[-1].samples==([.[]|select(.type=="sample")]|length)
        and all(.[]; .type=="started" or .type=="complete" or (.type=="sample" and .ok==true))' "$evidence/probes.jsonl" >/dev/null
    jq -se '[.[].action]==["create-start","create-complete","relabel-start","relabel-complete","delete-start","delete-complete"]
        and ([.[].unixMs]==([.[].unixMs]|sort))' "$evidence/events.jsonl" >/dev/null
    # Every target must be observed before, during and after the mutation window.
    jq -se --slurpfile events "$evidence/events.jsonl" '
        ($events[0].unixMs) as $start | ($events[-1].unixMs) as $end
        | [.[]|select(.type=="sample")]|group_by(.label)
        | length==8 and all(.[]; any(.[];.unixMs<$start) and any(.[];.unixMs>=$start and .unixMs<=$end) and any(.[];.unixMs>$end))' "$evidence/probes.jsonl" >/dev/null
    echo 'Native continuity passed: no failed fresh HTTP connections across empty Namespace create/relabel/delete'
)
