#!/bin/sh
# Runs in the existing immutable test-tools image: no Python dependency.
set -eu
targets=$1
duration=${2:-45}
case $duration in ''|*[!0-9]*) exit 2;; esac
test "$duration" -ge 1 && test "$duration" -le 60
for tool in jq wget timeout date sleep grep; do command -v "$tool" >/dev/null; done
printf '%s' "$targets" | jq -e 'type=="array" and length==8
    and ([.[].label]|unique|length)==8
    and all(.[]; (.label|type)=="string" and (.label|test("^[A-Za-z0-9_/-]+$"))
        and (.address|type)=="string" and (.address|test("^[0-9a-fA-F:.]+$"))
        and (.port==8080 or .port==18080))' >/dev/null
rows=$(printf '%s' "$targets" | jq -r '.[]|[.label,.address,(.port|tostring)]|@tsv')
jq -cn --argjson at "$(date +%s%3N)" --argjson targets "$targets" '{type:"started",unixMs:$at,targets:$targets}'
deadline=$(($(date +%s) + duration))
samples=0 failures=0
while test "$(date +%s)" -lt "$deadline"; do
    while IFS="$(printf '\t')" read -r label address port; do
        case $address in *:*) target="http://[$address]:$port/health";; *) target="http://$address:$port/health";; esac
        started=$(date +%s%3N)
        status=0
        response=$(timeout 2 wget --no-proxy --timeout=1 --tries=1 --server-response --output-document=/dev/null "$target" 2>&1) || status=$?
        ok=false
        if test "$status" = 0 && printf '%s\n' "$response" | grep -Eq 'HTTP/1\.[01] 200( |$)'; then ok=true; else failures=$((failures+1)); fi
        ended=$(date +%s%3N)
        jq -cn --arg label "$label" --argjson at "$started" --argjson elapsed "$((ended-started))" --argjson ok "$ok" --argjson status "$status" \
            '{type:"sample",label:$label,unixMs:$at,elapsedMs:$elapsed,ok:$ok,wgetExit:$status}'
        samples=$((samples+1))
    done <<EOF
$rows
EOF
    sleep 0.2
done
jq -cn --argjson at "$(date +%s%3N)" --argjson samples "$samples" --argjson failures "$failures" \
    '{type:"complete",unixMs:$at,samples:$samples,failures:$failures}'
# The parent rejects failed samples independently of observer exit status.
