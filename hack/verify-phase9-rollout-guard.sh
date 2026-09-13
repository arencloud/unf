#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture='{"items":[{"metadata":{},"spec":{"containers":[{"name":"agent","image":"candidate"}]},"status":{"phase":"Running","containerStatuses":[{"name":"agent","ready":false,"restartCount":0,"state":{"running":{}},"lastState":{}},{"name":"install-primary-cni","ready":true,"restartCount":0,"state":{"running":{}},"lastState":{}}]}}]}'
check() { jq -L "$root/hack" -e 'include "phase9-rollout-guard"; phase9_candidate_staging_healthy("candidate")' >/dev/null; }
check <<<"$fixture"
jq '.items[0].status={phase:"Pending"}' <<<"$fixture" | check
jq '.items[0].status.containerStatuses[0].ready=true' <<<"$fixture" | check
jq '.items[0].spec.containers[0].image="prior" | .items[0].status.containerStatuses[0].restartCount=9' <<<"$fixture" | check
for mutation in \
  '.items=null' \
  '.items[0].metadata.deletionTimestamp="2026-09-13T00:00:00Z"' \
  '.items[0].status.phase="Failed"' \
  '.items[0].status.phase="Unknown"' \
  '.items[0].status.containerStatuses[0].restartCount=1' \
  '.items[0].status.containerStatuses[1].restartCount=1' \
  '.items[0].status.containerStatuses[0].restartCount=null' \
  '.items[0].status.containerStatuses[0].state={terminated:{exitCode:0}}' \
  '.items[0].status.containerStatuses[0].lastState={terminated:{exitCode:143}}' \
  '.items[0].status.containerStatuses[0].state={waiting:{reason:"CrashLoopBackOff"}}' \
  '.items[0].status.containerStatuses[0].state={waiting:{reason:"CreateContainerConfigError"}}'; do
    if jq "$mutation" <<<"$fixture" | check 2>/dev/null; then
        echo "Rollout guard accepted failed candidate: $mutation" >&2
        exit 1
    fi
done
init_fixture=$(jq '.items[0].status.initContainerStatuses=[{
  name:"install-primary-cni",ready:true,restartCount:0,lastState:{},
  state:{terminated:{exitCode:0,reason:"Completed"}}}]' <<< "$fixture")
check <<< "$init_fixture"
jq '.items[0].status.initContainerStatuses[0].state={running:{}}' <<< "$init_fixture" | check
for mutation in \
  '.items[0].status.initContainerStatuses[0].restartCount=1' \
  '.items[0].status.initContainerStatuses[0].restartCount=null' \
  '.items[0].status.initContainerStatuses[0].state.terminated.exitCode=1' \
  '.items[0].status.initContainerStatuses[0].state.terminated.reason="Error"' \
  '.items[0].status.initContainerStatuses[0].state.terminated.signal=9' \
  '.items[0].status.initContainerStatuses[0].lastState={terminated:{exitCode:0}}' \
  '.items[0].status.initContainerStatuses[0].state={waiting:{reason:"CrashLoopBackOff"}}'; do
    if jq "$mutation" <<< "$init_fixture" | check 2>/dev/null; then
        echo "Rollout guard accepted failed init container: $mutation" >&2
        exit 1
    fi
done
bash -n "$root/hack/deploy-openshift-service-fabric.sh"
echo 'Phase 9 rollout guard rejects regular/init failures and restarts while permitting successful init completion'
