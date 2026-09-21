#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
bash -n "$root/hack/locality-lab-profile-check.sh" "$root/hack/verify-locality-incarnation-gate.sh"
jq -n -e -L "$root/hack" '
 include "locality-lab-profile";
 {spec:{automountServiceAccountToken:false,restartPolicy:"Never",containers:[{command:["test"]}]}}
 | locality_lab_pod("check") as $good
 | [($good|.spec.containers[0].securityContext.privileged=true),
      ($good|.spec.containers[0].securityContext.allowPrivilegeEscalation=true),
      ($good|.spec.containers[0].securityContext.readOnlyRootFilesystem=false),
      ($good|.spec.containers[0].securityContext.runAsUser=1),
      ($good|.spec.containers[0].securityContext.runAsGroup=1),
      ($good|.spec.containers[0].securityContext.seLinuxOptions.type="container_t"),
      ($good|.spec.containers[0].securityContext.seccompProfile.type="Unconfined"),
      ($good|.spec.containers[0].securityContext.capabilities.add += ["SYS_CHROOT"]),
      ($good|.spec.containers[0].securityContext.capabilities.add |= .[:-1]),
      ($good|.spec.containers[0].securityContext.capabilities.drop=[]),
      ($good|.spec.volumes += [{name:"host",hostPath:{path:"/"}}]),
      ($good|.spec.automountServiceAccountToken=true),
      ($good|.spec.containers += [{name:"extra"}]),
      ($good|.spec.containers[0].volumeMounts[0].mountPath="/host")] as $bad
 | if ($good|locality_lab_pod_valid) and ($bad|length==14 and all(.[];locality_lab_pod_valid|not))
   then {result:"passed",positiveCases:1,negativeCases:14}
   else error("lab privilege profile accepted a mutation") end
'
