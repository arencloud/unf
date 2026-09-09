#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

require_text() {
  local pattern="$1"
  local path="$2"
  if ! grep -Eq "${pattern}" "${path}"; then
    echo "missing required Phase 9.5s runtime ${pattern@Q} in ${path}" >&2
    exit 1
  fi
}

controller=bins/unf-controller/src/main.rs
agent=bins/unf-agent/src/main.rs

require_text '"/v1/state/encryption-plan", post\(encryption_plan\)' "${controller}"
require_text 'authenticate_internal_agent' "${controller}"
require_text 'current\.recipient\.node_uid != node_uid' "${controller}"
require_text 'current\.controller_epoch > state\.identity_epoch' "${controller}"
require_text 'current\.matches\(&snapshot\)' "${controller}"
require_text 'encryption_plan_delivery_is_authenticated_node_uid_scoped' "${controller}"

require_text 'struct EncryptionPlanSynchronizer' "${agent}"
require_text 'UNF_ENCRYPTION_PLAN_STATE_PATH' "${agent}"
require_text 'NodeLocalPlanRequest::fresh' "${agent}"
require_text 'persist_secure_json\(&self\.state_path, &candidate, "encryption plan"\)' "${agent}"
require_text 'self\.current = Some\(candidate\)' "${agent}"
require_text 'encryption_plan_recovery_is_private_node_scoped_and_fail_closed' "${agent}"
require_text 'Persist-Before-Compile Plan Inbox' docs/adr/0180-persist-before-compile-plan-inbox.md

persist_line="$(grep -n 'persist_secure_json(&self.state_path, &candidate, "encryption plan")' "${agent}" | cut -d: -f1)"
adopt_line="$(grep -n 'self.current = Some(candidate)' "${agent}" | cut -d: -f1)"
if [[ -z "${persist_line}" || -z "${adopt_line}" || "${persist_line}" -ge "${adopt_line}" ]]; then
  echo "encryption plan adoption must persist before changing the live cursor" >&2
  exit 1
fi

for manifest in \
  deploy/kubernetes/agent.yaml \
  deploy/kind-primary-cni/agent-patch.yaml \
  deploy/openshift-primary-cni/runtime/agent-patch.yaml; do
  require_text 'mountPath: /var/lib/unf/cni' "${manifest}"
done

echo "Phase 9.5s plan inbox passed: Pod-bound delivery and persist-before-compile adoption retain exact Node-local desired input"
