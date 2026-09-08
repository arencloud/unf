#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

export UNF_EGRESS_PROVIDER_NAME=native
export UNF_EGRESS_KIND_EVIDENCE=${UNF_EGRESS_NATIVE_KIND_EVIDENCE:-"${project_root}/.artifacts/phase8-egress-native-reachability-kind.json"}
export UNF_EGRESS_KIND_DIAGNOSTICS=${UNF_EGRESS_NATIVE_KIND_DIAGNOSTICS:-"${project_root}/.artifacts/phase8-egress-native-reachability-kind-$(date +%s)"}

"${project_root}/hack/verify-kind-egress-lifecycle.sh"
