#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${project_root}"

rg --fixed-strings --quiet 'causal-constrained-convergence-v1' crates/unf-egress/src/bgp.rs
rg --fixed-strings --quiet 'EGRESS_BGP_CAPSULE_MARKER' crates/unf-egress/src/bgp.rs
rg --fixed-strings --quiet 'reconcile_bgp_egress_reachability_plans' bins/unf-controller/src/main.rs
rg --fixed-strings --quiet 'reconcile_snapshot(&synchronizer.config' bins/unf-agent/src/main.rs
rg --fixed-strings --quiet '| 8.8d | BGP provider and routing policy | **Verified** |' docs/development/phase8-egress-fabric-plan.md
rg --fixed-strings --quiet '| Causal-constrained BGP convergence | **Verified** |' docs/project-status.md
rg --fixed-strings --quiet '**Status:** Accepted and implemented for Phase 8 milestone 8.8d' docs/adr/0151-causal-constrained-bgp-convergence.md

bgp_image=${GOBGP_IMAGE:-localhost/unf-gobgp:v4.9.0}
fixture_id="${BASHPID}"
network_name="unf-bgp-${fixture_id}"
containers=()
example_pid=""
failure_marker=""
example_log=""

cleanup() {
  local container
  if [[ -n "${example_pid}" ]]; then
    kill "${example_pid}" >/dev/null 2>&1 || true
  fi
  for container in "${containers[@]}"; do
    podman rm --force "${container}" >/dev/null 2>&1 || true
  done
  podman network rm "${network_name}" >/dev/null 2>&1 || true
  if [[ -n "${failure_marker}" ]]; then
    rm -f -- "${failure_marker}"
  fi
  if [[ -n "${example_log}" ]]; then
    rm -f -- "${example_log}"
  fi
}
trap cleanup EXIT

podman image exists "${bgp_image}"
podman network create --ipv6 "${network_name}" >/dev/null

start_speaker() {
  local role=$1
  local name="unf-bgp-${role}-${fixture_id}"
  podman run --detach \
    --name "${name}" \
    --network "${network_name}" \
    --publish 127.0.0.1::50051 \
    "${bgp_image}" \
    --api-hosts=0.0.0.0:50051 \
    --log-level=info >/dev/null
  containers+=("${name}")
}

start_speaker gateway-a
start_speaker gateway-b
start_speaker fabric-a
start_speaker fabric-b

speaker_endpoint() {
  local name=$1
  local published
  published=$(podman port "${name}" 50051/tcp)
  printf 'http://%s' "${published}"
}

export UNF_BGP_GATEWAY_A_ENDPOINT
export UNF_BGP_GATEWAY_B_ENDPOINT
export UNF_BGP_FABRIC_A_ENDPOINT
export UNF_BGP_FABRIC_B_ENDPOINT
UNF_BGP_GATEWAY_A_ENDPOINT=$(speaker_endpoint "${containers[0]}")
UNF_BGP_GATEWAY_B_ENDPOINT=$(speaker_endpoint "${containers[1]}")
UNF_BGP_FABRIC_A_ENDPOINT=$(speaker_endpoint "${containers[2]}")
UNF_BGP_FABRIC_B_ENDPOINT=$(speaker_endpoint "${containers[3]}")

speaker_ipv4() {
  podman inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

speaker_ipv6() {
  podman inspect --format '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$1"
}

export UNF_BGP_GATEWAY_A_IPV4 UNF_BGP_GATEWAY_A_IPV6
export UNF_BGP_GATEWAY_B_IPV4 UNF_BGP_GATEWAY_B_IPV6
export UNF_BGP_FABRIC_A_IPV4 UNF_BGP_FABRIC_A_IPV6
export UNF_BGP_FABRIC_B_IPV4 UNF_BGP_FABRIC_B_IPV6
UNF_BGP_GATEWAY_A_IPV4=$(speaker_ipv4 "${containers[0]}")
UNF_BGP_GATEWAY_A_IPV6=$(speaker_ipv6 "${containers[0]}")
UNF_BGP_GATEWAY_B_IPV4=$(speaker_ipv4 "${containers[1]}")
UNF_BGP_GATEWAY_B_IPV6=$(speaker_ipv6 "${containers[1]}")
UNF_BGP_FABRIC_A_IPV4=$(speaker_ipv4 "${containers[2]}")
UNF_BGP_FABRIC_A_IPV6=$(speaker_ipv6 "${containers[2]}")
UNF_BGP_FABRIC_B_IPV4=$(speaker_ipv4 "${containers[3]}")
UNF_BGP_FABRIC_B_IPV6=$(speaker_ipv6 "${containers[3]}")

wait_for_endpoint() {
  local endpoint=$1
  local host_port=${endpoint##*:}
  local attempt
  for attempt in $(seq 1 40); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/${host_port}" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_for_endpoint "${UNF_BGP_GATEWAY_A_ENDPOINT}"
wait_for_endpoint "${UNF_BGP_GATEWAY_B_ENDPOINT}"
wait_for_endpoint "${UNF_BGP_FABRIC_A_ENDPOINT}"
wait_for_endpoint "${UNF_BGP_FABRIC_B_ENDPOINT}"

if [[ "${UNF_BGP_INJECT_FAILURE:-0}" == "1" ]]; then
  failure_marker=$(mktemp /tmp/unf-bfd-marker.XXXXXX)
  example_log=$(mktemp /tmp/unf-bfd-example.XXXXXX)
  rm -f -- "${failure_marker}"
  export UNF_BGP_FAILURE_MARKER="${failure_marker}"
  cargo run --quiet -p unf-gobgp --example dual_stack_transaction >"${example_log}" 2>&1 &
  example_pid=$!
  for _ in $(seq 1 160); do
    if [[ -f "${failure_marker}" ]]; then
      break
    fi
    if ! kill -0 "${example_pid}" 2>/dev/null; then
      cat "${example_log}"
      wait "${example_pid}"
    fi
    sleep 0.25
  done
  if [[ ! -f "${failure_marker}" ]]; then
    cat "${example_log}"
    wait "${example_pid}" || true
    exit 1
  fi
  podman stop --time 0 "${containers[0]}" >/dev/null
  if ! wait "${example_pid}"; then
    cat "${example_log}"
    exit 1
  fi
  example_pid=""
  cat "${example_log}"
  echo "Phase 8.8e live BFD gate passed: bounded BFD, real peer failure, exact dual-stack route loss, correlated-incident collapse, and surviving-path preservation"
else
  cargo run --quiet -p unf-gobgp --example dual_stack_transaction
  echo "Phase 8.8d live BGP gate passed: dual-stack MP-BGP/BFD, two gateways, two fabric failure domains, Causal Route Capsules, scoped rollback, and exact withdrawal"
fi
