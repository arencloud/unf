# ADR 0037: Controller distribution of NetworkPolicy egress state

Status: Accepted and live verified on dual-stack kind

## Context

ADR 0032 introduced independent ingress and egress IR, ADR 0035 made the five
policy-map families one transaction, and ADR 0036 added source-selected TC
lookup. The controller still compiled NetworkPolicy through its ingress-only
entry point and emitted empty egress snapshot lists, so no populated egress map
could affect live forwarding.

A NetworkPolicy may produce ingress IR, egress IR, or both. Treating one object
as one compiled policy would either discard a direction or require combining two
different selection domains. Distribution also has to retain the existing
revision rule: only an effective compiled-state change advances policy state.

## Decision

The controller compiles every effective NetworkPolicy direction and stores the
resulting ordered IR vector under the object's namespace/name key. Accepted and
rejected status remains object-based, while `compiled_policies` reports the
number of direction-specific IR records.

Snapshot construction partitions all compiled policies by direction. Ingress IR
continues through the identity, IPv4-source, and IPv6-source lowerers. Egress IR
goes only through the IPv4-destination and IPv6-destination lowerers. The five
entry lists are returned in one schema-v4 snapshot and agents activate them with
one `POLICY_CONFIG` revision. Status `resolved_policy_entries` is the aggregate
of all five lists.

An object update compares the complete IR vector with its prior value. It
advances the policy revision only when that vector changes. Deletion removes all
directions produced by the object in the same revision transition.

## Verification

Controller tests prove an egress-only object is accepted, advances revision,
produces populated IPv4 and IPv6 egress entries, and cannot contaminate any
ingress list. Formatting, lint, workspace tests, and the release eBPF build cover
the static boundary.

`hack/verify-networkpolicy-egress.sh`, invoked by `make kind-test`, creates an
exact self-cleaning three-Namespace fixture and requires revision convergence on
both agents. It verifies selected-source default isolation, non-selected source
pass-through, combined Namespace/Pod destination selectors, named TCP and UDP
ports, protocol-only SCTP, bounded IPv4 and IPv6 `ipBlock` exceptions,
direction-correct allow/default-deny event provenance, policy deletion recovery,
and final baseline reconvergence against direct dual-stack Pod addresses.

## Consequences

NetworkPolicy egress is now live in controller snapshots and the TC dataplane;
it is no longer protected by an empty-list distribution gate. Ingress and egress
remain independently selected and lowered even when one Kubernetes object
contains both directions.

This slice does not claim direction-aware operator explanation or simulation,
direction retention in historical export, controller-offline replacement with a
populated egress bank, stateful established/related reply handling, or OpenShift
egress qualification. Those remain explicit Phase 3 work.
