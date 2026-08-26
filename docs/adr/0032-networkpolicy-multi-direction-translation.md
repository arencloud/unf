# ADR 0032: Multi-direction NetworkPolicy translation behind an enforcement gate

## Status

Accepted and implemented for userspace translation. Egress dataplane admission
and enforcement remain intentionally disabled.

## Context

A Kubernetes `NetworkPolicy` can isolate ingress, egress, or both directions,
while one `PolicyIr` has exactly one direction. API defaulting also changes the
effective directions when `policyTypes` is omitted or empty. Translation must
preserve these semantics without allowing an egress object into the existing
destination-oriented ingress dataplane.

## Decision

`NetworkPolicyCompiler::compile_directions` produces one independent IR for each
effective direction, ordered ingress then egress. Both IRs retain the Kubernetes
object's stable policy ID and object provenance; the explicit direction
disambiguates decisions and rule IDs.

Missing or empty `policyTypes` applies Kubernetes API defaulting: ingress is
always effective, and egress is additionally effective only when the egress rule
list is non-empty. Explicit `Ingress` and `Egress` values select exactly those
directions. Unknown values fail with a typed error.

The policy Pod selector targets the destination for ingress and the source for
egress. Ingress `from` peers become rule sources; egress `to` peers become rule
destinations. Omitted or empty peer and port lists retain wildcard semantics.
Both directions share selector, protocol, numeric/named port, and bounded range
parsing. ADR 0033 subsequently added bounded egress `ipBlock` translation and
destination-address evaluation.

The established `NetworkPolicyCompiler::compile` entry point remains the
controller's enforcement admission boundary. It delegates to the complete
translator but returns IR only when the result is exactly one ingress policy;
any effective egress direction returns `UnsupportedEgress`. The controller
therefore records egress objects as rejected and cannot advance the policy
revision or publish them to ingress-only agents.

## Verification

Policy tests cover egress-only source selection, peer and port pairing, allow and
default isolation, all implicit/explicit direction defaults, ignored rules in an
unselected direction, unknown policy types, and destination-`ipBlock` rejection.
A controller test proves translated egress remains rejected, does not enter the
compiled policy collection, and does not advance the dataplane revision.

The focused gate is
`cargo test -p unf-policy -p unf-controller --all-features`. Repository-wide
formatting, lint, test, eBPF, and live ingress regression gates cover the retained
enforcement boundary.

## Consequences

The compatibility layer can now express Kubernetes direction/defaulting
semantics and feed the already direction-aware evaluator without redesigning the
ingress API. Existing ingress reconciliation and dataplane snapshots remain
unchanged and fail closed for egress.

This ADR does not claim source-side lowering/maps, TC egress enforcement,
retained-flow direction, simulation/status integration, lifecycle/provenance
recovery, or kind/OpenShift egress qualification.
