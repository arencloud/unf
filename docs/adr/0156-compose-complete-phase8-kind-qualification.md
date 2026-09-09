# ADR 0156: Compose complete Phase 8 Kind qualification

**Status:** Accepted and implemented for Phase 8 milestone 8.10

## Context

The focused Phase 8 gates proved each egress domain independently, but they did
not prove that watched intent, deterministic multi-address HA, temporal DNS and
Internet authority, diversity-quorum reachability, causal operations, recovery,
and platform teardown compose on one long-lived cluster. Milestone 8.10 requires
one committed, machine-readable, kube-proxy-free dual-stack Kind result rather
than a transitive claim from separate successful runs.

Composition also exposed three boundaries that focused tests did not cover:

- a Node acting as both source and gateway must apply the source fence before
  local gateway NAT classification;
- recovery must prefer the durable current Service-selection checkpoint when a
  prepared pending contract produces an equivalent active packet bank; and
- primary-CNI rollback must recognize and remove the exact Node-UID-owned empty
  `unf-egress0` dummy link and resume safely after a complete route-removal
  boundary.

## Decision

`hack/verify-kind-egress-phase8.sh` is the milestone gate. It admits an exact
runtime revision and a separately recorded qualification revision, then runs the
following components serially on the same three-Node Kubernetes v1.35.0 fixture:

1. watched dual-stack EgressPool/EgressPolicy lifecycle, bilateral activation,
   source steering, gateway NAT, operations, recovery, safe reuse, and release;
2. three-gateway measured HA with complete live-shard seeding, graceful drain,
   source-agent replacement, abrupt failure fencing, and exclusive ownership;
3. quorum-authorized FQDN discovery and autonomous expiry;
4. Authority-Carved Internet classification, loss, expiry, and recovery;
5. durable Diversity-Quorum Reachability replay; and
6. live native provider/fabric reachability and recovery.

The qualifier waits for controller-owned Node inventory and agent convergence,
not only Kubernetes Pod readiness. Operations polling remains bounded and never
weakens the required evidence set. Component evidence is hashed into a schema-v1
aggregate. The final rollback validates and removes only exact current-ABI and
primary-CNI-owned state, restores captured CoreDNS and NodePort sysctls, and
requires the isolated no-CNI baseline.

## Evidence

Runtime and qualifier `2f404edcff94becd6d023bd8885c3c71ce4993b4` passed the
uninterrupted gate in 1,013 seconds on `kind-unf-service-dev`. The aggregate is
`.artifacts/phase8-egress-complete-kind.json`, with SHA-256
`c364a99a05f1bd9a1b0416bf3305feabc3de58d25119bfc20b0fc66bb7efbc88`.
It records six component paths, hashes, and durations and confirms exact ABI-v15
plus primary-CNI rollback. This rerun includes proof-authorized full-release
acknowledgement through verified `unf-egress0` absence and zero-churn
warm-standby rejoin with independently replayed contingency state.

Focused regression additionally includes the real-kernel selection recovery
case, agent unit and strict-Clippy gates, the primary-CNI installer/rollback
fixture, and shell/static validation of the composed harness.

## Consequences

- Milestone 8.10 is Verified. The independent digest-pinned OpenShift 8.11 gate
  subsequently passed and closes Phase 8 through ADR 0157; it does not alter or
  retroactively broaden this Kind evidence.
- Kubernetes readiness remains scheduling evidence, never HA fencing or
  promotion authority.
- Equivalent prepared state is not allowed to supersede a durable checkpoint;
  controller reconciliation may safely reissue it after recovery.
- Kind evidence does not imply RHCOS, SELinux, CRI-O, OpenShift EgressIP, or
  five-Node cross-worker behavior. Those claims belong exclusively to 8.11.
