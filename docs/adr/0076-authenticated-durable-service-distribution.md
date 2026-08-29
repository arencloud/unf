# ADR 0076: Service intent is authenticated and durable before dataplane use

Status: Accepted and implemented for userspace distribution

## Context

ADR 0075 leaves one retained-last-valid `ServiceSnapshot` in the controller.
Service map design must not start until every selected agent can receive exactly
that versioned intent, reject stale or mutated replay, recover through a
controller outage, and report convergence independently from identity, policy,
and routing. Distribution must reuse the established security boundary rather
than introduce a second trust mechanism.

## Decision

The controller exposes `GET /v1/state/services` only on its internal TLS API.
The handler uses the existing audience-bound ServiceAccount token,
TokenReview, Pod UID, Node placement, and `unf-agent` service-account checks. It
returns the retained compiled snapshot or `503` when no authoritative compiled
revision exists.

Compatibility schema v2 adds service snapshot schema v1 to the exact
controller/agent tuple. Agent-status schema v3 adds desired, applied, and failed
service epoch/revision pairs, service/frontend/backend counts, a cumulative error
counter, and a bounded last-error string. Controller convergence requires the
agent's desired and applied service pair to match the retained compiled pair and
requires no current service failure.

Each configured agent polls at a minimum one-second interval through the same
CA-pinned, hot-reloadable client and projected token used by other internal
state. It strictly deserializes and normalizes every snapshot. Within one
controller epoch, revision regression and content mutation at an unchanged
revision are rejected. A new nonzero controller epoch may begin at a lower
revision. The previous applied snapshot is never changed on rejection.

Before publishing an applied revision, the agent atomically writes pretty JSON,
fsyncs the file and parent, renames into place, and enforces mode `0600` at
`/var/lib/unf/cni/v1/service-snapshot.json`. Symlinked, non-regular, weak-mode,
oversized, incompatible, or malformed durable state is rejected. On startup a
valid copy is restored as desired/applied userspace state before polling, so a
temporary controller outage does not erase known-good intent. This persisted
file is not a BPF map or permission to forward Service traffic.

The portable DaemonSet adds the exact `/var/lib/unf/cni` host directory already
used by primary-CNI variants. OpenShift admission now allows exactly that third
agent-only mount in addition to bpffs and BTF. All four deployment variants
render locally. Earlier live OpenShift admission evidence covered the two-path
boundary; the additive third path must be live requalified during the planned
OpenShift service-fabric milestone.

## Verification

`make service-distribution-test` runs the compiler prerequisite, focused agent
durable adoption/recovery/schema/revision tests, controller service-convergence
tests, strict Clippy, and Kubernetes, OpenShift, Kind primary-CNI, and OpenShift
primary-CNI rendering. The full workspace currently passes 254 tests with one
explicitly privileged route test ignored by the generic gate.

## Consequences

Phase 4.3 is Verified at the userspace and rendered-manifest boundary. Agents can
prove which service intent they have durably accepted without changing packet
handling. Phase 4.4 must separately accept fixed-layout service map and
connection-state semantics, then prove transactional staging, readback,
activation, rollback, recovery, capacity failure, ownership, and cleanup. No
ClusterIP, NAT, backend selection, or kube-proxy replacement claim follows from
this decision.
