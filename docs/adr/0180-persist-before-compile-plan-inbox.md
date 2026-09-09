# ADR 0180: Persist-Before-Compile Plan Inbox

- Status: Accepted and implemented for Phase 9.5s
- Date: 2026-09-10

## Context

A secure plan relay is ineffective until the running controller and agent use
it. Adoption must tolerate retries and restarts without briefly exposing an
unpersisted cursor to the local compiler, and a recreated Node must never
inherit the old Node's input.

## Decision

Phase 9.5s introduces the **Persist-Before-Compile Plan Inbox**.

The controller exposes `/v1/state/encryption-plan` only on its internal TLS
listener. Existing TokenReview binds the request to the current agent Pod,
service account, and Node. Delivery additionally checks the authoritative Node
UID and controller incarnation. A missing or byte-current plan returns `204`;
rollback, replacement, malformed state, or same-generation equivocation fails
closed.

The running agent polls independently of generation activation, verifies the
entire nested capsule, and writes an owner-only atomic checkpoint before
changing its in-memory cursor. Startup validates this checkpoint before opening
persistent BPF. Failed pulls retain the exact predecessor. The inbox does not
invoke the compiler and cannot activate any local state.

The controller catalog is intentionally an empty typed boundary until the next
slice supplies a complete-cut plan producer. This keeps distribution and
production independently testable and prevents placeholder plans.

## Consequences

- Plan reception cannot race ahead of durable recovery state.
- Controller outage is availability loss, not plaintext fallback or plan loss.
- Node replacement and controller rollback are explicit failures.
- The existing `/var/lib/unf/cni` host mount covers the new private checkpoint
  on Kubernetes, Kind, and OpenShift without broader host access.
- The next slice must populate the catalog from authoritative policy,
  topology, public-key, Service, and egress inputs, then invoke local compile.

## Verification

`make encryption-plan-runtime-test` inherits 9.5r, checks endpoint and adoption
ordering structurally, exercises authenticated Node/UID scoping and strict
startup recovery, confirms all deployment variants expose only the existing
state mount, and applies strict Clippy to the protocol, controller, and agent.
