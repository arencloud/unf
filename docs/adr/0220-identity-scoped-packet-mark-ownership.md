# ADR 0220: Identity-Scoped Packet-Mark Ownership

- Status: Accepted and implemented for Phase 9.9 remediation
- Date: 2026-09-11

## Context

The first digest-pinned Phase 9 rollout on the five-Node dual-stack cl02
fixture crossed its pre-attachment fleet barrier, after which workstation TCP
connections to the Kubernetes API and SSH timed out on every Node while ICMP
continued to pass. The prior Phase 8 runtime did not exhibit this behavior.
The staged deployer stopped before qualification and made no success claim.

The TC parser deliberately ignores ICMP but processes TCP, UDP, and SCTP on
every non-loopback interface. After allowing a TCP tuple with an unknown source
or destination identity, the encryption finalizer cleared bits 8 through 23 of
`skb->mark`. The route-mark lease owns that field only after an exact managed
identity pair selects Phase 9 authority. On an identity-incomplete physical-
uplink packet, the existing mark can instead belong to OpenShift host
networking, filtering, or another cooperating dataplane. Erasing it had no
ownership proof and explains the protocol-specific management-path loss.

## Decision

UNF introduces **Identity-Scoped Packet-Mark Ownership**. Encryption may mutate
its leased field only after both packet endpoints resolve to managed identities
and an explicit Native or Required decision is validated against the active
causal cut. When either identity is unknown, the finalizer returns to native
processing without changing any bit of the existing packet mark.

Required traffic retains the existing proof-carrying behavior: it overwrites
only the leased field with the selected route mark after policy, Service,
egress, generation, decision, transport, epoch, kernel-readback, MTU, and flow-
lease checks pass. An explicit Native decision between two managed identities
may release the leased field because the same identity-scoped authority proves
that Phase 9 owns the choice. Missing Required authority still drops and never
downgrades to plaintext.

## Consequences

- Host, control-plane, external-to-Pod, and Pod-to-external packets preserve
  foreign mark metadata byte-for-byte when their identity pair is incomplete.
- Managed Required and explicit Native semantics remain unchanged.
- The rule is O(1), needs no map, interface allowlist, protocol exception, or
  platform-specific mark knowledge, and applies equally to IPv4 and IPv6.
- An OpenShift deployment attempt that loses management connectivity is a gate
  failure, not qualification evidence; cl02 must be recovered and the corrected
  immutable tuple must pass the complete gate from a known baseline.

## Verification

The privileged encryption-finalizer test supplies a nonzero foreign mark in a
real UAPI `__sk_buff` context, executes an unmanaged TCP/6443 packet through the
release eBPF tail-call graph with `BPF_PROG_TEST_RUN`, and requires both `PIPE`
and byte-exact mark preservation. The same test retains dual-stack Required,
Native, draining, and revocation assertions. `make encryption-composition-test`
rebuilds the verifier-approved object, executes this regression plus egress and
Service composition, and applies strict Clippy. Fresh Kind and independent
OpenShift qualification remain mandatory before Phase 9 can close.
