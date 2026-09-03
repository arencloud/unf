# ADR 0127: Bind egress activation to gateway and local-path proof

**Status:** Accepted and implemented for the Phase 8.5 path-activation slice

## Context

Source and gateway application acknowledgements established bilateral control
plane readiness, and the source dataplane could consume pre-certified path
state. Neither fact alone was sufficient to cross `Fenced -> Active`. The
controller cannot attest source-local kernel routes, while a source route does
not prove that every selected gateway has the exact bilateral contract.
Persisting an active bank across process replacement would also inherit stale
authority without rechecking either side.

## Decision

The internal authenticated API exposes a strict schema-v1 source activation
grant. It is issued only to the same current Pod-bound agent that fetched the
exact admitted source projection. The grant binds controller epoch, projection
and contract revisions, recipient Node name/UID, contract digest, and sorted
positive application acknowledgements for the complete unique selected-gateway
set. Every gateway application must remain current, non-withdrawn, Pod-current,
and contain the exact source contract. A domain-separated SHA-256 digest detects
wire mutation; TLS and Pod-bound TokenReview remain the authentication boundary.

The source independently verifies that grant against its replay-admitted
projection. It then snapshots the last successfully applied native remote-route
state, checks exact local Node name/UID ownership, reconstructs and reads back
the complete dual-stack route plan, rereads each configured uplink's interface
index and MTU from sysfs, and rejects a route snapshot changed during
acquisition. Exact gateway name/UID, family transport/next hop, route revision,
lease epoch, output interface, and MTU become path certificates. Only the
combination of the grant and all compiler-required certificates activates every
source in one inactive-bank transaction.

Source authority withdrawal, unavailable or invalid readiness/path evidence,
and synchronization failure return any active source bank to a new atomically
selected fenced bank. Destination ownership is retained so managed targets drop
without capturing unrelated native egress; candidate and selection tables plus
all egress connections are removed. Startup never trusts recovered `Active`
bytes: it first performs the same banked fence transition and requires fresh
controller and kernel proof before reactivation.

## Consequences

No single controller predicate, cached route revision, persistent bank, or
gateway acknowledgement can activate egress. Interface reuse, MTU drift,
gateway UID replacement, route loss, torn snapshots, Pod replacement, restart,
and readiness withdrawal fail closed. Exact replay is idempotent, including
recompilation when path revision or MTU changes.

The native provider currently certifies remote direct-neighbor gateways only.
A selected gateway equal to the source Node remains fenced until local-gateway
address ownership and NAT semantics are implemented. This milestone performs
no source translation and makes no gateway NAT, reverse-flow, failover, Kind,
or OpenShift packet claim.

`make egress-path-activation-test` inherits the verifier-backed source-steering
gate and adds strict grant/admission tests, replacement-Pod rejection,
dual-stack route/transport/interface/MTU certificate derivation, missing-route
rejection, active-to-fenced bank reconstruction, restart fencing, static
boundary checks, and strict Clippy.
