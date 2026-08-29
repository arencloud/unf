# ADR 0063: CNI success follows one durable link-and-route transaction

Status: Accepted and implemented for the local full-CNI lifecycle

## Context

The durable attachment journal, dual-stack IPAM, portable veth lifecycle, and
native route lifecycle were independently verified by ADRs 0058–0062. Returning
ADD success between any of those operations would expose an unreachable endpoint
or release an address while owned kernel state remained. A short-lived CNI
process also has to recover an invocation interrupted in `preparing`, `aborting`,
or `deleting` without inferring ownership from names alone.

## Decision

`unf-cni` uses a bounded, five-second, one-request-per-connection Unix client for
the root-authenticated local agent API. The transaction schema adds non-mutating
`inspect` so replay observes an exact durable phase rather than parsing an error
message. The local agent remains the sole owner of the attachment/lease journal;
the CNI process remains the bounded kernel actor for one attachment.

ADD runs `inspect/prepare → veth apply/readback → native route apply/readback →
commit`. A Ready replay verifies the durable specification and exact live links,
addresses, neighbors, and routes before returning the same CNI 1.1 result. The
result names host and sandbox interfaces, reports both deterministic MACs,
binds routed IPv4 `/32` and IPv6 `/128` addresses to the sandbox interface, and
reports both gateway/default routes. A Preparing replay resumes idempotently.

Failure after prepare first persists `aborting`. Cleanup deletes exact routes and
neighbors before the exact owned veth, then completes abort and releases the
lease. If conflict or cleanup fails, abort intent and the lease remain durable;
the plugin returns retry and never claims success. A later invocation can inspect
Aborting, repeat exact cleanup, complete it, and begin a fresh ADD. If commit is
ambiguous and the agent has already advanced to Ready, `begin_abort` is rejected,
so the CNI process does not tear down a potentially successful attachment.

CHECK requires an exact Ready record, strict veth and route readback, and exact
equality with `prevResult`. DEL persists `deleting`, obtains cleanup ownership
and interface indexes, deletes routes/neighbors before links, and completes the
journal transition only after kernel cleanup. Repeated DEL succeeds after the
record is absent. A missing sandbox namespace and already-absent interfaces are
explicit cleanup inputs, while foreign same-key routes or same-named links stop
cleanup and retain the lease. Agent unavailability makes ADD, CHECK, and DEL
retryable because none can safely change durable ownership without the journal.

STATUS succeeds only when the transaction service answers. At the time of this
decision, GC remained a bounded pre-ownership no-op pending cluster runtime
authority. ADR 0071 subsequently adds CNI 1.1 valid-attachment reconciliation
without changing the ADD/CHECK/DEL transaction or overlay deployment.

## Alternatives

Committing before route readback would make durable Ready state weaker than CNI
success. Releasing a lease at begin-delete would permit address reuse while host
routes or links still existed. Treating all CHECK input as advisory would miss a
runtime result/configuration mismatch. Guessing recovery from transition error
text would couple correctness to presentation strings. Removing a link after a
foreign route conflict could indirectly delete state UNF does not own.

## Verification

`make cni-lifecycle-test` repeats the standalone veth and route gates, the CNI
protocol gate, CNI/state unit tests, and strict lint. Its privileged atomic gate
uses disposable host and sandbox namespaces plus a journal reopened by every
invocation. It proves Preparing restart recovery, exact dual-stack ADD output,
Ready replay, CHECK success and MTU-drift rejection, route-first DEL, repeated
DEL, and cleanup after the sandbox namespace disappears.

The gate then creates the exact veth with a foreign sandbox default route. ADD
must fail, preserve that route and link, and retain an Aborting record and lease.
After the foreign route is removed, another invocation must finish the retained
abort, reuse the released lowest addresses in a fresh transaction, reach Ready,
and delete cleanly. Unit coverage independently verifies bounded socket framing,
schema mismatch rejection, inspect serialization, and deletion-only route plans
whose zero indexes represent already-absent interfaces.

## Consequences

Milestones 6.2 and 6.2b are Verified. The repository now contains a complete
local dual-stack CNI resource transaction, but not cluster networking support.
Controller node-block distribution, cross-node routing/recovery, installation,
and isolated primary-CNI Kind qualification remain required before deployment.
