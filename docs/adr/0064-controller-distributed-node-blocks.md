# ADR 0064: Primary-CNI node blocks are explicitly opted in and controller distributed

Status: Accepted and implemented for startup distribution

## Context

The local CNI lifecycle verified by ADR 0063 accepted manually configured IPv4
and IPv6 node blocks. That was sufficient for isolated resource transactions,
but not for a cluster: every agent needs an authoritative assignment, agents
must not obtain another Node's block, overlapping blocks must fail closed, and
controller convergence must distinguish a persisted assignment from one that
has merely been desired.

The existing overlay deployment must remain unchanged. This slice also cannot
claim cross-node reachability: distributing blocks does not install remote
routes or recover them after Node changes.

## Decision

Primary-CNI participation is explicit. The controller considers only Nodes with
`network.unf.io/primary-cni=enabled`. For each opted-in Node it reads the
authoritative Node UID and `spec.podCIDRs` (falling back to the singular
`spec.podCIDR` only for input compatibility). A valid assignment contains
exactly one canonical, usable IPv4 block and one canonical, usable IPv6 block.
The bounded `unf-ipam` validation rules remain authoritative.

Reconciliation is deterministic and order independent. If either family
overlaps another candidate, both Nodes are rejected; a missing UID, missing
family, extra family, non-canonical CIDR, or unusable block is also rejected.
The controller status reports assigned and rejected counts. Accepted assignments
receive stable per-Node revisions: an unrelated Node change does not invalidate
an unchanged agent acknowledgement, while removal/rejection and later restoration
receives a new revision. Kubernetes watch relists build a complete replacement
set while the last-known-good assignments remain served, then swap atomically at
`InitDone`; unchanged assignments retain their revisions and departed Nodes are
retired.

An agent authenticated by the existing audience-scoped Kubernetes token may GET
`/v1/state/node-block` on the internal TLS endpoint. TokenReview plus current Pod
UID and authoritative Pod placement bind the request to one Node; the endpoint
returns only that Node's schema-v1 snapshot. The strict snapshot contains its
revision, Node name, Node UID, and exact dual-stack provider provenance.

When the CNI transaction socket is enabled without manual blocks, the agent
requires a controller URL, fetches and validates its snapshot before binding the
socket, and checks it against any durable attachment journal. Provider drift
with retained attachments fails startup. The accepted snapshot is atomically
replaced at an absolute, non-symlink path, synced, and restricted to mode 0600.
Only after persistence does the agent publish the assignment as applied. Agent
status additively carries desired and applied node-block revisions, and cluster
convergence requires their exact per-Node match for opted-in Nodes.

The paired manual block flags remain a development-only override. They do not
acknowledge a controller assignment. Changing an in-use assignment requires the
ownership procedure from ADR 0057: drain the Node, remove owned attachments,
then restart against the new assignment. Runtime block rotation is not part of
this slice.

## Alternatives

Enabling every watched Node would silently affect overlay installations.
Trusting agent-supplied blocks would permit duplicate allocation domains.
Rejecting only the later overlapping Node would make the result depend on watch
order. A global acknowledgement revision would make an unchanged Node appear
stale whenever another Node changed. Persisting a new snapshot before checking
the attachment journal could replace the last-known provenance even though the
agent must fail startup.

## Verification

`make cni-node-block-test` repeats the complete local CNI lifecycle gate, then
verifies canonical block overlap and strict snapshot serialization, controller
opt-in/default behavior, exact family validation, order-independent overlap
rejection and recovery, atomic relist/departure handling, stable per-assignment
revisions, and convergence fencing until desired/applied acknowledgement. Agent
tests verify manual/distributed
argument boundaries, snapshot schema/target validation, atomic mode-0600
persistence, and symlink rejection. Strict lint covers the changed controller,
agent, state, and IPAM surfaces.

## Consequences

Milestone 6.6a is Verified. The controller-to-agent startup distribution boundary
is implemented without changing the overlay manifests. Cross-node route intent,
typed kernel lifecycle and recovery, runtime route reconciliation, cluster CNI
installation, and isolated dual-stack primary-CNI qualification remain required.
