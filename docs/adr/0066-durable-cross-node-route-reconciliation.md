# ADR 0066: Cross-node routing converges from complete durable snapshots

Status: Accepted and implemented for local runtime reconciliation

## Context

ADR 0065 proves that one provider-neutral remote Node/block intent can be
lowered into exact native routes, but a production agent needs a complete source
of truth and must survive Node changes, controller interruption, process restart,
and partial kernel failure. Watching Nodes independently on every agent would
duplicate Kubernetes semantics and could expose mixed block/address generations.
Deleting old routes before proving their replacements would turn a recoverable
update failure into an outage.

## Decision

The authenticated controller API exposes `/v1/state/remote-routes` only on its
internal TLS listener. A schema-v1 response is scoped to the authenticated
agent's authoritative Node placement and contains the controller epoch, global
routing revision, local Node/block provenance, and the complete sorted set of
remote Node identity, stable assignment revision, dual-stack blocks, and IPv4
and IPv6 transport addresses.

Only Nodes explicitly opted into primary-CNI ownership participate. Their
transport input is exactly one usable IPv4 and one usable IPv6 `InternalIP` from
Node status. Missing, duplicate, malformed, loopback, multicast, link-local, or
unspecified transport input withholds the entire snapshot. Block assignment
revision remains stable when only transport changes; the complete routing
revision advances. This preserves the distinction between attachment ownership
and routing topology.

Native reconciliation is a separate opt-in agent mode requiring explicit IPv4
and IPv6 uplink names with independent per-family on-link choices. The agent binds the route snapshot to its durable
controller-issued Node-block snapshot, lowers both families independently, and
rejects same-epoch revision regression or content mutation without a revision
change. A new controller epoch permits revision restart.

At startup the agent validates and repairs the owner-only last-known-good route
snapshot before polling the controller. Controller failure therefore retains
known-good routes. A complete newer snapshot is applied transactionally:

1. preflight every destination/table key in the union of old and new plans;
2. add distinct new routes and replace changed same-key routes under rollback;
3. retire stale exact routes only after desired additions succeed;
4. read back the complete desired set and absence of stale keys;
5. atomically persist the snapshot with mode `0600` and directory sync;
6. publish applied epoch, revision, and route count.

Any kernel or persistence failure restores the prior exact plan. Foreign keys
stop mutation. Desired and applied epoch/revision, applied entry count, and a
cumulative reconciliation-error count are included additively in agent status
schema v2 and exposed as metrics. Controller convergence requires the remote
route acknowledgement only for Nodes with accepted primary-CNI block ownership.
`unfctl status` renders the controller routing revision, admitted/invalid
primary-CNI inputs, and each agent's block, route epoch/revision, entry, and
error provenance.

## Alternatives considered

Per-agent Kubernetes watches were rejected because they duplicate controller
admission and cannot provide one atomic cross-object generation. Incremental
add/delete messages were rejected because loss or reordering needs a separate
repair protocol. Expiring routes during controller outage was rejected because
it converts control-plane unavailability into dataplane failure. Treating route
protocol 196 alone as ownership was rejected because exact destination, table,
gateway, interface, scope, flags, and protocol matching is required before
replacement or deletion.

## Verification

`make cni-route-reconciliation-test` composes every earlier CNI gate with strict
controller/agent snapshot tests and the privileged native-route namespace gate.
The real gate proves restart readback/repair, same-key dual-stack next-hop
replacement, addition before stale retirement, complete Node departure cleanup,
rollback after an injected IPv6 replacement failure, idempotence, forwarding,
and foreign-key preservation. Unit tests cover exact transport admission,
stable assignment versus global routing revisions, Node add/change/delete,
strict serialization, local provenance, per-family uplink/on-link paths, secure persistence, epoch transition,
regression/mutation rejection, and desired/applied/error acknowledgement.

The workspace gate passes 227 tests with one separately exercised privileged
route test excluded from the generic invocation.

## Consequences and boundary

Milestone 6.6c is Verified for local controller/agent runtime and real Linux
route lifecycle. Native static routing still assumes the configured per-family
uplink can reach the advertised Node transport address; this is explicit rather
than inferred as one flat L2. BGP, overlay, hybrid, VRF, encryption, aggregation,
and topology-aware backend selection can consume the provider-neutral intent
without changing CNI attachment ownership.

This ADR does not claim a deployed primary CNI. Isolated dual-stack Kind
installation, cross-worker Pod lifecycle, rollback/coexistence qualification,
and subsequent RHCOS/SELinux validation on cl02 remain milestone 6.6d.
