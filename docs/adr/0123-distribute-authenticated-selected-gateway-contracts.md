# ADR 0123: Distribute authenticated selected-gateway contracts

**Status:** Accepted and implemented for the Phase 8.5 selected-gateway distribution slice

## Context

The fixed egress contract already defines a gateway projection, but no live
controller endpoint delivered it. Serving every contract to every Node would
expose unnecessary intent and weaken the bilateral proof boundary. Returning
`204 No Content` forever after a gateway had accepted state would also make
withdrawal ambiguous and unsafe for the future NAT path.

This slice must not imply that requesting a source projection proves the source
agent installed it. Source application acknowledgement, gateway host staging,
address ownership, and packet activation remain separate transactions.

## Decision

The internal TLS API adds authenticated `POST /v1/state/egress-gateway`. As with
all agent-only routes, Pod-bound TokenReview determines the service account,
Pod UID, Node name, and authoritative Node UID. The request advertises only
bounded supported schemas and capabilities; it contains no Node or gateway
selector.

After an authenticated source request, the controller independently issues and
replays the exact source envelope before retaining it as eligible distribution
material. This is controller admission, not an agent-application
acknowledgement. Any desired-model change or source-Node deletion withdraws
that retained material.

For each gateway request, the controller derives the exact recipient and
filters admitted source contracts to ready and reachable gateway candidates
whose Node name, UID, capabilities, and lease epoch all match. It then issues
the existing digest-bound canonical `EgressGatewayProjection`. Contracts are
never selected by request data, and an unselected Node receives no foreign
contract.

Gateway distribution owns a separate monotonic revision. Before any admitted
source exists, `204` means there has never been gateway authority. Once that
revision exists, an empty candidate set is sent as a signed/digest-bound empty
projection: an explicit withdrawal. The domain ledger admits withdrawals,
rejects regression and same-revision mutation, and treats exact replay as
idempotent.

The agent polls source and gateway routes independently. It reconstructs its
principal from the separately authenticated Node snapshot, validates recipient,
schema, capabilities, contract integrity, candidate membership, ordering,
bounds, and projection digest, then adopts the result through its gateway
ledger. Transport, authentication, decoding, validation, or replay failure
retains the current in-process gateway projection. After process restart the
ledger is reacquired from the controller before any future packet activation;
this slice creates no gateway packet or host authority that would need recovery.

## Consequences

Selected gateways now receive only the minimum bilateral contract material
needed to reproduce a future source flow proof, with an unambiguous withdrawal
state. Source and gateway polling can make progress independently, and Node
deletion/relist cannot leave a stale source contract eligible.

The endpoint does not acknowledge source-map installation, configure an egress
address/interface/route, stage gateway NAT maps, or process packets. A later
source/gateway activation handshake must require exact application and path
acknowledgements before crossing `Fenced -> Active`.

`make egress-gateway-distribution-test` inherits all earlier Phase 8.5 gates and
adds exact controller aggregation/withdrawal, domain mutation/replay tests,
agent polling assertions, and strict Clippy.
