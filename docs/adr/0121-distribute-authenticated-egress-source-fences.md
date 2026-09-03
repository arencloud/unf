# ADR 0121: Distribute authenticated egress source fences

**Status:** Accepted and implemented for the Phase 8.5 live source-distribution slice

## Context

ADR 0120 gave the agent transactional ownership of the fixed egress maps, but
no controller route could feed those maps. Activating an issued contract at the
same boundary would be unsafe: source-local path evidence and the TC steering /
NAT stages are not implemented yet. The controller also does not yet watch a
native UNF egress API, so production desired-state ownership must remain empty
until that separate adapter is added.

## Decision

The internal TLS API exposes authenticated `POST /v1/state/egress-source`.
The request is a strict, bounded schema/capability advertisement. Existing
Pod-bound TokenReview authentication determines the Node; no Node selector is
accepted from request data. The controller resolves the Node UID from its
authoritative NodePort Node record and issues only desired material stored for
that exact Node. Absence returns `204 No Content` and never synthesizes intent.

The wire response is a self-contained schema-v1 envelope containing the exact
Node projection, normalized model, and all contract facts. The agent obtains
its Node UID independently through the existing authenticated Node snapshot,
then replays the entire contract and applies the monotonic projection ledger.
Every plan is compiled with a `Fenced` admission and no path certificates into
the inactive ABI-v1 bank. Existing readback, rollback, and one-pointer activation
then publish the fence transaction. Equal responses are idempotent; transport,
authentication, schema, capability, recipient, replay, regression, or map
failure retains the last-known-good bank and ledger.

On restart, the agent reconstructs the applied controller epoch, projection
revision, contract revision, and (for non-empty source banks) contract digest
from the pointer-selected map bank before polling. Regression and same-revision
mutation are therefore rejected across process lifetime, not only in memory.

The advertised capability set means the agent understands and can lower those
contract semantics. It does not authorize `Active`: only later verified path
certificates and packet-stage readiness may cross that admission boundary.

## Consequences

The live source distribution path now reaches persistent maps without turning
reference contracts into an unverified packet claim. Controller state is
deliberately empty in production until a watched native/OpenShift desired-state
adapter populates it. No egress address is configured, no gateway projection is
served live, and no TC steering, SNAT, reverse NAT, or packet behavior is claimed.

`make egress-live-distribution-test` inherits the real-kernel map transaction
gate and adds exact-Node controller projection, envelope mutation, independent
agent advertisement, strict Clippy, and fail-closed distribution checks.
