# ADR 0380: Descriptor-Anchored Joint Attachment and Route Observations

Date: 2026-09-14

Status: locally verified implementation; isolated cl02-before-Kind gate pending

The publication primitive in ADRs 0378–0379 cannot by itself authenticate a live
workload or its routes. Add `NativeRoutingProvider::observe_bound_attachment`
and opaque `NativeAttachmentObservation` as a production integration boundary.
No current agent/CNI caller or packet path is switched by this change.

Only Ready attachments with a valid workload UID and nonzero creation nonce are
eligible. Preparing, Aborting, Deleting and legacy/unbound records fail. The
existing CNI-derived veth plan independently checks full ownership aliases,
reciprocal namespace identity, addresses, indices, MACs and MTU. Its retained
host/peer namespace descriptors are duplicated before route work starts.

Both route connections are opened after entering those exact descriptors, not
by reopening the namespace pathname or relying on the executor's current
namespace. Independent host/peer reads may run concurrently. The existing exact
route/neighbor matcher rejects missing and conflicting state. A second strict
link/path readback brackets the route observations. The opaque result owns the
original record, route plan/readback and held link observation; it has no public
deserialize/clone constructor or permission bit.

Recheck removes the active held observation before its first await. Any link,
path, route or neighbor failure, or cancellation after starting, leaves the
wrapper retired; readback and descriptor access then return `None`. Restoration
does not rearm it. A fresh observation requires complete new checks. Cancelled
read-only namespace workers may finish asynchronously; no claim of immediate
worker/descriptor reclamation is made.

This remains a **snapshot**, not an atomic cross-resource transaction, route
lock, device-lifetime lease or local Required plaintext permission. The supplied
record must still come from the actual CNI journal and be joined to independently
authenticated current placement. Packet-time device invalidation, immutable
publication, current-cut/restart fencing and policy/Service/egress composition
remain separate obligations.

Local validation: 809 workspace tests pass, 26 ignored; route tests include eight
ineligible-record mutations and rejection of valid metadata without real kernel
state. Strict workspace/all-target Clippy, formatting and shell syntax pass.
The disposable fixture requires 28 observations: ten positives, six exact
IPv4/IPv6 route/neighbor drift rejections, two link/path drift rejections, one
cancelled recheck and nine sticky-retirement checks. It independently checks
that failed/cancelled observations expose neither readback nor namespace FDs.
The full fixture must pass cl02 before matching retained Kind.

The route matcher currently dumps namespace route/neighbor tables. This adapter
is not a polling loop or measured scale optimization. Batched startup/inventory
reuse, bounded worker admission and equal-workload resource measurements remain
integration/stabilization requirements; repeated per-attachment table dumps must
not be presented as a scalable steady-state design. Live runtime `f984db9`, core
ABI 15 and encryption ABI 2 remain unchanged. Full Phase 9 and S1–S5 stay open.
