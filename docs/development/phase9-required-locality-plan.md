# Phase 9 Required locality and replica closure

This completes the open boundary from ADRs 0293–0294 and 0324. Existing
`450de80` fleets remain Native by default while this work is implemented and
qualified. A successful scoped reply gate is not full Phase 9 closure.

## Safety and efficiency boundary

A security identity may name Pods on several Nodes. Same-Node placement must
never produce an identity-wide Native exception that also matches a remote
replica. The selected **final backend address** and source workload address
must both belong to the exact local Node UID and current placement cut.
Policy, Service selection and egress ownership remain authoritative first.

Use one canonical address-owner record per managed Pod address, not a matrix
of every local source/destination identity pair. This bounds stored locality
evidence by addresses rather than pairs. It is a structural cost property,
not a measured CPU, memory or throughput improvement.

A content digest proves integrity, not authenticity, kernel attachment,
routing or packet delivery. Replay a locality certificate against independently
authenticated current placement before admitting it. A consuming implementation
must additionally prove local workload attachment/route ownership and bind the
exact generation; neither a Pod CIDR match nor a controller placement statement
alone authorizes plaintext. Stale or absent locality proof leaves the ordinary
Required path authoritative; it never becomes a Native fallback.

## Milestones and exit gates

| Slice | State | Exit requirement |
|---|---|---|
| L1 exact address ownership | Verified locally — ADR 0325 | Shared validated placement preserves dual-stack IP/UID/identity/Node ownership; ambiguous ownership and capacity fail before expansion; no policy-pair enumeration in the placement-only API; 758 workspace tests pass |
| L2 replayable locality certificate | Verified locally — ADR 0326 | Versioned, canonical, Node/revision-bound certificate; independent placement replay; negative replica, move, UID reuse, stale-cut, malformed-wire and address-substitution tests; 770 workspace tests pass; no packet-path change |
| L3 consuming integration | In progress — L3a verified locally, ADR 0327 | Explicit wire/map compatibility and restart migration; authenticated distribution; exact local attachment/route readback; banked publication and packet-policy-first consumption; status/explanation without claiming observed delivery from placement alone |
| L4 cl02 validation | Pending | Same-Node and mixed local/remote replicas; IPv4/IPv6 TCP/UDP; PodIP, Service and translated ports; policy isolation and replies; positive remote ciphertext and zero remote Required plaintext; move/replacement/recovery; full fixture cleanup |
| L5 matching Kind validation | Pending | Same immutable runtime and L4 matrix after cl02; retained state preserved; observer failures and losses remain failures |
| Q complete Phase 9 lifecycle | Pending | Full current-runtime cl02 lifecycle then independent matching Kind, including staged Required baseline, rotation, failure/recovery, composition, history and cleanup; update release pins and platform status only with complete evidence |

### L3 consuming-boundary checklist

L3a (ADR 0327) implements runtime Pod-UID capture, versioned durable attachment
ownership and veth incarnation cookies. 778 workspace tests and strict Clippy pass;
cl02/Kind kernel lifecycle validation and the actual locality consumer remain
pending. Existing unbound attachments are never silently upgraded into locality
authority. This prerequisite does not close L3.
ADR 0328 verifies the isolated production CNI/kernel ownership qualifier on
cl02 after a creation-only alias seal repair. The full workspace passes 779
tests. ADR 0329 verifies the identical isolated image on retained Kind. Both
live CNI installations remain unchanged; interrupted-creation recovery, live
rollout and the actual locality consumer are still pending.
ADR 0330 implements a versioned, durable nonce and exact pending-pair recovery
for interrupted creation; all 784 workspace tests and strict Clippy pass.
ADR 0331 verifies all four interrupted-creation states and twelve negative
checks on isolated cl02; ADR 0332 verifies the identical image on retained Kind.
Both live fleets remain unchanged. Protocol-compatible live rollout and the
actual locality consumer remain pending.
ADR 0333 adds a locally verified OpenShift candidate-protocol installation gate:
787 workspace tests pass. Its isolated cl02/Kind packaging qualification and
the Kind live upgrade ordering remain open; no live installation has changed.
ADR 0334 verifies the isolated packaging slice on cl02; matching Kind is next.
ADR 0335 completes that identical-image Kind packaging gate. Live rollout,
runtime UID capture and consuming locality integration remain open.
ADR 0336 adds opt-in live runtime UID/nonce/lease and normal-retirement evidence
to the complete selective Required reply gate. Local positive/19-negative
validation passes; real cl02 rollout and matching Kind are pending.
ADR 0337 verifies live cl02 rollout and the complete expanded CNI/reply gate
on `450de80`. Matching Kind remains pending. This closes the cl02 runtime UID
prerequisite only; it does not admit local Required plaintext or close L3.
ADR 0338 extends staging failure checks to Kind's init installer, including
successful-completion semantics and seven negative mutations. Matching Kind
runtime rollout and the live CNI/Required reply gate remain next.
ADR 0339 verifies that matching Kind rollout and expanded live gate: three
runtime UID/nonce bindings and retirements, 24 allowed/eight denied requests,
positive ciphertext and exact cleanup. Both fleets now run `450de80`.
The actual authenticated kernel locality consumer remains the next L3 boundary.
ADR 0340 strengthens ADD/strict attachment readback with descriptor-anchored
namespace IDs and reciprocal veth references; 790 workspace tests pass.
The expanded isolated impostor red/green gate is pending on cl02, then Kind.
This remains snapshot evidence, not a packet-time device-lifetime capability.
ADR 0341 verifies the expanded isolated cl02 gate, including old-accept/new-reject
namespace impostors with matching reciprocal index numbers. Matching Kind is
next; live binaries remain unchanged.
ADR 0342 verifies the identical isolated Kind image and complete red/green
matrix, with retained rotated-log review. Both platform snapshot gates pass;
continuous device-lifetime fencing and authenticated consumption remain open.
ADR 0343 starts an isolated device-reference delivery investigation for that
lifetime gap. The fixture is implemented but emits no verified result until
positive delivery, target invalidation and attempt/drop evidence pass a strict
gate on cl02 before Kind. It is not a live plaintext exception.
ADR 0344 preserves the first cl02 pilot's EEXIST failure and removes ambiguous
filter handles and non-probe counter noise. The exact eight-snapshot statistics
gate passes 96 negative mutations locally; corrected cl02 execution is next.
ADR 0345 verifies the complete corrected cl02 target-device reference gate:
eight positive payloads, four exact denied attempts, rename/down/recovery and
no implicit rebinding on ifindex reuse. Matching Kind remains pending. This
primitive does not establish source/peer lifetime or live locality permission.
The first matching Kind device-reference gate fails its IPv4 positive control.
ADR 0344 records missing fixture reverse routes, observed Node RPF defaults and
the diagnostic gap. Exact reverse-route/RPF readback and failure capture are
added; a corrected-image cl02 rerun must precede matching Kind again.

- Bind both local address owners to independently read-back workload attachment
  and route ownership. Reject host/physical ingress masquerading as a workload,
  foreign interfaces, replaced workload UIDs and reused interface indices.
- Bind the locality digest, identity epoch and active generation into versioned
  distribution/map authority. Preserve recovery of existing schema-2 transport
  generations; never reset state or silently reinterpret old Native records.
- Verify the actual post-Service backend and local delivery path. A local CIDR
  alone, stale attachment snapshot or changed route toward an underlay interface
  must not permit plaintext. Keep policy isolation, stateful replies and egress
  ownership checks ahead of locality handling, including NAT/DSR composition.
- Distinguish placement eligibility, kernel admission and observed delivery in
  status/explanation. Add cold-start, deletion/reassignment, attachment/route
  drift and restart regressions before any live locality activation.

During each platform validation, inspect controller, every agent and installer
logs before/during/after the run. Include previous containers after any restart.
If a tail/byte limit or CRI rotation truncates the window, record it and inspect
retained rotated logs rather than claiming the truncated tail was complete.
Track warnings and request timeouts as well as crashes/OOM/verifier errors.
Never reset maps, authority journals, history or frontiers to manufacture a pass.

Commit and push each verified slice before the next. S1–S5 stabilization remains
separate, with measured equal-workload comparisons and supported load envelopes.
