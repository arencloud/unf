# Phase 9 Required locality and replica closure

This plan completes the open boundary from ADRs 0293–0294 and 0324. cl02 now runs
`45d85d5`: ADR 0412 verifies scoped rotation, configured recovery and the complete
reply/inventory gate after ADR 0410's retained failure. ADR 0413 passes matching
persistent Kind on identical `45d85d5` images. Both retain
the Native baseline. On the preceding `6d71a30` tuple, configured recovery
and the complete scoped reply/inventory gate pass in ADRs 0395–0396, cl02 first.
The preceding `8db97bb` gate passes in ADRs 0390–0391 after the retained ADR 0387
failure. The
historical `f984db9` Kind runtime is unavailable
after the workstation reboot. ADR 0388 verifies a separately approved persistent
Kind bootstrap on the prior cl02-passing `f984db9` Native runtime; current-runtime
qualification follows cl02 first. Neither fresh bootstrap nor a successful
scoped reply gate is full Phase 9 closure.

The historical read-only cl02 checkpoint (ADR 0388) finds all five Native recovery
journals settled at generation `1789972093114`, without a state reset. This
eventual recovery does not repair or requalify ADR 0387's Required failure.
Its WARN-only agent logs lack the successful key-lifecycle timeline.
ADR 0389 reproduces that retention gap and implements the positive authenticated
tombstone check, preserving all successor/packet authority barriers. Local
regressions pass; immutable runtime qualification follows cl02 first, then Kind.
ADR 0390 verifies that complete cl02 runtime gate, including traffic/ciphertext,
actual inventory counts, retirement and byte-identical existing journals. The
matching Kind gate passes in ADR 0391; production locality consumption remains
required. Missing SIGTERM handling observed during image checks remains a
separate recovery defect, not hidden by the traffic pass. ADRs 0392–0394 repair
signal handling and qualify isolated PID-1 shutdown on cl02 then Kind; configured
fabric rollout/recovery passes on cl02 in ADR 0395 with the complete scoped
traffic gate; ADR 0396 passes matching configured recovery and expanded traffic
on persistent Kind. Both fleets then ran `6d71a30`. These slices do not close L3.
ADR 0397 implements bounded native base/split BTF layout discovery, removing
the future consumer's dependence on diagnostic bpftool/jq subprocesses. Its
local mutation tests pass; the complete native-offset device fixture must pass
cl02 before Kind. Layout metadata alone grants no packet authority.
ADR 0398 passes the complete native-offset fixture on cl02, including independent
layout parity, lifetime/publication checks and unchanged CNI journals. Matching
persistent Kind remains required; live runtime stays `6d71a30`.
ADR 0399 retains Kind's pre-BPF rejection of documented compiler-attribute BTF
tags and adds a regression-backed parser repair. Offline metadata replay is
not live qualification; the rebuilt fixture must pass cl02 again before Kind.
ADR 0400 passes the complete repaired `90cb651` fixture on cl02, with exact
layout parity, traffic accounting, cleanup and journal preservation. The
same immutable image must now pass persistent Kind.
ADR 0401 passes that complete matching Kind gate. Native bounded kernel-layout
discovery is qualified on both deployed kernels; actual authenticated packet
consumption, migration and L4/L5/Q remain open.
ADR 0402 adds locally verified per-incarnation journal retirement before durable
teardown, with failure/retry fences and single-record rollback. The kernel gate
and actual bank publisher must install and consume this boundary; no live
locality permission is enabled by the journal API alone.
ADR 0403 adds the kernel-backed incarnation gate: exact journal registration,
full-nonce/serial leases, synchronous scoped deletion and no tombstone growth.
Local regressions pass; real kernel qualification is next on cl02 then Kind.
The live authenticated bank consumer and restart fencing are still pending.
ADR 0404 passes the real kernel/journal gate on cl02 with immutable `bbb5a65`
diagnostics, exact existing-journal preservation and reviewed logs. Matching
Kind is next; this is not yet production packet consumption.
ADR 0405 passes matching Kind on the identical immutable image, preserving
existing journals and reviewing retained logs. The kernel/journal gate is now
qualified on both kernels; authenticated bank/packet integration remains next.
ADR 0406 adds typed observed-bank preparation, exact placement/journal joining,
batched route scans, same-socket namespace coordinates and cancellation-safe
bounded work. Local regressions pass; the combined real-kernel fixture must
pass cl02 then Kind. Frozen device maps, packet publication and agent consumption
remain pending; this preparation does not admit packets.
ADR 0407 passes the complete observed-bank fixture on cl02, preserving all
116 existing records. Matching Kind follows. The log audit separately finds
recurring key-floor/witness failures and an incomplete attestation cut; this
encryption-health finding requires repair/requalification, not a state reset.
ADR 0408 passes matching Kind on the identical diagnostic, preserving journals
and reviewing retained logs. Observed-bank preparation is qualified on both
kernels; production bank/packet integration and full lifecycle closure remain.
ADR 0409 reproduces and repairs a viable-key-transition progress stall behind
a faster member's issuance floor, preserving complete-cut and drain barriers.
Current-runtime cl02-before-Kind requalification remains required; other
warning causes and actual locality packet integration are not closed by it.
ADR 0410 deploys `7fbf7ee` on cl02 with successful provenance/CNI/journal checks,
but retains the newly exposed activation drain-window failure. Kind stays on
`6d71a30`; repair and repeat cl02 qualification before advancing the candidate.
ADR 0411 reproduces the activation failure and caps drain at the predecessor's
sealed expiry without extending authority or skipping zero-state retirement.
The rebuilt runtime still requires cl02-before-Kind qualification.
ADR 0412 passes that scoped cl02 qualification on `45d85d5`, including common
key activations 6480–6483, ciphertext and exact preservation of 116 records.
Matching Kind is next; production locality integration and full lifecycle stay open.
ADR 0413 passes matching persistent Kind, including common activations 163/164,
the full scoped reply/inventory gate and exact journal preservation. Both fleets
run `45d85d5`; resume production L3 bank/packet consumption, then L4/L5/Q.
ADR 0414 implements a separate sealed endpoint-linear bank, exact shared-FD
binding, private device seeds, the bounded preparation worker and original-cut
publication fence. Isolated kernel qualification is pending on cl02 before
matching Kind. The actual agent packet path, compatibility/restart boundaries
and L4/L5/Q remain open; a redirect request is not observed delivery.
ADR 0415 passes the complete repaired `b432bec` bank diagnostic on cl02: 28
native checks, nineteen kernel decisions, exact sealing/publication and nonce
retirement, with unchanged production journals and full log review. Matching
Kind follows on the identical image. This does not qualify production delivery.
ADR 0416 closes that paired isolated bank gate on corrected `fd416df`, cl02
first then identical-image Kind, including exact cleanup inventories, unchanged
journals and full log review. Actual socket delivery and production L3
integration remain next; L4/L5/Q are not promoted.
ADR 0417 adds the bounded actual-socket gate: eight positive and sixteen
negative TCP/UDP dual-stack cases, retaining every existing native/kernel
check. cl02-before-Kind immutable qualification remains required; synthetic
policy input and native replies do not qualify production composition.
ADR 0418 passes that complete `35f9e1b` gate on cl02 then identical-image Kind:
eight actual successful exchanges and sixteen denials on each platform,
complete cleanup, unchanged journals and reviewed logs. Production admission
coordination and packet composition remain required; L3/L4/L5/Q stay open.
ADR 0419 implements the shared applied-writer admission coordinator with
cancel/failure-safe guards and O(1) publication locking. Its expanded kernel
and socket fixture requires cl02 then identical-image Kind. Actual production
writer hooks and packet wiring remain open, not inferred from library tests.
ADR 0420 passes the complete coordinated-admission gate on cl02 then matching
Kind, retaining all native/kernel/socket checks and full log/state review.
Next close the durable startup/rollback boundary before production writer and
packet integration. L3/L4/L5/Q remain open; live runtime is still `45d85d5`.
ADR 0421 adds the durable schema-5 journal reader floor before locality lease
issuance, preserving records while blocking unhooked reopen/older CNI writers.
The complete diagnostic adds a frozen-old-agent rejection check; immutable
cl02-before-Kind qualification and actual startup fencing remain required.
ADR 0422 passes that complete reader-floor gate on cl02 then matching Kind,
including the frozen old executable's rejection, all kernel/socket checks,
unchanged production journals and log review. Actual early runtime-map fencing
and production agent/packet wiring remain next; L3/L4/L5/Q stay open.
ADR 0423 adds exclusive owned runtime pins, atomic fresh creation, exact loaded
map-ID verification and reopen withdrawal of fence/bank/continuations. Missing
pins are never silently recreated. The complete paired diagnostic and actual
agent startup/boot decision remain pending; production is still `45d85d5`.
ADR 0424 passes the full runtime-owner gate on cl02 then identical-image Kind,
including armed reopen withdrawal, exact bindings and retained failure cases.
Production journals/runtime remain unchanged and logs are reviewed. Actual
agent startup/boot fencing and consuming integration are next; L3/L4/L5/Q stay open.

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
| L3 consuming integration | In progress — ownership prerequisites and isolated target-device lifetime verified on both platforms, ADRs 0339–0346; live candidate distribution/status/retirement verified cl02 then Kind, ADRs 0353–0354 | Explicit wire/map compatibility and restart migration; continuous source/peer lifetime and exact attachment/route readback; banked publication and packet-policy-first consumption; status/explanation without claiming observed delivery from placement alone |
| L4 cl02 validation | Pending | Same-Node and mixed local/remote replicas; IPv4/IPv6 TCP/UDP; PodIP, Service and translated ports; policy isolation and replies; positive remote ciphertext and zero remote Required plaintext; move/replacement/recovery; full fixture cleanup |
| L5 matching Kind validation | Pending | Same immutable runtime and L4 matrix after cl02; retained state preserved; observer failures and losses remain failures |
| Q complete Phase 9 lifecycle | Pending | Full current-runtime cl02 lifecycle then independent matching Kind, including staged Required baseline, rotation, failure/recovery, composition, history and cleanup; update release pins and platform status only with complete evidence |

### L3 consuming-boundary checklist

ADR 0347 adds the locally verified nonce-bound controller/wire distribution
boundary. Current-Pod/Node authentication, guarded placement coordinates,
bounded wire and independent source replay do not activate locality. ADR 0348
adds the locally verified Required-only background agent fetch, bounded stream,
single replay slot and current-cut handoff. ADR 0349 adds locally verified
candidate-only status with explicit false kernel/delivery claims. Live
cl02-before-Kind distribution qualification remains pending.
ADR 0350 adds its opt-in platform gate, joining each worker observation to
Kubernetes metadata, its public plan and fresh applied reports, with Native
candidate retirement. Two positive and 105 negative local gate cases pass.
ADRs 0353–0354 verify the complete live expanded gate on identical `f984db9`
images, cl02 before retained Kind, with reviewed logs and preserved state.
This closes candidate distribution, not continuous lifetime or packet admission.
ADR 0355 adds locally verified descriptor-retaining veth observations, strict
rechecks and sticky retirement. Isolated cl02-before-Kind qualification remains
pending; holding namespace FDs does not pin device placement or close L3.
ADR 0356 verifies its complete isolated cl02 fixture; matching Kind is next.
ADR 0357 verifies the identical retained-Kind fixture and complete log/state
audit. Both snapshot prerequisites pass; continuous packet-time proof is next.
ADR 0358 investigates a separate drop-only TC program reading current device/
peer namespace cookies against independent socket observations. This is not
yet kernel-qualified or production authority; cl02 must precede matching Kind.
ADR 0359 verifies its complete corrected drop-only cl02 gate, including current
peer namespace cookies after move/return. Matching retained Kind remains next;
continuous safe delivery and authenticated source/target ownership stay open.
ADR 0360 records Kind's split-module metadata failure before BPF load and a
locally checked all-layout agreement correction. The revised immutable fixture
must pass cl02 before Kind; neither full platform row is closed by this repair.
ADR 0359 records the corrected `03984e9` image's complete cl02 rerun; matching
retained Kind remains required before this isolated readback primitive closes.
ADR 0361 verifies the matching corrected Kind gate with all ten checks and
current/rotated logs. Both kernels support this isolated readback primitive;
source/target ownership binding and lifetime-safe consumption remain next.
ADR 0362 implements an isolated two-ended device-map lease experiment for the
delivery-lifetime gap. Kernel-reference semantics are audited as a design lead,
not a completed production proof. Both platform gates remain required.
ADR 0363 verifies the corrected serial cl02 gate with sixteen deliveries and
fourteen denials. Matching Kind is next; concurrent lifetime and authenticated
ownership/publication/packet composition remain separate open boundaries.
ADR 0364 verifies the identical retained-Kind serial gate and complete log/state
review. Both kernels pass the isolated delivery/invalidation mechanism; it is
not yet authenticated production locality or a concurrent lifetime guarantee.
ADR 0365 adds full kernel alias and administrative-up checks to that diagnostic,
using the real CNI alias derivation on synthetic bound fixture records. Local
layout/adapter checks pass; expanded cl02-before-Kind execution remains next.
ADR 0366 verifies all 62 expanded cl02 attempts and the complete log/state audit.
Matching Kind remains next; this is not live attachment/placement authentication.
ADR 0367 verifies the identical expanded Kind gate, cleanup and retained logs.
Both kernels pass the serial ownership/admin-state mechanism; concurrent
lifetime and the authenticated/banked production consumer remain open.
ADR 0368 replaces fixture target seeding with a non-transmitting kernel-context
invocation. Local adapter/workspace checks pass; wrong-context and full traffic
qualification remain pending on cl02 before retained Kind.
ADR 0369 verifies the complete cl02 context-acquisition and 62-probe traffic
gate, including cleanup, fresh convergence and reviewed logs. Matching Kind
remains next; concurrent lifetime and authenticated production admission stay open.
ADR 0370 verifies the identical Kind context/traffic gate, cleanup and retained
log review. Both kernels pass this prerequisite; concurrent movement and the
immutable, authenticated production consuming boundary remain open.
ADR 0371 implements the next bounded concurrent target-peer movement fixture,
with exact sequences/run tokens, per-CPU counters and independent receiver-loss
checks. Local checks pass; the complete cl02-before-Kind gate remains pending.
ADR 0372 verifies the complete cl02 serial/concurrent gate with working foreign
positive controls and zero unauthorized foreign delivery. Its 136 requested but
unobserved redirects remain an attribution gap, not a lossless result. Matching
Kind and production lifetime/publication/consumption remain open.
ADR 0373 verifies that matching Kind experiment and full current/rotated log
review. Its 43 unobserved redirects remain a finding. Four-endpoint device-map
invalidation is the next lifetime investigation; full L3 and Phase 9 stay open.
ADR 0374 adds locally checked references for all four endpoints so peer
unregister can invalidate admission until explicit rebind. The expanded serial,
slot-readback and concurrent gates require cl02-before-Kind qualification.
ADR 0375 verifies that complete cl02 gate, including exact missing-peer slots
through return, continued denial and explicit recovery. The bounded run has
zero unobserved redirects by remaining revoked, not by transparent handoff.
Matching Kind and the authenticated immutable production consumer remain open.
ADR 0376 verifies that matching Kind gate, including all seventy serial checks,
40,000 concurrent packets, sticky slot invalidation and explicit recovery.
Generation-coherent publication and authenticated production consumption are next;
full Phase 9 and stabilization remain open.
ADR 0377 implements a locally checked whole-program dispatch experiment for
generation-coherent publication and retirement, retaining sealed map descriptors
and exact sequence attribution. The complete cl02-before-Kind gate is next;
authenticated production attachment/address/route consumption remains open.
The first cl02 publication run failed at the fixture's dotted bpffs directory.
ADR 0377 records the corrected separate private mount and retained failure;
the entire corrected-image cl02 gate remains required before Kind.
ADR 0378 verifies that complete corrected cl02 gate, including exact per-sequence
publication attribution, last-reference retirement and frozen-bank invalidation.
Matching retained Kind is next; no production locality permission is enabled.
ADR 0379 verifies that identical Kind publication/retirement gate, with complete
sequence attribution and current/rotated log review. Both isolated mechanisms
pass; authenticated production attachment/address/route consumption remains open.
ADR 0380 implements the locally verified joint attachment/route snapshot API,
with descriptor-anchored route reads and sticky recheck/cancellation retirement.
Its isolated cl02-before-Kind gate is next. Journal/placement authentication,
bank consumption and scale-efficient inventory integration remain open.
ADR 0381 verifies the complete isolated cl02 joint observation gate, including
all 28 drift/recovery/cancellation checks and full log/state review. Matching
Kind remains required before this snapshot prerequisite closes.
ADR 0382 verifies matching Kind's complete 28-check ledger and current/rotated
logs on the identical image. Stale-safe actual journal inventory integration is
next; neither snapshot API alone grants production locality permission.
ADR 0383 adds locally verified stale-safe journal cuts and bounded read copies.
Actual agent inventory selection and locked consumption must use the cut; it is
not itself journal/placement joining or a packet permission. Runtime gates remain.
ADR 0384 joins the actual transaction-server journal to replayed placement with
exact address/UID matching, stale-cut checks, bounded selected copies and
candidate-only counts. All 820 workspace tests and strict Clippy pass; no live rollout or
kernel/packet admission is claimed. The retained Kind runtime is unavailable
after the workstation reboot; fresh qualification cannot replace continuity evidence.
ADR 0385 adds the locally verified opt-in live inventory counter/retirement
observer, requiring the existing CNI UID/nonce and locality placement gates.
Its complete cl02-first runtime gate remains pending; counts are not kernel proof.
ADR 0386 requalifies the existing `f984db9` cl02 Required reply baseline before
rollout and verifies/pushes immutable `d007071` candidate images. Admission
retries remain recorded; the new inventory runtime is not yet qualified.
ADR 0387 verifies the guarded `d007071` cl02 rollout and exact journal
preservation, but its complete Required gate fails at generation admission.
Missing key epoch 6117 and deferred drain/catch-up warnings require investigation
before another platform promotion. Fixture cleanup succeeds; four pending
encryption generations remain despite fresh ordinary policy/Service reports.

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
ADR 0345 records that complete cl02 rerun on `40def8e`, including explicit
private RPF/return-route evidence, exact statistics and final convergence.
Matching revised-image Kind remains required.
ADR 0346 verifies that identical-image Kind rerun, including private 0/2 RPF
settings with valid return routes, exact attempt/denial statistics and cleanup.
The tested target-device reference mechanism passes both platforms; it is not
yet the authenticated/banked UNF locality consumer or a source/peer lifetime proof.

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
