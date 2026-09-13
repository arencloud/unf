# Stabilization and scale qualification

Requested 2026-09-12. Phase 9's closure (ADR 0292) was reopened by S1's
transport coverage findings (ADR 0293). Phase 9 and S1–S5 remain open.

Current checkpoint: ADRs 0316–0317 qualify runtime `5ea1bd2` on cl02, then
retained Kind with identical images and no state reset. Each passes 24 Native
allow cases, eight reverse denials, empty-Namespace continuity (232/720 fresh
connections, zero failures), exact cleanup and full agent convergence. Current
UNF Pods have zero restarts. Log warnings, Kind's per-packet log amplification
and operator health findings remain tracked. No sustained-load/resource savings
are claimed.

ADR 0318 adds locally verified Required policy-tracked reply contracts with
explicit initiating-pair provenance and fail-closed schema-2 compatibility.
Both cl02 and retained Kind now run `67c2772` with a Native baseline.
ADRs 0319–0324 implement and qualify the scoped selective Required reply gate
on cl02 first, then identical-image Kind, with exact policy/generation adoption,
public reply provenance, ciphertext and cleanup checks.
ADR 0320 records the first cl02 reply gate failing its IPv6 translated UDP
probe after admission and 11 preceding probes. Failed-capture retention is
repaired; root cause remains under investigation. Native cleanup is positively
verified; Kind was not advanced past that failed cl02 gate.
ADR 0321 records a later destination-side revision mismatch during a failed
Native TCP control and moves capture-object preparation before admission.
This corrects a moving-fixture qualifier, not S4's policy/Service update
continuity requirement. ADR 0322 verifies the corrected scoped cl02 reply
gate (12 Required requests, 12 Native controls, eight reverse denials,
ciphertext and Native cleanup). ADRs 0323–0324 then verify the live-revision
observer on cl02 first and matching retained Kind, closing this reply slice.

Next: finish Required locality/replica coverage and full current
runtime lifecycle qualification, cl02 before Kind. Empty-Namespace no-op
continuity does not establish arbitrary policy/Service update atomicity. Active
tuple collisions and LRU capacity behavior remain load-envelope boundaries.
ADRs 0325–0326 complete the local exact-address placement/certificate slices:
one record per address, independent replay and streamed digest serialization.
The live packet path is unchanged. Kernel consumption and platform locality
tests remain open in the [locality closure plan](phase9-required-locality-plan.md).

Repair evidence is retained chronologically in the ADRs:

- ADRs 0294–0305: explicit Native locality/replies, exact-predecessor receipt
  recovery, key-independent Native publication and immutable build provenance;
  bounded Native gates pass on both platforms with runtime `54f5511`.
- ADRs 0308–0312: continuity failures, dependency-aware namespace invalidation,
  paired captures and exact read-only attribution to expired Service tuples.
- ADRs 0313–0314: owner-claimed expiry, concurrent-touch and encrypted-DSR
  regressions; RHCOS verifier rejection, state-preserving recovery, and the
  minimal fixed-width copy repair proven red/green on isolated cl02.
- ADR 0315: serial rollout rejects failed/restarted candidates while permitting
  the pre-admission staging needed by the fleet barrier.
- ADRs 0316–0317: the repaired runtime passes the expanded Native/churn gate
  on cl02 first, then matching-image retained Kind.

S2 profiling lead, not an attributed CPU result: `policy_snapshot` calls
`dataplane_policy_state` for every authenticated pull; the latter clones the
full cached tuple even on a matching revision and the endpoint returns the
complete JSON body. Measure allocation/serialization and transfer costs before
considering immutable sharing or conditional delivery. Any optimization must
retain current-Pod authentication, authority readiness, cold-start/failed-apply
recovery and epoch/revision fencing, including older-agent compatibility.

Commit and push each completed step before the next. Platform feature tests run
on OpenShift cl02 first, then isolated Kind; local checks precede deployment.
Both platform results must name the same immutable runtime images. Credentials
remain in ignored, owner-only local files and never enter evidence or Git.

| Step | State | Required exit evidence |
|---|---|---|
| P9 coverage repair | In progress | ADRs 0316–0317 qualify Native/empty-Namespace continuity. ADRs 0323–0324 qualify scoped Required replies/ciphertext/cleanup on identical `67c2772` images, cl02 first then retained Kind. Required locality/replicas and full lifecycle qualification remain open |
| S1 baseline and budgets | In progress | Attribute internal DNS/Pod-endpoint failures and operator health first; feature/limit inventory; hardware/kernel/MTU/offloads, endpoints/policies/services/flows; idle/loaded CPU, RSS/cgroup peak, BPF memory, throughput, latency percentiles, convergence |
| S2 control-plane scale | Pending | Profile policy compilation, snapshots, informer churn and agent pulls; remove measured repeated work; bound queues/caches; compare equal input and churn fixtures before/after |
| S3 agent and dataplane efficiency | Pending | Map occupancy/update work, connection creation/expiry, telemetry backpressure, Service selection, encryption and egress under mixed dual-stack load; policy correctness and bounded recovery |
| S4 interactions and soak | Pending | Increasing-load tests for policy, Services, selection/DSR, egress/FQDN/HA, encryption/rotation and observability; outages/replacements under load; no unexplained leaks, drops or growth |
| S5 supported load envelope | Pending | Reproducible resource-versus-load curves, saturation point, latency/loss/recovery bounds, known constraints and supported configurations |

Preserve the existing 2-GiB controller limit and record agent limits before
changes. Choose tighter numerical CPU/memory and latency targets from S1
measurements. Resource improvements need repeatable equal-workload comparisons.
Five-node evidence establishes a lab envelope; higher node counts require their
own evidence. Do not claim unlimited scale or superiority without measurements
(master prompt §§57–59).

## Risks observed during the Phase 9 resume

These observations guide later work; they do not mark S1–S5 complete.

| Observation | Required follow-up |
|---|---|
| Capture-object creation after adoption exposes a destination policy/encryption revision fence; corrected steady-state reply gates pass both platforms | ADRs 0321–0324: keep observer setup before admission; S4 must separately qualify real policy/Service churn continuity without relaxing authority checks |
| Kind's three agent log tails reach the 2-MiB cap; retained current/rotated logs total 20,788,148 bytes in the reply audit; telemetry/egress requests time out before the test | ADR 0324: S1/S3 measure and reduce per-packet log amplification; S4 attribute controller-request continuity. Retained logs have no ERROR/restart; do not infer lossless history or zero operational failures |
| Runtime `571379d` passes expanded cl02 Native isolation/translated-port coverage; DNS/OAuth later recover after initial timeouts | ADRs 0295–0296: fresh matching-image Kind, then controlled traffic continuity during reconciliation/churn; do not turn a steady-state pass into an uninterrupted-service claim |
| Short pre-repair sample: controller 1.335 CPU cores; agents 0.155–0.253 cores with 343–663 MiB cgroup memory; original agent RSS figures withdrawn | ADR 0295 correction: `/proc/1` was host systemd because agents use hostPID. Match the UNF executable within its container cgroup before sampling RSS. Repeat controlled healthy workloads with pinned/shared/file accounting and longer windows; do not compare freshly restarted cgroups as equal workloads |
| S1 synchronized capture and kernel readback show missing same-Node Native and policy-isolated-return decisions despite policy-allowed requests | ADR 0293: reproduce, repair explicit transport coverage without weakening Required/policy checks, measure state/CPU impact, then cl02-first/Kind qualification; assess Required locality/replica/return cases separately |
| `24a66ca` recovered the missing frontier, but the full cl02 gate failed during Required migration; Native cleanup intent left split journals and mixed Prepared/Active key epochs | Repair restart-safe key attestation and generation recovery, preserve exact key expiry and admission barriers, and prove actual cleanup before Kind or scale claims |
| `cfff9c3` stayed within the 2-GiB controller limit without OOM, but Required migration timed out with 5,972 proof selections | Requalify ADRs 0270–0272 on cl02 before Kind; keep exact runtime and evidence provenance |
| A recovery checkpoint briefly needed approximately 912 KB, exceeding its 900 KB bound; a later cut fit | Remove the persistence gap with bounded, integrity-checked storage and explicit migration/recovery compatibility; do not simply increase the bound |
| The persistence gap stranded all five agents at startup: their durable active generation was one exact successor ahead of the controller, with a newer pending Native cut | Qualify ADR 0281's authenticated complete-admission recovery; preserve predecessor checks and verify actual encryption state, not only policy/Service convergence |
| Six pre-existing unhealthy operators: authentication, console, ingress, insights, kube-controller-manager and network | Investigate DNS/route timeouts separately from UNF pod readiness; network reports an unsafe `DisableMultiNetwork` change. Record attribution and repeat before/after health checks |
| One agent cgroup had no memory limit; the controller's configured request is below measured CPU use | Measure all agents, BPF memory and scheduler impact before choosing requests/limits; avoid OOM-triggered dataplane disruption |
| Large policy and encryption snapshots are repeatedly materialized | Profile steady-state pulls, unchanged-input work and churn before introducing conditional delivery or caching; preserve epoch/digest and authentication checks |
| Encryption operations retain 512 records, while a five-Node Required activation emits 5,972 path observations; cumulative `lossAffected` includes intentional historical eviction | ADR 0282 adds independent checkpoint replay and restart comparison with explicit retention and zero upstream loss. Qualify both full platform runs; never clear history or silently raise retention |
| Current `cb59e90` lifecycle runs take several minutes at some Required/workload-change boundaries; path logs show rendezvous retries while agents retain their predecessor | Measure transition latency and proof work under equal inputs. A within-deadline lifecycle pass is not sufficient evidence of fast convergence under heavy churn |
| Qualifier `2e20161` passed the application outage matrix but could not validate capture loss; raw statistics disappeared during cleanup | ADR 0289 retains capture evidence and filters only unrelated traffic. Require an uninterrupted complete cl02 result before Kind and S1, without inferring plaintext absence from an incomplete capture |

A preliminary one-file CLI compression experiment on the captured roughly
22-MB checkpoint produced 795,360 bytes with gzip level 6 and 332,688 bytes with
zstd level 3. This is neither a production-code benchmark nor a codec migration
decision. Any adoption must measure the actual Rust implementation, preserve
bounded decode and integrity checks, and define rollback compatibility.

The follow-up Rust gzip experiment used the same 22,164,122-byte public checkpoint
capture. The existing miniz backend produced 791,134 bytes at its default level
and 788,764 at its highest level: only 2,370 bytes saved, insufficient evidence
for the observed roughly 13-KB overflow. Experimental zlib-rs produced 960,543
and 802,704 bytes; the host C zlib backend produced 772,137 and 802,704 bytes.
These are single-capture size measurements, not production CPU benchmarks;
the exact overflowing cut was not captured. No backend, dependency, recovery
format or bound was changed. The failed experiments were removed before building
the replica-coverage candidate. A bounded persistence solution still needs its
own recovery and rollover verification.

ADR 0277 subsequently implements a versioned, window-bounded fallback only for
cuts whose old gzip representation cannot fit. The actual Rust implementation
round-trips the captured 22,164,122-byte envelope at 336,656 compressed bytes,
versus 791,134 for gzip. Normal compatible writes stay gzip. cl02 transition,
replacement and final-compatible-format evidence remain pending; ADR 0278 adds
explicit zero-persistence-error checks around those lifecycle boundaries.
