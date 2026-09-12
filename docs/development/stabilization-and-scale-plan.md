# Stabilization and scale qualification

Requested 2026-09-12. Status: planned after Phase 9 closure.

Commit and push each completed step before the next. Platform feature tests run
on OpenShift cl02 first, then isolated Kind; local checks precede deployment.
Both platform results must name the same immutable runtime images. Credentials
remain in ignored, owner-only local files and never enter evidence or Git.

| Step | State | Required exit evidence |
|---|---|---|
| P9 closure | In progress | Compact proof authority, cl02 migration, ciphertext/fail-closed tests, rotation/replacement, cleanup, controller within 2 GiB, then fresh Kind lifecycle |
| S1 baseline and budgets | Pending P9 | Feature/limit inventory; hardware/kernel/MTU/offloads, endpoints/policies/services/flows; idle/loaded CPU, RSS/cgroup peak, BPF memory, throughput, latency percentiles, convergence |
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
| `cfff9c3` stayed within the 2-GiB controller limit without OOM, but Required migration timed out with 5,972 proof selections | Requalify ADRs 0270–0272 on cl02 before Kind; keep exact runtime and evidence provenance |
| A recovery checkpoint briefly needed approximately 912 KB, exceeding its 900 KB bound; a later cut fit | Remove the persistence gap with bounded, integrity-checked storage and explicit migration/recovery compatibility; do not simply increase the bound |
| Six pre-existing unhealthy operators: authentication, console, ingress, insights, kube-controller-manager and network | Investigate DNS/route timeouts separately from UNF pod readiness; network reports an unsafe `DisableMultiNetwork` change. Record attribution and repeat before/after health checks |
| One agent cgroup had no memory limit; the controller's configured request is below measured CPU use | Measure all agents, BPF memory and scheduler impact before choosing requests/limits; avoid OOM-triggered dataplane disruption |
| Large policy and encryption snapshots are repeatedly materialized | Profile steady-state pulls, unchanged-input work and churn before introducing conditional delivery or caching; preserve epoch/digest and authentication checks |
| Encryption operations retain 512 records, while a five-Node Required activation emits 5,972 path observations; cumulative `lossAffected` includes intentional historical eviction | Preserve truthful loss accounting. Develop bounded evidence/coalescing or scoped continuous verification before claiming loss-free operations; do not clear history or ignore the flag to obtain a pass |

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
