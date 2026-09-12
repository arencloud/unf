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
