# ADR 0282: Retention-aware independent operations qualification

Date: 2026-09-12

Status: Implemented in both platform gates; full lifecycle runs pending

ADR 0200 deliberately bounds encryption history to 512 records and permanently
reports retention eviction. A cl02 activation represents thousands of paths;
requiring cumulative `lossAffected == false` therefore contradicted that design.
It could only pass a smaller/fresher history, not prove correct larger operation.

Both platform gates now capture history before disruptive work, immediately
before controller replacement, and after convergence. ADR 0280's independent
CLI verifier replays each strict checkpoint, its hash chain and eviction anchor,
counter lower bounds, generation and loss accounting. Input is limited to 1 MiB.
The gate compares verified captures: revisions, generations, all 54 bounded
counters and eviction totals cannot regress; same-revision replay must be exact;
retained overlapping records must agree; adjacent windows must link by digest.
An indexed overlap check avoids pairwise record scans. Both sides must report
zero upstream loss. Explicit upstream loss is not reclassified as retention.

Evidence includes checkpoint hashes, retained-window scope, total and new
retention evictions, and the original loss classification. An entirely evicted
interval is NOT claimed to have independently verified full-history continuity.
The gate no longer calls an evicted history "loss-free causal operations". It
does not clear history, increase retention, alter runtime telemetry, or infer
packet loss from diagnostic retention. Diagnostic proof remains separate from
packet and activation authority.

Pure comparison fixtures exercise retention, idempotence, adjacent windows,
upstream loss, sequence/generation/counter regression, eviction reset and
conflicting overlap. The CLI's separate tests cover strict schema and cryptographic
tamper rejection. The real cl02 retained checkpoint can be replayed and compared
without any cluster mutation. Both platform static gates include these checks.

Verification: both platform static gates and all 13 comparison fixtures passed.
Comparison of the independently verified cl02 capture retained its 917,141
evicted observations, `lossAffected: true`, and zero reported upstream losses;
the emitted evidence explicitly limits completeness to the retained window.

This strengthens independent restart verification while aligning the retention
claim with the architecture. cl02 still must pass before the same runtime is
qualified on Kind; no full platform or heavy-load result is implied.
