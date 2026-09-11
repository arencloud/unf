# ADR 0235: Monotonic Platform Health Delta

## Status

Accepted

## Context

The Phase 9 OpenShift gate records unhealthy ClusterOperators before migration
and checks platform health again after exact cleanup. Its original equality
check rejected both regressions and improvements. A qualification run that
repairs pre-existing operator degradation must not fail merely because the
final unhealthy set is smaller than the admitted baseline.

## Decision

Treat the initial unhealthy ClusterOperator names as the maximum admitted set.
At the final boundary, compute the exact set difference `final - baseline` and
require it to be empty. Record the baseline, final, and newly unhealthy sets in
the evidence artifact.

This is deliberately asymmetric: an operator may recover during qualification,
but a newly unhealthy operator always rejects the run. Node readiness and all
UNF-specific convergence, traffic, ciphertext, recovery, and cleanup checks
remain independent mandatory gates.

## Consequences

- Platform improvement is accepted and preserved as evidence.
- Any health regression remains fail closed, including a replacement of one
  unhealthy operator by a different unhealthy operator.
- Reviewers can reconstruct the decision from the three recorded sets without
  relying on log ordering or mutable cluster state.
