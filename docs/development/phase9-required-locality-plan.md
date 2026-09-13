# Phase 9 Required locality and replica closure

This completes the open boundary from ADRs 0293–0294 and 0324. Existing
`67c2772` fleets remain Native by default while this work is implemented and
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
| L2 replayable locality certificate | Pending | Versioned, canonical, Node/revision-bound certificate; independent placement replay; negative replica, move, UID reuse, stale-cut, malformed-wire and address-substitution tests |
| L3 consuming integration | Pending | Explicit wire/map compatibility and restart migration; authenticated distribution; exact local attachment/route readback; banked publication and packet-policy-first consumption; status/explanation without claiming observed delivery from placement alone |
| L4 cl02 validation | Pending | Same-Node and mixed local/remote replicas; IPv4/IPv6 TCP/UDP; PodIP, Service and translated ports; policy isolation and replies; positive remote ciphertext and zero remote Required plaintext; move/replacement/recovery; full fixture cleanup |
| L5 matching Kind validation | Pending | Same immutable runtime and L4 matrix after cl02; retained state preserved; observer failures and losses remain failures |
| Q complete Phase 9 lifecycle | Pending | Full current-runtime cl02 lifecycle then independent matching Kind, including staged Required baseline, rotation, failure/recovery, composition, history and cleanup; update release pins and platform status only with complete evidence |

During each platform validation, inspect controller, every agent and installer
logs before/during/after the run. Include previous containers after any restart.
If a tail/byte limit or CRI rotation truncates the window, record it and inspect
retained rotated logs rather than claiming the truncated tail was complete.
Track warnings and request timeouts as well as crashes/OOM/verifier errors.
Never reset maps, authority journals, history or frontiers to manufacture a pass.

Commit and push each verified slice before the next. S1–S5 stabilization remains
separate, with measured equal-workload comparisons and supported load envelopes.
