# ADR 0384: Real Journal Locality Candidate Selection

Date: 2026-09-21

Status: locally verified; runtime qualification pending

Join replayed locality placement to the actual CNI transaction server's shared
journal, not a second file reader. Only Ready attachments with a workload UID
and nonzero creation nonce are eligible. Match each IPv4/IPv6 lease address to
the exact certificate address and workload UID; exclude absent addresses and
legacy/unbound records. A conflicting UID rejects the selection. This remains
candidate metadata, not independent kernel readback or packet authorization.

Capture the opaque journal cut while holding the transaction mutex. Retain
only matching records with their per-family identities, placement context and
certificate digest. Reuse the existing allocation only when all three inputs
remain current. Cancellation while awaiting the lock, uncertain persistence,
context mismatch or a changed applied placement cut clears the selection.
The future kernel/publication consumer must recheck this cut while holding the
same mutex; these selected records alone are never a consumption capability.

Bound retained logical payload to 16 MiB and account before cloning. This is
not an RSS bound: vector spare capacity and allocator metadata are excluded.
Changed-cut selection scans the journal and binary-searches canonical address
ownership, rather than enumerating identity pairs. Unchanged-cut refresh does
not rescan or clone the selection. No measured performance claim follows.

Candidate status gains selected attachment/address counts and logical payload
bytes. These are last-observation metadata, not a continuously current journal
view. `kernelAdmitted` and `observedDelivery` remain false. Native retirement
clears the inventory with the placement candidate. No wire/map admission ABI,
CNI journal schema or live packet path changes.

Regression coverage includes Ready/delete transitions, unchanged-cut allocation
reuse, absent/legacy ownership, UID/context/digest changes, single-family
selection, lock-wait cancellation, persistence failure and recovery, payload
overflow, observational status and changed applied-cut rejection.
All 820 workspace tests pass, with 26 ignored; strict workspace/all-target
Clippy and formatting pass. Logs are retained in
`.artifacts/p9-inventory-resume-workspace.log` and
`.artifacts/p9-inventory-resume-clippy.log`.

The resume preflight finds all five cl02 agents fresh and converged at policy
1078 / Service 347, with zero UNF container restarts. The 20-minute controller,
agent and installer log window contains 102,697 bytes, no ERROR entries, and
432 bounded-flow-history, four proof-assistance, two key-publication, two
bounded-topology and one clsact warning. Insights upload timeout and the unsafe
network-operator configuration remain open; no platform-health closure is claimed.
Evidence: `.artifacts/p9-resume-20260921-cl02-before` and
`.artifacts/p9-resume-20260921-cl02-state`.

The retained Kind API refuses connections after the workstation reboot and
its `/tmp` runtime wrapper/storage location is absent. Historical evidence is
preserved. Do not silently recreate it or claim retained-state continuity from
a fresh cluster. cl02-first runtime qualification, matching Kind, authenticated
kernel/packet consumption, full Phase 9 and S1–S5 remain open.
