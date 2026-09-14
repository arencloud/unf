# ADR 0377: Whole-Program Device Generation Publication Experiment

Date: 2026-09-14

Status: locally verified fixture; cl02-before-Kind qualification pending

The four-endpoint gate qualifies revocation, but its explicit rebinds occur while
senders are idle. Production publication must not combine an old cached device
pointer with replacement binding/configuration tables. Investigate one dispatch
slot selecting an entire classifier instance with its own maps, rather than
separately replacing related live table entries.

The upstream [program-array update](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/arraymap.c)
exchanges its referenced program pointer and releases the old program reference.
[Program release](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/syscall.c)
defers exposed-program destruction through RCU; subsequent
[program cleanup](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/core.c)
releases its used-map references. These semantics motivate the experiment, not
a completed deployed-kernel proof. Kernel device-map invalidation remains
independent of the publisher.

The private dispatcher drops on an empty or unsuccessful tail call. Each bank
has distinct configuration, cached-pointer, device, ownership, tag, counter and
sequence maps. The publisher requires exact map types/capacities, sealed authority
maps, a valid generation tag, and an exact match between all seven checked map
IDs and the classifier's kernel-reported map IDs. It holds every checked map
descriptor through the publication syscall, preventing map-ID reuse in that
gap. It does not export pointer contents. The dispatcher must itself reference
only its dispatch table and counters, not a bank's device/configuration maps.

The fixture stages A as the valid ownership bank and B with a deliberately
mismatched expected source owner, making B deny. This is a diagnostic ownership
negative, not a production policy transaction. Both are seeded while idle, their
configuration/pointer/device/ownership/tag maps are frozen, and their seed pins
are removed. An unsealed publication and later user updates to frozen device
maps must fail; an empty dispatcher must reject forty armed-receiver attempts.

Forty thousand uniquely sequenced IPv4/IPv6 packets run through 22 checked
publication operations. Per-generation ledgers must assign every sequence
exactly once: A requests delivery, B rejects. Observed receiver sequences must
match A's ledger exactly, with zero foreign delivery, socket drops or unobserved
redirects. A compact typed reader inspects all 65,536 ledger slots and exports
only populated public observations, avoiding a large per-byte JSON map dump.

After the alternating swaps finish on A, the fixture removes A's exact program
and authority-map pins while A remains selected. The final swap to B releases
the last A program reference while both senders are still running. Retained
public counter/ledger maps do not reference A's device/configuration maps. The
old authority-map IDs must become unavailable; this does not claim instantaneous
physical reclamation or a measured RCU grace period. Finally, moving B's target
peer must still invalidate its frozen device-map slot through the kernel.

All prior seventy serial/recovery attempts and the 40,000-packet sticky-movement
gate remain mandatory. The publication stage adds a ninth non-transmitting seed,
forty empty-dispatch denials and its separate 40,000-packet matrix. Disposable
pin removal is exact and scoped; no live UNF maps, history, journals or authority
are changed. Missing observers or unexpected syscall errors remain failures.

The separate BPF object builds with SHA-256
`4ce81c6b2606eceb75330d933de977cffac3e450456a83fc0cc463fad6a2d47a`.
All 807 workspace tests pass (26 ignored), four explicit adapter tests pass,
and strict workspace/all-target Clippy and formatting pass. Publication gate:
one positive / 43 negative cases; existing movement gate: three positive / 141
negative cases. Runtime loading, map freezing, last-reference retirement and the
complete matrix must pass cl02 before identical-image retained Kind.

This is not the production publisher, authenticated attachment/address/route
join, complete source-side concurrency or policy/Service/egress composition.
Whole-bank staging costs and tail-call/resource budgets are unmeasured. Full
Phase 9 and stabilization S1–S5 remain open; no scale or superiority claim follows.

## First cl02 failure and fixture repair

The `94c3478` image (`sha256:f2cff2f7ea5378b06e7ff51fc936a307ca1dfac6d2e36793ff8b438e737b424a`)
failed before creating bank B: its dotted parent name was placed inside bank A's
bpffs. Linux [reserves dotted bpffs entries](https://github.com/torvalds/linux/blob/v5.14/kernel/bpf/inode.c#L353-L363)
and returns EPERM. This is a fixture setup failure, not a passed publication gate.
The corrected fixture keeps B's guarded parent on tmpfs, mounts a separate owned
bpffs beneath it, and explicitly unmounts both during cleanup. No loader path
guard or kernel permission is weakened; the BPF object is unchanged.

The failed archive is retained at
`.artifacts/p9-device-lease-94c3478-cl02/fixture.tgz`, SHA-256
`f75527416af693f96c1687e855cb962cddeedb159f843f48426a177a5ba7b4bd`.
Its seventy serial attempts reached `[70,30,40,0]`; the publication stage never
ran. Before/during/after controller, five-agent and installer logs were reviewed.
The after window has 433 bounded flow-history, 14 path-proof, five key-publication
and two bounded topology-history warnings, with no ERROR entries. All five live
agents remain converged at policy 496 / Service 203. Existing warnings remain
stabilization work, not a claim of clean runtime logs.

Shell syntax and the one-positive/43-negative publication gate and
three-positive/141-negative movement gate pass after the mount correction.
A complete corrected-image cl02 run is required before matching Kind.
