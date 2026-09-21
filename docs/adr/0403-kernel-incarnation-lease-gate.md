# ADR 0403: Kernel Incarnation Leases Without Tombstone Growth

Date: 2026-09-21

Status: locally verified; disposable kernel qualification pending cl02 then Kind

## Decision

The new `unf-locality` library owns an `IncarnationGate`: a fresh anonymous Aya
hash map keyed by the entire 32-byte CNI creation nonce, with a nonzero 64-bit
lease serial. Creation installs ADR 0402's synchronous retirement callback in
exactly one real `AttachmentJournal`. An opaque registration rejects other
journals and reopened instances independently of the changing inventory cut.
Issuance also requires a current cut and the exact current Ready, UID-bound
record, while the caller holds the journal transaction lock.

A consumer must compare **nonce and serial in that exact map**, not presence
alone. Existing live entries reuse their serial; retirement deletes only the
affected nonce and verifies absence. Reissuing a removed nonce consumes a new
serial, so a previously published bank cannot rearm merely because its nonce
reappears. The gate keeps one serial counter, not an accumulating tombstone set.
Map entries are bounded by the explicitly requested capacity (1–65,536), with
no LRU eviction of another live attachment. Capacity failure stops new issuance;
the future publisher must budget/rotate its runtime gate safely. This is not
unlimited capacity or a measured performance claim.

The map is preallocated and program-read-only. The Linux 5.14
[BPF UAPI](https://raw.githubusercontent.com/torvalds/linux/v5.14/include/uapi/linux/bpf.h)
defines `BPF_F_RDONLY_PROG`; the
[hash-map implementation](https://raw.githubusercontent.com/torvalds/linux/v5.14/kernel/bpf/hashtab.c)
provides the deletion/lookup primitive. Aya 0.14's checked standalone-map and
descriptor APIs are used without new unsafe code or raw syscalls. Only a fresh
map can construct a gate: there is no pinned-map or deserialization constructor.
A duplicate descriptor allows the future bank loader to retain this exact map.

An ambiguous write, mismatching readback or serial exhaustion permanently stops
issuance on that gate. Revocation remains available, so failed admission cannot
prevent later CNI deletion. A failed revocation propagates through the journal
as a failed durable transaction. Previously published unrelated leases are not
automatically invalidated by another attachment's failure.

## Verification and remaining boundary

Five model tests cover full-key distinction, repeated retirement/reissue with
constant retained entry count, ambiguous write/readback errors, lookup errors,
foreign/zero serials, exhaustion and invalid capacity before privileged work.
An additional journal test proves registration identity across mutations,
foreign hooks and reopen. All 849 workspace tests pass (26 privileged ignored),
strict all-target Clippy and formatting pass. Shell syntax validation passes;
ShellCheck is unavailable. Logs: `.artifacts/p9-incarnation-gate-{tests,workspace,clippy-3}.log`.

`kernel_incarnation_gate` and its disposable platform runner test the real
kernel map, journal callback, persistence-failure revocation, stale/foreign cuts,
serial reissue, attachment replacement, capacity failure and temporary cleanup.
They do not attach BPF programs, create network links, use production pins or
reset any live CNI journal. Run the immutable diagnostic image on cl02 before
matching Kind; neither platform pass is claimed by this source milestone.

This gate is one required condition, not packet authority. Kernel deletion is
not a recall of packets that already passed a lookup. Continuous device lifetime,
exact aliases, authenticated placement, policy/Service/egress ordering and
packet-time route checks remain mandatory in the immutable consumer. Startup
must fence old dispatch before serving CNI; dropping/reopening a journal alone
does not revoke a bank retained by the kernel. The live agent has not installed
this gate or published any locality bank. L3, L4/L5/Q and Phase 9 stay open.
