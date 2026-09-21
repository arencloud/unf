# ADR 0414: Sealed endpoint-linear locality bank

Date: 2026-09-21

Status: implementation; isolated cl02-before-Kind kernel qualification pending

## Decision

Connect the previously qualified observed placement/journal, native BTF and
incarnation-gate primitives to a separate, fresh eBPF bank. Storage grows with
endpoints and their exact addresses, not source/destination identity pairs.
Actual map capacities follow the selected inventory. This is a structural
bound, not a measured CPU, RSS or throughput improvement.

The explicit, padding-free locality ABI v1 contains placement coordinates,
canonical family/address owners, complete aliases, nonce/serial leases,
namespace cookies, MACs and device indexes. The loader accepts opaque leased
observations, not a serialized permission. It binds the actual held runtime
and journal map FDs, verifies their kernel IDs after loading, and verifies the
classifier's complete map-ID set. Temporary pins live only in an owned private
bpffs directory and are removed before publication. No kernel pointer is read
or exported to userspace.

One dedicated joined namespace thread binds the actual retained host/peer
devices and runs a non-transmitting private seed. The seed program is unloaded
before config/address/endpoint/device/pointer maps are frozen. Freeze alone
does not revoke an existing BPF writer; destroying the seed capability is a
separate required operation. The loader performs final link/route rechecks.

The existing persistent one-slot observation worker also owns kernel allocation,
seeding, sealing and rechecking. Cooperative cancellation/deadline checks do
not release a started worker's permit before its namespace thread and runtime
drain. The sixty-second budget is not a hard scheduler/syscall latency promise.
The original journal cut is retained across off-lock preparation. Final
publication validates that original cut, current applied context, live gate and
exact runtime under the caller's journal/applied-state locks. It cannot accept
a caller-supplied newer cut to hide a retirement or failed persistence.

A separate mutable applied-placement fence is withdrawn before state changes.
Publishing one bank program into one dispatch slot does not rearm this fence.
Uncertain write/readback attempts both fence and dispatch withdrawal, surfacing
any failure. Startup fencing before CNI service remains an agent-integration
requirement, not something this library can assert on its own.

## Consumer boundary

The classifier requires policy-first trusted runtime input, exact source/target
address identity, actual ingress, full live nonce/serial values, frozen device
references and current reciprocal ownership/cookies. It validates the actual
final destination's full FIB result, direct destination, device and MACs before
decrementing hop limit and requesting peer redirect. Service input preserves
original workload ownership while FIB lookup uses actual post-NAT bytes.
DSR requests a separate NAT continuation and requires complete rechecking on
reentry. Missing continuations drop. Counters distinguish redirect/NAT requests
from application delivery.

This implementation deliberately rejects marked packets, IPv4 options,
fragments, unsupported transport protocols and unsupported IPv6 extension
chains. These are **open compatibility boundaries**, not an unrestricted
Required-locality implementation. Linux 5.14 FIB lookup uses mark zero, so
erasing a foreign mark would not prove its route. Native fallback is not granted
for a rejected matched endpoint. Linux 5.14 also rejects program-read-only
creation flags on special FD arrays and supplies that flag itself on devmaps;
the loader checks the resulting map shape/flags. Primary implementation:
[arraymap.c](https://raw.githubusercontent.com/torvalds/linux/v5.14/kernel/bpf/arraymap.c),
[devmap.c](https://raw.githubusercontent.com/torvalds/linux/v5.14/net/core/devmap.c),
[filter.c](https://raw.githubusercontent.com/torvalds/linux/v5.14/net/core/filter.c).

## Verification boundary and remaining work

Shared ABI size/offset/padding and malformed-input tests, bounded control tests,
complete-alias/canonical-address tests and existing worker cancellation tests
are local verification. A separate disposable fixture supplies artificial
trusted policy input: its planned kernel checks cover sealed publication,
dual-stack redirect requests and header rewriting, stale context/identity,
missing continuation, route loss/restoration, nonce retirement and stale-cut
republication rejection. It transmits no workload packet and cannot qualify
production policy/Service integration or observed application delivery.

Local evidence: all 881 workspace tests pass (26 privileged tests intentionally
ignored), strict workspace all-target Clippy passes, both pinned-nightly eBPF
binaries compile, and formatting/shell syntax checks pass. Logs are
`.artifacts/p9-locality-bank-{workspace-final,workspace-clippy,clippy-final,bpf-build-3}.log`.

Run the complete immutable diagnostic first on cl02, then the identical image
on Kind. Preserve any verifier/runtime failure and all log observations.
The production agent and its existing packet ABI remain unchanged. Main-path
and reverse-Service integration, explicit ABI migration/startup fencing,
pure-local Required placement demand, compatibility coverage, authenticated
restart continuity, actual delivery/lifecycle qualification and L4/L5/Q remain
open. Phase 9 is **not verified** by this implementation milestone.

Read-only resume evidence found all five cl02 agents converged and Ready with
zero Pod restarts. Its twenty-minute regular/init log window contained 433 WARN
records and no ERROR: 420 bounded flow-history retention, nine peer-proof
503 retries, two attestation-row 400 rejections, one clsact warning and one
bounded topology-history retention. These are retained observations, not a
clean-log or uninterrupted-key-progress claim. Evidence is under
`.artifacts/p9-locality-bank-resume-cl02-{logs,state}`; existing CNI journals
were captured separately before the diagnostic.
