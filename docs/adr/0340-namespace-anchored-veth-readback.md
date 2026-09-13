# ADR 0340: Namespace-Anchored Veth Pair Readback

Date: 2026-09-13

Status: implemented and verified locally; isolated cl02 then Kind pending

L3 cannot treat two independently matching endpoint shapes as proof that those
endpoints are connected. Interface indexes are namespace-relative; aliases and
MAC addresses are public ownership metadata. Another pair in different
namespaces can reproduce those fields and indexes.

`unf-link` now verifies both reciprocal `IFLA_LINK` references and both
observer-relative `IFLA_LINK_NETNSID` values after ADD configuration and during
strict readback. Expected NSIDs are queried with `RTM_GETNSID`/`NETNSA_FD` from
the already-open workload namespace and the calling thread's held host namespace
descriptor. The workload descriptor is cloned for namespace entry, not reopened
by pathname. The host anchor uses the fixed `/proc/thread-self/ns/net` magic
link, not the process leader's namespace. Missing/unassigned/duplicate namespace
IDs, ambiguous link attributes, zero indexes and mismatches fail closed. Equal
indexes across distinct namespaces remain valid. NSIDs are never persisted or
compared across observers.

Linux 5.14's [link serialization](https://github.com/torvalds/linux/blob/v5.14/net/core/rtnetlink.c)
emits namespace-relative peer information; its
[namespace-ID query](https://github.com/torvalds/linux/blob/v5.14/net/core/net_namespace.c)
resolves the supplied descriptor. This is the upstream design basis, not proof
of downstream RHCOS execution. Actual cl02 kernel qualification remains required.
No new namespace-ID assignment request is added to production; ordinary link
readback can cause the kernel to allocate its peer namespace-ID metadata.

Three new local tests cover reciprocal namespaces, equal indexes, sixteen
one-sided link mutations and malformed namespace-ID attributes. The full
workspace passes 790 tests, with 26 explicitly ignored privileged tests;
strict Clippy, formatting and shell syntax checks pass. This does not label
ignored kernel tests verified.

The isolated ownership qualifier adds a four-private-namespace impostor case.
It retains the real pair and bind-overlays only the fixture namespace handle
with a separately cloned peer. Names, aliases, MACs, indexes, managed addresses,
routes and neighbors match, but the peer namespace does not. Both old CHECK and
replayed ADD must accept that fixture before the candidate must reject it for
the peer-reference mismatch. The original handle is restored and CHECK must
recover with an unchanged journal. The test image includes only the pinned
ADR 0330 predecessor adapter as a red-test reference; no live binary is
downgraded. Fourteen diagnostic-checked negative cases and normal cleanup are
required. Platform execution remains pending at this source checkpoint.

This is a readback-time observation, not a continuous device-lifetime lease,
an authenticated controller placement statement or packet-time delivery proof.
Concurrent replacement after observation still requires L3's consuming fence.
Cleanup's intentionally partial-state semantics, journal/wire schemas, BPF pins
and live installations remain unchanged. Two namespace-ID queries and a held-FD
clone are added per strict pair observation; no CPU/latency improvement is
claimed. Qualify cl02, commit/push, then the identical image on retained Kind.
