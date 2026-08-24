# Dataplane

## Initial hook

UNF starts with TC classifier programs because TC works with an existing CNI and
provides both ingress and egress attachment without owning the pod lifecycle. XDP,
cgroup, and socket hooks will only be introduced for measured feature needs.

The parser accepts Ethernet with IPv4 or IPv6 TCP, UDP, and SCTP. It validates
the IPv4 header length, skips non-initial IPv4 fragments, validates the fixed
IPv6 header, and traverses at most six IPv6 extension headers and 256 extension
bytes. Hop-by-Hop is accepted only first; Routing, Destination Options,
initial/atomic Fragment, and AH are supported. Jumbograms, ESP/No Next Header,
non-initial fragments, malformed or over-limit chains, and unsupported protocols
fail open. The parser reads the flow tuple with bounded helpers, increments a
per-CPU counter, reads the active identity configuration once per packet, resolves
both endpoints from that bank, and reads the atomically active policy bank.
An actual deny returns `TC_ACT_SHOT`; allow and shadow-only deny return
`TC_ACT_PIPE`.
SCTP's common header exposes source and destination ports in the same first four
transport bytes, so protocol 132 uses the existing exact/protocol-wildcard policy
key layout without an ABI change.

## Maps

| Name | Key | Value | Owner | Update/lifetime | Capacity/failure |
|---|---|---|---|---|---|
| `FLOW_COUNTERS` | constant `u32` slot 0 | per-CPU `u64` | eBPF program | increment per parsed flow; program lifetime | one entry; forwarding continues if lookup fails |
| `FLOW_EVENTS` | none (ring) | `FlowEvent` ABI v2 | eBPF producer, agent consumer | ephemeral, unpinned | 256 KiB; events drop under pressure without changing the already-computed forwarding decision |
| `IDENTITY_V4`, `IDENTITY_V4_B` | IPv4 network-order bytes | identity ID, schema version, flags, revision | controller desired state; agent transactional writer; TC reader | physical banks 0/1; inactive map is replaced and validated before activation; pinned under `/sys/fs/bpf/unf/v2` | 65,536 entries per bank; unknown/mismatched identity resolves to ID zero and forwarding continues |
| `IDENTITY_V6`, `IDENTITY_V6_B` | 16 IPv6 network-order bytes | identity ID, schema version, flags, revision | controller desired state; agent transactional writer; TC reader | physical banks 0/1 stage with their IPv4 counterpart; pinned under the same ABI directory | 65,536 entries per bank; unknown/mismatched identity resolves to ID zero and forwarding continues |
| `IDENTITY_CONFIG` | constant `u32` slot 0 | controller epoch, identity revision, combined entry count, schema, active bank | agent writer; TC reader | one atomic write activates both address-family maps; pinned | one entry; failed activation preserves the previous pointer |
| `POLICY_RULES` | source/destination identity, protocol, destination port, bank | actual/shadow verdict and policy/rule/reason provenance, schema, revision | controller compiler; agent transactional writer | stale inactive keys are removed, then populated and validated before activation; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries, and the active bank remains selected when staging fails |
| `POLICY_IPV4` | exact/fallback source IPv4, destination identity, protocol, destination port, bank | same policy decision/provenance value as `POLICY_RULES` | controller IPv4-aware compiler; agent transactional writer | staged and validated alongside `POLICY_RULES`; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `POLICY_IPV6` | destination identity, port, protocol, bank, and source IPv6 prefix | same policy decision/provenance value as `POLICY_RULES` | controller IPv6-aware compiler; agent transactional writer; TC LPM reader | staged and validated alongside the other policy maps; pinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `POLICY_CONFIG` | constant `u32` slot 0 | controller epoch, policy revision, combined entry count, schema, active bank | agent writer; TC reader | one atomic write activates matching banks; pinned | one entry; failed activation preserves the previous pointer |

`FlowEvent` carries no Kubernetes strings. ABI v2 records the applied policy
revision, actual verdict/reason/policy/rule, and optional shadow
verdict/reason/policy/rule. In `POLICY_RULES`, TC looks up the exact protocol/port,
then the same protocol with port zero, then the protocol/port-zero global fallback
in the bank selected by `POLICY_CONFIG`.
Identity and policy config/value pairs must have the expected schema and an
identical nonzero revision.
Event and map ABIs use fixed C layouts, explicit schema/version fields, and
compile-time size assertions.

Userspace flow export preserves forwarding priority. Destination-resolved events
enter a 4,096-record non-blocking channel and a 2,048-key pending aggregator. A
full bound increments `unf_telemetry_dropped_events_total` and discards telemetry
immediately; it never blocks TC consumption or changes the verdict already
returned by eBPF. HTTP batches contain at most 512 logical flows. Controller
retention is independently capped at 4,096 keys with eviction accounting. Flow
export schema v2 carries exactly one complete IPv4 or IPv6 address pair per key;
topology schema v3 exposes both address families for each workload.

Bounded NetworkPolicy `endPort` ranges are expanded into exact keys before
distribution. The compatibility compiler caps one inclusive range at 1,024
ports, while the shared lowering path caps the complete snapshot at the physical
131,072-entry allocation for one bank. The agent validates the same snapshot
bound before encoding or mutating the inactive bank.

Bounded IPv4 `ipBlock` peers use `POLICY_IPV4`. For an exact source and then the
arbitrary-external source, TC checks exact protocol/port, protocol-specific
port-zero, and global protocol/port-zero entries before consulting
`POLICY_RULES`. The controller emits exact entries for known Pod addresses and
bounded block addresses, preserving the shared evaluator's native/compatibility
precedence.

IPv6 `ipBlock` peers use `POLICY_IPV6`, an LPM trie whose fixed destination,
port, protocol, and bank dimensions precede the source address. Snapshot schema
v3 carries identity, exact IPv4, and IPv6 prefix decisions; the agent stages and
validates all three inactive banks before the single `POLICY_CONFIG` activation
write. More-specific exception decisions and known-Pod `/128` decisions override
broader external prefixes. See ADR 0014.

## Failure behavior

An interrupted identity or policy stage cannot replace its active bank, and
controller interruption leaves both last activated revisions in use. The nine
enforcement maps are an all-or-none pinned set in an ABI-versioned bpffs
directory. On startup the agent checks map capacities, reconstructs both banks'
rollback caches, validates each config-selected bank's count and uniform
revision, and refuses partial or malformed persistent state. Debris from an
interrupted inactive-bank stage is structurally validated but need not share one
revision. A controller-managed fresh process stays NotReady until both initial
snapshots apply; a complete validated last-known-good set may restore readiness
while the controller is unavailable.

This overlay prototype deliberately
fails open when the destination identity is unknown, config is absent or
incompatible, an IPv6 extension chain is unsupported, malformed, or exceeds its
bounds, or no valid identity/IP entry exists. A source without an identity
can still be enforced when a valid IPv4 exact/fallback or IPv6 prefix entry exists.
Fail-open events are marked observed/identity-unknown with revision zero. TC
attachments use persistent replacement identities. On Linux 6.6 and newer, the
agent pins one TCX link per interface index in the configured direction below the
ABI v2 link directory and atomically updates that link to the newly loaded
program. On older kernels, it owns a fixed priority/handle tuple per direction
and replaces the legacy netlink filter in place. The old program therefore
remains attached until the replacement program is loaded and handed over.
Invalid map state never becomes a deny by accident. ABI v1 pin directories are
not removed automatically; operators may delete them only after validating an
ABI v2 rollout. See ADRs 0008, 0016, 0017, 0018, and 0019. Permanent startup
validation failures terminate the agent after readiness is fenced so the
orchestrator can retry after repair.

## Build boundary

The TC package is excluded from the host workspace and built for
`bpfel-unknown-none` with an isolated nightly `build-std=core` command. Shared ABI
tests still run on stable in the host workspace. See ADR 0002.

## Next dataplane milestone

Test deterministic physical map-pressure failure while preserving the active
bank, then validate the legacy netlink handoff path on an older supported kernel
and OpenShift host.
