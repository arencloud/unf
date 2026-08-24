# Dataplane

## Initial hook

UNF starts with TC classifier programs because TC works with an existing CNI and
provides both ingress and egress attachment without owning the pod lifecycle. XDP,
cgroup, and socket hooks will only be introduced for measured feature needs.

The parser accepts Ethernet/IPv4 TCP and UDP. It validates the IPv4 header
length, skips non-initial fragments, reads the flow tuple with bounded helpers,
increments a per-CPU counter, resolves identities, and reads the atomically active
policy bank. An actual deny returns `TC_ACT_SHOT`; allow and shadow-only deny
return `TC_ACT_PIPE`.

## Maps

| Name | Key | Value | Owner | Update/lifetime | Capacity/failure |
|---|---|---|---|---|---|
| `FLOW_COUNTERS` | constant `u32` slot 0 | per-CPU `u64` | eBPF program | increment per parsed flow; program lifetime | one entry; forwarding continues if lookup fails |
| `FLOW_EVENTS` | none (ring) | `FlowEvent` ABI v2 | eBPF producer, agent consumer | ephemeral, unpinned | 256 KiB; events drop under pressure without changing the already-computed forwarding decision |
| `IDENTITY_V4` | IPv4 network-order bytes | identity ID, schema version, flags, revision | controller desired state; agent map writer; TC reader | revisioned reconciliation; program lifetime, currently unpinned | 65,536 entries; unknown/mismatched identity resolves to ID zero and forwarding continues |
| `POLICY_RULES` | source/destination identity, protocol, destination port, bank | actual/shadow verdict and policy/rule/reason provenance, schema, revision | controller compiler; agent transactional writer | stale inactive keys are removed, then the inactive bank is populated and validated before activation; currently unpinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries, and the active bank remains selected when staging fails |
| `POLICY_IPV4` | exact/fallback source IPv4, destination identity, protocol, destination port, bank | same policy decision/provenance value as `POLICY_RULES` | controller IPv4-aware compiler; agent transactional writer | staged and validated alongside `POLICY_RULES` under the same inactive bank; currently unpinned | 262,144 entries across two banks; compiler and agent cap each bank at 131,072 entries |
| `POLICY_CONFIG` | constant `u32` slot 0 | controller epoch, policy revision, combined entry count, schema, active bank | agent writer; TC reader | one atomic write activates matching banks in both policy maps | one entry; failed activation preserves the previous pointer |

`FlowEvent` carries no Kubernetes strings. ABI v2 records the applied policy
revision, actual verdict/reason/policy/rule, and optional shadow
verdict/reason/policy/rule. TC performs an exact protocol/port lookup first and
then a protocol/port-zero fallback in the bank selected by `POLICY_CONFIG`.
Config and values must have the expected schema and identical nonzero revision.
Event and map ABIs use fixed C layouts, explicit schema/version fields, and
compile-time size assertions.

Bounded NetworkPolicy `endPort` ranges are expanded into exact keys before
distribution. The compatibility compiler caps one inclusive range at 1,024
ports, while the shared lowering path caps the complete snapshot at the physical
131,072-entry allocation for one bank. The agent validates the same snapshot
bound before encoding or mutating the inactive bank.

Bounded IPv4 `ipBlock` peers use `POLICY_IPV4`. TC checks an exact source/port
entry, exact-source fallback, arbitrary-external/port entry, then the external
fallback before consulting `POLICY_RULES`. The controller emits exact entries for
known Pod addresses and bounded block addresses, preserving the shared evaluator's
native/compatibility precedence. Snapshot schema v2 carries both entry sets; the
agent stages and validates both inactive banks before the single `POLICY_CONFIG`
activation write.

## Failure behavior

An interrupted stage cannot replace the active bank, and controller interruption
leaves the last activated revision in use. This overlay prototype deliberately
fails open when the destination identity is unknown, config is absent or
incompatible, or no valid identity/IP entry exists. A source without an identity
can still be enforced when a valid IPv4 exact or external-fallback entry exists.
Fail-open events are marked observed/identity-unknown with revision zero. Agent
restart also recreates unpinned maps before resynchronizing, so this is not yet a
production fail-closed design. Invalid map state never becomes a deny by
accident. See ADR 0008.

## Build boundary

The TC package is excluded from the host workspace and built for
`bpfel-unknown-none` with an isolated nightly `build-std=core` command. Shared ABI
tests still run on stable in the host workspace. See ADR 0002.

## Next dataplane milestone

Persist last-known-good state across agent restart, aggregate applied node status,
and test explicit control-plane and map-pressure failure modes.
