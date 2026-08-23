# Dataplane

## Initial hook

UNF starts with TC classifier programs because TC works with an existing CNI and
provides both ingress and egress attachment without owning the pod lifecycle. XDP,
cgroup, and socket hooks will only be introduced for measured feature needs.

The Phase 1 parser accepts Ethernet/IPv4 TCP and UDP. It validates the IPv4 header
length, skips non-initial fragments, reads the flow tuple with bounded helpers,
increments a per-CPU counter, and submits a compact event. It always returns
`TC_ACT_PIPE`; it cannot drop traffic.

## Maps

| Name | Key | Value | Owner | Update/lifetime | Capacity/failure |
|---|---|---|---|---|---|
| `FLOW_COUNTERS` | constant `u32` slot 0 | per-CPU `u64` | eBPF program | increment per parsed flow; program lifetime | one entry; forwarding continues if lookup fails |
| `FLOW_EVENTS` | none (ring) | `FlowEvent` ABI v1 | eBPF producer, agent consumer | ephemeral, unpinned | 256 KiB; events drop under pressure, forwarding continues |
| `IDENTITY_V4` | IPv4 network-order bytes | identity ID, schema version, flags, revision | controller desired state; agent map writer; TC reader | revisioned reconciliation; program lifetime, currently unpinned | 65,536 entries; unknown/mismatched identity resolves to ID zero and forwarding continues |
| `POLICY_RULES` | source/destination identity, protocol, destination port, bank | actual/shadow verdict and policy/rule/reason provenance, schema, revision | controller compiler; agent transactional writer | inactive bank is populated and validated before activation; currently unpinned | 262,144 entries across two banks; active bank remains selected when staging fails |
| `POLICY_CONFIG` | constant `u32` slot 0 | controller epoch, policy revision, entry count, schema, active bank | agent writer; future TC reader | one atomic write activates a complete bank | one entry; failed activation preserves the previous pointer |

`FlowEvent` carries no Kubernetes strings. TC now resolves IPv4 addresses through
`IDENTITY_V4`. Resolved policy state is now staged in `POLICY_RULES`, but TC does
not read it yet, so event policy and rule IDs remain zero. Event and map ABIs use
fixed C layouts, explicit schema/version fields, and compile-time size assertions.

## Build boundary

The TC package is excluded from the host workspace and built for
`bpfel-unknown-none` with an isolated nightly `build-std=core` command. Shared ABI
tests still run on stable in the host workspace. See ADR 0002.

## Next dataplane milestone

Read the active transactional policy bank for lookup-only classification and
provenance, then enable a separately verified `TC_ACT_SHOT` enforcement path.
