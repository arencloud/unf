# ADR 0129: Proof-salted collision-safe gateway NAT

**Status:** Accepted and implemented for the Phase 8.5 gateway-NAT slice

## Context

Source steering already preserves the original tuple and sends an admitted
flow to a selected gateway, but the gateway still needs to translate that
source into its lease-owned egress address. A gateway can serve heterogeneous
contracts whose revision numbers and candidate indexes overlap, so reusing the
source-side intent banks would alias unrelated authority. A last-writer-wins
reverse map would also allow two original flows to claim the same translated
tuple, silently redirecting replies to the wrong workload.

The design must remain verifier-bounded, dual-stack, restart-recoverable, and
independent of desired-state churn. It must not treat a proof digest as an
identity credential or allow missing projection state to leak an owned flow to
native routing.

## Decision

Persistent ABI v14 adds seven dedicated, two-bank gateway-NAT projection maps:
sources, IPv4/IPv6 destination LPM tables, addresses, gateways, selections, and
one aggregate activation pointer. Keys use the authoritative source identity as
their namespace. Values bind contract revision and digest, lease epoch, intent
digest, gateway digest, selection witness, family, and exact candidate indexes.
The aggregate pointer intentionally carries no single contract revision because
one gateway atomically serves many independent contracts.

The agent independently compiles each admitted gateway projection, replaces and
reads back the inactive bank, validates every identity/contract binding, swaps
one pointer, and retires the prior bank. Startup reconstructs the active bank
from the pins, rejects count/schema/bank/binding disagreement, and removes
crash-staged inactive state before packet attachment.

After source-side NetworkPolicy has allowed the original flow, a small ownership
preflight tail-calls an IP-family-specific gateway program. Existing forward or
reverse state remains authoritative through projection changes until its TCP or
UDP timeout. A new TCP initial SYN or UDP flow is admitted only by an exact
active source, destination, family, address, local-primary gateway, lease,
digest, and witness chain. Every malformed owned chain drops.

Translated ports come from a proof-salted odd-stride permutation over the
32,768-port ephemeral range. The permutation is a full cycle, while the packet
path performs 32 bounded probes. It inserts the reverse key first with
`BPF_NOEXIST`, then the forward key with `BPF_NOEXIST`, and removes a partial
pair on failure. Therefore collision handling never overwrites the first flow;
exhausting the bounded probe budget drops the new flow. Forward and reverse
lookups validate the complete original and translated tuples plus contract,
lease, proof, and gateway commitments before checksum-safe IPv4 or IPv6 rewrite.

Gateway NAT is verifier-isolated in two additional tail-call slots. Its IPv6
rewrite avoids stack-resident address arrays, keeping both the new gateway path
and the established Service dataplane below kernel instruction and combined
stack limits.

## Consequences

UNF now has real-kernel dual-stack TCP gateway SNAT and exact reverse restoration
with deterministic collision resistance, heterogeneous contract isolation,
projection-churn continuity, and fail-closed recovery. Port selection is stable
for a given proof and original tuple, but not a promise that all 32,768 ports are
searched per packet. UDP uses the same state machinery and bounded lifetime;
the focused packet gate exercises TCP in both families.

This slice does not claim safe address release, reachability withdrawal,
gateway failover, NAT event export, end-to-end Kind traffic, or OpenShift
qualification. Those remain explicit Phase 8.5 and later gates.

`make egress-gateway-nat-test` inherits the prior egress gates and adds ABI,
compiler, verifier, map-recovery, checksum, reverse-translation, and colliding
first-candidate evidence. The real-kernel test proves that the second flow gets
a different port and that the first reverse mapping remains unchanged.
