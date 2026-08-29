# ADR 0077: Transactional service maps precede source-side TC translation

Status: Accepted and implemented for Phase 4.4 map state. Packet translation is
still gated on Phase 4.5.

## Context

The schema-v1 Service snapshot is deterministic and durably distributed, but a
userspace acknowledgement is not a forwarding contract. A service revision can
change frontends, backend membership, endpoint lifecycle, and both address
families together. Exposing any subset would create mixed-revision traffic.
Backend selection must also remain stable for an admitted flow when later
EndpointSlice revisions reorder or drain endpoints.

UNF primary CNI owns the Pod veth and already attaches both TC directions. That
gives the initial ClusterIP foundation an exact hook boundary without adding a
socket, cgroup, XDP, or Linux-netfilter dependency.

## Decision

The first service forwarding hook will run on host-side Pod-veth TC ingress,
before host routing. It will resolve and DNAT an exact ClusterIP tuple before
the existing identity/policy decision uses the translated backend tuple. The
reverse translation will run on the Pod-veth TC egress path. Initial Phase 4.5
coverage is Pod-originated primary-CNI ClusterIP traffic; host-network clients,
overlay-only attachment, NodePort, LoadBalancer, DSR, and traffic-policy modes
remain separate gates.

UNF will use a custom bounded eBPF service connection table rather than making
Linux conntrack authoritative or cloning all of Linux conntrack. One persistent
LRU table stores fixed 40-byte forward/reverse tuple keys and fixed 88-byte
values containing the client, frontend, selected backend, stable ServiceId and
BackendId, service revision, protocol/family, flags, and last-seen time. A flow
will install both directions transactionally as far as BPF map operations
permit: reverse first, forward second, and reverse removal if forward insertion
fails. Existing entries retain their BackendId across service revisions;
new-flow selection consults only the active service bank. Protocol timeouts,
checksum mutation, pair validation, and packet-path failure behavior are Phase
4.5 work, but their ABI is reserved now to avoid another immediate persistent
state migration.

Service map ABI v1 consists of:

- exact IPv4 and IPv6 frontend maps keyed by address, network-order port,
  protocol, and logical bank;
- IPv4 and IPv6 backend maps keyed by ServiceId, BackendId, and bank, retaining
  ready/serving/terminating flags;
- a backend-slot map keyed by ServiceId, revision-local frontend index, ordered
  slot, and bank; its value is the stable BackendId;
- one configuration array entry containing epoch, revision, frontend/backend/
  slot counts, schema, and active bank; and
- the reserved persistent service connection LRU.

Frontend index is intentionally revision-local. Connection state stores the
stable BackendId, so reordering does not change an admitted flow. Per bank the
limits are 131,072 frontends, 262,144 backends, and 524,288 frontend/backend
references. Physical dual-bank hash capacities are twice those limits and use
no preallocation. The connection table is bounded at 262,144 entries. A bank
byte in each desired-state key was selected instead of map-in-map: the single
configuration write already provides atomic visibility, while avoiding extra
inner-map lifetime, pinning, and verifier complexity without measured benefit.

The agent compiles and capacity-checks the entire inactive bank before kernel
mutation, replaces all five desired-state tables, and reads every desired value
back. It then writes an owner-only, fsynced pending checkpoint, switches
`SERVICE_CONFIG[0]` once, and atomically renames the checkpoint into place.
Recovery discards a pre-switch pending file or promotes a pending file that
matches the active tuple, closing both process-crash windows. Checkpoint failure
restores the previous file, config pointer, and inactive bank. Any partial
staging/readback/capacity failure restores the inactive bank without changing
the active pointer. Successful activation garbage-collects the former bank;
partial cleanup is restored for a later retry.

Persistent BPF-state ABI v4 adds the seven service pins to the historical
eleven-map v3 desired-state set, producing eighteen owned pins under
`/sys/fs/bpf/unf/v4`. Startup accepts only an all-present or all-absent set,
checks capacities, validates every desired-state entry, and requires the active
maps to exactly recompile from the mode-0600 durable snapshot. Missing,
incompatible, or divergent recovery state fails before TC attachment. Historical
v1/v2/v3 cleanup ownership remains explicit; current v4 removal still requires
`--allow-current-abi`.

## Verification

`make service-dataplane-test` runs IR/compiler/distribution prerequisites,
fixed-layout ABI and deterministic lowering tests, corrupt config/entry tests,
strict Clippy, and the release BPF verifier build. Its privileged host test
loads the real eBPF object with a one-entry backend-slot map, activates revision
1, forces revision 2 to fail after earlier inactive tables were mutated, and
proves the active config/revision and all earlier tables rolled back exactly.

Deployment renders, cleanup scripts, incompatible-version fixtures, and
clean-rebuild fixtures use the v4/eighteen-pin boundary. Live kube-proxy-free
translation, connection insertion/expiry, and cluster lifecycle evidence are
not claimed by this ADR.

## Consequences

Agents now acknowledge a service revision as applied only after its complete
kernel state and durable checkpoint commit. Controller outage and process
replacement can reconstruct the exact active service bank without treating
Kubernetes strings as packet-path ABI.

Phase 4.5 can implement dual-stack TCP/UDP translation and connection
persistence against an already versioned map and hook contract. SCTP forwarding,
Maglev, session affinity, topology-aware selection, generic NAT/RELATED
tracking, and broader service exposure remain deliberately unclaimed.
