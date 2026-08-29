# ADR 0078: Source-side TC owns the initial dual-stack ClusterIP translation

Status: Accepted and implemented for Phase 4.5

## Context

ADR 0077 fixed the transactional desired-state and persistent connection ABI,
but did not forward packets. The first forwarding slice needs identical IPv4 and
IPv6 semantics, stable backend choice through EndpointSlice churn, correct
transport checksums, and an exact failure boundary without making Linux
conntrack authoritative or implying NodePort and LoadBalancer support.

## Decision

On host-side Pod-veth ingress, UNF checks the complete destination address,
network-order port, and protocol against the active service bank before policy
evaluation. TCP and UDP new flows select a deterministic slot from the complete
client/frontend tuple and ServiceId. Only backends marked ready and not
terminating enter slots; all endpoint lifecycle records remain in backend maps
for provenance. An exact frontend with zero eligible backends drops. A tuple
with no exact frontend remains untouched.

The selected packet is DNATed to the backend address and port. IPv4 header and
TCP/UDP pseudo-header checksums, or the equivalent IPv6 transport checksum, are
updated with kernel checksum helpers. A reverse connection entry is inserted
before the forward entry; forward insertion failure removes the reverse entry.
Host-side Pod-veth egress validates the complete reverse tuple and applies SNAT
back to the ClusterIP and service port.

Both connection entries contain the full client, frontend, and backend tuples,
stable ServiceId and BackendId, selection revision, protocol/family, schema, and
last-seen time. Lookups reconstruct the expected forward/reverse keys, delete a
corrupt or expired pair, and refresh both directions. Existing valid flows are
consulted before active desired state, so backend replacement, draining, or
frontend removal does not break them before protocol timeout. A new flow always
uses the active bank.

The bounded parser translates only unfragmented IPv4 and IPv6 TCP/UDP packets.
Non-initial IPv4 fragments cannot expose a reliable transport tuple and pass
unchanged. An IPv4 packet with more fragments or any IPv6 Fragment header is
not translated, preventing partial NAT. Existing bounded IPv6 extension-header
policy parsing remains intact. SCTP service forwarding, host-network clients,
NodePort, LoadBalancer, session affinity, traffic policy, DSR, and generic
RELATED handling remain outside this decision.

Runtime flow, connection, decision, and event workspaces use per-CPU arrays.
They are deliberately not pinned desired state and keep verifier call chains
under the kernel's 512-byte eBPF stack limit. The build gate pins Rust nightly
`2026-07-15` to match the qualified LLVM 22 `bpf-linker`.

## Verification

`make service-dataplane-test` runs all service IR, compiler, distribution, and
transactional-state prerequisites, strict Clippy, the pinned release eBPF build,
and two privileged live-kernel tests. The first forces a partial inactive-bank
capacity failure and proves exact rollback. The second loads both TC programs
through the kernel verifier and executes packets with `BPF_PROG_TEST_RUN`.

The packet test covers IPv4 and IPv6 TCP and UDP DNAT plus reverse SNAT. It
checks addresses, ports, IPv4 header checksums, TCP/UDP checksums, two map
entries per flow, persistence on the old backend after a revision change, new
flow selection from the replacement revision, forced timeout and reselection,
fixed connection-map BackendId/revision/tuple provenance, exact backendless
drop, and unrelated pass-through.

This is repeatable live-kernel program evidence, not a kube-proxy-free cluster
claim. Phase 4.7 must separately prove end-to-end Kind routing, DNS, lifecycle,
replacement, and cleanup; Phase 4.8 follows on OpenShift.

## Consequences

Phase 4.5 is Verified at its bounded packet-program scope. UNF now has a native
dual-stack ClusterIP fast path whose desired state is transactional and whose
established translations are independent of later service revisions. Phase 4.6
must expose translation and failure outcomes through metrics, status, history,
and explanation before cluster qualification begins.
