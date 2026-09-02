# ADR 0109: Enforce explicit LoadBalancer DSR with a verifier-isolated pipeline

**Status:** Accepted and implemented for Phase 7.7

## Context

Phase 7.6 leaves NAT as the verified forwarding default. Direct Server Return
can remove reverse translation from the node path, but it also changes the host
contract: the backend must accept the LoadBalancer VIP, the Service and backend
transport tuples must match, and the forward path must have a resolved route,
neighbor, output interface, and sufficient MTU. Silently mixing DSR and NAT for
one admitted flow would make return behavior and provenance ambiguous.

The main TC classifier is already intentionally feature-rich and close to the
Linux verifier's bounded-state ceiling. Adding FIB resolution inline would make
otherwise valid programs kernel-version-sensitive.

## Decision

DSR is admitted only for a UNF-owned LoadBalancer when both annotations are
present:

```yaml
network.unf.io/service-forwarding-mode: dsr
network.unf.io/dsr-backend-vip-ownership: acknowledged
```

The acknowledgement is an operator assertion that every admitted backend owns
every advertised VIP. UNF validates that each backend uses the same protocol and
port as the Service. The same Service's ClusterIP and NodePort frontends remain
NAT. Absence of the annotations remains NAT, and explicit DSR that cannot satisfy
its contract is rejected or dropped; it never falls back per flow.

The controller preserves the intent in schema v4. Per-Node Network Behavior
Contracts require `DsrIpv4` and `DsrIpv6` capabilities for the corresponding
frontends. The agent binary advertises those implemented capabilities, but it
does not become Ready or attach either hook unless the kernel loads the complete
program pipeline and the jump table is populated.

The TC path selects and policy-checks the backend exactly as NAT does, including
strict locality/topology, ClientIP affinity, Maglev, source ranges, endpoint
lifecycle, and backend identity. DSR retains the packet's VIP and Service port.
A synthetic FIB lookup against the selected backend proves route, effective MTU,
output interface, and resolved neighbor. Direct workload output rewrites the
source/destination Ethernet addresses before redirect; configured transport
interfaces use kernel neighbor output with the FIB-selected next hop so stacked
VLAN encapsulation and checksum completion remain device-owned. The agent binds
that per-Node transport topology into a mutable load-time symbol, and eBPF reads
it as volatile state so optimization cannot remove the transport branch. Any
FIB, neighbor, MTU, redirect, or jump-table failure drops with bounded DSR
provenance.

Policy evaluation and DSR FIB resolution run in verifier-isolated TC tail
programs. A runtime-only four-entry program array connects IPv4/IPv6 parse and
selection, policy, and DSR route stages. The program array and per-CPU handoff
scratch are not persistent ownership. A missing tail target fails closed.

DSR writes only forward Service connection state. A backend reply sourced from
the VIP bypasses reverse NAT, while forward events retain original frontend,
selected backend, actual algorithm/tier/affinity, and forwarding-mode evidence.
Persistent ownership advances from ABI v10 to v11 because connection-state
semantics changed even though the exact persistent map count remains 25.

## Evidence

`make service-dsr-dataplane-test` covers strict annotation admission,
capability-bound contract compilation, exact DSR frontend flags, ABI validation,
recovery and cleanup ownership, strict Clippy, eBPF compilation, kernel verifier
acceptance, and a privileged dual-stack packet test. The packet test proves VIP
and port preservation, source-range rejection before selection, forward-only
connection state, DSR event provenance, and an unchanged direct-return reply.
The same 13-test real-kernel suite re-runs the existing ClusterIP, NodePort,
affinity, topology, and LoadBalancer NAT packet paths after the pipeline split.
The focused script also inspects the optimized object and rejects a build that
does not retain `bpf_redirect_neigh`.

Independent Phase 7.9 Kind and 7.10 OpenShift gates configure backend VIP
ownership and prove actual route/neighbor/MTU and return-path behavior on their
recorded platforms. ADRs 0111 and 0112 record those non-transitive results.

## Consequences

- NAT remains the absence default and rolling-compatible fallback for Services
  that do not request DSR.
- DSR is limited to explicit UNF LoadBalancer VIPs and equal Service/backend
  transport tuples.
- Backend VIP ownership is intentionally an external host-configuration
  contract; this milestone validates the acknowledgement but does not configure
  addresses inside workload network namespaces.
- This is direct or neighbor-routed DSR: the synthetic backend route must resolve
  to the backend or an owning-Node next hop. Kind qualifies direct transport and
  cl02 qualifies its stacked-VLAN routed transport. Other gateways, tunnels, and
  asymmetric external fabrics remain unqualified until their own evidence exists.
- Runtime tail-call maps are recreated before hook attachment and cannot be
  mistaken for recoverable persistent state.
- Operations and simulation consume the new forwarding provenance in milestone
  7.8; platform qualification remains non-transitive.
