# ADR 0070: Primary-CNI bootstrap recovery is identity-, NAT-, and epoch-aware

Status: Accepted and implemented; expanded isolated dual-stack Kind verified,
live OpenShift rerun pending

## Context

The first completed OpenShift primary-CNI installation exposed four related
recovery gaps. Terminal Pods retained released addresses in the controller,
reply state disappeared on every unrelated policy revision, one TC hook could
observe only one side of a translated tuple, physical Node addresses did not
retain host-network Pod selector metadata, and a controller restart could issue
new provenance revisions for unchanged Node blocks that running agents did not
refresh.

Targeted NetworkPolicies allowed the installation to finish, but those policies
are qualification scaffolding rather than a supportable operating model.

## Decision

The controller treats `Succeeded` and `Failed` Pods as retired endpoints during
both watch updates and initial relists. Retirement removes their Pod binding,
address indexes, and unreferenced identity before a replacement can claim a
reused address. Other phases, including `Unknown`, remain admitted until a
terminal or delete event is observed.

Primary-CNI agents select `--hook-coverage both`. Ingress attachments on every
non-loopback interface are the single policy enforcement and flow-telemetry
point. Egress attachments are supplemental: they can refresh or seed the shared
bounded connection map for the other side of translated and locally originated
tuples, but always return `TC_ACT_PIPE` and emit no duplicate flow event. This
preserves Pod ingress enforcement on forwarded traffic while excluding local
kubelet-to-Pod probes from a second, directionally wrong verdict. Overlay mode
retains its existing single-hook default. Established TCP, UDP, and SCTP state
remains protocol-time-bounded and requires a live nonzero policy configuration,
but no longer disappears because an unrelated Pod or policy update advances the
global revision. Replacing the eBPF program still resets all runtime state.

Accepted primary-CNI Node InternalIPs receive Kubernetes' Node-traffic
exception in both directions and address families. The controller lowers one
exact-address fallback per Node, not one entry per Node and workload identity.
The reserved-identity fallback is accepted by agents only when it is an exact
nonzero address, wildcard protocol/port, provenance-free allow with no shadow;
all other reserved-identity policy shapes fail validation. Node assignment or
transport changes advance the policy revision as well as routing state.

Host-network Pods keep their status addresses and real Namespace, Pod labels,
service account, and named ports for address-aware policy lowering, while their
shared Node addresses remain excluded from the unique identity registry. When
multiple host-network Pods share one address, an exact-address ingress decision
uses additive NetworkPolicy semantics: any matching allow wins. This is an
explicit consequence of the platform losing individual Pod identity once
multiple host-network processes use the same Node address.

The remote-route reconciler now refreshes its authenticated local Node-block
snapshot before each complete route snapshot. A revision-only change for the
same Node UID and exact provider blocks is persisted atomically and adopted
without restarting the agent. A Node UID or live block-address change remains a
fail-closed drain/restart boundary so active CNI leases cannot silently change
ownership.

## Verification

Controller tests prove terminal transition and initial-relist retirement,
same-IP replacement, dual-stack host-network address lowering, real Namespace
selection, shared-address additive allow, and no address insertion into the
identity registry. Shared eBPF tests prove protocol timeouts, survival across
policy revision changes, and refusal without active policy state. Agent tests
prove revision-only Node-block adoption, secure persistence, idempotence, and
rejection of Node UID or provider changes.

The expanded `make primary-cni-kind-test` gate passes on three
default-CNI-disabled Nodes. In addition to its prior dual-stack lifecycle,
outage, foreign-CNI, and exact rollback coverage, it proves kubelet HTTP probes
remain healthy under namespace default-deny, Pod-to-Node IPv4/IPv6 traffic
bypasses egress isolation, IPv4 Service forwarding, retained terminal-Pod
dual-stack lease reuse, and exact controller-epoch reconvergence. The host
kernel does not expose an ip6tables NAT table, so kube-proxy explicitly disables
its IPv6 proxier; the evidence artifact records IPv6 ClusterIP forwarding as a
fixture exclusion while retaining direct IPv6 and dual-stack Service discovery.

The first staged cl02 agent rollout from revision `58e4deb` proved that making
both TC directions authoritative is incorrect: CoreDNS kubelet probes were
dropped and authentication degraded. The controller was not upgraded. Agents
were rolled back to the prior digest, and scoped legacy-netlink cleanup removed
only the residual UNF egress filters. Authentication, console, and DNS recovered;
Insights retained its pre-existing external upload timeout. This failed attempt
is retained as evidence rather than credited as qualification.

Live OpenShift verification still requires immutable images, a staged cl02
rollout, deletion of every annotated temporary policy, operator/canary closure,
and explicit outage and Node reboot evidence.

## Consequences

Bootstrap traffic no longer depends on a globally revision-fenced reply cache,
and Service NAT has both tuple observation points in primary-CNI mode without
two enforcement or telemetry points. Exact Node exceptions grow linearly with
Nodes rather than with Nodes multiplied by identities. The single-hook overlay
default and persistent eleven-map ABI remain unchanged.
Runtime reply entries are still bounded and ephemeral; generic `RELATED` ICMP,
arbitrary conntrack helpers, non-L4 association, and survival across program
replacement remain outside this decision.
