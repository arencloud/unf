# ADR 0068: OpenShift primary CNI requires an installation-time handoff

Status: Accepted; live qualification pending a suitable disposable cluster

## Context

ADR 0067 verified exclusive UNF primary-CNI ownership and exact rollback in a
default-CNI-disabled Kind fixture. OpenShift 4.22 has materially different
ownership boundaries: CRI-O reads `/etc/kubernetes/cni/net.d`, CNI executables
live under `/var/lib/cni/bin`, Multus is the kubelet entry point on an ordinary
OVN installation, and the Cluster Network Operator continuously reconciles the
default provider. RHCOS uses an immutable composefs root and SELinux enforcing.

A read-only 2026-08-28 audit of cl02 found OpenShift 4.22.9, dual-stack Pod and
Service pools, three control-plane Nodes, two Ready workers, healthy
MachineConfigPools and ClusterOperators, RHCOS 9.8, kernel 5.14, and SELinux
enforcing. It also found `networkType: OVNKubernetes`, five running
`ovnkube-node` operands, `00-multus.conf` delegating to
`10-ovn-kubernetes.conf`, no Node `spec.podCIDRs`, and no UNF-owned primary-CNI
files, routes, links, state, or socket. The current namespaced UNF deployment is
the qualified overlay and does not own CNI lifecycle.

OpenShift accepts a custom or no-CNI network type only as an installation-time
choice. The [OpenShift installation documentation](https://docs.redhat.com/en/documentation/assisted_installer_for_openshift_container_platform/2026/html/installing_openshift_container_platform_with_the_assisted_installer/installing-with-ui)
requires custom manifests for `None` or a third-party provider. The
[Cluster Network Operator contract](https://github.com/openshift/cluster-network-operator#unsafe-changes)
classifies a provider change as unsafe; forcing one requires deleting the
operator's applied-state checkpoint and can permanently break cluster
connectivity. A successful API server dry run proves only schema admission, not
a supported or recoverable migration.

## Decision

UNF will not convert an existing OVN cluster in place. OpenShift primary-CNI
qualification requires a new disposable cluster installed through the custom
CNI (`networkType: None`) path. Installer inputs are versioned under
`deploy/openshift-primary-cni/` and require:

- dual-stack cluster and Service pools with one IPv4 and one IPv6 Node block;
- no vendor default CNI, no OVN operands, and no foreign CNI configuration;
- standalone kube-proxy during this foundation stage;
- Multus disabled so one exact UNF configuration is CRI-O's primary contract;
- at least two RHCOS workers plus dual-stack transports on every opted-in Node;
  and
- explicit, digest-pinned bootstrap artifacts before the cluster is created.

The implementation gate must adapt the Kind ownership contract to OpenShift's
real paths. A dedicated MachineConfig/operand design will own only exact
fingerprinted UNF files and required forwarding inputs. Host-network bootstrap
components must not depend on ordinary Pod networking; all Nodes capable of
running non-host-network Pods need a local transaction agent and an assigned
dual-stack `spec.podCIDRs` block. The gate must prove SELinux labels, CRI-O
ADD/CHECK/DEL, cross-worker IPv4 and IPv6, kube-proxy Service behavior,
controller-outage recovery, node reboot recovery, MachineConfigPool convergence,
foreign-state refusal, and scoped teardown to the original no-CNI baseline.

There is no supported in-place rollback from UNF to OVN. For this disposable
qualification tuple, operational rollback means exact UNF teardown to the
recorded no-CNI baseline followed by cluster reprovisioning from the saved OVN
install configuration. Unknown or drifted host state must stop teardown.

`make openshift-primary-cni-audit` writes a mode-0600 schema-v1 evidence record
without changing cluster configuration. `make openshift-primary-cni-preflight`
uses the same checks but fails unless the candidate already satisfies the
installation-time boundary. The cl02 audit correctly fails eligibility; that is
a safety result, not primary-CNI qualification.

## Consequences

Milestone 6.6e is In progress. Its platform design and fail-closed candidate
audit are Verified, while installer bootstrap, MachineConfig ownership,
qualification, teardown, and recovery remain open. Existing cl02 stays healthy
on OVN and remains valid for UNF overlay qualification. It must be reprovisioned
through the versioned `None` networking inputs, or a separate matching cluster
must be supplied, before the live primary-CNI gate can proceed.

This ADR does not claim Red Hat production support. The OpenShift custom-CNI
installation path is documented as a Technology Preview boundary, and UNF
remains an uncertified development CNI.
