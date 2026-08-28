# ADR 0069: OpenShift primary CNI uses a DNS-independent bounded bootstrap

Status: Accepted and statically Verified; live qualification pending reinstall

## Context

ADR 0068 requires a new OpenShift cluster installed through the custom-CNI
`None` path. A manifest set copied from Kind would deadlock: ordinary OpenShift
DNS Pods need the primary CNI, while a primary-CNI agent configured with the
controller Service DNS name needs DNS before it can obtain its Node block and
open the local transaction socket. RHCOS also uses different CNI paths and
persistent host configuration must be owned through MachineConfig.

The current cl02 hardware audit found `br-ex` as both default-family uplinks,
MTU at least 1500, dual-stack Node transports, RHCOS 9.8, kernel 5.14, and
SELinux enforcing on the intended five-Node shape.

## Decision

The reinstall package under `deploy/openshift-primary-cni/` has two boundaries:

1. Assisted Installer inputs select `networkType: None`, preserve the cl02
   dual-stack pools, enable standalone kube-proxy, and disable Multus.
2. After the bootstrap API is available, `make openshift-primary-cni-deploy`
   activates UNF only after strict candidate, infrastructure-name, and explicit
   disposable-cluster acknowledgement checks.

The deployer selects one control-plane Node deterministically, pins the
host-network controller to that Node, and injects its sole IPv4 InternalIP as
the `unf-primary-controller.internal` host alias on every agent. Disposable TLS
includes that exact DNS identity. Controller discovery therefore needs neither
cluster DNS nor an existing Pod network; the normal controller Service remains
available after bootstrap.

Two MachineConfigs own one exact sysctl file on master and worker pools. The
deployer waits for a new rendered configuration and complete pool convergence,
then reads back IPv4/IPv6 forwarding and SELinux on every Node. The initial
native provider pins both families to `br-ex` and refuses a default-route or MTU
mismatch before any MachineConfig or CNI mutation.

Because OpenShift does not guarantee Kubernetes controller-manager PodCIDR
allocation for a third-party provider, `node-blocks.json` explicitly assigns
one non-overlapping `/23` and `/64` pair to each of the five physical cl02 Node
names. A standard-library IP network validator requires an exact Node set,
exact OpenShift pool/prefix agreement, canonical subnets, one block per family,
and global non-overlap. Assignment refuses foreign existing values and reads
back every patch. Activation permits this mutation only when the pre-assignment
audit has no blocker other than missing PodCIDRs. Server-side dry run verified
all five assignments against current cl02 without changing its Node objects.

The dedicated runtime overlay:

- uses immutable controller and agent image digests built from revision
  `a521b45e48df3b6be2090c1ff6e59579bcebe273`;
- runs the controller and agent on host networking, with every opted-in Node
  receiving a local agent;
- grants separate required SCCs to the controller and agent service accounts;
- uses fail-closed admission policies to bind the primary agent to exactly seven
  recognized host paths, two exact containers, host namespaces, and its Node
  selector; and
- retains the three-capability non-privileged agent while isolating host-file
  installation in one privileged `spc_t` sidecar.

The installer sidecar waits up to 180 seconds for the root-authenticated local
agent socket. Only then does it atomically publish `/var/lib/cni/bin/unf` and
`/etc/kubernetes/cni/net.d/10-unf.conflist`. A mode-0600 four-field ownership
marker binds platform plus binary/configuration SHA-256 fingerprints. Foreign
configuration, unowned paths, symbolic-link directories, malformed ownership,
or fingerprint drift fail closed. Replay is idempotent.

`make openshift-primary-cni-package-check` verifies both Kustomize renders,
immutable image references, custom-CNI and Node-block inputs, MachineConfigs,
exact paths and CNI shape. Its disposable mounted-host fixture additionally
proves first install, exact replay, foreign-config refusal, and binary-drift
refusal with the published agent image. OpenShift 4.22 server-side dry runs
accepted the SCCs, admission policies, and MachineConfigs without mutating
cl02.

## Consequences

The reinstall configuration and activation workflow are ready for a new cl02
installation. This is not live primary-CNI qualification: CRI-O
ADD/CHECK/DEL, Node readiness, dual-stack forwarding and Services, reboot and
controller-outage recovery, exact teardown, and reprovision recovery remain the
6.6e2 live gate.

The initial `br-ex` choice is deliberately platform-specific and verified, not
an implicit portability claim. A rebuilt cluster with another default uplink
must update the versioned agent patch and pass the package/preflight gates; the
deployer will not auto-guess or silently fall back.
