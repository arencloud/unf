# ADR 0090: Make the IPv4 NodePort host-kernel contract explicit

**Status:** Accepted and implemented; live evidence pending (2026-08-30)

## Context

The first live Phase 5.7 run proved that UNF classified and translated IPv4
NodePort traffic correctly in both directions, but Linux discarded the
reverse-translated reply before it left the receiving Node. IPv6 passed the
same cross-worker matrix. Packet capture and flow provenance isolated the
failure to host IPv4 validation after TC rewrote a backend reply to the exact
Node address and NodePort.

The distribution defaults used by the Kind Nodes had reverse-path filtering
enabled and did not accept a locally sourced address on the forwarding path.
Disabling only reverse-path filtering or enabling only local-source acceptance
was insufficient. With both settings applied to every existing interface,
Cluster NodePort passed through either worker, Local passed through the backend
worker, and Local remained fail-closed on the worker without a local backend.

## Decision

Every UNF primary-CNI Node that exposes IPv4 NodePorts has this host contract:

- `net.ipv4.conf.*.rp_filter=0`, including `all` and `default`; and
- `net.ipv4.conf.*.accept_local=1`, including `all` and `default`.

The `default` values cover interfaces created after activation, while the
wildcards configure interfaces already present. Existing IPv4 and IPv6
forwarding requirements remain unchanged.

The isolated Kind configurator captures the exact per-Node, per-interface
values before the first mutation, never overwrites that backup on an idempotent
run, applies the contract, and restores every surviving captured key during
rollback. The OpenShift installer persists the same contract through the
master and worker MachineConfigs and verifies every live interface before CNI
activation.

The NodePort cleanup audit runs from privileged host-network qualification Pods
that mount the host bpffs and UNF state. It does not assume the Kind Node image
contains `bpftool`.

## Consequences

- IPv4 NodePort behavior no longer depends on distribution-specific sysctl
  defaults.
- Rollback of the disposable Kind fixture restores the exact captured baseline
  instead of guessing host defaults.
- Applying the OpenShift MachineConfig may roll and reboot both pools; the
  deployer already waits for exact pool convergence before activating UNF.
- This contract does not add generic host routing, host-network-client,
  LoadBalancer, or DSR support.

## Verification

The static installer gate verifies both persistent MachineConfigs and the
reversible Kind scripts. `make nodeport-kind-test` must then pass the complete
dual-stack NodePort lifecycle and exact rollback before ADRs 0089–0090 become
live verified. Phase 5.8 independently qualifies the persistent settings on
RHCOS.
