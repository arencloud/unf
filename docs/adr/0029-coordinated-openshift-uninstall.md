# ADR 0029: Coordinated OpenShift uninstall

Status: Accepted and live verified on dual-stack OpenShift 4.22

## Context

UNF intentionally persists BPF maps, TCX links, and legacy netlink filters across
agent replacement. Deleting the DaemonSet or Namespace alone therefore leaves
programs and pinned state on worker hosts. ADR 0022 provides an ownership-checked
per-node cleanup command, but deliberately does not stop agents, coordinate every
node, remove cluster resources, or prove a clean reinstall.

Uninstall must prevent agents from recreating state during cleanup, retain the
same SCC/admission boundary for privileged cleanup work, refuse an accidental
cluster target, and preserve user `SecurityPolicy` objects unless their deletion
is separately authorized.

## Decision

`hack/uninstall-openshift.sh` is the operator-facing orchestrator. It is a
non-mutating dry run by default and requires both `--execute` and an exact
`--confirm-context` match before changing cluster state. It refuses to begin
unless every selected agent is Ready.

The preflight executes `unf-agent cleanup` without `--execute` in every current
agent Pod. Each node must expose a valid current-ABI plan containing all eleven v3
map pins. The plan covers UNF ingress and egress legacy program names on all
current non-loopback interfaces and describes the exact Kubernetes and
cluster-scoped resource disposition.

Execution uses this order:

1. capture the admitted agent image, security context, and exact bpffs/BTF mount
   contract;
2. delete the agent DaemonSet with foreground propagation and require all agent
   Pods to stop;
3. create one node-pinned, non-retrying cleanup Job per selected worker using the
   `unf-agent` service account, constrained SCC, three-capability security
   context, and ADR 0028 admission-protected host mounts;
4. require every Job to report an execute plan and completion;
5. inspect each host and require `/sys/fs/bpf/unf/v3`, UNF program names, and the
   reserved legacy handles to be absent in both directions;
6. remove cleanup Jobs and either delete the dedicated `unf-system` Namespace or
   only the exact UNF namespaced objects; and
7. remove the exact admission bindings/policies, SCC, ClusterRoleBindings, and
   ClusterRoles after privileged cleanup is complete.

Namespace deletion is separately selected with `--delete-namespace`. The
`SecurityPolicy` CRD and all custom resources are preserved by default.
`--delete-crd` is explicit, and existing custom resources additionally require
`--confirm-crd-data-loss`. No recursive host deletion, generic qdisc removal,
broad label-based cluster-resource deletion, or inferred context confirmation is
used.

`make openshift-uninstall` exposes the safe dry run. Execution arguments are
passed explicitly through `OPENSHIFT_UNINSTALL_ARGS` or by invoking the script.

## Verification

`make openshift-uninstall-test` is a disruptive but self-restoring cl02 gate. It
records controller/agent and CRD identities, reviews a complete two-node dry run,
requires 18 planned v2 map pins, proves no Pod replacement, and rejects an
incorrect context confirmation. It then performs the coordinated uninstall with
Namespace deletion while preserving the CRD.

The gate requires the Namespace and all exact cluster resources to be absent,
the CRD UID to remain unchanged, and both hosts to contain neither v2 state nor
UNF filters. It redeploys the OpenShift overlay and runs the complete adaptive
dual-stack qualification, proving fresh map/filter creation, SCC and admission
recovery, encrypted authenticated transport, agent convergence, enforcement,
provenance, and healthy cluster operators. An exit trap attempts a clean redeploy
after any failure once destructive execution begins.

## Consequences

OpenShift uninstall is now reviewable, ordered, node-complete, and recoverable
instead of being a Namespace deletion that silently leaves host enforcement
state. Cleanup authority exists only while the dedicated SCC, admission policy,
and service account are still present, then those privileges are removed.

The script currently targets the OpenShift overlay and requires every selected
Node to be reachable. A failed or unavailable worker is a safe refusal requiring
operator repair before uninstall. CRD deletion remains intentionally destructive
and opt-in. Package-manager integration, immutable release image digests, and
non-OpenShift installer equivalents remain separate release-engineering work.
If execution fails after agent shutdown, the script intentionally leaves cleanup
Jobs and remaining authority available for inspection instead of silently
re-enabling agents against partially cleaned state; the qualification wrapper's
lab-only recovery trap is the tested exception.
