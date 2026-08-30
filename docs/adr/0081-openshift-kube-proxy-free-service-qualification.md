# ADR 0081: Qualify the service fabric on kube-proxy-free OpenShift

Status: Accepted and live verified for Phase 4.8

## Context

Phase 4.7 proved the bounded ClusterIP contract on a dedicated Kind fixture, but
that result could not establish RHCOS, enforcing SELinux, CRI-O, native legacy
netlink attachment, OpenShift operator, or five-Node recovery behavior. The
dedicated cl02 installation already ran UNF as its installer-time primary CNI,
so Phase 4.8 needed a guarded transition from the existing persistent ABI v3
state to ABI v4 before kube-proxy could be removed.

Live qualification attempts exposed two important boundaries. An interrupted
installer transaction must be recovered only when every staged artifact matches
either the previously committed marker or the exact desired release. A
controller-produced schema-v3 flow checkpoint also contained a bounded 1 ms
wall-clock regression. Blind deletion or repair would have hidden both recovery
requirements, so the preserved checkpoint became migration evidence.

## Decision

The OpenShift service release is fixed by an in-repository record and immutable,
anonymously pullable development-image digests. Revision
`f721f9a7a0084e908bfa3eda2896ec2c3521ebbb` is the source of the qualified
controller and agent:

- controller: `quay.io/arencloud/unf-controller-dev@sha256:d056a16560656d53974a5b4393627716e203473e08ed5575e3c8679b6639d2c9`;
- agent: `quay.io/arencloud/unf-agent-dev@sha256:ed4904a70bc2b17e9a88e4f297dc4e16769d7e65dba16dfb1a82002bf13da37e`;
- test tools: `quay.io/arencloud/unf-test-tools-dev@sha256:f57a7ee9668d6b87f4e00c4e8df9240b8889c6ee50f817ea1e884732b2f42b13`.

The staged workflow requires explicit infrastructure acknowledgement, a clean
committed worktree, matching Kind evidence, and healthy kube-proxy. It replaces
the controller first, requires compatibility and service-state health, then
replaces one `OnDelete` agent at a time. The controller must migrate only a
bounded legacy clock regression to checkpoint schema v4; new aggregation clamps
receive time monotonically, while malformed current or unbounded legacy state
remains fail closed.

Only after all five agents converge may the qualification workflow disable
kube-proxy. It rejects remaining proxy resources or `KUBE-SVC` rules and proves
cross-worker direct Pod and DNS continuity plus IPv4 and IPv6 TCP/UDP ClusterIP.
It exercises readiness withdrawal, terminating endpoint exclusion, backend
deletion/recovery, exact no-backend behavior, and current translation evidence.
With the controller scaled to zero, it independently replaces the source-Node
and destination-Node agents while repeatedly probing all four Service paths.
The controller must then restore its durable schema-v4 state and regain complete
agent convergence without agent replacement.

Because flow history is intentionally bounded, the final observability check
creates a fresh no-backend outcome after controller recovery, restores the
backend, and waits for both the drop and successful translation before checking
service explanation. This tests the contract without assuming an early event
survives unrelated high-cardinality cluster traffic indefinitely. Cleanup must
return CNI attachment counts to baseline, remove the fixture Service state,
retire only recognized ABI v3 pins, retain ABI v4, and introduce no new unhealthy
ClusterOperator. Failure after proxy removal requests bounded kube-proxy
restoration; success deliberately leaves kube-proxy disabled.

## Verification

The exact workflows are:

```console
UNF_OPENSHIFT_SERVICE_EXPECTED_INFRASTRUCTURE=cl02-st7gq \
UNF_OPENSHIFT_SERVICE_ACKNOWLEDGE_DISPOSABLE=cl02-st7gq \
make openshift-service-deploy OPENSHIFT_KUBECONFIG=.tools/cl02-audit.kubeconfig

UNF_OPENSHIFT_SERVICE_EXPECTED_INFRASTRUCTURE=cl02-st7gq \
UNF_OPENSHIFT_SERVICE_ACKNOWLEDGE_DISPOSABLE=cl02-st7gq \
make openshift-service-test OPENSHIFT_KUBECONFIG=.tools/cl02-audit.kubeconfig
```

The gate passed from workflow revision
`a0ab2e5dbbe29f65950cd36eb3834bca85809283` on OpenShift 4.22.10 / Kubernetes
1.35.6 across three control-plane and two worker Nodes. Every Node ran RHCOS
9.8.20260812-0, kernel 5.14.0-687.39.1, CRI-O 1.35.6, enforcing SELinux, dual
Pod and Node address families, and native legacy netlink attachment.

`.artifacts/phase4-openshift-service-deploy.json` records the controller-first,
node-serial migration with kube-proxy retained. The preserved schema-v3
checkpoint became schema v4 with 1,024 entries and zero reversed receive-time
pairs. `.artifacts/phase4-openshift-service.json` records the uninterrupted
kube-proxy-free pass, 5/5 fresh and converged agents, source/destination agent
replacement, lifecycle and outcome evidence, exact fixture cleanup, ABI-v3
retirement, ABI-v4 retention, kube-proxy absence, and no new unhealthy operator.
Insights was already unavailable before the gate because its external upload
was unreachable and remained the sole baseline exception.

A post-pass audit observed transient controller readiness/liveness probe
timeouts during the final high-cardinality checkpoint burst. The controller did
not restart, returned Ready without intervention, retained a valid schema-v4
checkpoint, and all agents stayed converged. This is recorded as a production-
scale checkpoint/write-pressure boundary rather than expanded by the bounded
Phase 4 claim.

## Consequences

Phase 4's bounded service-fabric foundation is Verified on its exact Kind and
OpenShift tuples. The successful cl02 state uses UNF as the primary CNI and sole
qualified ClusterIP dataplane, with kube-proxy disabled, the controller Ready,
all five agents converged, and persistent ABI v4 only.

This does not qualify SCTP Services, NodePort, LoadBalancer, ExternalName,
session affinity, internal/external traffic policies, topology-aware routing,
Maglev, DSR, host-network Service clients, fragments, generic NAT/RELATED
tracking, additional OpenShift/Kubernetes/kernel tuples, production images,
signatures, attestations, or production availability and scale. Those require
separate post-foundation milestones and evidence.
