# ADR 0149: Authenticate and durably order DQR evidence

**Status:** Accepted and implemented for Phase 8 milestone 8.8b

## Context

Diversity-Quorum Reachability defines the evidence needed to prove an exact
external path set, but a safe compiler also needs an authenticated transport,
durable replay boundary, loss semantics, and deterministic expiry. An observer
must not be able to redefine its plan or failure domain, two replicas in one
failure domain must not manufacture quorum, and controller restart must neither
erase replay positions nor extend finite authority.

The existing gateway reachability acknowledgement and Proof of Safe Forgetting
transactions already fence desired revision, allocation revision, provider,
lease epoch, addresses, and action. DQR must enter those transactions without a
second, weaker readiness path.

## Decision

1. A cluster-scoped `EgressReachabilityPlan` is the controller-owned statement
   of the exact DQR contract. A namespaced
   `EgressReachabilityObservation` separates controller-owned identity in
   `spec` from observer-owned evidence in the `status` subresource. The spec
   embeds the exact plan as well as observer name, failure domain, and vantage,
   making event order irrelevant and preventing the observer from selecting its
   own quorum identity.
2. The unbound `unf-reachability-observer` ClusterRole grants only `get` on the
   observation object and `get`, `update`, and `patch` on its status. Operators
   bind it with a namespaced RoleBinding in a dedicated Namespace for each
   independently administered observer. It grants neither object creation nor
   spec mutation. The agent ServiceAccount receives no observer authority.
3. The controller translates status only after independently replaying the
   embedded plan and digest. A bounded evidence store permits one current plan
   per intent owner and one current object per observer. Plan revisions and
   observer `(sourceEpoch, revision)` positions are monotonic; same-position
   mutation, regression, aliasing, malformed evidence, and oversized relists
   fail closed without replacing last-known-good durable evidence.
4. Current plans and observations, retained post-deletion replay positions, and
   exact materialized assessments share one canonical, domain-separated
   SHA-256 checkpoint in `unf-egress-desired-state`. Relists replace each input
   class transactionally. Observation loss and plan deletion remove current
   authority but retain the position needed to reject stale recreation.
5. Any changed evidence is materialized and checkpointed before it may affect a
   reachability acknowledgement. A revision-aware pending barrier prevents an
   unrelated reconciliation from consuming an in-flight update and retries
   persistence or reconciliation without publishing uncommitted authority.
6. Positive assessments schedule their earliest absolute authority deadline.
   Expiry rematerializes `DenyClosed`, persists it, and issues an exact rejected
   acknowledgement without waiting for a Kubernetes event. Consumers also
   enforce the absolute deadline independently, so scheduling delay cannot
   preserve stale readiness.
7. The acknowledgement bridge requires exact desired/plan equality and the
   exact gateway UID set. Verified Ensure evidence becomes `Ready`; verified
   Withdraw evidence becomes `Withdrawn`; missing, mismatched, or expired
   evidence becomes a higher-revision rejection. The existing safe-forgetting
   transaction can therefore consume DQR withdrawal without weakening its
   source-fence or gateway-drain requirements.

## Consequences

- Authentication and failure-domain administration are explicit Kubernetes
  authorization decisions. Merely adding observer replicas cannot increase
  diversity.
- Observations may arrive before a plan, but they create no authority until the
  exact controller plan exists. This removes watch-order dependence.
- Restart, relist, deletion, and recreation preserve deterministic replay and
  explanation provenance. The checkpoint exposes the exact plan, observations,
  assessment verdict/reason, deadline, and digest.
- The existing development-only `static` provider remains on its explicit
  self-acknowledgement path until 8.8c replaces it with a live reference
  provider. This milestone does not claim route mutation, real route observers,
  packet activation, BGP/BFD, production availability, scale, or OpenShift
  qualification.

## Verification

`make egress-reachability-lifecycle-test` inherits the DQR contract and
three-Node service-fabric prerequisite. Focused tests cover API/CRD equality,
strict translation, order-independent materialization, replay and
same-position-mutation rejection, deletion with retained positions, canonical
checkpoint recovery and mutation rejection, exact acknowledgement bridging,
consumer-side expiry, deployment rendering, and strict linting.

The dedicated kube-proxy-free dual-stack Kind lifecycle proves namespaced
status-only observer RBAC, agent denial, two independently bound failure
domains, durable `Ready`, controller-restart recovery, autonomous
`DenyClosed`, replay and mutation rejection, higher-revision recovery, and
exact current-state cleanup while retained positions survive. It writes
schema-v1 evidence to `.artifacts/phase8-egress-reachability-kind.json`. The
fixture deliberately uses a non-live owner and performs no route or address
mutation; live activation and withdrawal are the independent 8.8c gate.
