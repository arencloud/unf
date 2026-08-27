# ADR 0048: Bounded Kind failure and scale qualification

Status: Accepted and live verified for the default Kind profile

## Context

Phase 3 already had focused failure evidence for one agent, map pressure,
persistent-state corruption, external-export pressure, and adjacent-version
rollouts. Those gates did not provide one reproducible record tying a larger
policy/identity fixture to Kubernetes-object churn, simultaneous node-agent
loss, controller unavailability, forwarding continuity, recovery budgets, and
the exact environment.

An unbounded statement such as "scale tested" would be misleading. Fixture
cardinality, time budgets, kernel/Kubernetes/CNI facts, and queue/error behavior
must be part of the evidence.

## Decision

`make kind-scale-failure-test` is the default bounded Phase 3 qualification
profile. Its deterministic generator creates four temporary Namespaces. Each
Namespace contains four clients on the control-plane node, two servers on the
worker, one source-selected egress NetworkPolicy, and one destination-selected
ingress NetworkPolicy. The resulting profile has 24 workload Pods and eight
NetworkPolicies and exercises direct-Pod IPv4 and IPv6 traffic.

The gate requires:

- all fixture Deployments and the controller's Pod, Namespace, policy, identity,
  ingress, and egress state to converge within 180 seconds;
- three disable/enable Namespace-selector cycles, a selected Pod-label removal
  and restoration, and paired ingress/egress policy additions and removals to
  complete within one 180-second churn budget;
- both node agents to be deleted while the controller is scaled to zero and to
  become Ready from the exact previously applied identity/policy revisions and
  populated pinned maps within 180 seconds;
- offline agents to report desired revision zero while retaining the exact
  nonzero applied revisions; equality is required again after controller
  recovery under its new epoch;
- TCP/8080 allow and TCP/9090 deny to remain continuous over both families;
- the controller to reconverge within 180 seconds and agent export queues to
  drain within 60 seconds;
- no exported-flow drops, no telemetry-drop increase, zero controller reconcile
  errors, and no more than ten expected aggregate agent sync failures during the
  deliberate outage;
- exact removal of all fixture Namespaces and restoration of the baseline
  NetworkPolicy, indexed-address, and agent-convergence counts.

The latest schema-v1 JSON record is written to
`.artifacts/phase3-scale-kind-result.json`. Every attempt is appended to a JSONL
history beside it. The record includes Git revision and tree state, live
controller/agent compatibility tuples, UTC time, host CPU/kernel,
Kubernetes/CNI/node runtime and capacity, Pod MTU/offloads, fixture cardinality,
budgets, measurements, peak state, recovered agents, and post-cleanup state.

Generator inputs are bounded to 2–16 Namespaces, 1–32 clients and 1–16 servers
per Namespace, and at most 256 workload Pods. A changed profile is distinct
evidence and does not broaden the default claim automatically.

## Evidence

On 2026-08-27 the default profile passed on Kubernetes 1.35.0 and dual-stack
kindnet with Linux 7.1.4. It produced 1,355 resolved policy entries and 62
indexed Pod IPs. Initial convergence took 11 seconds, the complete churn set 39
seconds, simultaneous two-agent offline recovery 32 seconds, and controller
reconvergence 7 seconds. Six expected agent sync errors occurred during the
outage, with zero telemetry-drop delta and no exported-flow drops. Exact cleanup
restored one baseline NetworkPolicy, 14 indexed Pod IPs, and two converged
agents.

## Consequences

Phase 3 now has repeatable combined-failure evidence at a declared cardinality
and environment. It does not establish a production capacity limit, qualify
clusters larger than two nodes, prove high availability for multiple controller
replicas, or cover other Kubernetes, kernel, CNI, or hardware combinations.
Those remain separate support-matrix work.
