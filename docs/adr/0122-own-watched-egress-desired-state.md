# ADR 0122: Own watched native and OpenShift egress desired state

**Status:** Accepted and implemented for the Phase 8.5 desired-state slice

## Context

ADR 0121 deliberately left the live source-distribution store empty. Populating
it directly from independent Kubernetes watch events would allow partially
observed pools and policies, stale relist entries, invalid updates, or a
controller restart to change authority without one coherent model revision.
OpenShift EgressIP compatibility must enter the same provider-neutral model,
but UNF must neither adopt its status nor imply that requested addresses are
allocated, reachable, or ready gateways.

## Decision

UNF owns cluster-scoped structural `network.unf.io/v1alpha1` `EgressPool` and
`EgressPolicy` APIs. Pools bind canonical dual-stack prefixes to an explicit
provider. Policies select Namespace labels, workload labels, and optional
ServiceAccounts, constrain destination CIDRs, and request either pool-backed
families/counts or explicit addresses with an explicit provider. The two
address modes are mutually exclusive. Stable Kubernetes UIDs become domain
owners; malformed CIDRs, selectors, providers, and ambiguous ownership are
rejected before model admission.

The controller also discovers and reads OpenShift `k8s.ovn.org/v1` `EgressIP`
objects when that API exists. Only the foreign spec is translated; status is
not read as address allocation, gateway selection, reachability, or authority.
The optional watcher is disabled cleanly on platforms without the API.

Every adapter writes source-keyed records into one `EgressDesiredStore`.
Apply, delete, and full relist operations compile the entire candidate model on
a clone and advance one monotonic revision only after normalization succeeds.
An invalid incremental update or failed/incomplete relist preserves the entire
last-known-good transaction. Complete relists remove stale records only from
their own adapter prefix. Equal input is idempotent.
Referenced pool tombstones remain pending and are retried after policy changes,
so out-of-order Kubernetes delete delivery converges without exposing a broken
intermediate model.

Schema-v1 checkpoints contain the source records, explicit-provider ownership,
and revision in canonical order. The controller restores the exact checkpoint
from the dedicated `unf-egress-desired-state` ConfigMap before starting
watchers and persists accepted revisions by server-side apply. Unknown schema,
noncanonical order, duplicate ownership, invalid complete models, and oversized
payloads fail closed.

Any accepted semantic change clears previously prepared source distributions.
Until allocation, policy facts, gateway/reachability acknowledgements, and
contracts are recomputed in a later slice, the authenticated source endpoint
returns no new authority rather than serving a contract for an older model.

Installation grants only get/list/watch for native egress resources and the
foreign EgressIP API, plus the existing bounded ConfigMap write authority.
Coordinated uninstall preserves all UNF CRDs and custom resources by default;
the explicit data-loss flags cover all three native CRDs.

## Consequences

Kubernetes desired state is now durable, canonical, revisioned, provider
neutral, and replayable across restart. Native and OpenShift inputs cannot fork
allocation or dataplane semantics, and foreign status remains foreign-owned.

This slice does not allocate an address, acknowledge a gateway, publish an
active source contract, configure an interface or route, or change packet
behavior. Authenticated selected-gateway distribution is the next boundary;
source/gateway TC steering and collision-safe dual-stack NAT remain later
Phase 8.5 gates.

`make egress-desired-state-test` inherits all earlier Phase 8.5 gates and adds
structural/check-in CRD equality, native translation, shared-store atomicity,
relist/rejection/restart tests, OpenShift status non-adoption, bounded RBAC and
deployment assertions, and strict Clippy.
