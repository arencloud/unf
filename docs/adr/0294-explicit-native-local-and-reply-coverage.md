# ADR 0294: Explicit Native Local and Reply Coverage

Date: 2026-09-13

Status: implementation and local regressions verified; cl02 then Kind pending

## Decision

Repair ADR 0293's missing transport authority in the producer, not through a
permissive packet-path fallback. Deduplicate endpoint identities before local
pair enumeration, including hairpins. For each policy-allowed inter-Node fact,
cover both transport directions on the participating Nodes only when the
encryption model independently resolves that direction to Native. A reply's
transport record never grants permission for a new reverse connection:
per-packet policy and established-flow checks remain authoritative.

A Required baseline skips Native enumeration entirely. Selective Required
records are never overwritten or downgraded. Wire/map schemas, key lifetimes,
cryptography and missing-authority fail-closed behavior remain unchanged.

Stop before inserting beyond the remaining 65,536 decision slots and refuse the
whole cut instead of publishing partial coverage. This is bounded allocation,
not removal of the capacity limit: 257 distinct local identities alone exceed
the local Cartesian budget. Replica deduplication removes replica-driven work
from this stage, but no measured CPU or throughput improvement is claimed.

## Verification

The same-Node and isolated-return regressions failed on the old implementation
before repair. Five new tests cover locality/hairpin, policy-tracked replies,
policy-denied new reverse traffic, unknown-authority denial, deterministic
replica deduplication, early capacity refusal and unrelated denied remote pairs.
Updated existing assertions account for the additional local self record.

`cargo test --workspace` passes 737 tests with 25 specialized tests ignored;
strict all-target/all-feature workspace Clippy and formatting pass.
`hack/verify-native-transport-coverage-gate.sh` checks the actual probe boundary:
transport/exec errors and malformed responses cannot count as successful denial.

The portable live fixture requires exact runtime revisions, a digest-pinned
tools image, an empty owned Namespace and Native baseline. It isolates client
ingress and server egress, then requires 16 request/reply successes across
same/cross-Node, PodIP/Service, TCP/UDP and IPv4/IPv6, plus eight unsolicited
reverse denials. All listeners must first respond locally; cleanup requires
positive Namespace absence and agent convergence. cl02 runs before matching-image
fresh Kind. Neither live result is claimed in this implementation commit.

The initial old-runtime live attempt stopped at observer preflight: the
controller API's Pod-IP proxy request returned BadRequest. No fixture was
created and this is not a traffic result. The qualifier now uses one owned,
authenticated, loopback-only port-forward for controller observations, removed
on exit. Agent API version checks remain separate. No dataplane check falls
back to that management tunnel.

Subsequent socket and Deployment inspection correct the initial binding
inference: the controller listens on `0.0.0.0:9962`, not only loopback. Controlled
proxy requests identify the actual cause: `--request-timeout=15s` appends a
`timeout` query parameter, which the strict version endpoint rejects as unknown.
The same request without that parameter succeeds, while explicitly adding it
reproduces HTTP 400 with the field-validation error. Preserve strict API query
validation; bound management reads without injecting unrelated query fields.

The next old-runtime attempt passed version checks but timed out downloading
OpenAPI before Pod creation. Its empty owned Namespace was removed. Fixture
creation now uses server-side apply without client-side schema download;
ordinary API resource validation, admission and field ownership still apply,
and ownership conflicts are never forced. This observer/setup failure is not
evidence of either allowed or denied traffic.

The subsequent live run on old runtime `cb59e90`, qualifier `d4eed22`, passes
all local listener checks, then fails the first allowed same-Node TCP request
to `10.128.0.13:8080`. A concurrent public state snapshot reports all five
agents converged. The owned Namespace is removed. Evidence remains under
`.artifacts/s1-native-coverage-old-cl02-ssa*`; this is the live red regression,
not a candidate pass. The fixture now also declares restricted Pod security,
uses the Namespace-assigned OpenShift UID (non-root UID on Kind), drops all
capabilities, and bounds each tools container at 500m CPU/128Mi memory. No SCC
grant or security-policy exemption is introduced.

## Open boundaries

Required locality with identities replicated across local and remote Nodes,
and Required policy-isolated replies, need separate address/locality-bound
contract design and tests. Native-only coverage cannot close Phase 9. Operator
health, decision-count/resource measurements, load envelopes and S1–S5 remain
open. Retain historical passing gates and failed diagnostic attempts. No secrets,
private authority journals or packet payloads enter Git.
