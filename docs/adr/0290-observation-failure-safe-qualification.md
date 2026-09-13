# ADR 0290: Observation-Failure-Safe Qualification

Date: 2026-09-13

Status: assertion audit and stricter full cl02 verified; matching-image Kind pending

## Findings

ADR 0289 preserves the passing `f96aec2` cl02 gate. A final code review found
negative assertions that conflated observation failure with the desired result:

- `! http_probe_once` accepted an API/exec failure, HTTP error or wrong body as
  network denial.
- A failed host command could look like absent encryption state. Cleanup also
  checked only tables 20001/20002 and IPv4 rules, although runtime tables rotate
  through 20000–29999 and protocol 85 owns routes and table-less rejection rules.
- Negating a firewall pipeline could hide failure of `iptables-save` itself.

These are qualifier gaps, not evidence that the passing runtime leaked plaintext
or retained kernel state. They must nevertheless be closed before final release
qualification. No runtime image, cryptographic authority or convergence deadline
changes in this milestone.

## Decision

Run a small script inside each client Pod that distinguishes healthy HTTP,
GNU Wget network failure (exit 4), and all other probe errors. Require the exec
transport itself to succeed and return exactly one known result. API failure,
deadline, unsupported Wget, HTTP server error and wrong body never count as
network denial. Positive traffic probes use the same result boundary.

Collect successful JSON netlink dumps of links, IPv4/IPv6 rules and all routing
tables. Explicitly validate the documents. Count encryption interface names/
aliases, reserved rotating-table state, and protocol-85 state, including
table-less unreachable fences. Require a positive all-zero snapshot from every
expected Node and retain those snapshots in diagnostics and final evidence.
Read failures are retryable unavailability, never proof of cleanup. This is
read-only: foreign or suspicious state is not automatically removed.

Preflight independently requires both firewall dumps to succeed and refuses
legacy Service chains, while preserving kubelet firewall chains. Register
namespace ownership only after successful creation; partial fixture setup can
then clean up its own namespace without adopting an existing one. Kind history
captures now use the run-specific diagnostic directory. Add public recovery
progress messages to the OpenShift run so agent recovery and epoch waiting are
distinguishable without intrusive observation.

## Verification

`hack/verify-phase9-negative-evidence.sh` exercises actual remote helper code
with mocked commands: healthy/refused IPv4 and IPv6 probes, API/deadline/server/
body/tool failures, every netlink read failure/empty response, malformed dumps,
renamed owned links, current rotated tables, IPv6 routes, table-less fences,
foreign state, firewall read failures and leftover Service chains. It also
guards drift of the runtime's protocol/table constants and both gate call sites.
The suite passes under jq 1.6 and 1.8.1; both platform static gates include it.

On cl02, actual fixture Pods independently returned `http-ok` from the healthy
local server and `network-denied` from a refused local connection. The real host
snapshot correctly detected live selective state on the source worker. After
the prior full gate finished, all five RHCOS hosts passed the new read-only
firewall check and reported zero encryption links, rules and routes in both
families. Temporary debug Pods were removed. These focused checks are not a
replacement for the stricter uninterrupted full run, which must pass on cl02
before the identical pinned runtime is qualified on fresh Kind.

## First stricter run

Qualifier `c076962` passed all five firewall/jq preflights, but timed out during
Required migration on the unchanged `cb59e90` runtime. Its last snapshot
contained only four Nodes: three reported generation 1789263303363/epoch 467;
one retained generation 1789263229881/epoch 466 with that newer cut pending.
The source worker snapshot was absent. This run did not reach the new outage
probe or final cleanup assertions and does not supersede the prior passing
gate's exact scope. Diagnostics are retained under
`.artifacts/phase9-cb59e90-strict-evidence-openshift-diagnostics`.

Concurrent workstation registry image downloads were active during this run.
They were stopped before further diagnosis to remove observer-link contention
as a variable; they are not a proven cause of the timeout. No Kind cluster or
feature test was started. The failure handler restored Native intent and the
replacement controller became Ready with zero restarts; all five Nodes were
Ready. Actual cleanup is not inferred from intent/readiness alone. Repeat the
strict gate without parallel image transfers before attributing the failure or
moving to Kind; no convergence deadline is increased.

## Stricter cl02 control run passed

Runtime `cb59e9080a4cce5544c1ae3c69974233d53d8c52`, qualifier
`dbefd3e41257a6c801523967bcc29e15236b40a9`, passed the full gate at
2026-09-13 02:04:15 UTC in 1,420 seconds, without parallel registry downloads.
This removes that variable from this passing run; it does not establish the
cause of the preceding timeout or prove repeated-run reliability.

- Eight strict Required network-denial results and eight healthy Native results;
  command/observation errors cannot satisfy denial.
- Capture ran 01:52:28–01:54:10 UTC, stopped explicitly after the fault window,
  exited zero and reported zero kernel drops. Offline counts: 563 WireGuard,
  zero Required plaintext, and 200 Native plaintext frames.
- Source-agent replacement, natural key rotation and controller replacement
  passed. All eight persistence checkpoints reported positive writes, zero
  errors/restarts, and the 2-GiB controller ceiling. Maximum stored state was
  881,608 bytes; all sampled codecs were gzip, not a live zstd-transition test.
- Independent history replay covered revisions 3,226,000–3,674,836 with 512
  retained records and zero reported upstream loss. Retention evicted 448,836
  observations across the comparison; the claim is retained-window-only.
- All five Nodes converged to Native generation 1789264948131 with no pending
  generation or encryption epochs. Every successful host snapshot positively
  reported zero owned links, IPv4/IPv6 rules and routes. Final agents converged.
- The same six operators remained unhealthy; none newly unhealthy. Internal
  DNS and direct Pod-endpoint timeouts remain unresolved stabilization work,
  not an external-DNS-only issue or evidence of whole-cluster health.

Private evidence is archived as
`.artifacts/phase9-cb59e90-dbefd3e-openshift.json` (SHA-256
`5950ed9152825209424c3203eeb0cec1d2fe4df5e0b90228ac2893b89bd3a942`)
and the corresponding `.pcap` (SHA-256
`c7b7c44a701840385dc8ab08cd34d46bca0ff85580d92617ca33ea8ec2500304`).
Raw capture, history and per-Node cleanup observations remain under
`.artifacts/phase9-cb59e90-isolated-observer-openshift-diagnostics`.
Qualify these exact immutable runtime images on fresh Kind next. Phase 9 and
S1–S5 are not declared complete by this cl02 result.
