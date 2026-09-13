# ADR 0290: Observation-Failure-Safe Qualification

Date: 2026-09-13

Status: assertion audit implemented; stricter full cl02/Kind runs pending

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
