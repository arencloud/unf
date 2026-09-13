# ADR 0287: RHCOS-Compatible Fault Qualification

Date: 2026-09-13

Status: host-tool compatibility repair implemented; full lifecycle pending

## Observation

Runtime `cb59e90`, qualifier `dc738f8`, passed baseline history verification on
the first transfer (269,143 bytes; revision 1,605,891; 512 retained records;
zero reported upstream observation loss), five-Node Required migration,
persistence checks, post-fixture convergence, and Required/selective dual-stack
PodIP and Service traffic on cl02. It failed at the first link-fault selection:
RHCOS jq 1.6 rejected an unparenthesized `if ... end as` expression accepted by
the workstation's jq 1.8.1. Selection failed before any link-lowering mutation.
The failure trap removed test intent and fixtures; this is not verified exact
cleanup. Phase 9 remains open and Kind has not qualified this runtime.

The capture container also reached its fixed 60-second timeout while the gate
was still running. A successor qualifier must tie capture completion to the
fault lifecycle before claiming complete outage-window plaintext absence.

## Decision

Parenthesize the conditional binding for jq 1.6 compatibility. Execute a small
read-only selector fixture through the actual host jq on every platform Node
during preflight, before migration or link faults. Require exact selection of
the synthetic active device and rejection of a foreign Node. Print jq version
to the qualification log. These checks read no authority and alter no links.

Running the full guard regressions under jq 1.6 additionally exposed an empty
input hazard: a failed netlink pipeline could appear successful. Separate the
netlink command from JSON validation, require its successful exit, and parse
captured JSON explicitly with `--argjson`. Refuse empty/malformed responses and
empty target descriptors. A successful complete netlink listing remains
necessary before treating a retired interface as absent. Foreign/replaced
interfaces are still never changed by name alone.

## Verification

The complete `hack/verify-phase9-link-fault.sh` suite passes with workstation
jq 1.8.1 and the existing development test-tools image's jq 1.6, including real
shared host-command quoting and mocked netlink operations. New regressions
refuse empty successful reads and empty targets. Both platform static gates
pass. Live selector preflight is also exercised read-only on cl02's RHCOS host;
this is not a ciphertext/fail-closed or full lifecycle pass. No runtime image,
key, journal, authorization barrier, or convergence deadline changes.
