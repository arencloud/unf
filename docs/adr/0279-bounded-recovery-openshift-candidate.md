# ADR 0279: Bounded recovery OpenShift candidate

Date: 2026-09-12

Status: cl02 deployment failed during startup revalidation; full gates pending

Runtime `d128aabd777c5caa71ea522ed091f0471467a327` combines the proven
replica-aware receipt join with deadline-bound timeout responders (ADR 0276)
and bounded checkpoint fallback (ADR 0277). Its immutable public images are
pinned in the Phase 9 release record and Kustomization. Kind remains pending.

All 723 workspace tests passed with 24 specialized tests excluded by the generic
invocation, and strict all-target/all-feature workspace lint passed. The delayed
peer regression failed before the fix and passed afterward, including altered
nonce/foreign-round refusal and expiry. The isolated marked WireGuard engine
passed 4,096 rounds per family, peer-loss denial, fresh recovery, duplex counters
and ciphertext-only underlay capture. The actual compact-store capture test
restored identical typed authority from gzip and window-bounded zstd.
The assembled release controller links only the ordinary system C/math/GCC
runtime libraries and does not depend on a dynamic libzstd installation.

cl02 must pass preserved-state deployment and the full migration, fixture,
traffic, selective, failure, rotation, replacement, operations and cleanup gate.
ADR 0278 adds explicit persistence-error and resource-limit checks around planned
controller replacement, with final gzip compatibility. Archive each runtime's
evidence separately. No previous Kind or cl02 result qualifies this successor.

The 512-record operations retention boundary and its cumulative loss reporting
remain explicit. Any further conformance work must preserve the architecture's
truthful loss accounting, not clear history to obtain a pass. Neither Phase 9
completion nor heavy-load readiness is claimed by publishing this candidate.

A full-history redacted secret scan covered 598 commits and raised nine
historical findings. Source review identified eight Rust map-key type names
misclassified as API keys and one explicitly invalid Bearer-token fixture that
requires HTTP 401. No actual credential was found in those flagged locations.
No scanner rule or path was suppressed, and recent milestone scans remained
clean. Raw reports and all operational credentials stay in ignored local paths.

## Deployment result and durable-gap diagnosis

Harness `7ce4ed6` installed the exact controller and five agents, but deployment
timed out with agent startup attachment fenced. No full encryption gate or Kind
run followed. Native intent remained configured, yet node journals showed that
the earlier failed run had not finished its Native encryption transition.

The saved controller frontier was generation `1789245078215`, acknowledged by
all five Nodes. Independently captured public active facts from all five Node
journals agreed on generation `1789245125471`, each with that saved frontier as
its exact prior. Their pending Native cut was `1789245583383`. Authenticated
replay of the existing pending fact returned HTTP 503 with `encryption generation
frontier predecessor mismatch`: the controller lacked the intermediate frontier.
The earlier checkpoint-write gap had survived subsequent policy/Service
convergence and ordinary pod readiness.

No checkpoint or Node authority was deleted or manually rewritten. Recovery
must reconstruct the exact missing frontier from authenticated durable Node
facts, preserving the existing predecessor check and refusing skipped history.
Temporary host-debug Pods used for capture were removed automatically. The new
fallback has local verification but has not yet qualified this transition on
cl02; publication alone does not repair already-missing controller history.
