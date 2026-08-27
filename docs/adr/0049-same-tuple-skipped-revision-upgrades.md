# ADR 0049: Same-tuple skipped-revision upgrades

Status: Accepted and live verified for one two-commit Kind window

## Context

ADR 0047 qualified one adjacent N to N+1 revision. Operators may need to skip an
intermediate patch, but commit ancestry alone does not establish compatibility.
Both endpoints of a skipped window must publish the same persistent-state and
wire-schema tuple, and the rollout must retain the controller-first,
one-node-at-a-time, observable, reversible behavior of the adjacent gate.

## Decision

`make kind-skipped-upgrade-test` qualifies a same-tuple skipped window. The
default N is `HEAD^^`; the baseline builder refuses fewer than two commits of
distance. A release ref may be older, but it must be an ancestor at or beyond
that minimum distance.

Unlike the first adjacent gate, which supported a historical baseline predating
the version endpoint, the skipped gate requires compatibility schema v1 from
the N controller and both N agents. Their tuple must match, and the N+2
controller and agents must publish the exact same tuple:

- persistent BPF-state ABI;
- identity snapshot schema;
- policy snapshot schema;
- agent-status schema;
- flow-export schema.

Build revision is intentionally excluded from tuple equality and is asserted
separately for provenance. The gate uses dedicated baseline image names so an
adjacent and skipped baseline cannot be confused through a reused tag.

The live sequence establishes N/N, upgrades the controller to N+2, replaces one
agent at a time through an explicit mixed state, reaches all N+2, rolls one
agent back to N and forward again, rolls the controller back to N while agents
remain N+2, and finishes at N+2. Every state requires two authenticated fresh
agents, advancing telemetry, TCP/8080 allow, and TCP/9090 deny.

## Evidence

On 2026-08-27, `make kind-skipped-upgrade-test` passed with:

- N: `e6e5ac63caf462a80440d21447e46ceac3291e54`;
- intentionally skipped revision:
  `9dc602300e5efe35af113b109753cf9c31b268de`;
- N+2: `a630ee1adbead7e3612e6bfd7380a80f3c058d12`;
- exact commit distance: 2;
- exact compatibility tuple equality across both controllers and all agents;
- deterministic controller N+2 / agent N+2 / agent N mixed operation;
- supported same-tuple agent and controller downgrade plus forward recovery;
- uninterrupted enforcement and telemetry continuity.

Workspace formatting, strict lint, 164 tests, eBPF release build, manifest
rendering, distance-guard negative checks, and shell syntax also passed.

## Consequences

UNF can qualify an explicitly measured skipped patch window without inferring
compatibility from ancestry. This is evidence for the exact two-commit window,
not an unlimited promise that every future same-tuple skip is supported. A
listed schema/ABI mismatch remains incompatible and must be rejected or
migrated under separate gates. Unsupported downgrade and clean-rebuild behavior
also remain separate milestone-2 work.
