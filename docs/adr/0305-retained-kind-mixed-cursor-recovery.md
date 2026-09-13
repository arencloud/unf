# ADR 0305: Retained Kind Mixed-Cursor Recovery

Date: 2026-09-13

Status: controller-only recovery and matching-image Native gate passed

After ADR 0304's cl02 pass, import the same exact manifests into retained
`unf-s1-571379d`. Update only its controller to runtime `54f5511`. All three
agent Pod UIDs and zero restart counts match the pre-upgrade capture; their
runtime remains `571379d`. No Node, Pod, journal, key, map or frontier reset
was used to remove the original recovery condition.

Before replacement, the persistent frontier still had revision
`1789273418666` and two receipts. The control-plane Node's public journal had
that generation while both workers had `1789273423267`, with the exact old
generation as predecessor. The replacement controller logged restoration of
that same partial frontier and cached successor at 06:10:49 UTC. It published
a complete generation from authenticated Node facts at 06:10:51, a fresh
key-independent Native plan `1789279853266` at 06:10:53, and another complete
generation at 06:10:54.

The following complete three-Node public capture showed all journals at
`1789279853266`, predecessor `1789273423267`, and the stored frontier at the
new generation with three receipts. This proves progress out of the retained
mixed-cursor condition with old agents, not just recovery of a clean fixture.
It is not a traffic, Required cryptographic activation or soak result.

| Ignored frontier evidence | SHA-256 |
|---|---|
| `s1-provenance-54f5511-kind-before/frontier-store.json` | `d0a7d7d76c9752b9efd01e7dd5e3a9d286037a88e49cf0d21517e7af3455d9ee` |
| `s1-provenance-54f5511-kind-controller-only/frontier-store.json` | `793a6bb6bd2b8910e4951c324d02277695da0d343ebeb181d1096285ffe8cb5b` |

All three agents were subsequently replaced serially with the cl02-qualified
image, each becoming Ready with the exact revision and zero restarts before
the next replacement. The original RollingUpdate strategy was restored after
all replacements. The same adoption-fenced Native gate passed on runtime
`54f55112e37bb91c35e46683b4bf32533bd4294d`, qualifier
`0d246b0` (the committed recovery checkpoint), after the cl02 pass: 24 allowed
requests/stateful returns, eight unsolicited denials, both IP families,
same/cross-Node PodIP and Service paths with translated ports, exact fixture
cleanup and all three agents converged. Evidence JSON SHA-256:
`e4a63153231122d145e525e1bbb2e7adbd8c43badc340429b8d407c37220f138`,
ignored `.artifacts/s1-provenance-54f5511-native-kind/evidence.json`.

This closes this bounded Native recovery slice on both platforms, not the
entire Phase 9. Full lifecycle on the repaired runtime, fresh-Kind coverage,
Required locality/replica and reply coverage, controlled continuity, and
S1–S5 remain open. The release's full Kind qualification remains pending.
