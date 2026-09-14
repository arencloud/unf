# ADR 0360: Split-Module Device Layout Validation

Date: 2026-09-14

Status: locally verified correction; corrected cl02-before-Kind gates pending

The first matching Kind packet-device observation gate on source `6fc49da`
fails before BPF loading: its veth split BTF contains distinct-ID copies of
`sk_buff`, `net_device` and `net`, unlike the qualified RHCOS inventory. The
decoder rejects these as ambiguous names. This remains a failed qualification,
not a successful packet-time check. Evidence is retained in
`.artifacts/p9-device-observation-6fc49da-kind`.

The decoder now permits at most one definition of each required structure per
inventory. It checks every base/module combination (at most sixteen), including
resolved members, pointer targets, integer shapes, bounds and structure sizes.
Every combination must produce the same sizes and relevant layout; disagreement
fails closed. Duplicate definitions within either inventory still fail. No
first-match selection, hard-coded newer-kernel offsets or relaxed field checks
are introduced. Missing/ambiguous diagnostics now identify the structure name.

Two positive and 32 negative local cases pass. The additional positive case
uses module-local type references; ten new negative cases cover conflicting
member offsets, sizes, missing members, bad pointers and within-module duplicates.
Replaying the retained Kind inventory yields device/index/net/cookie/private-peer
byte offsets 16/224/264/4608/2752. This metadata replay is not verifier or runtime
qualification. The diagnostic BPF object and all live UNF binaries are unchanged.

The failed fixture cleans up its private and Kubernetes namespaces without
attaching BPF. Post-failure controller, every agent and installer logs plus
retained current/rotated agent CRI logs are reviewed. The current window shows
three proof-assistance warnings; older retained CRI also contains activation
retries. No live UNF ERROR, panic, OOM or verifier failure is observed. All live
containers remain Ready with zero restarts and all three agents converge at
policy 49 / Service 19. Completed init installers are checked separately.

A fresh immutable fixture must pass cl02 first, then retained Kind. Drop-only
introspection is still not continuous safe forwarding or authenticated locality
authority. L3, full Phase 9 qualification and stabilization S1–S5 remain open.
