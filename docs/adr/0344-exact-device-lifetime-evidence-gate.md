# ADR 0344: Exact Device-Lifetime Evidence Gate

Date: 2026-09-13

Status: local gate verified; corrected cl02 kernel run pending

The ADR 0343 cl02 pilot reaches target deletion and ifindex reuse, but fails
with EEXIST at the explicit fresh-binding stage. Its private archive and error
remain failed-run evidence. It is not a verified lifecycle and Kind is not
advanced. Raw mirred snapshots show an absent target (`to_dev: "*"`) after
deletion/reuse and increasing overlimits. Match-all classifiers also count
unrelated IPv6 traffic, so raw totals cannot be labeled exact probe counts.

The fixture now gives each filter an explicit handle and uses exact IPv4/IPv6
UDP destination/port flower matches with hardware offload disabled. Each
family has a distinct filter priority. Rebinding records the newly created
action and existing filters before replacement; TC commands are retained for
failure attribution. No live UNF interface/filter is modified.

`local-delivery-device-gate.jq` independently checks all eight action snapshots:
kind, redirect direction/verdict, exact action/device identity, binding/reference
counts, software execution, and exact packet/overlimit totals. The retired
action must have ten probe attempts and four overlimits (two down-state probes,
two after index reuse), with no implicit target rebinding. A distinct action
must start unused and then deliver two probes. Eight exact positive payloads
and absence of denied tokens are checked alongside receiver/socket liveness;
empty payloads alone never prove denial. Linux reports this action's failed
redirect attempts as overlimits, not the generic `drops` field.

The local gate passes a positive fixture, 96 one-field mutations and six
malformed/reordered cuts. Shell syntax and diff checks pass. Only a complete
corrected cl02 run, exact statistics, fixture cleanup and log review can verify
the kernel slice; then commit/push before identical-image Kind. The pending
live locality consumer still needs authenticated placement, immutable source
attachment authority, banked publication, post-policy/post-Service integration,
restart/recovery and measured costs. L3, L4/L5, Q and S1–S5 remain open.

The first corrected cl02 run (`bf495ca`) fails before traffic: its software-only
flower filter references a separately created action without matching offload
flags. The kernel explicitly rejects the mismatch. Both action creations now
also specify `skip_hw`, as supported by the pinned tc command's action syntax.
The failed fixture is retained and cleaned up; no denial/continuity evidence
is inferred from this setup failure. The complete cl02 rerun remains required.
