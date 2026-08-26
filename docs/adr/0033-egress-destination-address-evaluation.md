# ADR 0033: Address-aware egress destination evaluation

## Status

Accepted and implemented in the userspace translator/evaluator. Dataplane
lowering and enforcement remain intentionally disabled.

## Context

Egress `ipBlock` selects a destination address, but the original policy `Flow`
only carried source addresses because all enforced address blocks were ingress
peers. Endpoint metadata alone cannot faithfully decide an external or
address-selected egress destination.

The retained flow schema already preserves destination IPv4 and IPv6 addresses.
Changing every existing ingress caller before egress controller integration
would create unrelated API churn, while silently ignoring destination blocks
would weaken policy.

## Decision

Add `DestinationAddresses` and
`evaluate_for_direction_with_addresses` to the shared policy evaluator. The
existing `evaluate` and `evaluate_for_direction` entry points delegate with no
destination address, preserving their endpoint-only behavior and serialized
contracts.

Address-bearing selectors use one family for one concrete flow. An IPv4 block
matches only an IPv4 destination and an IPv6 block only an IPv6 destination. No
address, both families at once, an address outside the CIDR, or an address inside
an `except` boundary does not match and therefore falls through to the selecting
policy's isolation default.

The multi-direction NetworkPolicy translator now accepts egress `ipBlock` and
stores bounded IPv4/IPv6 CIDRs and exceptions on the rule destination selector.
It reuses the existing validation and bounds: at most 1,024 IPv4 addresses or
1,024 IPv6 CIDR boundaries per block, valid in-family strict subsets, and no
reserved unspecified IPv4 address.

The controller continues to use the ingress-only enforcement admission entry
point, so no egress policy—including an address block—can enter agent snapshots
or affect forwarding in this slice.

## Verification

Policy tests compile IPv4 and IPv6 egress blocks, evaluate an included external
destination as allowed, and require default deny for exceptions, outside-CIDR
addresses, absent addresses, and invalid dual-family input. Existing ingress
block, selector, port, evaluator, and lowering tests remain unchanged.

The focused gate is `cargo test -p unf-policy --all-features`. Repository-wide
formatting, lint, tests, eBPF builds, and the rebuilt-kind ingress regression gate
protect the retained enforcement boundary.

## Consequences

Userspace now has faithful destination-address semantics for egress policy and
can consume the destination addresses already present in retained flow records.
This removes the final evaluator-level `ipBlock` gap without pretending that an
ingress-oriented BPF map can enforce it.

Source-side map keys/lowering, snapshot and policy-map ABI design, TC egress
lookups, controller distribution, direction-aware explanation/simulation, and
live dual-stack egress qualification remain subsequent slices.
