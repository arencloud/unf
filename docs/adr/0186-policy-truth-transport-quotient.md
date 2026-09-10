# ADR 0186: Policy-Truth Transport Quotient

- Status: Accepted and implemented for Phase 9.5y
- Date: 2026-09-10

## Context

WireGuard transport is L3 while Kubernetes and UNF policy authority is L4. A
single identity pair may deny most ports and allow one. Requiring all L4 classes
to be allowed would incorrectly withhold transport; treating any transport as
packet authorization would broaden connectivity.

The ordinary Kubernetes default-allow case also has no policy object. Inventing
a synthetic policy ID to satisfy encryption provenance would be operationally
misleading and would make explanations disagree with the policy dataplane.

## Decision

Phase 9.5y introduces the **Policy-Truth Transport Quotient**.

The projection consumes effective protocol/port observations and emits one
canonical encryption fact per identity pair. Any policy-authorized L4 class
requests L3 transport availability, while a pair with only deny outcomes stays
out of required plans. This quotient never authorizes a packet: the original
policy lookup remains first in the TC pipeline, before Service/egress selection
and encryption lookup.

An identity pair with no policy observations is explicitly represented as
`NoApplicablePolicy`, allowed, and carrying no policy ID. Explicit-rule and
default-action authority require real nonzero policy IDs. Mixed observations
retain only the IDs contributing to the effective transport-demand outcome,
deduplicate them canonically, and bind the reason into the path contract and its
decision witness.

## Consequences

- One allowed port can provision shared L3 transport without allowing any
  denied port through the policy-first packet path.
- Default-allow explanations remain truthful and contain no fabricated owner.
- L4 rule cardinality is removed from WireGuard peer/interface cardinality.
- Destination replicas still require address-exact late transport binding; that
  independent fast-path slice remains next before Kubernetes runtime projection.

## Verification

`make encryption-policy-quotient-test` inherits the demand-sparse fleet gate and
tests no-policy default allow, mixed allow/deny L4 classes, all-denied pairs,
canonical real policy provenance, contract digest/witness binding, and strict
Clippy for the encryption domain.
