# ADR 0015: Bounded IPv6 extension-header traversal

Status: Accepted and live verified

## Context

The first IPv6 dataplane slice handled TCP, UDP, and SCTP only when the fixed
IPv6 header pointed directly to the transport header. Legitimate extension
headers therefore bypassed observation and policy. Unbounded traversal is not
acceptable in TC because malformed chains and verifier complexity must not make
forwarding availability depend on parser behavior.

## Decision

Traverse at most six IPv6 extension headers and at most 256 extension bytes. The
parser accepts Hop-by-Hop Options only in first position, Routing, Destination
Options, initial or atomic Fragment, and Authentication headers. Every header
length and the first four transport bytes must fit inside the fixed header's
nonzero 16-bit payload length before the tuple is read.

TCP, UDP, and SCTP then reuse the existing identity, prefix-policy, active-bank,
enforcement, and flow-event paths. The shared no-std ABI crate owns the pure
single-header decoder so length and fragment behavior have host unit coverage.
The TC layer owns the verifier-bounded chain and payload fence.

Malformed or over-limit chains, a misplaced Hop-by-Hop header, jumbograms,
non-initial fragments, ESP, No Next Header, and unknown terminal protocols fail
open without an event. They never manufacture a deny from incomplete state.

## Consequences

- Common IPv6 option chains receive the same L3/L4 enforcement and provenance as
  direct-header traffic without changing the flow or policy ABI.
- The kind test-tools image emits real UDP Hop-by-Hop, Destination Options, and
  combined chains; the full gate proves explicit allow and deny decisions.
- Unit tests cover Routing, initial/non-initial Fragment, Authentication, ESP,
  No Next Header, and variable-length decoding.
- Full jumbogram, ESP, and non-initial-fragment enforcement requires a different
  policy and reassembly/security model and remains out of scope.
