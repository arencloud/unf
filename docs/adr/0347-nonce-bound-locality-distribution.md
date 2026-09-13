# ADR 0347: Nonce-Bound Locality Placement Distribution

Date: 2026-09-13

Status: controller/wire source slice verified locally; live consumption pending

The next L3 boundary distributes placement evidence without turning it into
packet permission. `POST /v1/state/encryption-locality` uses the existing
authenticated internal-agent channel and bounded authority materialization/
response-delivery lane. Under the informer read guard it rechecks the current
agent Pod, exact recipient Node UID, cluster, membership and identity/routing
coordinates, then constructs both source facts and certificate from that cut.
Unready, stale, foreign, missing-IPAM and inconsistent-UID cuts fail closed.
Zero revisions are not promoted into apparently initialized placement truth.

Schema 1 has a fresh OS-random nonzero request nonce. The response carries the
nonce, certificate and strict typed raw placement snapshots. The decoder
requires both the outstanding request and independently current applied context,
reprojects the authenticated source facts and replays the certificate against
them. The certificate checksum is not sender authentication. All source facts
must arrive over the authenticated controller connection; this API cannot
establish that transport provenance by inspecting bytes.

Wire size is capped at 16 MiB before decoding. Issuance checks source and final
response sizes through a bounded counting writer, avoiding a second complete
JSON allocation solely for sizing. The future HTTP caller must also cap actual
stream collection, including absent/misleading Content-Length. Placement work
does not enumerate policy identity pairs; it still copies bounded source facts
and serializes responses. No measured CPU/memory/throughput improvement or
unlimited-scale claim follows from this source change.

Verification: 797 workspace tests pass, 26 remain explicitly ignored. Seven new
tests cover exact IPv4/IPv6 placement and explicit empty cuts; request nonce and
all context coordinates; source UID/address/identity substitution; unknown
fields and malformed/oversized wire; current agent/Node incarnation scoping;
unready, stale and inconsistent controller cuts. Existing certificate/generation
goldens remain unchanged. Formatting and strict all-target/all-feature Clippy
are required before committing.

This slice adds no agent polling, durable authority, map ABI, plaintext fallback,
route mutation or packet admission. Live fleets remain on `450de80`; cl02 and
Kind have not qualified this endpoint. The next source boundary is the bounded
authenticated agent fetch and current-cut handoff, followed by platform gates
in cl02-before-Kind order. Banked admission, exact source/peer lifetime proof,
L4/L5/Q and S1–S5 remain open.
