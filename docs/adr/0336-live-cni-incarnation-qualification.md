# ADR 0336: Live Runtime CNI Incarnation Qualification Boundary

Date: 2026-09-13

Status: qualifier verified locally; live rollout and platform evidence pending

The isolated CNI tests establish transaction/kernel behavior, but cannot prove
that the actual CRI runtime supplies Pod UID to the installed executable. The
existing selective Required reply qualifier now has an explicit
`UNF_REQUIRED_REPLY_REQUIRE_CNI_OWNERSHIP=true` gate for that separate boundary.
It is required for the new CNI runtime rollout qualification; the default keeps
the older-runtime reply-only qualifier compatible without inventing UID proof.

After its three owned Pods are Ready, the gate compares their current API Pod
UID, Node and dual-stack IPs with separately read, bounded, root-owned local
CNI journals. Each Pod must have exactly one Ready schema-4 attachment, the
primary network/interface, a valid nonzero creation nonce and exact address
ownership. Duplicate owners, lease addresses or nonces are rejected. A missing
UID remains missing authority; it is not filled in from the API or inferred
from a container ID. After normal namespace deletion, both Nodes must positively
retire all three UIDs before successful evidence is written. The observer never
changes attachments, routes, journals or runtime metadata to produce a pass.

The complete existing 24 allowed requests, eight unsolicited reverse denials,
dual-stack TCP/UDP PodIP/Service/remapped-port matrix, positive ciphertext,
zero observed remote Required plaintext and Native cleanup remain required.
New `cniOwnership` evidence is emitted only after both live ownership and
retirement checks succeed. Older reply-only evidence keeps its original shape.

The validator passes a valid incarnation and 19 negative mutations, including
foreign Node/UID, host-network/deleting/unready Pods, missing or wrong address,
legacy schema, preparing attachment, foreign link/network, malformed nonce,
duplicate ownership, duplicate address and duplicate nonce. The existing reply
and capture gate regressions and shell syntax pass. Rust remains at 787 passing
workspace tests from ADR 0333; this source slice changes only qualification.

This proves runtime/attachment metadata and traffic only when the live gate
passes. It does not independently authenticate a CRI sandbox ID, prove
packet-time interface lifetime, or grant Required same-Node plaintext authority.
Live cl02 rollout and this expanded gate precede matching retained Kind.
The schema-4 agent must not be automatically downgraded after nonce-bearing
records appear; preserve state and use compatible recovery. No journal or
generation reset is permitted. L3's consuming integration, L4/L5/Q and S1–S5
remain open until their own complete evidence exists.
