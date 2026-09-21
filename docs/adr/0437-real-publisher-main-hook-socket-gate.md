# ADR 0437: Real publisher/main-hook socket gate

Date: 2026-09-21

Status: fixture implemented and locally checked; cl02-first execution pending

The next bounded gate connects the actual agent bank publisher to the main
packet hook instead of supplying synthetic packet-time locality input. It
creates two real CNI attachments/routes in a private fabric and peer namespaces,
installs the actual journal retirement hook and exclusively owned runtime maps,
loads the actual main ELF/continuations against those exact maps, and drives
the production publisher's observation, sealing, publication and reuse path.

Both directions attach the real main ingress classifier. A structurally admitted
empty encryption cut has no ordinary Native/remote transport permission, so a
bank miss cannot mask failed local delivery. The matrix requires sixteen
positive and twenty negative IPv4/IPv6 TCP/UDP socket exchanges: unpublished
denial, PodIP and translated-port Service delivery/replies, real writer-guard
withdrawal, completed-but-not-republished denial, fresh republication, policy
denial before locality, policy restoration and journal retirement while the
old links still exist. Unique source ports and sequenced 1,200-byte payloads
prevent prior connections or replies from satisfying later cases.

Namespace socket operations use fresh joined OS threads, not namespace changes
on Tokio workers. Test resources are bounded; exact private link and bpffs
inventories must return to their original state, and namespaces are removed
only under their captured identities. No host sysctls, production CNI records,
interfaces, maps or journals are modified. The two-test suite additionally
requires compiled-source equality and exact executed/result counts. Kind
requires matching successful cl02 image, suite and compiled-source evidence.

The main diagnostic image packages this new suite and the exact sealed bank
from its already immutable `5f03031` base image beside the main ELF, matching
the production loader's sibling-path contract. That bank is a separately
qualified component, not newly rebuilt source implied by the main-image label.

Local verification: 909 workspace tests pass; thirty platform/privileged tests
remain explicitly ignored. Agent test compilation, strict all-target Clippy,
formatting and shell syntax pass. The new socket test is **not yet a platform
pass**. Corrected reverse-Service qualification (ADR 0436) precedes advancing
composition on cl02, then matching Kind.

This fixture still supplies placement/admitted-plan coordinates directly and
uses the real writer guard around fixture-applied inputs, not the controller's
authenticated plan loop or complete live reconciler. It does not qualify
remote ciphertext, mixed replicas, DSR sockets, recovery or crash-stage cleanup.
Even a pass therefore cannot close L3/L4/L5/Q or stabilization by itself.
