# ADR 0417: Sealed-bank socket delivery gate

Date: 2026-09-21

Status: implemented; cl02-first immutable qualification pending

Extend the complete isolated bank fixture with real application sockets on its
two exact, descriptor-held CNI namespaces. Attach the existing test classifier
only to the newly created private source host-veth ingress. The real sealed
consumer makes forward decisions; private native routes carry replies. This
is **not** production policy/Service/egress integration or encrypted remote
traffic qualification. Synthetic trusted input remains explicit.

The bounded matrix adds eight positive and sixteen negative observations:

- TCP and UDP over IPv4/IPv6 deliver and return unique 1,200-byte payloads on
  current authority and after restoring the exact target routes.
- Both families deny UDP with no published bank, an unarmed fence, a wrong
  source identity, withdrawn dispatch, republished-but-unarmed authority or
  absent target routes.
- Both TCP and UDP deny after actual journal BeginDelete revokes the source
  nonce, while the links still exist.

Each case uses fresh sockets and kernel-selected server ports, checks exact
peer addresses and payloads, and bounds blocking I/O/connect by two seconds.
Denials require timeout rather than treating arbitrary socket errors as policy
success; denied TCP also requires an empty accept queue. Namespace entry occurs
only on fresh joined OS threads; returned sockets retain their creation netns.
No host interface or production map is attached/mutated. Aya retains the TC
detach guard; the outer fixture checks exact link/bpffs/Namespace cleanup.
The 28 native and nineteen non-transmitting bank checks remain mandatory.

The `kernel-delivery` platform gate requires the exact 8/16 log counts and
completion marker. Evidence schema 2 separates confirmed Namespace removal
from test success; failed diagnostics can now honestly report successful
cleanup. Old evidence is never rewritten. Kind still requires the identical
image's successful cl02 result for this exact suite.

Local locality tests and strict all-target Clippy pass; shell syntax and
formatting pass. No live claim follows from those checks. Run the complete
immutable suite on cl02, retain failures/logs, then matching persistent Kind.
Production consuming integration and L3/L4/L5/Q remain open.
