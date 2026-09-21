# ADR 0442: Paired private locality source recovery qualification

Date: 2026-09-21

Status: verified filesystem/offline-worker and existing socket composition

The `a6eeb4c` diagnostic passes cl02 first, then persistent Kind on the identical
immutable image:

`quay.io/arencloud/unf-test-tools-dev@sha256:5e7b8f9553c20e5c3b1151b33a27622dbb6438adc2c443c0d099ca4fa052b908`

Both platforms pass all seven actual-main classifier checks before the expanded
three-test composition suite. The new root-filesystem test verifies bounded
private checkpoint replay, symlink/hard-link/FIFO/oversize rejection, foreign
header preservation, partial-temporary repair and the actual offline acquisition
worker with no controller URL or token. Source replay grants no kernel authority.
The existing real publisher/main-hook socket matrix still passes sixteen
positive exchanges and twenty expected denials, with exact cleanup.

The agent test binary SHA-256 is
`f61f80b4274b158213bdcf4bc3e730fb8f7de3137b5d07776cbe727ce5190e0f`;
the actual main ELF SHA-256 is
`79e361037c6301707ef32f7ca71e1698b015382bf58788942ec01e22e6e817b9`.
Compiled source equality is checked in both suites. The sealed bank remains
the separately qualified immutable base component (ADR 0437).

Production remains `45d85d5` on both fleets: all UNF regular containers are
Ready with zero restarts, journals are byte-identical, and Kind's empty
control-plane journal remains absent. No runtime/map/key/history reset occurs.
All current regular/init logs and retained/rotated logs, including controllers,
are reviewed. No ERROR, observer failure or partial/non-JSON record is found.
cl02 has 427 current WARNs (406 flow retention, fourteen peer-proof, four
topology retention and three key-publication retries), plus 8,038 retained WARNs
in 22 categories. Kind has four current peer-proof WARNs and 79 retained WARNs
in twelve categories. These findings remain open, not a stability claim.

Evidence roots: `.artifacts/p9-kernel-main-{bridge,composition}-a6eeb4c-{cl02,kind}`
and `.artifacts/p9-main-a6eeb4c-*`.

| Artifact | SHA-256 |
| --- | --- |
| cl02 main result | `25657369344339ddefccf32e83a6e6318f03fae2bab849d010faf8d02cdf1282` |
| cl02 main log | `7e9ad384058d4a95024618d287a0d40cde876c4059df972d041bc4cf1daac2dc` |
| cl02 composition result | `9a5bb7a6308d193b07539587d9fc66a0122c12abedcacfe95fa0868fa6ab7c61` |
| cl02 composition log | `e512e40cfc017113f28147a8b93b755a3f712121256b2b6fd5becfb42adca7c8` |
| Kind main result | `11e4945ae15242f4477659818b25c95d93b3dbfdd7d665c46ca35d23f4f0a4a6` |
| Kind main log | `46db74f311aac983479eba25a3f38a4770e7df4291d3a053bc6c3c8c7b4fc446` |
| Kind composition result | `16464fe15b02c4c4a22ce69c68db334d9f7a8ca32c18f2ee136efa25a3cd2be9` |
| Kind composition log | `21e020db6d69881527006747d5c4d32604ce901c073289e164cb35c9dcf66add` |

This does not qualify full process-restart traffic, crash-stage pin reclamation,
DSR sockets, actual authenticated fleet reconciliation, mixed replicas or remote
Required transport. ADR 0441's later DSR expansion has its own pending gate.
Phase 9 L3/L4/L5/Q and stabilization S1–S5 remain open.
