# ADR 0444: Paired local DSR socket qualification

Date: 2026-09-21

Status: verified private-network DSR composition; full fleet closure open

The `4c47699` diagnostic passes cl02 first, then persistent Kind on the same
immutable image:

`quay.io/arencloud/unf-test-tools-dev@sha256:6ab91c2b2a1c18f073c8514d6ba70dd33b672c48472cf943d29f15f96ffae5bc`

On each platform all seven actual-main checks precede the three-test source
recovery/publisher/socket suite. The complete matrix passes 24 positive
exchanges and 24 denials. Eight DSR LoadBalancer exchanges use only backend
PodIP listeners, with exact 1,200-byte requests/replies for IPv4/IPv6 TCP/UDP.
The sixteen actual forward/reverse connection entries carry reversible NAT
state, not VIP-only DSR state. Four DSR requests fail during identity-writer
withdrawal; fresh republication restores delivery. No ordinary Native transport
decision can mask a locality-bank miss. Exact link, namespace, bpffs and outer
fixture cleanup passes.

Compiled source equality passes. Agent test binary SHA-256:
`ba76b04a516a5842e2d9ab8ef805931760fa62acdc765fdc840303697673e221`.
Main ELF SHA-256:
`faee6bb87885f044b747f11400d7805434dddb03c3a876597ac05b11ea1f6e49`.
The sealed bank remains the immutable qualified base from ADR 0437.

Both production fleets stay `45d85d5`, Ready/zero restarts. All production
journals remain byte-identical, including preserved absence on Kind's empty
control-plane Node. Current regular/init and retained/rotated logs include
controllers. No ERROR, observer failure, partial record or malformed JSON is
found. cl02 has 425 current WARNs in three categories and 8,200 retained WARNs
in 22 categories; Kind has six current peer-proof WARNs and 81 retained WARNs
in twelve categories. Existing findings remain open; no state or history reset.

Evidence roots: `.artifacts/p9-kernel-main-{bridge,composition}-4c47699-{cl02,kind}`
and `.artifacts/p9-main-4c47699-*`.

| Artifact | SHA-256 |
| --- | --- |
| cl02 main result | `fe415418e4fbffb883a1bec2c2e5924675714547c0e7148e7805584f18374708` |
| cl02 main log | `0f7cdd3a5190db5cee01b0d7d157a291e497146c4b2791c933cc8401d40c1d51` |
| cl02 composition result | `1fb8cfc0fea5b9928bd05f5414c29d582eae9bd67553a9e6863cb5b9baa21a41` |
| cl02 composition log | `d69e5a34f07151435dc0d9a3dc317a07d607a26aa407654ccc0f1f2df36232a0` |
| Kind main result | `25e0d521681d2104bd0865696d828c75511d350590e537181e3f42f7d9f1ab52` |
| Kind main log | `20a77212aecd1edd6623b94f7351e26f6d230ded0984354f1cea7b23ab4e10bc` |
| Kind composition result | `3ca6f4367bad335ff679af9435de605a5a80ceaa6ec8f88637261e4998dd97f7` |
| Kind composition log | `d792c6c4dc382ce81ab13002a1943f38a9e0c2672a2fead1d1ecbce5f3ac8ac0` |

This closes the bounded local DSR publisher/main-hook socket slice. It does not
prove remote Required ciphertext, mixed replicas, workload replacement, full
process recovery, authenticated fleet reconciliation or load/resource stability.
ADR 0443's later private-pin lifetime implementation needs its own paired gate.
L3/L4/L5/Q and S1–S5 remain open.
