# ADR 0346: Retained Kind Device-Reference Delivery Qualification

Date: 2026-09-13

Status: isolated matching Kind target-device lifetime slice verified

After the revised cl02 result in ADR 0345 is committed and pushed, retained
Kind worker `unf-s1-571379d-worker` passes the complete identical-image gate.
Source: `40def8e47674c2fc77e482a7c0ce67a52befff76`.
Image: `quay.io/arencloud/unf-test-tools-dev@sha256:ca0943efb8562cbc85b5c3486ba8d47d0c7a8c110bf45aa42308f18ec82e1d27`.
The OCI manifest is checked before import into the retained isolated runtime.

All eight positive IPv4/IPv6 UDP payloads, four exact denied attempts,
rename/down/up behavior, deletion/index reuse and explicit new-device binding
pass. The old action remains targetless after replacement. All eight action
snapshots pass the strict independent gate, including replay from the archived
raw evidence after cleanup. The former Kind IPv4 failure remains failed evidence.

Both new private target namespaces report all/eth0 RPF values 0/2, unlike the
Node namespace's separately observed 0/0 values. Their verified reverse routes
select eth0. No reverse-path check is disabled. The corrected fixture passes
under these settings; the deleted earlier fixture's precise settings and sole
failure cause were not observed and are not retroactively asserted.

Result SHA-256, identical to cl02:
`1109c54d99868430fb6b58499d051ba5b5d58996cc4a27071173e3410a1b9883`.
Private fixture archive SHA-256:
`9b35c32bd42ee8eef4b0859946bf9faee18183a98ba7b409404c36e54a70c95f`.
All private namespaces and the qualification namespace are removed. The Node
UID is preserved. All live UNF containers are Ready with zero restarts; init
installers remain Completed/exit 0. Controller/agents are fresh and converged
at policy revision 50 / Service revision 19. Live source remains `450de80`.

Controller, all agents and installers are reviewed across before/test/after
intervals. The final API read contains 33,036 lines / 18,247,427 bytes, below
each per-file cap. Current and retained rotated agent files add 271,115 lines /
160,765,444 bytes of overlapping coverage. The API window retains three proof
assistance warnings; the wider retained files contain eighteen proof, nine
plan-synchronization, six activation and two older startup-barrier warnings.
No observed ERROR/panic/OOM, verifier rejection or stopped-dataplane match is
found. Per-packet INFO amplification remains an S3 finding, not a resource win.

Both platforms now verify the tested target-device reference mechanism.
It does not prove source authentication, peer namespace relocation safety,
arbitrary TC composition or live packet permission. The authenticated/banked
locality consumer, L4/L5, full lifecycle Q and S1–S5 remain open. No live CNI,
BPF, transport generation, authority journal or release pin is changed.
