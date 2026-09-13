# ADR 0341: OpenShift Namespace-Anchored Veth Qualification

Date: 2026-09-13

Status: isolated cl02 slice verified; matching Kind pending

Source `a83b4c51a0517976c0c8bbbf28b33c01109f8c44` is packaged as
`quay.io/arencloud/unf-test-tools-dev@sha256:f64e73ac1c4ad0f9fef4fa5495aaac84b43eb631d58dfa266501bcb5a8e7c9bd`.
Anonymous registry inspection confirms the digest and OCI source revision.
The candidate adapter SHA-256 is
`e3a985e4c39baef4e5b639df951840844048a2e43f8320d19521a3faf1250e86`;
the pinned predecessor is
`97feafa727c23130203ddf5e862497a4ca4deeb2f0e9add55dd5b4d2fbd2c756`.

ADR 0340's expanded qualifier passes on cl02 worker `bc-24-11-27-b6-49`,
RHCOS 9.8/kernel 5.14.0-687.39.1.el9_8 with SELinux Enforcing. It uses four
private network namespaces in an isolated privileged, tokenless container,
without host mounts. The genuine host's index/peer reference is 5/4 and the
impostor's is 4/5. Both observed peer NSID integers happen to be zero, but refer
to different namespaces: integer equality across observers is not authority.
The old adapter accepts both CHECK and replayed ADD against the impostor;
the fixed adapter rejects both with the exact anchored-pair error. Restoring
the original namespace handle restores successful CHECK without changing the
journal. All fourteen negative checks, four interrupted-creation states,
legacy replay, UID replacement, address reuse and normal cleanup pass.

Result SHA-256: `1d5445fd9c6c9ff5e643c6ba61bbf36c3a5f26bea0ddeddd88808fb75a9eca70`.
Private fixture archive SHA-256: `48bb0948980140ec76a5e7d22bfa3af745f8b0cb2dda44308cb23cb62d4e62e6`.
The fixture namespace is deleted; the worker UID is unchanged. All five live
agents and the controller remain Ready with zero restarts and converge at
policy revision 383 / Service revision 204. Live binaries remain `450de80`;
there is no live CNI, BPF, journal or authority reset/change.

Controller, all five agents and installers are reviewed before/during/after.
The final review has 444 lines / 103,065 bytes, below per-file caps: 435 bounded
flow-history warnings, five proof-assistance warnings, one key-publication
warning and one bounded topology-history warning. No observed ERROR/panic/OOM,
verifier rejection or stopped-dataplane match appears. These warnings remain
operational findings. An initial controller status observer raced creation of
its own port-forward log file; the local observer was corrected and a new
read-only capture succeeds. This observer failure is not a product-test pass.

Commit/push this result before the identical isolated Kind gate. Continuous
device-lifetime fencing, authenticated locality consumption, L4/L5, Q and
S1–S5 remain open. No full platform row or release pin is promoted.
