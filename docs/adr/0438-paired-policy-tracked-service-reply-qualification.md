# ADR 0438: Paired policy-tracked Service reply qualification

Date: 2026-09-21

Status: verified isolated main-program gate; production composition remains open

All seven exact main-program tests pass cl02 first, then persistent Kind using
the identical immutable corrected `b87d050` image:

`quay.io/arencloud/unf-test-tools-dev@sha256:8125e6550446885c7e2fae6659e05375a728d8b136bcb3d0c49c10160cf29ddd`

Both runs positively check compiled source
`b87d05073848ac68afc92e44ba6a00af2e7c0456`. Test binary SHA-256 is
`b75d2ba4c328a582bf784bf9392a5f6ddd7285ed5e605bd1f7515db20ef212b6`;
main ELF SHA-256 is
`557943f9f756a6cdc2869ce0067ecad6b41f4e0ffd02f2312bc5866ac5ac2834`.

The new reply case executes IPv4/IPv6 × TCP/UDP through the actual main hook.
Every combination preserves established replies across revision churn and
backend ownership across VIP rewriting, while rejecting missing/expired
forward witnesses, absent policy configuration, missing transport decisions
and unsolicited replies after a denied request. All six prerequisite tests
also pass: compiled provenance, existing encryption, locality-bank-miss
fallback, source egress precedence, DSR and Service translation/churn.
The failed ADR 0436 attempt remains failed and retained; it is not overwritten.

These are BPF_PROG_TEST_RUN results, not live selected-bank sockets. Both gate
processes exit zero without restarts and exact-UID namespace cleanup passes.
Both production fleets remain `45d85d5` and Ready/zero restarts. Production
journals are byte-identical, including Kind's absent empty control-plane
journal. No production map/key/history reset or image rollout occurred.

Current and retained/rotated regular/init logs, including both controllers,
have no ERROR, incomplete JSON or observer failures. cl02's current window
has 457 WARNs (431 flow retention, 22 peer-proof retries, four topology
retention); retained logs contain 7,277 across the same 22 previously reviewed
categories. Kind has one current peer-proof WARN and 71 retained WARNs across
the same twelve categories. These findings remain stabilization input.

Evidence roots: `.artifacts/p9-kernel-main-bridge-b87d050-{cl02,kind}` and
`.artifacts/p9-main-b87d050-*`.

| Artifact | SHA-256 |
| --- | --- |
| cl02 result | `6f1768fce62694e3e24562e72669622669f126de39e4259a3a007bf882b85f06` |
| cl02 test log | `779ecc09aed4628a95c95fd136179f7c4e4a2594baaf463d3e2b9649bcca2ca6` |
| Kind result | `7ef5ad1d9540d49e2fec32d0361c35a6d72c4c1fd94f1991e44f0273b3f1ffbc` |
| Kind test log | `0b7f9d59ce6f1b4f49a1cf579cf4af663d0401fe9cb140731f3ae10cac7e0ff6` |

Next execute ADR 0437's actual publisher/main-hook socket composition, cl02
first. L3/L4/L5/Q and S1–S5 stay open; this isolated gate is not full Phase 9.
