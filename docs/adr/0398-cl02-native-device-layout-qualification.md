# ADR 0398: cl02 Native Device Layout Qualification

Date: 2026-09-21

Status: complete isolated cl02 gate verified; matching Kind pending

Source `e2e98ad` runs on cl02 worker `bc-24-11-27-b6-49`, unchanged Node UID
`1ade5ebe-7f24-4f35-b9d4-aca5b13b1c2b`, RHCOS kernel
`5.14.0-687.39.1.el9_8.x86_64`, using public immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:ade532bdeba39f04beb8fcfbe2fcc8b5f0c4240954144d7edcd0f01b76f00128`.
The diagnostic BPF remains ADR 0379's
`4ce81c6b2606eceb75330d933de977cffac3e450456a83fc0cc463fad6a2d47a`.

Native discovery matches independently derived bpftool/jq offsets exactly;
repeated native discovery returns identical bytes and BTF digest. Native output,
not the reference JSON, configures the actual device programs. All seventy
serial cases pass: thirty deliveries, forty denials, nine non-transmitting
context seeds, two wrong-context rejections and sticky endpoint invalidation.

The 40,000-packet movement matrix records 2,013 deliveries and 37,987 guard
rejections. The separate 40,000-packet generation-publication matrix records
8,587 allow-generation deliveries and 31,413 deny-generation rejections.
Independent replay attributes every sequence exactly once. Both matrices have
zero foreign delivery, receiver socket loss or unobserved redirects. All 22
publication readbacks, forty empty-dispatch denials, frozen-write/unsealed-bank
rejections and exact retirement of five old authority maps pass. No lossless
handoff, production publication or throughput claim follows.

Private namespaces/mounts and the exact fixture Kubernetes Namespace are
removed. All 116 existing CNI records remain byte-identical. The first post-test
ordinary status sample overlaps reconciliation after Namespace deletion; a
subsequent fresh sample converges all five agents at policy 407 / Service 193.
Current UNF Pods remain Ready with zero restarts and unchanged live `6d71a30`
images. No production map, journal or authority history is reset.

All eleven current regular/init log streams are reviewed before, during and
after the fixture. Final window: 450 WARN, zero ERROR. It retains 437 bounded
flow-history checkpoints, ten proof-assistance HTTP 503 retries, two bounded
topology-history checkpoints and one expired-resource-version watch/relist.
These operational findings remain tracked; a scoped pass does not erase them.

Evidence: `.artifacts/p9-device-lease-e2e98ad-cl02` and
`.artifacts/p9-native-layout-cl02-*`. Archive SHA-256:
`bb8373592b7300607dee317fde89124aa669e7e8e9a1cf249e20ea5b5e523b83`.
Result SHA-256:
`ee05fb131372af1a6433ba9659e99d49f66b20ba721ead452b77bdabbe44881c`.
Next: identical-image persistent Kind qualification, then actual L3 consumer
integration. Locality admission/delivery and production-authority claims remain
false. L4/L5/Q and stabilization S1–S5 remain open.
