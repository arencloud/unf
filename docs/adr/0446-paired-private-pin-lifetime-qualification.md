# ADR 0446: Paired private-pin lifetime qualification

Date: 2026-09-21

Status: verified privileged diagnostics; restricted fleet deployment held

The `762c980` diagnostic passes cl02 first, then persistent Kind on this identical
immutable image:

`quay.io/arencloud/unf-test-tools-dev@sha256:a67e88099c8e508ae42ccf3dc23911052a5ac98251262ca063cf5ba4ac53d61d`

Each platform passes seven actual-main classifier tests, followed by the
four-test composition suite. The new lifetime test verifies that a returned map
FD remains valid after the private mount thread exits; temporary pins/maps are
reclaimed after success, injected error, injected panic and SIGKILL of a child
paused with a real pinned map. The parent mount namespace/directory remain
unchanged. Foreign preparation residue is preserved and refused. The deliberate
panic is present in both diagnostic logs and is part of the explicit test;
it is not an unexpected production crash or a suppressed failure.

The real production bank loader then uses that private-mount path in the actual
publisher/main-hook socket fixture. All 24 positive exchanges and 24 denials
pass, including PodIP, translated Service and reversible DSR requests/replies,
writer withdrawal/republication, policy denial and journal retirement. Private
source recovery also passes. Exact link, namespace, bpffs and outer fixture
cleanup succeeds; all test containers terminate successfully without restarts.

| Packaged component | SHA-256 |
| --- | --- |
| Agent test binary | `ac8538c8b821cdb9c57f8acefe835eb912d1d3fd49ca893758a6c3d49a2de384` |
| Locality library test binary | `fbaca345cf780a0a3ed9d7cfda1c549c9a794e0632c6fbc2734fc709ecfc1d2e` |
| Actual main ELF | `eaea640f23f6134ed96363e970979d6d1c340c75dc237fab93852f1cdd37774d` |
| Qualified immutable base bank | `93da80e50201d45841b1253d489328518bdc5f593518f9329d6e9345dca0faa3` |

Agent compiled source equality is checked. Both production fleets stay
`45d85d5`, Ready/zero restarts, with byte-identical journals and preserved empty
Kind control-plane absence. No production map, key, history or permission reset.
Current regular/init and retained/rotated controller/agent/installer logs are
reviewed: no ERROR, observer failure, partial record or malformed JSON. cl02
has 442 current WARNs (408 flow retention, 25 peer-proof, eight topology retention
and one key retry), plus 8,475 retained WARNs in 22 categories. Kind has seven
current peer-proof WARNs and 86 retained WARNs in twelve categories. All remain
findings, not a heavy-load/stability result.

Evidence roots: `.artifacts/p9-kernel-main-{bridge,composition}-762c980-{cl02,kind}`
and `.artifacts/p9-main-762c980-*`.

| Artifact | SHA-256 |
| --- | --- |
| cl02 main result | `14abaf92e95171120e120bd04fcddc7e457e2bf7ef25d81b7796ce8586201553` |
| cl02 main log | `a9d724c93d62bbcbbd8c6ddcf246a46e05822842803c8ad6cdea8355ce2cf948` |
| cl02 composition result | `a75019a0821e5b527af425d99efa1a74b099bf3ebaafa1edb2ec0fb552c403f0` |
| cl02 composition log | `4e7be510cea74226597b6279d18e3150244dd405cba71001d20f420f59556eab` |
| Kind main result | `2f6fd57648227e61662d0c3480f1ae9e9ed07d5e00e22adce21dc314ef6c5144` |
| Kind main log | `8eabbd5833813ff7a5b45fbafe141520c5d424ed0ab47cd1ece80338ddf56e2d` |
| Kind composition result | `a3a0e038dfe3d0d63094ee1c601156e9b921d9d376e83740eeea7fce43869b2f` |
| Kind composition log | `3aa95fd37ecbf0e565d8a06f34091f5f543053ca0c309f9c6f5071b2e533e4bd` |

These privileged diagnostics do not close ADR 0445's live cl02 capability/SCC
decision. Full agent process recovery, authenticated reconciliation, replacement,
mixed replicas, remote Required/current-runtime lifecycle and consuming status
remain open. Phase 9 L3/L4/L5/Q and S1–S5 are not promoted.
