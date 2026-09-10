# Phase 9 encryption performance measurement

Status: **Verified** on 2026-09-10. The machine-readable evidence is
[`phase9-encryption-performance.json`](phase9-encryption-performance.json),
SHA-256 `a29a3f383e4d6e871ea30d5a637212be80a27119450cc84f59039c7b905348fc`,
produced by committed harness revision
`f2a39673f34b645abdb58132183523a41d17ddac`.

## Result

The two-namespace Fedora 44 / Linux 7.1.4 fixture used four iperf3 TCP streams
for three measured seconds and 200 ICMP samples per family. Native means routed
veth transport; encrypted means Linux kernel WireGuard over that same veth.
This is a reproducible host microbenchmark, not a production capacity claim.

| Path | Throughput | p50 / p95 / p99 latency | Loss | Retransmits | Sender / receiver CPU | Client max RSS |
|---|---:|---:|---:|---:|---:|---:|
| Native IPv4 | 134.34 Gbit/s | 0.026 / 0.046 / 0.061 ms | 0% | 1 | 334.77% / 251.79% | 5,088 KiB |
| WireGuard IPv4 | 2.81 Gbit/s | 0.103 / 0.897 / 4.000 ms | 0% | 0 | 7.97% / 48.87% | 4,932 KiB |
| Native IPv6 | 120.75 Gbit/s | 0.028 / 0.044 / 0.057 ms | 0% | 5 | 319.61% / 245.13% | 4,932 KiB |
| WireGuard IPv6 | 2.64 Gbit/s | 0.102 / 0.259 / 1.560 ms | 0% | 0 | 7.76% / 49.77% | 4,928 KiB |

WireGuard delivered 2.09% and 2.19% of the unusually fast same-host veth
baseline for IPv4 and IPv6. Median latency was 3.96× and 3.64× native. These are
regressions and are intentionally retained; the native baseline benefits from
same-host offload and the encrypted path is limited by kernel cryptographic
work. CPU percentages are iperf3 process observations at different achieved
throughputs, and RSS does not isolate kernel WireGuard memory, so they must not
be interpreted as equivalent-work efficiency.

The underlay capture contained 2,684,452 WireGuard UDP packets and zero inner
addresses. First dual-stack handshake convergence took 84 ms. Native MTU 1500
accepted its exact IPv4/IPv6 1472/1452-byte ICMP payloads and rejected one byte
more; derived encrypted MTU 1420 accepted 1392/1372 and rejected one byte more.

## Rotation, scale, and map cost

A second epoch was fully configured and warmed before the measured cutover.
Four route replacements took 131,954 µs; the 400-sample, 10-ms probe lost five
consecutive samples. The observed interruption is therefore bounded to roughly
50–60 ms at probe resolution, while the userspace route-command wall time is
reported separately. Kind and OpenShift must remeasure the real bank flip and
fleet barrier rather than treating this namespace result as a cluster SLA.

Serial `wg set` plus exact peer readback took 37.9 ms, 553.3 ms, 2.521 s, and
5.008 s at 1, 16, 64, and 128 peers. This deliberately pessimistic CLI loop is
not the UNF typed-netlink batch path; it is retained as a reproducible kernel/
tooling ceiling and demonstrates why UNF coalesces by Node and performs bounded
full-set reconciliation.

The verifier-qualified packet path performs four persistent lookups and one
connection-state write for a new direct flow, five plus one for an address-bound
flow, and three plus one for an established flow. The live Aya recovery gate
observed zero mutations for an already exact quiescent generation. Per-CPU
scratch accesses are excluded from these fixed counts.

## Reproduction and interpretation

Run `make encryption-performance-live`; dependencies include the full Phase 9
recovery chain and real Aya-map gate. The harness requires `iperf3`, `jq`,
`tcpdump`, `wg`, network namespaces, and passwordless scoped sudo. It creates
unique namespaces and removes them through an exit trap.

No adaptive fallback may use these results to weaken `Required`. The useful
optimization direction is bounded Node-level peer coalescing, delta-minimal map
staging, and prewarmed two-epoch cutover—not plaintext downgrade, per-workload
tunnels, or custom cryptography. End-to-end CNI CPU/memory, real BPF activity,
Service/egress composition, and multi-worker behavior remain mandatory in Kind
and OpenShift milestones 9.8 and 9.9.
