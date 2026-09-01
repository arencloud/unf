# Phase 7 Maglev measurement

Status: **Verified** on 2026-09-01. The reproducible fixture is
`crates/unf-service/examples/maglev-measurement.rs`; run it through
`hack/verify-service-maglev.sh` or `make service-maglev-dataplane-test`.

## Decision

UNF admits deterministic Maglev for 2–4,096 eligible backends when its fixed
table fits the shared 524,288-slot inactive-bank budget. Table sizes are the
first measured prime in 251, 509, 1,021, 2,039, 4,093, 8,191, 16,381, 32,749,
or 65,537 that provides at least 16 slots per backend. Zero/one-backend plans,
or a table that cannot fit the remaining bank budget, use StableHash. The
frontend flag and service event report the algorithm actually materialized.

Kubernetes Services request Maglev with
`network.unf.io/service-selection-algorithm: maglev`. Absence retains
StableHash so a controller upgrade does not silently create schema-v4-only
intent that older agents cannot project. Current agents advertise both
capabilities; unknown annotation values fail closed.

## Recorded fixture

The release fixture uses 200,000 deterministic dual-stack TCP/UDP flow hashes,
2,000,000 packet-selection iterations, and a 32-byte logical slot key/value.
Nanoseconds are one workstation observation and are not a production SLA.

| Backends | Slots | Table balance error | Stable/Maglev add remap | Stable/Maglev remove remap | Maglev compile | Stable/Maglev lookup (2M) | Maglev logical bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 251 | 0.3984% | 66.61% / 33.47% | 50.00% / 49.92% | 3.0 µs | 2.88 / 2.74 ms | 8,032 |
| 8 | 251 | 1.9920% | 88.97% / 17.94% | 87.42% / 16.00% | 5.1 µs | 2.82 / 2.76 ms | 8,032 |
| 32 | 1,021 | 2.8404% | 96.96% / 6.28% | 96.90% / 96.89%¹ | 23.5 µs | 2.79 / 2.78 ms | 32,672 |
| 128 | 4,093 | 3.0540% | 99.22% / 3.31% | 99.21% / 99.23%¹ | 92.9 µs | 2.84 / 2.84 ms | 130,976 |
| 512 | 16,381 | 3.1073% | 99.80% / 1.21% | 99.82% / 99.81%¹ | 426 µs | 2.97 / 2.98 ms | 524,192 |
| 1,024 | 32,749 | 3.0688% | 99.90% / 0.58% | 99.91% / 99.90%¹ | 902 µs | 2.82 / 2.86 ms | 1,047,968 |
| 2,048 | 65,537 | 3.1234% | 99.95% / 0.35% | 99.95% / 0.38% | 1.91 ms | 2.88 / 2.84 ms | 2,097,184 |
| 4,096 | 65,537 | 6.2484% | maximum admitted cardinality | 99.98% / 0.19% | 1.90 ms | 3.07 / 2.93 ms | 2,097,184 |

¹ Removal crosses a fixed table-size boundary. This is deliberately observable
and publishes a new immutable bank and service revision. Existing validated
connections remain on their backend until protocol timeout; new flows use the
new table. The boundary is not described as minimal disruption.

The flow-distribution sample is also emitted in JSON. At high cardinality its
maximum per-backend error is dominated by the small number of sampled flows per
backend; adoption is bounded by the deterministic table-balance error, which is
at most 6.25%, and by the reported disruption/resource contract.

## Packet and upgrade cost

Both algorithms execute the same verifier-visible dataplane sequence: one
fixed flow hash, one modulo, and one `SERVICE_BACKEND_SLOTS` lookup. Maglev is a
userspace table representation, not another eBPF map lookup or packet loop.
Map ABI versions advance for the new actual-algorithm flags and event
provenance; persistent state advances to ABI v10. An older ABI remains separate,
last-known-good state is not partially opened, and activation still stages,
reads back, then flips one bank pointer.
