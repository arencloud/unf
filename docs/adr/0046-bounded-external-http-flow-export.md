# ADR 0046: Bounded external HTTP flow export

Status: Accepted and live verified on dual-stack Kind

## Context

The controller retains a useful bounded flow window, but external analytics and
longer retention require a supported handoff boundary. A receiver outage must
not add latency to the authenticated agent endpoint, block controller history,
or feed failure back into packet enforcement. The transport must also expose
loss honestly and must not leak credentials through plaintext or redirects.

## Decision

The first external backend is an optional controller-side HTTP POST worker.
After TokenReview identity binding, node-placement validation, schema validation,
and local history ingestion succeed, the request path copies the accepted batch
into a bounded `try_send` queue. The default capacity is 256 batches and the
validated operator range is 1–4,096. Queue pressure or an unavailable worker
drops only the external copy and increments batch and observation loss counters;
the agent still receives `204 No Content`.

External envelope schema v1 carries the controller epoch, an epoch-scoped export
sequence, the topology revision observed at ingestion, controller receive time,
and the complete agent flow-export schema-v3 batch. The stable
`(controller_epoch, export_sequence)` pair lets receivers deduplicate retries.
Delivery is at least once for an accepted queue item: network failures, 408, 429,
and 5xx responses retry with bounded exponential backoff; other HTTP responses
drop immediately. Attempts default to three and are limited to 1–10. The queue
is memory-only and no delivery can delay local retention.

HTTPS is required by default and uses platform roots plus an optional PEM CA
bundle, allowing public PKI and private/OpenShift-provided issuers. Plain HTTP
requires an explicit development flag. URLs containing credentials or fragments
are rejected, redirects are disabled, and an optional bearer-token file is
validated at startup and reread for every attempt so token rotation does not
require a controller restart. The token value is never logged.

Ten Prometheus metrics expose configured queue capacity, current queue depth,
process-lifetime queue high-water mark, enqueued batches, delivery attempts,
delivered batches/observations, delivery errors, and dropped
batches/observations. Accepted queue items receive their sequence while holding
the same small publication fence used to reserve their slot, so concurrent
ingestion cannot publish a lower sequence after a higher one. Retries retain the
same sequence.

## Verification

Unit tests reject unsafe configuration, prove a full queue drops synchronously
without waiting, exercise bearer-authenticated retry after 503, verify the wire
envelope, and concurrently enqueue batches to prove published sequence order.
The controller ingestion test proves only validated batches enter the external
queue. `make kind-external-flow-export-test`, included in `make kind-test`,
deploys a non-root receiver, validates the complete schema-v1 envelope and
bearer token, requires a same-sequence retry after an injected 503, removes the
receiver, and proves authenticated telemetry plus durable local history continue
while external drops become visible. After recovery, a three-second receiver
delay saturates a one-item queue under sustained traffic. The gate requires
capacity and high-water gauges of one, depth never above one, increasing
delivery and explicit batch/observation loss, strictly non-regressing receiver
sequences, continued local telemetry/history growth, and no controller
replacement or restart.

## Consequences

UNF now has a stable, bounded external flow handoff suitable for webhook
collectors and adapters. Receivers must use the epoch/sequence fence for
idempotence. Controller restart and queue overflow can lose external-only data;
the bounded local history remains the recovery window. The publication fence is
held only around non-blocking slot reservation, sequence assignment, and send;
network I/O remains isolated in the worker. A persistent spool,
multiple simultaneous sinks, Kafka/OTLP-native transports, receiver-side
backpressure negotiation, and CA-client hot reload remain future work.
