# ADR 0266: End-to-End Authority Delivery Lease

## Status

Accepted for Phase 9.9 implementation and requalification

## Context

ADR 0264 bounded concurrent handler materialization and guaranteed FIFO
progress. The ADR 0265 cl02 deployment proved that behavior under the normal
Native baseline, but the complete gate's Required transition repeatedly
OOM-killed the controller at its 2-GiB limit before generation advancement.

The recovered fleet plan occupied 22,179,791 uncompressed bytes and the Native
controller was healthy, so the failure was not one intrinsically oversized
plan. Axum serializes a JSON value into a buffered response body before a
middleware future returns. The middleware then released its queue and
materializer permits even though the body could remain owned by the HTTP
connection. Subsequent admitted requests could therefore create multiple
large policy or plan bodies concurrently outside the intended bound.

## Decision

Internal authority responses use an **End-to-End Authority Delivery Lease**:

1. The fixed-capacity queue slot and the sole materializer permit are owned
   permits, not borrows tied to the middleware stack frame.
2. After handler execution and the informer-cut fence succeed, the response
   body is wrapped in a pass-through stream that owns both permits.
3. Both permits remain unavailable after each delivered frame. They are
   released only when the body reaches end-of-stream or when the client,
   server, or cut-fence path drops the response.
4. Constant-work compatibility and authenticated status traffic retain their
   separate readiness- and revision-fenced control lane.
5. The response bytes, status, and headers are unchanged; this is a lifetime
   and admission correction, not a wire-schema or BPF-ABI change.

This makes the one-materializer invariant cover snapshot construction,
serialization, socket backpressure, and delivery. Large response ownership is
therefore constant with respect to agent concurrency while FIFO queue memory
remains capped at 16 active-plus-waiting requests.

## Consequences

- Slow or disconnected agents cannot leave large authority bodies outside the
  admission bound; disconnect releases capacity automatically.
- Other heavy authority reads wait behind the complete body lifetime. Agent
  retries and the constant-work control lane preserve bounded liveness.
- A focused async regression proves neither permit returns after the data frame
  and both return only after end-of-stream.
- Full workspace checks, a new fresh Kind lifecycle, immutable successor
  images, preserved-state cl02 deployment, and the complete platform gate are
  mandatory before Phase 9.9 can close.
