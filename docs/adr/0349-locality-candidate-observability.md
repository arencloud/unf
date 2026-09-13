# ADR 0349: Locality Candidate Observability Without Admission Claims

Date: 2026-09-14

Status: source slice verified locally; live qualification pending

`GET /v1/encryption/locality` reports an explicitly scoped placement-candidate
observation: absent, fetching, replayed or failed. The observation includes its
time, placement context, desired-plan digest and local address count. An empty
but successfully replayed cut is distinguishable from absent evidence.

The endpoint compares observed identity/routing coordinates with current agent
reported desired/applied values. That comparison is not an atomic kernel read,
fresh controller membership proof, current plan verification or packet verdict.
An old replay observation remains identifiable as such after reported revision
drift; it does not silently become current evidence. Dataplane readiness is
reported separately. `kernelAdmitted` and `observedDelivery` remain explicitly
false because neither consuming integration nor delivery telemetry exists yet.

Observations are small volatile snapshots of the existing candidate cache;
status reads do not fetch controller state, copy the complete certificate,
enumerate identity pairs or alter durable authority. A failed plan/fetch updates
the observational status without turning fallback transport into Native.

Verification: 804 workspace tests pass, 26 explicitly ignored. Tests cover
absent/fetching/replayed/failed observations, strict scope/schema fields, empty
replayed placement, reported route drift and false kernel/delivery claims.
Formatting and strict all-target/all-feature Clippy are required before commit.
No live image or BPF ABI is changed by this source milestone. The next gate is
authenticated distribution/status on cl02, followed by identical-image Kind.
L3 packet consumption, L4/L5/Q and S1–S5 remain open.
