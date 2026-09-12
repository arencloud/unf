# ADR 0280: Independent encryption history verification

Date: 2026-09-12

Status: Implemented; verified against a cl02 capture

`unfctl encryption-history` now independently replays the strict typed history
checkpoint before displaying it. `--file PATH` performs the same verification
offline without contacting the controller. Both HTTP and regular-file inputs
are capped at 1 MiB before parsing; replay retains the existing 512-record bound
and validates schema, sequence, eviction anchor, record digests, counter lower
bounds and reported loss. There is no wire change or controller/agent mutation.

The output retains the original checkpoint fields, including every eviction
and loss counter. Verification does not mean an evicted history is complete,
nor does diagnostic evidence grant packet or activation authority. This adds
an incident-analysis and conformance tool without expanding controller memory.

Tests accept a 514-observation fixture with 512 retained records and two explicit
evictions, reject tampering/unknown fields/oversized input, and prove file mode
works with an invalid controller URL. CLI lint passes. A public cl02 capture from
runtime `d128aab` independently verified at revision 917,653 with 512 retained
records, 917,141 evicted observations and zero reported upstream losses. Those
historical evictions remain visible; no loss-free full-history claim is made.

```sh
unfctl --output json encryption-history --file saved-encryption-history.json
```

This utility does not qualify the runtime's currently blocked startup recovery
or complete Phase 9. Successor platform qualification still runs cl02 first,
then Kind.
