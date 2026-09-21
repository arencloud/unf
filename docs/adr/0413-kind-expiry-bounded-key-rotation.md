# ADR 0413: Matching Kind Expiry-Bounded Rotation and Traffic

Date: 2026-09-21

Status: scoped matching runtime qualification verified

After ADR 0412's cl02 pass, persistent Kind runs the identical immutable
`45d85d5762d3340c1c64bdefcffef21071d8334f` controller and agent/CNI images listed
there. No key, journal, map, history or baseline reset is performed. The
previous `6d71a30` state is preserved through the guarded serial upgrade.

Public image provenance, embedded revisions, all three installed CNI hashes,
zero-grace CNI STATUS and unchanged Node UIDs pass. Four isolated PID-1
SIGTERM/SIGINT tests exit zero with no restarts and remove their Namespace.
All four retiring regular-container streams and three completed installer logs
are retained. The DaemonSet returns to its original RollingUpdate strategy.

A configured controller Recreate restart and exact-UID worker-agent replacement
both finish with terminal exit zero and shutdown request/completion logs.
Replacements are Ready with no restarts. This is Native planned recovery,
not Required-mode disruption or a loaded drain-deadline guarantee.

All three current agents record common activations 163 and 164. Logs record
transport-free predecessor retirement and exact Required transport retirement;
neither sealed-expiry drain failure nor unknown-epoch failure recurs.

The full expanded reply/inventory gate passes, qualifier `53f4ff5`:

- 24 allows (twelve Required, twelve Native), eight unsolicited denials;
  IPv4/IPv6 TCP/UDP, cross-worker PodIP, Service and translated ports.
- Three CNI UID/nonce bindings and retirements; two locality-candidate replays
  and retirements with real inventory-count checks.
- `eth0` capture: 73 WireGuard frames, zero Required plaintext, 89 Native
  controls and zero kernel capture drops.
- Required/Native convergence at observations 10/5. Namespace absent, all
  three Nodes Native, fresh ordinary reports converged at policy 35 / Service 19.
- Both pre-existing worker journals remain byte-identical. The control-plane
  journal remains absent, independently checked against no non-host-network Pods.
  Current regular/init containers have zero restarts and successful init exits.

Current, retired and retained CRI logs are reviewed. The overlapping current
and retained inventories each contain 56 warnings across twelve categories,
not 112 separate events. There are no ERRORs, observer failures, byte-cap hits,
partial CRI records or non-JSON agent records. Warnings retain 26 plan-sync,
15 proof-assistance, three receipt-generation mismatches, three startup fences,
two LoadBalancer retries and seven single-event restart synchronization warnings.
The single key-publication warning is a refused connection during planned
controller restart, not an activation failure. These retries remain S1 findings;
neither low resource consumption nor seamless rotation is claimed.

Evidence: `.artifacts/p9-drain-expiry-45d85d5-kind-*` and
`.artifacts/p9-drain-expiry-kind-*`. Passing traffic evidence SHA-256:
`280c77bc4e0437849c8add0fb3f9937f247ba904f85777cd3470c24d0189e9b9`.
Capture SHA-256:
`11fad8b48fd7a0fd4e287b7d2d715ea35242fd67b0cdf946a759679ffbd8a3a4`.

Both fleets now run `45d85d5`, Native baseline. ADRs 0409/0411's narrow
key-lifecycle repairs are qualified cl02 first, then Kind. Resume production
locality bank/packet integration: candidate `kernelAdmitted`, `observedDelivery`
and `localityAdmission` remain false. L3/L4/L5/Q, Phase 9 and S1–S5 remain open;
no release pin or full platform status is promoted.
