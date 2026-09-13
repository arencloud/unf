# ADR 0345: OpenShift Device-Reference Delivery Qualification

Date: 2026-09-13

Status: isolated cl02 target-device lifetime slice verified; Kind pending

After the three failed/observer-rejected runs preserved in ADRs 0343–0344,
the complete corrected gate passes on cl02 worker `bc-24-11-27-b6-49` with
RHCOS/kernel 5.14.0-687.39.1.el9_8 and SELinux Enforcing.
Source: `44d3502f60fa8bc2164983505768160c5957c46a`.
Image: `quay.io/arencloud/unf-test-tools-dev@sha256:9db4c3433411c5495860d6d6f499c93b96efc92f5ecef82f09ca6f6970186682`.
Anonymous inspection verifies its digest and OCI revision.

Four private network namespaces exercise the existing kernel TC primitive,
not live UNF policy or encryption. Eight exact UDP payloads are delivered over
IPv4/IPv6 during initial delivery, target rename, down/up recovery and explicit
new-device binding. Four probes are denied: two while the original target is
down and two after its deletion and replacement with the same index/MAC/IPs.
The old action's target is absent after deletion and remains absent after reuse,
even with ordinary forwarding routes toward the replacement. A separately
created action is unused before explicit filter rebinding and then delivers
two probes. The original action never acquires the replacement implicitly.

All eight action snapshots pass the independent strict gate, including exact
attempt/overlimit counts, device/action identity, reference/binding counts and
explicit software-only flags. The old action ends with ten probe attempts and
four overlimits. Payload absence alone is not the denial evidence. The same
gate is replayed independently against the retained archive after cleanup.

Result SHA-256: `1109c54d99868430fb6b58499d051ba5b5d58996cc4a27071173e3410a1b9883`.
Private fixture archive SHA-256: `b5a1ad004ef5f20fb9fc834668d8a35a2200739dcf5fb3aa4ea57e7307b29cc2`.
All private namespaces and the qualification namespace are removed. The worker
UID is unchanged. Live UNF stays `450de80`, Ready with zero current restarts,
and converged at policy revision 396 / Service revision 204.

Controller, all agents and installers are reviewed across the validation
intervals. The final 20-minute capture is 477 lines / 118,159 bytes, below caps.
It retains 404 bounded flow-history warnings, 45 proof-assistance warnings,
eight bounded topology-history warnings and four key-publication warnings.
No observed ERROR/panic/OOM, verifier rejection or stopped-dataplane match is
found. These warnings remain open operational findings; this is not a clean-log
or healthy-cluster claim. Earlier failures are not retroactively marked passed.

Commit/push before identical-image retained Kind. This proves only the tested
target-device reference semantics. Source authentication, veth peer namespace
relocation, arbitrary TC composition, authenticated/banked locality consumption,
restart recovery and performance remain unproven here. L3, L4/L5, Q and S1–S5
remain open; no production plaintext permission or release promotion is added.

## Reverse-route fixture rerun

After the first matching Kind failure, source
`40def8e47674c2fc77e482a7c0ce67a52befff76` adds verified return routes and
failure-time kernel evidence. Its image is
`quay.io/arencloud/unf-test-tools-dev@sha256:ca0943efb8562cbc85b5c3486ba8d47d0c7a8c110bf45aa42308f18ec82e1d27`.
The complete cl02 gate passes again with the same result SHA-256 above.
Archive SHA-256: `424447bd95dac017995fd135c6385116c27794a79b9b060652854d3c0caa2fc1`.
Both private target namespaces report all/eth0 RPF values 0/0; reverse-route
readback selects eth0. No RPF setting is changed by the test. This does not
establish what the deleted Kind fixture's private defaults were.

The fixture namespace is removed. An initial controller status read is not
fully converged; a subsequent independent read is fully converged, with all
five agents fresh at policy 398 / Service 204. Current UNF containers remain
Ready without restarts. The final 485-line / 120,759-byte log capture retains
405 flow-history, 49 proof-assistance, nine topology-history and four key
publication warnings, with no observed fatal pattern. Commit/push this rerun
before the identical revised image on retained Kind. The earlier Kind failure
remains failed evidence.
