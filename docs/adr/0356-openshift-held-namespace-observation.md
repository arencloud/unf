# ADR 0356: cl02 Held Namespace Observation Qualification

Date: 2026-09-14

Status: verified for isolated held-descriptor snapshot/retirement behavior

Source `b9cc5a8` is built and anonymously verified at immutable image
`quay.io/arencloud/unf-test-tools-dev@sha256:a2d65ae84e2b0d04c789b22c4be078fa040eec2eb8e907801b967efec348a38c`.
The full source revision is recorded in its OCI label. The fixture runs on
cl02 worker `bc-24-11-27-b6-49`, in three newly owned disposable network
namespaces, with no host-state mounts or live UNF binary/map changes.

All thirteen exact checks pass: five positive observations; MTU drift,
namespace-path bind replacement, peer namespace move and target deletion each
reject with their expected readback reason; all four restored states remain
retired until a new observation is explicitly constructed. Observer processes
finish successfully and private namespaces are removed. The fixture Kubernetes
Namespace is absent afterward and the Node UID remains unchanged.

Evidence directory: `.artifacts/p9-veth-observation-b9cc5a8-cl02`.
Raw fixture archive SHA-256:
`6530810e1d96e473c53b82a90d573cbbe0d85980871c4895092cfb1540300e8f`.
The retained `checks.jsonl` records every response rather than inferring denial
from a failed shell, missing process or timed-out observer.

Before/after controller, all agent and installer logs are captured. The final
20-minute window includes the entire fixture run and its cleanup. Current
containers have zero restarts; no ERROR, panic, OOM or verifier rejection is
observed. Bounded flow/topology history and 23 proof-assistance retry warnings
remain visible. All five agents finish fresh and converged at policy revision
448 / Service revision 203. Live runtime remains `f984db9` and Native by default.

This is descriptor-retaining snapshot evidence, not continuous device lifetime,
actual locality packet admission, observed delivery or full Phase 9/S1–S5.
The result explicitly keeps `packetTimeLifetime` and `kernelAdmitted` false.
Matching retained Kind on this exact immutable image is next.
