#!/usr/bin/env bash
set -Eeuo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

command -v rg >/dev/null 2>&1 || {
    echo "rg is required to verify the Phase 9 encryption boundary" >&2
    exit 1
}

require_text() {
    local relative_file=$1 expected=$2 description=$3
    [[ -f ${project_root}/${relative_file} ]] || {
        echo "Phase 9 boundary file is missing: ${relative_file}" >&2
        exit 1
    }
    rg --fixed-strings --quiet -- "${expected}" "${project_root}/${relative_file}" || {
        echo "Phase 9 boundary check failed: ${description} (${relative_file})" >&2
        exit 1
    }
}

require_text '.master-prompt/Rust Universal eBPF Network Fabric.md' \
    '# 25. Encryption' \
    "the master-prompt encryption requirement must remain present"
require_text docs/project-status.md \
    '| Phase 9 — attested encryption fabric | **In progress** |' \
    "the authoritative Phase 9 state must be in progress"
require_text docs/project-status.md \
    '| Architecture and acceptance boundary | **Verified** |' \
    "milestone 9.1 must be tracked as verified"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    '| 9.1 | Architecture and acceptance boundary | **Verified** |' \
    "the Phase 9 plan must verify milestone 9.1"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'source identity and security policy authorize the original flow before any' \
    "policy must precede encryption"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'they never fall back to plaintext;' \
    "required encryption must deny rather than downgrade"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'is never sent to the controller.' \
    "private keys must remain Node-local"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'Intent-Coalesced Cryptographic Fast Path' \
    "the bounded transport-coalescing design must remain explicit"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'No algorithm or performance advantage is accepted without a reproducible' \
    "performance claims must require measurements"
require_text docs/development/phase9-attested-encryption-fabric-plan.md \
    'hardware/TPM attestation' \
    "the attestation limitation must remain explicit"
require_text docs/adr/0158-bound-attested-encryption-fabric.md \
    'recency alone is insufficient.' \
    "configuration and path proof must remain distinct"
require_text docs/adr/0250-compact-causal-tombstone-chain.md \
    'Compact Causal Tombstone Chain' \
    "consecutive tombstoned admissions must retain compact causal ancestry"
require_text docs/adr/0252-policy-relevance-quotient.md \
    'Policy-Relevance Quotient' \
    "encryption planning must not scan irrelevant cluster policy partitions"
require_text docs/adr/0253-immutable-policy-relevance-kind-requalification.md \
    'Immutable Policy-Relevance Kind Requalification' \
    "the corrected policy planner must retain immutable fresh-Kind provenance"
require_text docs/adr/0254-live-set-immutable-runtime-census.md \
    'Live-Set Immutable Runtime Census' \
    "platform image provenance must distinguish live runtime from terminated diagnostics"
require_text docs/adr/0255-work-capped-zero-allocation-enforcement-fold.md \
    'Work-Capped Zero-Allocation Enforcement Fold' \
    "exact high-cardinality policy evaluation must remain allocation-free and bounded"
require_text docs/adr/0256-loadbalancer-pending-checkpoint-cleanup-closure.md \
    'LoadBalancer Pending-Checkpoint Cleanup Closure' \
    "the full Kind lifecycle must close a validated prepared LoadBalancer checkpoint"
require_text docs/adr/0257-immutable-work-capped-kind-requalification.md \
    'Immutable Work-Capped Kind Requalification' \
    "the bounded planner must retain immutable fresh-Kind provenance"
require_text docs/adr/0258-informer-cut-admission-barrier.md \
    'Informer-Cut Admission Barrier' \
    "agent pull admission must wait for one complete informer authority cut"
require_text docs/adr/0259-immutable-informer-cut-kind-requalification.md \
    'Immutable Informer-Cut Kind Requalification' \
    "the informer-cut barrier must retain immutable fresh-Kind provenance"
require_text docs/adr/0260-cut-fenced-single-flight-authority-admission.md \
    'Cut-Fenced Single-Flight Authority Admission' \
    "host-network agent authority admission must be constant-space and cut-fenced"
require_text docs/adr/0261-immutable-cut-fenced-kind-requalification.md \
    'Immutable Cut-Fenced Kind Requalification' \
    "cut-fenced authority admission must retain immutable fresh-Kind provenance"
require_text docs/adr/0262-causal-startup-admission-retry.md \
    'Causal Startup Admission Retry' \
    "agent startup must honor intentional authority backpressure without opening BPF state"
require_text docs/adr/0263-immutable-causal-startup-kind-requalification.md \
    'Immutable Causal-Startup Kind Requalification' \
    "causal startup retry must retain immutable fresh-Kind provenance"
require_text docs/adr/0264-bounded-fair-authority-admission.md \
    'Bounded Fair Authority Admission' \
    "authority materialization must combine bounded memory with admitted progress"
require_text docs/adr/0265-immutable-bounded-fair-kind-requalification.md \
    'Immutable Bounded-Fair Kind Requalification' \
    "bounded-fair admission must retain immutable fresh-Kind provenance"
require_text docs/adr/0266-end-to-end-authority-delivery-lease.md \
    'End-to-End Authority Delivery Lease' \
    "authority admission must cover response-body delivery lifetime"
require_text docs/adr/0267-immutable-delivery-leased-kind-requalification.md \
    'Immutable Delivery-Leased Kind Requalification' \
    "delivery-leased authority must retain immutable fresh-Kind provenance"
require_text bins/unf-controller/src/main.rs \
    'MAX_ENCRYPTION_POLICY_CLASS_EVALUATIONS' \
    "exact encryption policy planning must have a pre-allocation work bound"
require_text bins/unf-controller/src/main.rs \
    'INITIAL_AGENT_AUTHORITY_WATCHES' \
    "agent pull readiness must wait for one complete informer authority cut"
require_text bins/unf-controller/src/main.rs \
    'finish_initial_agent_authority_watch' \
    "informer relists must close the agent authority readiness barrier"
require_text bins/unf-controller/src/main.rs \
    'AGENT_AUTHORITY_MAX_IN_FLIGHT: usize = 1' \
    "internal authority materialization must be single-flight"
require_text bins/unf-controller/src/main.rs \
    'AGENT_AUTHORITY_ADMISSION_CAPACITY: usize = 16' \
    "internal authority admission must have a fixed queue bound"
require_text bins/unf-controller/src/main.rs \
    'admit_agent_authority_request' \
    "the host-network internal API must enforce authority admission"
require_text bins/unf-controller/src/main.rs \
    'agent_authority_cut_revision' \
    "materialized authority responses must be fenced by informer cut revision"
require_text crates/unf-policy/src/lib.rs \
    'evaluate_preselected_enforcement_with_addresses' \
    "preselected encryption policy enforcement must use the compact evaluator"
require_text bins/unf-controller/src/main.rs \
    'relevant_encryption_policies' \
    "encryption planning must preserve only pair-applicable policy truth"
require_text bins/unf-agent/src/encryption_maps.rs \
    'ancestry: Vec<FastPathMapTransaction>' \
    "the map bridge must retain digest-bearing compact transaction ancestry"
require_text bins/unf-agent/src/main.rs \
    'tombstoned_ancestry: Vec<FastPathMapTransaction>' \
    "the Linux recovery journal must retain matching compact ancestry"
require_text docs/architecture/components.md \
    'The accepted Phase 9 boundary keeps encryption intent, key authority,' \
    "component ownership must remain explicit"
require_text README.md \
    'Phase 9 begins the attested encryption fabric.' \
    "the user-facing status must expose the active phase"
require_text docs/roadmap.md \
    '## Phase 9 — attested encryption fabric' \
    "the roadmap must include Phase 9"
require_text Makefile \
    'encryption-fabric-boundary-test:' \
    "the architecture gate must be invocable"
require_text hack/verify-openshift-encryption-phase9.sh \
    'convergence_timeout_seconds' \
    "OpenShift convergence waits must carry one real wall-clock budget"

for milestone in 9.2 9.3 9.4 9.5 9.6 9.7 9.8 9.9; do
    require_text docs/development/phase9-attested-encryption-fabric-plan.md \
        "| ${milestone} |" \
        "milestone ${milestone} must remain tracked"
done

echo "Phase 9 encryption-fabric boundary passed: policy, contracts, keys, coalescing, rotation, evidence, performance, and exclusions agree"
