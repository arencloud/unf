.PHONY: egress-fabric-boundary-test egress-intent-test egress-contract-test egress-allocation-test egress-host-state-test egress-proof-test egress-dataplane-contract-test egress-dataplane-map-test egress-live-distribution-test egress-desired-state-test egress-gateway-distribution-test egress-control-plane-test egress-application-ack-test egress-source-steering-test egress-path-activation-test egress-gateway-address-test egress-gateway-nat-test egress-safe-forgetting-test egress-source-retirement-test egress-gateway-retirement-test egress-release-authority-test egress-nat-observability-test egress-kind-lifecycle-test service-selection-boundary-test service-selection-ir-test service-selection-contract-test service-selection-state-test service-selection-dataplane-test service-affinity-dataplane-test service-maglev-dataplane-test service-dsr-dataplane-test service-selection-operations-test service-selection-kind-up service-selection-kind-load service-selection-kind-deploy service-selection-kind-test service-selection-kind-down service-selection-openshift-deploy service-selection-openshift-test
.PHONY: build test lint fmt fmt-check support-matrix-check loadbalancer-boundary-test loadbalancer-ir-test loadbalancer-control-plane-test loadbalancer-host-state-test loadbalancer-cluster-dataplane-test loadbalancer-local-dataplane-test loadbalancer-operations-test loadbalancer-kind-up loadbalancer-kind-load loadbalancer-kind-deploy loadbalancer-kind-test loadbalancer-kind-down loadbalancer-openshift-deploy loadbalancer-openshift-test service-ir-test service-compiler-test service-distribution-test nodeport-host-state-test nodeport-transaction-test nodeport-cluster-dataplane-test nodeport-local-dataplane-test nodeport-operations-test nodeport-kind-test nodeport-openshift-deploy nodeport-openshift-test service-dataplane-test service-operations-test primary-cni-installer-test service-kind-up service-kind-load service-kind-deploy service-kind-test service-kind-down ebpf generate-crds controller agent cni cni-protocol-test cni-transaction-test cni-ipam-test cni-veth-test cni-routing-test cni-lifecycle-test cni-node-block-test cni-remote-routing-test cni-route-reconciliation-test cli artifacts images upgrade-baseline-images skipped-upgrade-baseline-images incompatible-version-images clean-rebuild-version-images openshift-images openshift-upgrade-images openshift-deploy openshift-test openshift-upgrade-test openshift-tls-rotation-test openshift-agent-report-retention-test openshift-host-mount-policy-test openshift-uninstall openshift-uninstall-test openshift-primary-cni-audit openshift-primary-cni-preflight openshift-primary-cni-package-check openshift-primary-cni-runtime-fault-test openshift-primary-cni-node-reprovision-test openshift-primary-cni-deploy openshift-service-deploy openshift-service-test kind-tool kind-up kind-load kind-upgrade-load kind-skipped-upgrade-load kind-incompatible-version-load kind-clean-rebuild-load kind-deploy kind-demo kind-topology-history-test kind-flow-history-retention-test kind-external-flow-export-test kind-upgrade-test kind-skipped-upgrade-test kind-incompatible-version-test kind-clean-rebuild-test kind-unsupported-downgrade-test kind-rollback-reporting-test kind-scale-failure-test kind-test kind-platform-matrix-test kind-down primary-cni-kind-up primary-cni-kind-load primary-cni-kind-deploy primary-cni-kind-test primary-cni-kind-rollback primary-cni-kind-down
.PHONY: egress-ha-planner-test
.PHONY: egress-ha-promotion-test
.PHONY: egress-ha-continuity-test
.PHONY: egress-ha-live-ownership-test
.PHONY: egress-ha-transaction-test
.PHONY: egress-ha-kind-test
.PHONY: egress-fqdn-evidence-test
.PHONY: egress-fqdn-control-test
.PHONY: egress-fqdn-dataplane-test
.NOTPARALLEL: kind-upgrade-test kind-skipped-upgrade-test kind-incompatible-version-test kind-clean-rebuild-test kind-unsupported-downgrade-test kind-rollback-reporting-test

KIND := .tools/bin/kind
KIND_PROVIDER ?= podman
KIND_NAME ?= unf-dev
KIND_CONFIG ?= $(CURDIR)/hack/kind-config.yaml
KIND_KUBECONFIG ?= $(CURDIR)/.tools/kind-$(KIND_NAME).kubeconfig
KUBE_CONTEXT ?= kind-$(KIND_NAME)
UNF_KIND_CONTROL_PLANE_NODE ?= $(KIND_NAME)-control-plane
UNF_KIND_WORKER_NODE ?= $(KIND_NAME)-worker
UNF_POLICY_TRANSITION_ATTEMPTS ?= 30
TEST_TOOLS_IMAGE := localhost/unf-test-tools:ipv6-ext-v1
UNF_BUILD_REVISION ?= $(shell git describe --always --dirty --abbrev=40 2>/dev/null || echo unknown)
UNF_UPGRADE_BASELINE_REF ?= HEAD^
UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE ?= localhost/unf-controller:upgrade-n
UNF_UPGRADE_BASELINE_AGENT_IMAGE ?= localhost/unf-agent:upgrade-n
UNF_SKIPPED_UPGRADE_BASELINE_REF ?= HEAD^^
UNF_SKIPPED_UPGRADE_BASELINE_CONTROLLER_IMAGE ?= localhost/unf-controller:upgrade-skip-n
UNF_SKIPPED_UPGRADE_BASELINE_AGENT_IMAGE ?= localhost/unf-agent:upgrade-skip-n
UNF_INCOMPATIBLE_CONTROLLER_IMAGE ?= localhost/unf-controller:incompatible-tuple
UNF_INCOMPATIBLE_AGENT_IMAGE ?= localhost/unf-agent:incompatible-tuple
UNF_CLEAN_REBUILD_CONTROLLER_IMAGE ?= localhost/unf-controller:clean-rebuild-abi5
UNF_CLEAN_REBUILD_AGENT_IMAGE ?= localhost/unf-agent:clean-rebuild-abi5
QUAY_AUTH_FILE ?= $(CURDIR)/.tools/quay-auth.json
UNF_DEV_IMAGE_TAG ?= dev
UNF_CONTROLLER_DEV_IMAGE ?= quay.io/arencloud/unf-controller-dev:$(UNF_DEV_IMAGE_TAG)
UNF_AGENT_DEV_IMAGE ?= quay.io/arencloud/unf-agent-dev:$(UNF_DEV_IMAGE_TAG)
UNF_TEST_TOOLS_DEV_IMAGE ?= quay.io/arencloud/unf-test-tools-dev:$(UNF_DEV_IMAGE_TAG)
BPF_TOOLCHAIN ?= nightly-2026-07-15
UNF_OPENSHIFT_UPGRADE_BASELINE_REF ?= HEAD^
UNF_OPENSHIFT_UPGRADE_IMAGE_RECORD ?= $(CURDIR)/.artifacts/phase3-openshift-upgrade-images.json
OPENSHIFT_KUBECONFIG ?= $(CURDIR)/.tools/cl01-audit.kubeconfig
OPENSHIFT_UNINSTALL_ARGS ?=
PRIMARY_CNI_KIND_NAME ?= unf-cni-dev
PRIMARY_CNI_KIND_CONFIG ?= $(CURDIR)/hack/kind-primary-cni-config.yaml
PRIMARY_CNI_KIND_KUBECONFIG ?= $(CURDIR)/.tools/kind-$(PRIMARY_CNI_KIND_NAME).kubeconfig
PRIMARY_CNI_KUBE_CONTEXT ?= kind-$(PRIMARY_CNI_KIND_NAME)
SERVICE_KIND_NAME ?= unf-service-dev
SERVICE_KIND_CONFIG ?= $(CURDIR)/hack/kind-service-fabric-config.yaml
SERVICE_KIND_KUBECONFIG ?= $(CURDIR)/.tools/kind-$(SERVICE_KIND_NAME).kubeconfig
SERVICE_KUBE_CONTEXT ?= kind-$(SERVICE_KIND_NAME)

build:
	cargo build --workspace

egress-fabric-boundary-test:
	hack/verify-egress-fabric-boundary.sh

egress-intent-test: egress-fabric-boundary-test
	hack/verify-egress-intent.sh
	cargo test -p unf-egress
	cargo test -p unf-controller openshift_egress_ip
	cargo clippy -p unf-egress -p unf-controller --all-targets --all-features -- -D warnings

egress-contract-test: egress-intent-test
	hack/verify-egress-contract.sh
	cargo test -p unf-egress
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-allocation-test: egress-contract-test
	hack/verify-egress-allocation.sh
	cargo test -p unf-egress allocation
	cargo test -p unf-egress gateway
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-host-state-test: egress-allocation-test
	hack/verify-egress-host-state.sh
	cargo test -p unf-egress distribution
	cargo test -p unf-egress host_state
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-proof-test: egress-host-state-test
	hack/verify-egress-proof.sh
	cargo test -p unf-egress proof
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-dataplane-contract-test: egress-proof-test
	hack/verify-egress-dataplane-contract.sh
	cargo test -p unf-ebpf-common
	cargo test -p unf-egress distribution
	cargo test -p unf-egress dataplane
	cargo clippy -p unf-ebpf-common -p unf-egress --all-targets --all-features -- -D warnings

egress-dataplane-map-test: egress-dataplane-contract-test
	hack/verify-egress-map-transaction.sh
	cargo clippy -p unf-agent -p unf-ebpf-common -p unf-egress --all-targets --all-features -- -D warnings

egress-live-distribution-test: egress-dataplane-map-test
	hack/verify-egress-live-distribution.sh
	cargo test -p unf-egress distribution
	cargo test -p unf-controller egress_distribution_is_exact_node_scoped_replayable_and_fail_closed
	cargo test -p unf-agent egress_agent_advertisement_is_exact_and_current
	cargo test -p unf-agent egress_persistent_authority_rejects_regression_and_same_revision_mutation
	cargo clippy -p unf-agent -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-desired-state-test: egress-live-distribution-test
	hack/verify-egress-desired-state.sh
	cargo test -p unf-api
	cargo test -p unf-egress desired
	cargo test -p unf-controller egress_api
	cargo test -p unf-controller native_egress_watch_is_atomic_revisioned_relist_safe_and_durable
	cargo test -p unf-controller openshift_egress_ip_watch_feeds_the_same_durable_model_without_status_adoption
	cargo clippy -p unf-api -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-gateway-distribution-test: egress-desired-state-test
	hack/verify-egress-gateway-distribution.sh
	cargo test -p unf-egress distribution
	cargo test -p unf-controller egress_gateway_distribution_requires_authenticated_source_admission_and_withdraws
	cargo test -p unf-agent egress_agent_advertisement_is_exact_and_current
	cargo clippy -p unf-agent -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-control-plane-test: egress-gateway-distribution-test
	hack/verify-egress-control-plane.sh
	cargo test -p unf-egress control_plane
	cargo test -p unf-controller live_egress_desired_state_drives_durable_allocation_and_gateway_withdrawal
	cargo clippy -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-application-ack-test: egress-control-plane-test
	hack/verify-egress-application-ack.sh
	cargo test -p unf-egress application_acknowledgements_bind_exact_source_and_gateway_state
	cargo test -p unf-controller egress_gateway_distribution_requires_authenticated_source_admission_and_withdraws
	cargo test -p unf-agent egress_agent_advertisement_is_exact_and_current
	cargo clippy -p unf-agent -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-source-steering-test: egress-application-ack-test
	hack/verify-egress-source-steering.sh
	cargo clippy -p unf-agent -p unf-ebpf-common -p unf-egress --all-targets --all-features -- -D warnings

egress-path-activation-test: egress-source-steering-test
	hack/verify-egress-path-activation.sh
	cargo test -p unf-egress source_activation_grant_binds_every_selected_gateway_application
	cargo test -p unf-controller egress_gateway_distribution_requires_authenticated_source_admission_and_withdraws
	cargo test -p unf-agent egress_path
	cargo test -p unf-agent active_egress_bank_compiles_to_destination_preserving_fences
	cargo clippy -p unf-agent -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-gateway-address-test: egress-path-activation-test
	hack/verify-egress-gateway-address.sh
	cargo test -p unf-egress gateway_address
	cargo test -p unf-controller egress_gateway_address_readiness_requires_exact_all_node_quorum
	cargo test -p unf-link --lib -- --skip privileged_gateway_address_transaction_is_exact_and_collision_safe
	unshare -Urn cargo test -p unf-link privileged_gateway_address_transaction_is_exact_and_collision_safe -- --ignored
	cargo clippy -p unf-agent -p unf-controller -p unf-egress -p unf-link --all-targets --all-features -- -D warnings

egress-gateway-nat-test: egress-gateway-address-test
	hack/verify-egress-gateway-nat.sh
	cargo clippy -p unf-agent -p unf-ebpf-common -p unf-egress --all-targets --all-features -- -D warnings

egress-safe-forgetting-test: egress-gateway-nat-test
	hack/verify-egress-safe-forgetting.sh
	cargo test -p unf-egress safe_forgetting
	cargo test -p unf-egress removal_requires_safe_forgetting_authority_before_reuse
	cargo clippy -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-source-retirement-test: egress-safe-forgetting-test
	hack/verify-egress-source-retirement.sh
	cargo test -p unf-controller egress_retirement_evidence_is_node_bound_exact_and_requires_applied_withdrawal
	cargo test -p unf-controller live_egress_desired_state_drives_durable_allocation_and_gateway_withdrawal
	cargo clippy -p unf-agent -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-gateway-retirement-test: egress-source-retirement-test
	hack/verify-egress-gateway-retirement.sh
	cargo test -p unf-agent gateway_retirement_preserves_active_pairs_and_collects_only_one_expired_lease
	cargo test -p unf-controller egress_retirement_evidence_is_node_bound_exact_and_requires_applied_withdrawal
	cargo test -p unf-egress exact_source_gateway_and_reachability_union_authorizes_release
	cargo clippy -p unf-agent -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-release-authority-test: egress-gateway-retirement-test
	hack/verify-egress-release-authority.sh
	cargo test -p unf-egress gateway_address
	cargo test -p unf-controller egress_retirement_evidence_is_node_bound_exact_and_requires_applied_withdrawal
	cargo test -p unf-link --lib -- --skip privileged_gateway_address_transaction_is_exact_and_collision_safe
	unshare -Urn cargo test -p unf-link privileged_gateway_address_transaction_is_exact_and_collision_safe -- --ignored
	cargo clippy -p unf-agent -p unf-controller -p unf-egress -p unf-link --all-targets --all-features -- -D warnings

egress-nat-observability-test: egress-release-authority-test
	hack/verify-egress-nat-observability.sh
	cargo test -p unf-ebpf-common egress_event_vocabulary_is_closed
	cargo test -p unf-agent egress_event_decoder_requires_exact_proof_bound_nat_evidence
	cargo clippy -p unf-agent -p unf-ebpf-common --all-targets --all-features -- -D warnings

egress-kind-lifecycle-test: egress-nat-observability-test primary-cni-installer-test
	bash -n hack/verify-kind-egress-lifecycle.sh
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) UNF_TEST_TOOLS_IMAGE=$(TEST_TOOLS_IMAGE) hack/verify-kind-egress-lifecycle.sh

egress-ha-planner-test: egress-kind-lifecycle-test
	hack/verify-egress-ha-planner.sh
	cargo test -p unf-egress ha::tests
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-ha-promotion-test: egress-ha-planner-test
	hack/verify-egress-ha-promotion.sh
	cargo test -p unf-egress ha_promotion::tests
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-ha-continuity-test: egress-ha-promotion-test
	hack/verify-egress-ha-continuity.sh
	cargo test -p unf-egress ha_continuity::tests
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-ha-live-ownership-test: egress-ha-continuity-test
	hack/verify-egress-ha-live-ownership.sh
	cargo test -p unf-egress --no-fail-fast
	cargo test -p unf-controller --no-fail-fast
	cargo test -p unf-agent --no-fail-fast
	cargo clippy -p unf-agent -p unf-controller -p unf-ebpf-common -p unf-egress -p unf-link --all-targets --all-features -- -D warnings

egress-ha-transaction-test: egress-ha-live-ownership-test
	hack/verify-egress-ha-transaction.sh
	cargo test -p unf-egress ha_promotion_is_durable_ordered_and_never_health_authorized
	cargo test -p unf-egress graceful_promotion_requires_source_fence_before_exact_revocation
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-ha-kind-test: egress-ha-transaction-test service-kind-load
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) apply -k deploy/kind-service-fabric
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout restart deployment/unf-controller daemonset/unf-agent -n unf-system
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout status deployment/unf-controller -n unf-system --timeout=180s
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout status daemonset/unf-agent -n unf-system --timeout=180s
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) hack/migrate-kind-bpf-abi-v15.sh
	bash -n hack/verify-kind-egress-ha.sh
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) UNF_TEST_TOOLS_IMAGE=$(TEST_TOOLS_IMAGE) hack/verify-kind-egress-ha.sh

egress-fqdn-evidence-test: egress-ha-kind-test
	hack/verify-egress-fqdn-evidence.sh
	cargo test -p unf-egress fqdn --no-fail-fast
	cargo clippy -p unf-egress --all-targets --all-features -- -D warnings

egress-fqdn-control-test: egress-fqdn-evidence-test
	hack/verify-egress-fqdn-control.sh
	cargo test -p unf-api --no-fail-fast
	cargo test -p unf-egress fqdn --no-fail-fast
	cargo test -p unf-controller egress_api --no-fail-fast
	cargo test -p unf-controller authenticated_fqdn_observation_batches_are_durable_monotonic_and_node_bound
	cargo clippy -p unf-api -p unf-controller -p unf-egress --all-targets --all-features -- -D warnings

egress-fqdn-dataplane-test: egress-fqdn-control-test
	hack/verify-egress-fqdn-dataplane.sh
	cargo clippy -p unf-agent -p unf-controller -p unf-ebpf-common -p unf-egress --all-targets --all-features -- -D warnings

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

support-matrix-check:
	hack/verify-support-matrix.sh

service-selection-boundary-test:
	hack/verify-service-selection-boundary.sh

service-selection-ir-test: service-selection-boundary-test
	cargo test -p unf-common -p unf-service
	cargo test -p unf-controller service_selection_fields_default_validate_and_canonicalize
	cargo test -p unf-controller service_schema_transition_negotiates_and_projects_v1_v2_v3_state
	cargo test -p unf-agent controller_preflight_accepts_the_bounded_service_schema_transition
	cargo clippy -p unf-common -p unf-service -p unf-controller -p unf-agent --all-targets --all-features -- -D warnings

service-selection-contract-test: service-selection-ir-test
	cargo test -p unf-service selection_contract
	cargo clippy -p unf-service --all-targets --all-features -- -D warnings

service-selection-state-test: service-selection-contract-test
	cargo test -p unf-state
	cargo test -p unf-controller service_selection_projection_is_exact_node_bound_and_capability_fenced
	cargo test -p unf-controller service_schema_transition_negotiates_and_projects_v1_v2_v3_state
	cargo test -p unf-controller agent_convergence_requires_the_compiled_service_revision
	cargo test -p unf-agent selection_
	cargo test -p unf-agent controller_preflight_accepts_the_bounded_service_schema_transition
	cargo clippy -p unf-common -p unf-state -p unf-service -p unf-controller -p unf-agent --all-targets --all-features -- -D warnings

service-selection-dataplane-test: service-selection-state-test ebpf
	cargo test -p unf-ebpf-common
	cargo test -p unf-service selection_dataplane_
	cargo test -p unf-loadbalancer load_balancer_host_bank_is_exact_banked_revision_bound_and_maglev_aware
	cargo test -p unf-agent service_event_decoder_and_status_preserve_bounded_provenance
	cargo test -p unf-agent service_map_config_and_entries_reject_corrupt_persistent_state
	cargo test -p unf-agent selection_recovery_
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-loadbalancer -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-service-map-transaction.sh

service-affinity-dataplane-test: service-selection-dataplane-test ebpf
	cargo test -p unf-ebpf-common
	cargo test -p unf-service selection_dataplane_
	cargo test -p unf-loadbalancer load_balancer_host_bank_is_exact_banked_revision_bound_and_maglev_aware
	cargo test -p unf-agent service_event_decoder_and_status_preserve_bounded_provenance
	cargo test -p unf-agent service_map_config_and_entries_reject_corrupt_persistent_state
	cargo test -p unf-agent cleanup_distinguishes_historical_and_current_map_ownership
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-loadbalancer -p unf-state -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-service-affinity-dataplane.sh

service-maglev-dataplane-test: service-affinity-dataplane-test ebpf
	cargo test -p unf-service maglev
	cargo test -p unf-loadbalancer maglev
	cargo test -p unf-agent service_event_decoder_and_status_preserve_bounded_provenance
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-loadbalancer -p unf-state -p unf-controller -p unf-agent --all-targets --all-features -- -D warnings
	hack/verify-service-maglev.sh

service-dsr-dataplane-test: service-maglev-dataplane-test ebpf
	cargo test -p unf-ebpf-common
	cargo test -p unf-service dsr_
	cargo test -p unf-loadbalancer load_balancer_host_bank_is_exact_banked_revision_bound_and_maglev_aware
	cargo test -p unf-controller service_selection_fields_default_validate_and_canonicalize
	cargo test -p unf-agent service_event_decoder_and_status_preserve_bounded_provenance
	cargo test -p unf-agent cleanup_distinguishes_historical_and_current_map_ownership
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-loadbalancer -p unf-state -p unf-controller -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-service-dsr.sh

service-selection-operations-test: service-dsr-dataplane-test
	cargo test -p unf-state flow_history_
	cargo test -p unf-agent service_event_decoder_and_status_preserve_bounded_provenance
	cargo test -p unf-controller advanced_service_status_is_fixed_cardinality_and_adjacent_compatible
	cargo test -p unf-controller service_flow_ingestion_validates_bounded_dataplane_provenance
	cargo test -p unf-controller node_port_simulation_is_node_local_read_only_and_fail_closed
	cargo test -p unf-controller load_balancer_simulation_and_explanation_are_provenance_exact_and_read_only
	cargo test -p unfctl cluster_ip_simulation_command_builds_exact_query
	cargo test -p unfctl node_port_simulation_command_builds_exact_query
	cargo test -p unfctl load_balancer_simulation_and_explanation_build_exact_queries
	cargo clippy -p unf-ebpf-common -p unf-state -p unf-service -p unf-loadbalancer -p unf-agent -p unf-controller -p unfctl --all-targets --all-features -- -D warnings

service-selection-kind-up: loadbalancer-kind-up

service-selection-kind-load: loadbalancer-kind-load

service-selection-kind-deploy: loadbalancer-kind-deploy

service-selection-kind-test: service-selection-operations-test primary-cni-installer-test cli
	bash -n hack/verify-kind-loadbalancer.sh
	bash -n hack/verify-kind-service-selection.sh
	kubectl kustomize deploy/kind-loadbalancer >/dev/null
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/verify-kind-service-selection.sh

service-selection-kind-down: loadbalancer-kind-down

loadbalancer-boundary-test:
	hack/verify-loadbalancer-boundary.sh

loadbalancer-ir-test: loadbalancer-boundary-test
	cargo test -p unf-common -p unf-service
	cargo test -p unf-controller load_balancer_translation_is_explicit_exact_and_last_valid
	cargo test -p unf-controller service_schema_transition_negotiates_and_projects_v1_v2_state
	cargo test -p unf-controller agent_convergence_requires_the_compiled_service_revision
	cargo test -p unf-agent controller_preflight_accepts_the_bounded_service_schema_transition
	cargo clippy -p unf-common -p unf-service -p unf-controller -p unf-agent --all-targets --all-features -- -D warnings

loadbalancer-control-plane-test: loadbalancer-ir-test
	cargo test -p unf-loadbalancer
	cargo clippy -p unf-loadbalancer --all-targets --all-features -- -D warnings

loadbalancer-host-state-test: loadbalancer-control-plane-test
	cargo test -p unf-controller load_balancer
	cargo test -p unf-agent load_balancer
	cargo test -p unf-agent cleanup_distinguishes_complete_v4_v5_v6_and_v7_map_ownership
	cargo test -p unf-state component_compatibility_fixes_the_upgrade_contract
	cargo clippy -p unf-common -p unf-ebpf-common -p unf-loadbalancer -p unf-state -p unf-controller -p unf-agent --all-targets --all-features -- -D warnings
	kubectl kustomize deploy >/dev/null
	kubectl kustomize deploy/openshift >/dev/null
	kubectl kustomize deploy/kind-primary-cni >/dev/null
	kubectl kustomize deploy/kind-service-fabric >/dev/null
	kubectl kustomize deploy/openshift-primary-cni/runtime >/dev/null
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-service-map-transaction.sh

loadbalancer-cluster-dataplane-test: loadbalancer-host-state-test
	cargo test -p unf-ebpf-common service_flow_hash
	cargo test -p unf-agent load_balancer
	cargo clippy -p unf-common -p unf-ebpf-common -p unf-service -p unf-loadbalancer -p unf-state -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-loadbalancer-cluster-dataplane.sh

loadbalancer-local-dataplane-test: loadbalancer-cluster-dataplane-test
	cargo test -p unf-ebpf-common
	cargo test -p unf-loadbalancer load_balancer_host_bank_is_exact_banked_revision_bound_and_maglev_aware
	cargo test -p unf-agent load_balancer_health_check_is_dual_stack_local_and_lifecycle_exact
	cargo clippy -p unf-common -p unf-ebpf-common -p unf-service -p unf-loadbalancer -p unf-state -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-loadbalancer-local-dataplane.sh

loadbalancer-operations-test: loadbalancer-local-dataplane-test
	cargo test -p unf-controller load_balancer
	cargo test -p unf-agent service_event_decoder_and_status_preserve_bounded_provenance
	cargo test -p unf-state flow_history
	cargo test -p unfctl load_balancer
	cargo clippy -p unf-state -p unf-loadbalancer -p unf-agent -p unf-controller -p unfctl --all-targets --all-features -- -D warnings
	kubectl kustomize deploy >/dev/null
	kubectl kustomize deploy/openshift >/dev/null

loadbalancer-kind-up: service-kind-up

loadbalancer-kind-load: service-kind-load

loadbalancer-kind-deploy: loadbalancer-kind-load
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/configure-kind-primary-cni.sh
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) UNF_INTERNAL_TLS_DIR=$(CURDIR)/.tools/kind-service-internal-tls hack/configure-internal-tls.sh
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) apply -k deploy/kind-loadbalancer
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) hack/configure-kind-service-bootstrap.sh
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout restart deployment/unf-controller -n unf-system
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout restart daemonset/unf-agent -n unf-system
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout status deployment/unf-controller -n unf-system --timeout=180s
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout status daemonset/unf-agent -n unf-system --timeout=180s
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) wait --for=condition=Ready nodes --all --timeout=180s

loadbalancer-kind-test: loadbalancer-operations-test primary-cni-installer-test cli
	bash -n hack/verify-kind-loadbalancer.sh
	kubectl kustomize deploy/kind-loadbalancer >/dev/null
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/verify-kind-loadbalancer.sh

loadbalancer-kind-down: service-kind-down

service-ir-test:
	cargo test -p unf-common -p unf-service
	cargo clippy -p unf-common -p unf-service --all-targets --all-features -- -D warnings

service-compiler-test: service-ir-test
	cargo test -p unf-controller service_snapshot
	cargo test -p unf-controller node_port_service_translation_preserves_family_port_and_policy
	cargo test -p unf-controller endpoint_slice_readiness
	cargo clippy -p unf-controller --all-targets --all-features -- -D warnings

service-distribution-test: service-compiler-test
	cargo test -p unf-agent service_snapshot
	cargo test -p unf-service service_schema_transition
	cargo test -p unf-controller service_schema_transition
	cargo test -p unf-agent service_schema_transition
	cargo test -p unf-controller agent_convergence_requires_the_compiled_service_revision
	cargo clippy -p unf-agent -p unf-controller -p unf-state --all-targets --all-features -- -D warnings
	kubectl kustomize deploy >/dev/null
	kubectl kustomize deploy/openshift >/dev/null
	kubectl kustomize deploy/kind-primary-cni >/dev/null
	kubectl kustomize deploy/kind-service-fabric >/dev/null
	kubectl kustomize deploy/openshift-primary-cni/runtime >/dev/null

nodeport-host-state-test: service-distribution-test
	cargo test -p unf-ebpf-common abi_layout
	cargo test -p unf-service node_port_node_snapshot
	cargo test -p unf-service node_port_dataplane
	cargo test -p unf-controller node_port_node_intent
	cargo test -p unf-controller agent_status_authentication_binds_service_account_pod_and_node
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-controller --all-targets --all-features -- -D warnings

nodeport-transaction-test: nodeport-host-state-test
	cargo test -p unf-service node_port
	cargo test -p unf-agent node_port
	cargo test -p unf-agent cleanup_distinguishes_complete_v4_v5_v6_and_v7_map_ownership
	cargo test -p unf-state component_compatibility_fixes_the_upgrade_contract
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-state -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-service-map-transaction.sh
	bash -n hack/uninstall-openshift.sh hack/verify-openshift-uninstall.sh

nodeport-cluster-dataplane-test: nodeport-transaction-test
	cargo test -p unf-ebpf-common service_flow_hash
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-nodeport-cluster-dataplane.sh

nodeport-local-dataplane-test: nodeport-cluster-dataplane-test
	cargo test -p unf-service node_port_dataplane_is_node_scoped_banked_and_policy_typed
	cargo test -p unf-agent node_port_cluster_and_local
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-nodeport-cluster-dataplane.sh

nodeport-operations-test: nodeport-local-dataplane-test
	cargo test -p unf-ebpf-common service_event_actions_accept_only_their_bounded_reasons
	cargo test -p unf-state flow_history_migrates_pre_nodeport_classification_checkpoints
	cargo test -p unf-agent service_event_decoder_and_status_preserve_bounded_provenance
	cargo test -p unf-agent node_port_service_checkpoint_is_composite_private_and_transition_fenced
	cargo test -p unf-controller node_port_simulation_is_node_local_read_only_and_fail_closed
	cargo test -p unf-controller service_flow_ingestion_validates_bounded_dataplane_provenance
	cargo test -p unfctl service_explanation_command_builds_bounded_query
	cargo test -p unfctl node_port_simulation_command_builds_exact_query
	cargo clippy -p unf-ebpf-common -p unf-state -p unf-service -p unf-agent -p unf-controller -p unfctl --all-targets --all-features -- -D warnings

service-dataplane-test: service-distribution-test
	cargo test -p unf-ebpf-common -p unf-service
	cargo test -p unf-agent service_map
	cargo clippy -p unf-ebpf-common -p unf-service -p unf-agent --all-targets --all-features -- -D warnings
	UNF_BPF_TOOLCHAIN=$(BPF_TOOLCHAIN) hack/verify-service-map-transaction.sh

service-operations-test: service-dataplane-test
	cargo test -p unf-state -p unf-agent -p unf-controller -p unfctl
	cargo clippy -p unf-ebpf-common -p unf-state -p unf-agent -p unf-controller -p unfctl --all-targets --all-features -- -D warnings

primary-cni-installer-test:
	hack/verify-kind-primary-cni-installer.sh
	hack/verify-openshift-primary-cni-installer.sh

service-kind-up: kind-tool
	hack/verify-kind-host-prerequisites.sh
	sudo env KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) create cluster --name $(SERVICE_KIND_NAME) --config $(SERVICE_KIND_CONFIG)
	sudo chown $$(id -u):$$(id -g) $(SERVICE_KIND_KUBECONFIG)
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/configure-kind-primary-cni.sh

service-kind-load: KIND_NAME = $(SERVICE_KIND_NAME)
service-kind-load: KIND_KUBECONFIG = $(SERVICE_KIND_KUBECONFIG)
service-kind-load: KUBE_CONTEXT = $(SERVICE_KUBE_CONTEXT)
service-kind-load: kind-load

service-kind-deploy: service-kind-load
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/configure-kind-primary-cni.sh
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) UNF_INTERNAL_TLS_DIR=$(CURDIR)/.tools/kind-service-internal-tls hack/configure-internal-tls.sh
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) apply -k deploy/kind-service-fabric
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) hack/configure-kind-service-bootstrap.sh
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout restart deployment/unf-controller -n unf-system
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout restart daemonset/unf-agent -n unf-system
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout status deployment/unf-controller -n unf-system --timeout=180s
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) rollout status daemonset/unf-agent -n unf-system --timeout=180s
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) kubectl --context $(SERVICE_KUBE_CONTEXT) wait --for=condition=Ready nodes --all --timeout=180s

service-kind-test: service-operations-test primary-cni-installer-test cli
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/verify-kind-service-fabric.sh

nodeport-kind-test: nodeport-operations-test primary-cni-installer-test cli
	KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KUBE_CONTEXT=$(SERVICE_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) UNF_NODEPORT_KIND=true hack/verify-kind-service-fabric.sh

service-kind-down:
	sudo env KUBECONFIG=$(SERVICE_KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) delete cluster --name $(SERVICE_KIND_NAME)

ebpf:
	cargo +$(BPF_TOOLCHAIN) build --manifest-path ebpf/unf-ebpf-tc/Cargo.toml -Z build-std=core --target bpfel-unknown-none --release

generate-crds:
	cargo run -p unf-api --example crdgen -- security-policy > deploy/crds/network.unf.io_securitypolicies.yaml
	cargo run -p unf-api --example crdgen -- egress-pool > deploy/crds/network.unf.io_egresspools.yaml
	cargo run -p unf-api --example crdgen -- egress-policy > deploy/crds/network.unf.io_egresspolicies.yaml

controller:
	cargo build -p unf-controller

agent:
	cargo build -p unf-agent

cni:
	cargo build -p unf-cni

cni-protocol-test:
	hack/verify-cni-protocol.sh

cni-transaction-test:
	cargo test -p unf-cni-state
	cargo test -p unf-agent cni_server
	cargo clippy -p unf-cni-state -p unf-agent --all-targets --all-features -- -D warnings

cni-ipam-test:
	cargo test -p unf-ipam
	cargo test -p unf-cni-state
	cargo test -p unf-agent cni_server
	cargo clippy -p unf-ipam -p unf-cni-state -p unf-agent --all-targets --all-features -- -D warnings

cni-veth-test:
	cargo test -p unf-link
	cargo clippy -p unf-link --all-targets --all-features -- -D warnings
	hack/verify-cni-veth.sh

cni-routing-test: cni-veth-test
	cargo test -p unf-route
	cargo clippy -p unf-route --all-targets --all-features -- -D warnings
	hack/verify-cni-routing.sh

cni-lifecycle-test: cni-routing-test
	hack/verify-cni-protocol.sh
	cargo test -p unf-cni-state -p unf-cni
	cargo clippy -p unf-cni-state -p unf-cni --all-targets --all-features -- -D warnings
	hack/verify-cni-lifecycle.sh

cni-node-block-test: cni-lifecycle-test
	cargo test -p unf-ipam
	cargo test -p unf-controller node_block
	cargo test -p unf-agent node_block
	cargo clippy -p unf-ipam -p unf-state -p unf-controller -p unf-agent --all-targets --all-features -- -D warnings

cni-remote-routing-test: cni-node-block-test
	cargo test -p unf-route
	cargo clippy -p unf-route --all-targets --all-features -- -D warnings
	hack/verify-cni-remote-routing.sh

cni-route-reconciliation-test: cni-remote-routing-test
	cargo test -p unf-controller remote_route
	cargo test -p unf-agent remote_route
	cargo test -p unfctl
	cargo clippy -p unf-state -p unf-route -p unf-controller -p unf-agent -p unfctl --all-targets --all-features -- -D warnings

cli:
	cargo build -p unfctl

artifacts: ebpf
	mkdir -p .artifacts
	cp ebpf/unf-ebpf-tc/target/bpfel-unknown-none/release/unf-ebpf-tc .artifacts/unf-ebpf-tc

images: artifacts
	podman build --build-arg UNF_BUILD_REVISION=$(UNF_BUILD_REVISION) --build-arg UNF_PACKAGE=unf-controller --tag localhost/unf-controller:dev --file images/Containerfile .
	podman build --build-arg UNF_BUILD_REVISION=$(UNF_BUILD_REVISION) --build-arg UNF_PACKAGE=unf-agent --tag localhost/unf-agent:dev --file images/Containerfile .
	podman build --tag $(TEST_TOOLS_IMAGE) --file images/SctpTestContainerfile .
	podman run --rm --entrypoint sh $(TEST_TOOLS_IMAGE) -ec 'command -v bpftool >/dev/null && command -v jq >/dev/null'

upgrade-baseline-images:
	UNF_UPGRADE_BASELINE_REF=$(UNF_UPGRADE_BASELINE_REF) UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE=$(UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE) UNF_UPGRADE_BASELINE_AGENT_IMAGE=$(UNF_UPGRADE_BASELINE_AGENT_IMAGE) hack/build-upgrade-baseline-images.sh

skipped-upgrade-baseline-images:
	UNF_UPGRADE_BASELINE_REF=$(UNF_SKIPPED_UPGRADE_BASELINE_REF) UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE=$(UNF_SKIPPED_UPGRADE_BASELINE_CONTROLLER_IMAGE) UNF_UPGRADE_BASELINE_AGENT_IMAGE=$(UNF_SKIPPED_UPGRADE_BASELINE_AGENT_IMAGE) UNF_UPGRADE_MIN_COMMIT_DISTANCE=2 hack/build-upgrade-baseline-images.sh

incompatible-version-images: images
	UNF_INCOMPATIBLE_CONTROLLER_IMAGE=$(UNF_INCOMPATIBLE_CONTROLLER_IMAGE) UNF_INCOMPATIBLE_AGENT_IMAGE=$(UNF_INCOMPATIBLE_AGENT_IMAGE) hack/build-incompatible-version-images.sh

clean-rebuild-version-images: images
	UNF_CLEAN_REBUILD_CONTROLLER_IMAGE=$(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE) UNF_CLEAN_REBUILD_AGENT_IMAGE=$(UNF_CLEAN_REBUILD_AGENT_IMAGE) hack/build-clean-rebuild-images.sh

openshift-images: images
	podman push --authfile $(QUAY_AUTH_FILE) localhost/unf-controller:dev docker://$(UNF_CONTROLLER_DEV_IMAGE)
	podman push --authfile $(QUAY_AUTH_FILE) localhost/unf-agent:dev docker://$(UNF_AGENT_DEV_IMAGE)
	podman push --authfile $(QUAY_AUTH_FILE) $(TEST_TOOLS_IMAGE) docker://$(UNF_TEST_TOOLS_DEV_IMAGE)

openshift-upgrade-images:
	UNF_OPENSHIFT_UPGRADE_BASELINE_REF=$(UNF_OPENSHIFT_UPGRADE_BASELINE_REF) QUAY_AUTH_FILE=$(QUAY_AUTH_FILE) UNF_OPENSHIFT_UPGRADE_IMAGE_RECORD=$(UNF_OPENSHIFT_UPGRADE_IMAGE_RECORD) hack/build-openshift-upgrade-images.sh

openshift-deploy:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/deploy-openshift.sh

openshift-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift.sh

openshift-upgrade-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) UNF_OPENSHIFT_UPGRADE_IMAGE_RECORD=$(UNF_OPENSHIFT_UPGRADE_IMAGE_RECORD) hack/verify-openshift-upgrade.sh

openshift-tls-rotation-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-tls-rotation.sh

openshift-agent-report-retention-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-agent-report-retention.sh

openshift-host-mount-policy-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-host-mount-policy.sh

openshift-uninstall:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/uninstall-openshift.sh $(OPENSHIFT_UNINSTALL_ARGS)

openshift-uninstall-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-uninstall.sh

# This audit is read-only apart from short-lived oc debug Pods. It records why
# a cluster is or is not eligible for the installation-time custom-CNI gate.
openshift-primary-cni-audit:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/audit-openshift-primary-cni.sh

# Qualification preflight is deliberately fail-closed. An OpenShift cluster
# installed with OVN cannot be converted into the UNF fixture in place.
openshift-primary-cni-preflight:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) UNF_OPENSHIFT_PRIMARY_REQUIRE_ELIGIBLE=true hack/audit-openshift-primary-cni.sh

openshift-primary-cni-package-check:
	hack/verify-openshift-primary-cni-package.sh

openshift-primary-cni-runtime-fault-test:
	OPENSHIFT_KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-primary-cni-runtime-fault.sh

openshift-primary-cni-node-reprovision-test:
	OPENSHIFT_KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-primary-cni-node-reprovision.sh

openshift-primary-cni-deploy:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/deploy-openshift-primary-cni.sh

openshift-service-deploy:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/deploy-openshift-service-fabric.sh

openshift-service-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-service-fabric.sh

nodeport-openshift-deploy: openshift-service-deploy

nodeport-openshift-test: openshift-service-test

loadbalancer-openshift-deploy:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) \
	UNF_OPENSHIFT_SERVICE_RELEASE_RECORD=$(CURDIR)/deploy/openshift-primary-cni/loadbalancer/release.json \
	UNF_OPENSHIFT_SERVICE_DEPLOY_EVIDENCE=$(CURDIR)/.artifacts/phase6-loadbalancer-openshift-deploy.json \
	UNF_OPENSHIFT_SERVICE_RENDER_PATH=$(CURDIR)/deploy/openshift-primary-cni/loadbalancer \
	hack/deploy-openshift-service-fabric.sh

loadbalancer-openshift-test: cli
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-loadbalancer.sh

service-selection-openshift-deploy:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) \
	UNF_OPENSHIFT_SERVICE_RELEASE_RECORD=$(CURDIR)/deploy/openshift-primary-cni/service-selection/release.json \
	UNF_OPENSHIFT_SERVICE_DEPLOY_EVIDENCE=$(CURDIR)/.artifacts/phase7-service-selection-openshift-deploy.json \
	UNF_OPENSHIFT_SERVICE_RENDER_PATH=$(CURDIR)/deploy/openshift-primary-cni/service-selection \
	hack/deploy-openshift-service-fabric.sh

service-selection-openshift-test: cli
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-service-selection.sh

kind-tool:
	mkdir -p .tools/bin
	GOBIN=$(CURDIR)/.tools/bin go install sigs.k8s.io/kind@v0.32.0

kind-up: kind-tool
	sudo env KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) create cluster --name $(KIND_NAME) --config $(KIND_CONFIG) --wait 5m
	sudo chown $$(id -u):$$(id -g) $(KIND_KUBECONFIG)
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/configure-kind.sh

kind-load: images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save localhost/unf-controller:dev | sudo podman load
	podman save localhost/unf-agent:dev | sudo podman load
	podman save $(TEST_TOOLS_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) localhost/unf-controller:dev
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) localhost/unf-agent:dev
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(TEST_TOOLS_IMAGE)

kind-upgrade-load: upgrade-baseline-images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save $(UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE) | sudo podman load
	podman save $(UNF_UPGRADE_BASELINE_AGENT_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE)
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(UNF_UPGRADE_BASELINE_AGENT_IMAGE)

kind-skipped-upgrade-load: skipped-upgrade-baseline-images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save $(UNF_SKIPPED_UPGRADE_BASELINE_CONTROLLER_IMAGE) | sudo podman load
	podman save $(UNF_SKIPPED_UPGRADE_BASELINE_AGENT_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(UNF_SKIPPED_UPGRADE_BASELINE_CONTROLLER_IMAGE)
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(UNF_SKIPPED_UPGRADE_BASELINE_AGENT_IMAGE)

kind-incompatible-version-load: incompatible-version-images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save $(UNF_INCOMPATIBLE_CONTROLLER_IMAGE) | sudo podman load
	podman save $(UNF_INCOMPATIBLE_AGENT_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(UNF_INCOMPATIBLE_CONTROLLER_IMAGE)
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(UNF_INCOMPATIBLE_AGENT_IMAGE)

kind-clean-rebuild-load: clean-rebuild-version-images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save $(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE) | sudo podman load
	podman save $(UNF_CLEAN_REBUILD_AGENT_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE)
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name $(KIND_NAME) $(UNF_CLEAN_REBUILD_AGENT_IMAGE)

kind-deploy: kind-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/configure-internal-tls.sh
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) apply -k deploy
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) rollout restart deployment/unf-controller -n unf-system
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) rollout restart daemonset/unf-agent -n unf-system
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) rollout status deployment/unf-controller -n unf-system --timeout=120s
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) rollout status daemonset/unf-agent -n unf-system --timeout=120s

kind-demo:
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) apply -f deploy/examples/demo.yaml
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) wait --for=condition=Ready pod/client -n frontend --timeout=120s
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) wait --for=condition=Ready pod/server -n backend --timeout=120s
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) wait --for=condition=Ready pod/np-server -n backend --timeout=120s
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context $(KUBE_CONTEXT) exec -n frontend client -- wget -qO- http://server.backend.svc.cluster.local:8080

kind-flow-history-retention-test: cli
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/verify-flow-history-retention.sh

kind-topology-history-test: cli
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/verify-topology-history.sh

kind-external-flow-export-test:
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/verify-external-flow-export.sh

kind-upgrade-test: kind-deploy kind-demo kind-upgrade-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE=$(UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE) UNF_UPGRADE_BASELINE_AGENT_IMAGE=$(UNF_UPGRADE_BASELINE_AGENT_IMAGE) UNF_UPGRADE_CURRENT_REVISION=$(UNF_BUILD_REVISION) hack/verify-kind-upgrade.sh

kind-skipped-upgrade-test: kind-deploy kind-demo kind-skipped-upgrade-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE=$(UNF_SKIPPED_UPGRADE_BASELINE_CONTROLLER_IMAGE) UNF_UPGRADE_BASELINE_AGENT_IMAGE=$(UNF_SKIPPED_UPGRADE_BASELINE_AGENT_IMAGE) UNF_UPGRADE_CURRENT_REVISION=$(UNF_BUILD_REVISION) UNF_UPGRADE_CURRENT_GENERATION=N+2 UNF_UPGRADE_REQUIRE_BASELINE_TUPLE=true hack/verify-kind-upgrade.sh

kind-incompatible-version-test: kind-deploy kind-demo kind-incompatible-version-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) UNF_INCOMPATIBLE_CONTROLLER_IMAGE=$(UNF_INCOMPATIBLE_CONTROLLER_IMAGE) UNF_INCOMPATIBLE_AGENT_IMAGE=$(UNF_INCOMPATIBLE_AGENT_IMAGE) UNF_CURRENT_REVISION=$(UNF_BUILD_REVISION) hack/verify-kind-incompatible-version.sh

kind-clean-rebuild-test: kind-deploy kind-demo kind-clean-rebuild-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) UNF_CLEAN_REBUILD_CONTROLLER_IMAGE=$(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE) UNF_CLEAN_REBUILD_AGENT_IMAGE=$(UNF_CLEAN_REBUILD_AGENT_IMAGE) UNF_CURRENT_REVISION=$(UNF_BUILD_REVISION) hack/verify-kind-clean-rebuild.sh

kind-unsupported-downgrade-test: kind-deploy kind-demo kind-clean-rebuild-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) UNF_CLEAN_REBUILD_CONTROLLER_IMAGE=$(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE) UNF_CLEAN_REBUILD_AGENT_IMAGE=$(UNF_CLEAN_REBUILD_AGENT_IMAGE) UNF_CURRENT_REVISION=$(UNF_BUILD_REVISION) UNF_REQUIRE_UNSUPPORTED_DOWNGRADE=true hack/verify-kind-clean-rebuild.sh

kind-rollback-reporting-test: kind-deploy kind-demo kind-clean-rebuild-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) UNF_CLEAN_REBUILD_CONTROLLER_IMAGE=$(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE) UNF_CLEAN_REBUILD_AGENT_IMAGE=$(UNF_CLEAN_REBUILD_AGENT_IMAGE) UNF_CURRENT_REVISION=$(UNF_BUILD_REVISION) UNF_REQUIRE_UNSUPPORTED_DOWNGRADE=true hack/verify-kind-clean-rebuild.sh

kind-scale-failure-test: kind-deploy kind-demo
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/verify-kind-scale-failure.sh

kind-test: cli kind-demo
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) UNF_KIND_CONTROL_PLANE_NODE=$(UNF_KIND_CONTROL_PLANE_NODE) UNF_KIND_WORKER_NODE=$(UNF_KIND_WORKER_NODE) UNF_POLICY_TRANSITION_ATTEMPTS=$(UNF_POLICY_TRANSITION_ATTEMPTS) hack/verify-kind.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/verify-topology-history.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/verify-flow-history-retention.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/verify-external-flow-export.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=$(KUBE_CONTEXT) hack/verify-kind-legacy-netlink.sh

kind-platform-matrix-test:
	hack/verify-kind-platform-matrix.sh

kind-down:
	sudo env KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) delete cluster --name $(KIND_NAME)

# This fixture is intentionally separate from the overlay-development cluster.
# It owns primary CNI state and is disposable by contract.
primary-cni-kind-up: kind-tool
	hack/verify-kind-host-prerequisites.sh
	sudo env KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) create cluster --name $(PRIMARY_CNI_KIND_NAME) --config $(PRIMARY_CNI_KIND_CONFIG)
	sudo chown $$(id -u):$$(id -g) $(PRIMARY_CNI_KIND_KUBECONFIG)
	KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) KUBE_CONTEXT=$(PRIMARY_CNI_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/configure-kind-primary-cni.sh

primary-cni-kind-load: KIND_NAME = $(PRIMARY_CNI_KIND_NAME)
primary-cni-kind-load: KIND_KUBECONFIG = $(PRIMARY_CNI_KIND_KUBECONFIG)
primary-cni-kind-load: KUBE_CONTEXT = $(PRIMARY_CNI_KUBE_CONTEXT)
primary-cni-kind-load: kind-load

primary-cni-kind-deploy: primary-cni-kind-load
	KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) KUBE_CONTEXT=$(PRIMARY_CNI_KUBE_CONTEXT) UNF_INTERNAL_TLS_DIR=$(CURDIR)/.tools/kind-primary-cni-internal-tls hack/configure-internal-tls.sh
	KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) kubectl --context $(PRIMARY_CNI_KUBE_CONTEXT) apply -k deploy/kind-primary-cni
	KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) kubectl --context $(PRIMARY_CNI_KUBE_CONTEXT) rollout status deployment/unf-controller -n unf-system --timeout=180s
	KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) kubectl --context $(PRIMARY_CNI_KUBE_CONTEXT) rollout status daemonset/unf-agent -n unf-system --timeout=180s
	KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) kubectl --context $(PRIMARY_CNI_KUBE_CONTEXT) wait --for=condition=Ready nodes --all --timeout=180s

primary-cni-kind-test: cli
	KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) KUBE_CONTEXT=$(PRIMARY_CNI_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/verify-kind-primary-cni.sh

primary-cni-kind-rollback:
	KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) KUBE_CONTEXT=$(PRIMARY_CNI_KUBE_CONTEXT) KIND_PROVIDER=$(KIND_PROVIDER) hack/rollback-kind-primary-cni.sh

primary-cni-kind-down:
	sudo env KUBECONFIG=$(PRIMARY_CNI_KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) delete cluster --name $(PRIMARY_CNI_KIND_NAME)
