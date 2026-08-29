.PHONY: build test lint fmt fmt-check support-matrix-check ebpf generate-crds controller agent cni cni-protocol-test cni-transaction-test cni-ipam-test cni-veth-test cni-routing-test cni-lifecycle-test cni-node-block-test cni-remote-routing-test cni-route-reconciliation-test cli artifacts images upgrade-baseline-images skipped-upgrade-baseline-images incompatible-version-images clean-rebuild-version-images openshift-images openshift-upgrade-images openshift-deploy openshift-test openshift-upgrade-test openshift-tls-rotation-test openshift-agent-report-retention-test openshift-host-mount-policy-test openshift-uninstall openshift-uninstall-test openshift-primary-cni-audit openshift-primary-cni-preflight openshift-primary-cni-package-check openshift-primary-cni-runtime-fault-test openshift-primary-cni-deploy kind-tool kind-up kind-load kind-upgrade-load kind-skipped-upgrade-load kind-incompatible-version-load kind-clean-rebuild-load kind-deploy kind-demo kind-topology-history-test kind-flow-history-retention-test kind-external-flow-export-test kind-upgrade-test kind-skipped-upgrade-test kind-incompatible-version-test kind-clean-rebuild-test kind-unsupported-downgrade-test kind-rollback-reporting-test kind-scale-failure-test kind-test kind-platform-matrix-test kind-down primary-cni-kind-up primary-cni-kind-load primary-cni-kind-deploy primary-cni-kind-test primary-cni-kind-rollback primary-cni-kind-down
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
UNF_CLEAN_REBUILD_CONTROLLER_IMAGE ?= localhost/unf-controller:clean-rebuild-abi4
UNF_CLEAN_REBUILD_AGENT_IMAGE ?= localhost/unf-agent:clean-rebuild-abi4
QUAY_AUTH_FILE ?= $(CURDIR)/.tools/quay-auth.json
UNF_DEV_IMAGE_TAG ?= dev
UNF_CONTROLLER_DEV_IMAGE ?= quay.io/arencloud/unf-controller-dev:$(UNF_DEV_IMAGE_TAG)
UNF_AGENT_DEV_IMAGE ?= quay.io/arencloud/unf-agent-dev:$(UNF_DEV_IMAGE_TAG)
UNF_TEST_TOOLS_DEV_IMAGE ?= quay.io/arencloud/unf-test-tools-dev:$(UNF_DEV_IMAGE_TAG)
UNF_OPENSHIFT_UPGRADE_BASELINE_REF ?= HEAD^
UNF_OPENSHIFT_UPGRADE_IMAGE_RECORD ?= $(CURDIR)/.artifacts/phase3-openshift-upgrade-images.json
OPENSHIFT_KUBECONFIG ?= $(CURDIR)/.tools/cl01-audit.kubeconfig
OPENSHIFT_UNINSTALL_ARGS ?=
PRIMARY_CNI_KIND_NAME ?= unf-cni-dev
PRIMARY_CNI_KIND_CONFIG ?= $(CURDIR)/hack/kind-primary-cni-config.yaml
PRIMARY_CNI_KIND_KUBECONFIG ?= $(CURDIR)/.tools/kind-$(PRIMARY_CNI_KIND_NAME).kubeconfig
PRIMARY_CNI_KUBE_CONTEXT ?= kind-$(PRIMARY_CNI_KIND_NAME)

build:
	cargo build --workspace

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

ebpf:
	cargo +nightly build --manifest-path ebpf/unf-ebpf-tc/Cargo.toml -Z build-std=core --target bpfel-unknown-none --release

generate-crds:
	cargo run -p unf-api --example crdgen > deploy/crds/network.unf.io_securitypolicies.yaml

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

openshift-primary-cni-deploy:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/deploy-openshift-primary-cni.sh

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
