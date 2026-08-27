.PHONY: build test lint fmt fmt-check ebpf generate-crds controller agent cli artifacts images upgrade-baseline-images skipped-upgrade-baseline-images incompatible-version-images clean-rebuild-version-images openshift-images openshift-deploy openshift-test openshift-tls-rotation-test openshift-agent-report-retention-test openshift-host-mount-policy-test openshift-uninstall openshift-uninstall-test kind-tool kind-up kind-load kind-upgrade-load kind-skipped-upgrade-load kind-incompatible-version-load kind-clean-rebuild-load kind-deploy kind-demo kind-topology-history-test kind-flow-history-retention-test kind-external-flow-export-test kind-upgrade-test kind-skipped-upgrade-test kind-incompatible-version-test kind-clean-rebuild-test kind-unsupported-downgrade-test kind-scale-failure-test kind-test kind-down
.NOTPARALLEL: kind-upgrade-test kind-skipped-upgrade-test kind-incompatible-version-test kind-clean-rebuild-test kind-unsupported-downgrade-test

KIND := .tools/bin/kind
KIND_PROVIDER ?= podman
KIND_KUBECONFIG := $(CURDIR)/.tools/kind-unf-dev.kubeconfig
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
OPENSHIFT_KUBECONFIG ?= $(CURDIR)/.tools/cl01-audit.kubeconfig
OPENSHIFT_UNINSTALL_ARGS ?=

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

ebpf:
	cargo +nightly build --manifest-path ebpf/unf-ebpf-tc/Cargo.toml -Z build-std=core --target bpfel-unknown-none --release

generate-crds:
	cargo run -p unf-api --example crdgen > deploy/crds/network.unf.io_securitypolicies.yaml

controller:
	cargo build -p unf-controller

agent:
	cargo build -p unf-agent

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

openshift-deploy:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) QUAY_AUTH_FILE=$(QUAY_AUTH_FILE) hack/deploy-openshift.sh

openshift-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) QUAY_AUTH_FILE=$(QUAY_AUTH_FILE) hack/verify-openshift.sh

openshift-tls-rotation-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-tls-rotation.sh

openshift-agent-report-retention-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-agent-report-retention.sh

openshift-host-mount-policy-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/verify-openshift-host-mount-policy.sh

openshift-uninstall:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) hack/uninstall-openshift.sh $(OPENSHIFT_UNINSTALL_ARGS)

openshift-uninstall-test:
	KUBECONFIG=$(OPENSHIFT_KUBECONFIG) QUAY_AUTH_FILE=$(QUAY_AUTH_FILE) hack/verify-openshift-uninstall.sh

kind-tool:
	mkdir -p .tools/bin
	GOBIN=$(CURDIR)/.tools/bin go install sigs.k8s.io/kind@v0.32.0

kind-up: kind-tool
	sudo env KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) create cluster --name unf-dev --config hack/kind-config.yaml --wait 5m
	sudo chown $$(id -u):$$(id -g) $(KIND_KUBECONFIG)
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/configure-kind.sh

kind-load: images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save localhost/unf-controller:dev | sudo podman load
	podman save localhost/unf-agent:dev | sudo podman load
	podman save $(TEST_TOOLS_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev localhost/unf-controller:dev
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev localhost/unf-agent:dev
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(TEST_TOOLS_IMAGE)

kind-upgrade-load: upgrade-baseline-images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save $(UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE) | sudo podman load
	podman save $(UNF_UPGRADE_BASELINE_AGENT_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE)
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(UNF_UPGRADE_BASELINE_AGENT_IMAGE)

kind-skipped-upgrade-load: skipped-upgrade-baseline-images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save $(UNF_SKIPPED_UPGRADE_BASELINE_CONTROLLER_IMAGE) | sudo podman load
	podman save $(UNF_SKIPPED_UPGRADE_BASELINE_AGENT_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(UNF_SKIPPED_UPGRADE_BASELINE_CONTROLLER_IMAGE)
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(UNF_SKIPPED_UPGRADE_BASELINE_AGENT_IMAGE)

kind-incompatible-version-load: incompatible-version-images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save $(UNF_INCOMPATIBLE_CONTROLLER_IMAGE) | sudo podman load
	podman save $(UNF_INCOMPATIBLE_AGENT_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(UNF_INCOMPATIBLE_CONTROLLER_IMAGE)
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(UNF_INCOMPATIBLE_AGENT_IMAGE)

kind-clean-rebuild-load: clean-rebuild-version-images
	ln -sf $$(command -v podman) .tools/bin/docker
	podman save $(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE) | sudo podman load
	podman save $(UNF_CLEAN_REBUILD_AGENT_IMAGE) | sudo podman load
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE)
	sudo env PATH=$(CURDIR)/.tools/bin:$$PATH KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) load docker-image --name unf-dev $(UNF_CLEAN_REBUILD_AGENT_IMAGE)

kind-deploy: kind-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/configure-internal-tls.sh
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev apply -k deploy
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev rollout restart deployment/unf-controller -n unf-system
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev rollout restart daemonset/unf-agent -n unf-system
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev rollout status deployment/unf-controller -n unf-system --timeout=120s
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev rollout status daemonset/unf-agent -n unf-system --timeout=120s

kind-demo:
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev apply -f deploy/examples/demo.yaml
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev wait --for=condition=Ready pod/client -n frontend --timeout=120s
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev wait --for=condition=Ready pod/server -n backend --timeout=120s
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev wait --for=condition=Ready pod/np-server -n backend --timeout=120s
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl --context kind-unf-dev exec -n frontend client -- wget -qO- http://server.backend.svc.cluster.local:8080

kind-flow-history-retention-test: cli
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-flow-history-retention.sh

kind-topology-history-test: cli
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-topology-history.sh

kind-external-flow-export-test:
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-external-flow-export.sh

kind-upgrade-test: kind-deploy kind-demo kind-upgrade-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE=$(UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE) UNF_UPGRADE_BASELINE_AGENT_IMAGE=$(UNF_UPGRADE_BASELINE_AGENT_IMAGE) UNF_UPGRADE_CURRENT_REVISION=$(UNF_BUILD_REVISION) hack/verify-kind-upgrade.sh

kind-skipped-upgrade-test: kind-deploy kind-demo kind-skipped-upgrade-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev UNF_UPGRADE_BASELINE_CONTROLLER_IMAGE=$(UNF_SKIPPED_UPGRADE_BASELINE_CONTROLLER_IMAGE) UNF_UPGRADE_BASELINE_AGENT_IMAGE=$(UNF_SKIPPED_UPGRADE_BASELINE_AGENT_IMAGE) UNF_UPGRADE_CURRENT_REVISION=$(UNF_BUILD_REVISION) UNF_UPGRADE_CURRENT_GENERATION=N+2 UNF_UPGRADE_REQUIRE_BASELINE_TUPLE=true hack/verify-kind-upgrade.sh

kind-incompatible-version-test: kind-deploy kind-demo kind-incompatible-version-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev UNF_INCOMPATIBLE_CONTROLLER_IMAGE=$(UNF_INCOMPATIBLE_CONTROLLER_IMAGE) UNF_INCOMPATIBLE_AGENT_IMAGE=$(UNF_INCOMPATIBLE_AGENT_IMAGE) UNF_CURRENT_REVISION=$(UNF_BUILD_REVISION) hack/verify-kind-incompatible-version.sh

kind-clean-rebuild-test: kind-deploy kind-demo kind-clean-rebuild-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev UNF_CLEAN_REBUILD_CONTROLLER_IMAGE=$(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE) UNF_CLEAN_REBUILD_AGENT_IMAGE=$(UNF_CLEAN_REBUILD_AGENT_IMAGE) UNF_CURRENT_REVISION=$(UNF_BUILD_REVISION) hack/verify-kind-clean-rebuild.sh

kind-unsupported-downgrade-test: kind-deploy kind-demo kind-clean-rebuild-load
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev UNF_CLEAN_REBUILD_CONTROLLER_IMAGE=$(UNF_CLEAN_REBUILD_CONTROLLER_IMAGE) UNF_CLEAN_REBUILD_AGENT_IMAGE=$(UNF_CLEAN_REBUILD_AGENT_IMAGE) UNF_CURRENT_REVISION=$(UNF_BUILD_REVISION) UNF_REQUIRE_UNSUPPORTED_DOWNGRADE=true hack/verify-kind-clean-rebuild.sh

kind-scale-failure-test: kind-deploy kind-demo
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-kind-scale-failure.sh

kind-test: cli kind-demo
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-kind.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-topology-history.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-flow-history-retention.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-external-flow-export.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-kind-legacy-netlink.sh

kind-down:
	sudo env KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) delete cluster --name unf-dev
