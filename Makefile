.PHONY: build test lint fmt fmt-check ebpf generate-crds controller agent cli artifacts images kind-tool kind-up kind-load kind-deploy kind-demo kind-test kind-down

KIND := .tools/bin/kind
KIND_PROVIDER ?= podman
KIND_KUBECONFIG := $(CURDIR)/.tools/kind-unf-dev.kubeconfig
TEST_TOOLS_IMAGE := localhost/unf-test-tools:ipv6-ext-v1

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
	podman build --build-arg UNF_PACKAGE=unf-controller --tag localhost/unf-controller:dev --file images/Containerfile .
	podman build --build-arg UNF_PACKAGE=unf-agent --tag localhost/unf-agent:dev --file images/Containerfile .
	podman build --tag $(TEST_TOOLS_IMAGE) --file images/SctpTestContainerfile .

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

kind-deploy: kind-load
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

kind-test: cli kind-demo
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-kind.sh
	KUBECONFIG=$(KIND_KUBECONFIG) KUBE_CONTEXT=kind-unf-dev hack/verify-kind-legacy-netlink.sh

kind-down:
	sudo env KUBECONFIG=$(KIND_KUBECONFIG) KIND_EXPERIMENTAL_PROVIDER=$(KIND_PROVIDER) $(CURDIR)/$(KIND) delete cluster --name unf-dev
