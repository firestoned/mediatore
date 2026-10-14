# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# All CI logic lives here (rules/github-workflows.md): workflows install tools
# and call these targets, and every target runs identically locally.

.PHONY: all help fmt fmt-check lint test deny audit check sbom guest dist image crds e2e live-admission-test \
        kind-install kind-create kind-delete kind-down kind-spire kind-deploy kind-up \
        kind-images kind-broker kind-banlieue-crds kind-e2e-entries kind-e2e-mtls kind-e2e-watcher kind-e2e-sandbox \
        kind-e2e kind-e2e-ci kind-e2e-logs \
        calm-validate calm-diagrams docs docs-serve docs-clean clean

# kind: a throwaway cluster with SPIRE for the live tests (docs/guides/testing.md).
KIND_VERSION       ?= 0.33.0
# Same Kubernetes minor as the measured homelab cluster (ADR-0005 appendix); digest-pinned.
KIND_NODE_IMAGE    ?= kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
KIND_CLUSTER_NAME  ?= mediatore
KIND_BIN_DIR       ?= /usr/local/bin
KIND_DIR           := .kind
KIND_KUBECONFIG    := $(KIND_DIR)/kubeconfig
KIND_SA_KUBECONFIG := $(KIND_DIR)/mediatore-sa.yaml
KIND_KUBECTL       := kubectl --kubeconfig $(KIND_KUBECONFIG)
KIND_HELM          := helm --kubeconfig $(KIND_KUBECONFIG)
# The same hardened charts and versions as the homelab; release `spire` in namespace
# `spire-server` gives the controller manager the className `spire-server-spire`.
SPIRE_CHART_REPO    ?= https://spiffe.github.io/helm-charts-hardened/
SPIRE_CHART_VERSION ?= 0.30.2
SPIRE_CRDS_VERSION  ?= 0.6.1
SPIRE_TRUST_DOMAIN  ?= sandbox.test
SPIRE_NAMESPACE     := spire-server
SPIRE_CLASS_NAME    := spire-server-spire
# Images: `docker` or `podman` (kind follows KIND_EXPERIMENTAL_PROVIDER). The kind tags
# are loaded into the cluster with `kind load`, never pulled, never pushed.
CONTAINER_CLI      ?= docker
MUSL_TARGET        := x86_64-unknown-linux-musl
KIND_IMAGE         := ghcr.io/firestoned/mediatore:kind
KIND_GUEST_IMAGE   := localhost/mediatore-guest:kind

# CALM (FINOS Common Architecture Language Model) configuration
CALM_CLI_VERSION  ?= 1.37.0
CALM_ARCH          := docs/architecture/calm/architecture.json
CALM_TEMPLATES     := docs/architecture/calm/templates/mermaid
CALM_DIAGRAMS_OUT  := docs/architecture/diagrams

all: check

help: ## Show this help
	@echo 'Usage: make [target] [VAR=value ...]'
	@echo ''
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ----- Quality gate ----------------------------------------------------------

fmt: ## Format the workspace
	cargo fmt --all

fmt-check: ## Check formatting without writing
	cargo fmt --all -- --check

lint: ## Clippy, warnings are errors (pedantic is on via workspace lints)
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test: ## Run the whole test suite (unit + dev-mode e2e)
	cargo test --workspace --all-features

deny: ## License / advisory / source checks
	cargo deny check

audit: ## cargo-audit advisory scan (CI uses the security-scan composite action)
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit --locked
	cargo audit

check: fmt lint test deny ## The pre-commit gate: fmt + clippy + test + deny

# ----- Supply chain ----------------------------------------------------------

sbom: ## Generate CycloneDX SBOM(s) for the workspace (*.cdx.json per crate)
	@command -v cargo-cyclonedx >/dev/null 2>&1 || cargo install cargo-cyclonedx --locked
	cargo cyclonedx --format json
	@echo "✓ CycloneDX SBOM(s) generated"

# ----- Artifacts ---------------------------------------------------------------

guest: ## Static musl builds of the two guest binaries
	cargo build --release --target x86_64-unknown-linux-musl -p mediatore-guest -p sandbox-token

dist: ## Host-built musl binaries into dist/ (what the images copy with BINARY_FROM=host)
	cargo build --release --target $(MUSL_TARGET) -p mediatore -p mediatore-guest -p sandbox-token
	@mkdir -p dist
	cp target/$(MUSL_TARGET)/release/mediatore target/$(MUSL_TARGET)/release/mediatore-guest target/$(MUSL_TARGET)/release/sandbox-token dist/

image: ## Build the server container image locally (the binary is compiled inside the image)
	$(CONTAINER_CLI) build -t ghcr.io/firestoned/mediatore:dev .

crds: ## Render mediatore's CRDs from their Rust types into deploy/base/crds/ (ADR-0008; never hand-edited, a unit test fails on a stale file)
	cargo run -q -p mediatore-claims --bin crdgen -- --out-dir deploy/base/crds

# ----- End to end --------------------------------------------------------------

e2e: ## Front-to-back dev-mode loop with real binaries (fake IdP, server, guest, sandbox-token)
	./dev/demo.sh

live-admission-test: ## ClusterStaticEntry round trip as the mediatore ServiceAccount against a real cluster (MEDIATORE_LIVE_KUBECONFIG, MEDIATORE_LIVE_TRUST_DOMAIN, MEDIATORE_LIVE_CLASS_NAME; MEDIATORE_LIVE_IDENTITY=impersonate|self)
	cargo test -p mediatore-spire --test live_kube -- --ignored

# ----- kind: SPIRE in a throwaway cluster, the live tests against it -----------

kind-install: ## Install the pinned kind CLI into $(KIND_BIN_DIR) if missing or another version
	@if command -v kind >/dev/null 2>&1 && kind version | grep -q "v$(KIND_VERSION) "; then \
		echo "✓ kind v$(KIND_VERSION) present"; \
	else \
		echo "Installing kind v$(KIND_VERSION) into $(KIND_BIN_DIR)..."; \
		OS=$$(uname -s | tr '[:upper:]' '[:lower:]'); ARCH=$$(uname -m); \
		case "$$ARCH" in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; esac; \
		BIN="kind-$${OS}-$${ARCH}"; URL="https://github.com/kubernetes-sigs/kind/releases/download/v$(KIND_VERSION)"; \
		TMP=$$(mktemp -d); cd $$TMP && \
		curl -sSLf -o $$BIN "$$URL/$$BIN" && curl -sSLf -o $$BIN.sha256sum "$$URL/$$BIN.sha256sum" && \
		EXPECTED=$$(awk '{print $$1}' $$BIN.sha256sum) && \
		if command -v sha256sum >/dev/null 2>&1; then ACTUAL=$$(sha256sum $$BIN | awk '{print $$1}'); else ACTUAL=$$(shasum -a 256 $$BIN | awk '{print $$1}'); fi && \
		[ "$$EXPECTED" = "$$ACTUAL" ] || { echo "ERROR: kind checksum mismatch"; exit 1; }; \
		chmod +x $$BIN; \
		if [ -w "$(KIND_BIN_DIR)" ]; then mv $$BIN $(KIND_BIN_DIR)/kind; else sudo mv $$BIN $(KIND_BIN_DIR)/kind; fi; \
		rm -rf $$TMP; echo "✓ kind v$(KIND_VERSION) installed"; \
	fi
	@command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl not found on PATH"; exit 1; }
	@command -v helm >/dev/null 2>&1 || { echo "ERROR: helm not found on PATH"; exit 1; }

kind-create: kind-install ## Create the kind cluster (no-op if it exists) and write $(KIND_KUBECONFIG)
	@mkdir -p $(KIND_DIR)
	@if kind get clusters 2>/dev/null | grep -qx $(KIND_CLUSTER_NAME); then \
		echo "✓ kind cluster '$(KIND_CLUSTER_NAME)' already exists"; \
	else \
		kind create cluster --name $(KIND_CLUSTER_NAME) --image $(KIND_NODE_IMAGE) --config dev/kind/cluster.yaml --wait 120s --kubeconfig $(KIND_KUBECONFIG); \
	fi
	@kind get kubeconfig --name $(KIND_CLUSTER_NAME) > $(KIND_KUBECONFIG)
	@$(KIND_KUBECTL) cluster-info

kind-delete: ## Delete the kind cluster and its kubeconfigs
	@if kind get clusters 2>/dev/null | grep -qx $(KIND_CLUSTER_NAME); then \
		kind delete cluster --name $(KIND_CLUSTER_NAME); \
	else \
		echo "✓ no kind cluster named '$(KIND_CLUSTER_NAME)'"; \
	fi
	@rm -rf $(KIND_DIR)

kind-down: kind-delete ## Alias for kind-delete

kind-spire: kind-create ## Install SPIRE (server, controller manager, agent, CSI driver) from the hardened charts
	@$(KIND_KUBECTL) get ns $(SPIRE_NAMESPACE) >/dev/null 2>&1 || $(KIND_KUBECTL) create ns $(SPIRE_NAMESPACE)
	@$(KIND_KUBECTL) get ns spire-system >/dev/null 2>&1 || $(KIND_KUBECTL) create ns spire-system
	$(KIND_HELM) upgrade --install spire-crds spire-crds --repo $(SPIRE_CHART_REPO) --version $(SPIRE_CRDS_VERSION) -n $(SPIRE_NAMESPACE)
	$(KIND_HELM) upgrade --install spire spire --repo $(SPIRE_CHART_REPO) --version $(SPIRE_CHART_VERSION) -n $(SPIRE_NAMESPACE) \
	  -f dev/kind/spire-values.yaml --set global.spire.trustDomain=$(SPIRE_TRUST_DOMAIN) --wait --timeout 10m
	@$(KIND_KUBECTL) -n $(SPIRE_NAMESPACE) rollout status statefulset/spire-server --timeout=300s
	@$(KIND_KUBECTL) -n spire-system rollout status daemonset/spire-agent --timeout=300s
	@echo "✓ SPIRE $(SPIRE_CHART_VERSION) up; controller manager className $(SPIRE_CLASS_NAME)"

kind-deploy: kind-create ## Apply the broker's CRD, ServiceAccount, RBAC and admission policies; mint its kubeconfig
	@$(KIND_KUBECTL) get ns banlieue-system >/dev/null 2>&1 || $(KIND_KUBECTL) create ns banlieue-system
	$(KIND_KUBECTL) apply -n banlieue-system -f deploy/base/crds -f deploy/base/serviceaccount.yaml -f deploy/base/rbac.yaml -f deploy/base/admission/clusterstaticentry-mediatore.yaml -f deploy/base/admission/agentsandbox-subject.yaml
	@./dev/kind/sa-kubeconfig.sh $(KIND_KUBECONFIG) $(KIND_SA_KUBECONFIG)

kind-up: kind-create kind-spire kind-deploy ## Cluster + SPIRE + the broker's identity, ready for the live tests

kind-images: kind-create dist ## Server image (the shipped Dockerfile's runtime stage) and the test-only guest image, loaded into the cluster
	$(CONTAINER_CLI) build --build-arg BINARY_FROM=host -t $(KIND_IMAGE) .
	$(CONTAINER_CLI) build -f dev/kind/Dockerfile.guest -t $(KIND_GUEST_IMAGE) .
	@# One image per call: under the podman provider a multi-image load ends up with one manifest.
	kind load docker-image --name $(KIND_CLUSTER_NAME) $(KIND_IMAGE)
	kind load docker-image --name $(KIND_CLUSTER_NAME) $(KIND_GUEST_IMAGE)

kind-broker: kind-up kind-images ## deploy/base in kind on the CSI driver's socket (dev/kind/broker overlay), rolled out
	$(KIND_KUBECTL) apply -k dev/kind/broker
	@# Same tag, new image: a restart is what makes the loaded image the running one.
	$(KIND_KUBECTL) -n banlieue-system rollout restart deploy/mediatore
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore --timeout=300s

kind-e2e-entries: kind-up ## Live entries round trip (ADR-0006) as the broker ServiceAccount against SPIRE in kind
	MEDIATORE_LIVE_KUBECONFIG=$(CURDIR)/$(KIND_SA_KUBECONFIG) MEDIATORE_LIVE_IDENTITY=self \
	MEDIATORE_LIVE_TRUST_DOMAIN=$(SPIRE_TRUST_DOMAIN) MEDIATORE_LIVE_CLASS_NAME=$(SPIRE_CLASS_NAME) \
	$(MAKE) live-admission-test

kind-e2e-mtls: kind-broker ## ADR-0007 live: broker SVID over the CSI driver, agent-issued client SVIDs over SPIFFE mTLS, the refusals
	./dev/kind/mtls-e2e.sh $(KIND_KUBECONFIG) $(SPIRE_TRUST_DOMAIN)

kind-banlieue-crds: kind-create ## banlieue's VirtualMachine and VirtualMachineClaim CRDs, rendered from the pinned banlieue-api, applied
	cargo run -q -p mediatore-testkit --bin banlieue-crds > $(KIND_DIR)/banlieue-crds.json
	@# A nullable enum carries `null`, which kubectl's client-side check refuses and the API server's structural validation accepts (banlieue applies the same file).
	$(KIND_KUBECTL) apply --validate=false -f $(KIND_DIR)/banlieue-crds.json
	cargo run -q -p mediatore-testkit --bin ek-fixture > $(KIND_DIR)/ek.pem
	cargo run -q -p mediatore-testkit --bin ek-fixture -- --hash > $(KIND_DIR)/ek.hash

kind-e2e-watcher: kind-banlieue-crds kind-broker ## ADR-0011 live: the Lease, a member's certificate becoming a node entry, a claim without a record binding nothing
	@# The controllers must start against existing CRDs: a broker that came up before them backs off for minutes.
	$(KIND_KUBECTL) -n banlieue-system rollout restart deploy/mediatore
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore --timeout=300s
	./dev/kind/watcher-e2e.sh $(KIND_KUBECONFIG) $(SPIRE_TRUST_DOMAIN) $(KIND_DIR)/ek.pem $(KIND_DIR)/ek.hash

kind-e2e-sandbox: kind-banlieue-crds kind-broker ## ADR-0008 live: the subject policy, an AgentSandbox becoming an owned claim and a record, bound to a claim entry, deleted through the finalizer
	$(KIND_KUBECTL) -n banlieue-system rollout restart deploy/mediatore
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore --timeout=300s
	./dev/kind/sandbox-e2e.sh $(KIND_KUBECONFIG) $(KIND_SA_KUBECONFIG) $(SPIRE_TRUST_DOMAIN) $(KIND_DIR)/ek.pem $(KIND_DIR)/ek.hash

kind-e2e: kind-e2e-entries kind-e2e-mtls kind-e2e-watcher kind-e2e-sandbox ## Every live suite against kind (grows with the roadmap)

kind-e2e-ci: ## CI shape: the suites, cluster state on failure, cluster deleted after
	@$(MAKE) kind-e2e || { $(MAKE) kind-e2e-logs; $(MAKE) kind-delete; exit 1; }
	@$(MAKE) kind-delete

kind-e2e-logs: ## What a failing live suite needs: entries, policy, broker and client pods, controller-manager and server logs
	-$(KIND_KUBECTL) get clusterstaticentries -o yaml
	-$(KIND_KUBECTL) get clusterspiffeids -o yaml
	-$(KIND_KUBECTL) -n banlieue-system get pods -o wide
	-$(KIND_KUBECTL) -n banlieue-system logs deploy/mediatore --tail=200
	-$(KIND_KUBECTL) -n mediatore-e2e get pods -o wide
	-$(KIND_KUBECTL) -n banlieue-system get lease mediatore-watcher -o yaml
	-$(KIND_KUBECTL) -n mediatore-e2e-watcher get virtualmachines,virtualmachineclaims -o yaml
	-$(KIND_KUBECTL) -n mediatore-e2e-sandbox get agentsandboxes,virtualmachineclaims,pods -o yaml
	-$(KIND_KUBECTL) -n mediatore-e2e-sandbox logs pod/node --tail=50
	-$(KIND_KUBECTL) get validatingadmissionpolicy mediatore-clusterstaticentry mediatore-agentsandbox-subject -o yaml
	-$(KIND_KUBECTL) -n $(SPIRE_NAMESPACE) logs statefulset/spire-server -c spire-controller-manager --tail=200
	-$(KIND_KUBECTL) -n $(SPIRE_NAMESPACE) logs statefulset/spire-server -c spire-server --tail=100
	-$(KIND_KUBECTL) get pods -A

# ----- CALM (architecture-as-code, FINOS) --------------------------------------

calm-validate: ## Validate the CALM architecture against the meta-schema
	@command -v npx >/dev/null 2>&1 || { echo "Error: npx not found. Install Node.js"; exit 1; }
	npx --yes @finos/calm-cli@$(CALM_CLI_VERSION) validate \
	  -a $(CALM_ARCH) \
	  -f pretty

calm-diagrams: ## Render CALM Mermaid diagrams into $(CALM_DIAGRAMS_OUT)
	@command -v npx >/dev/null 2>&1 || { echo "Error: npx not found. Install Node.js"; exit 1; }
	@mkdir -p $(CALM_DIAGRAMS_OUT)
	@# Remove only the files the CLI is about to (re)produce, never the whole dir.
	@rm -f $(CALM_DIAGRAMS_OUT)/system.md $(CALM_DIAGRAMS_OUT)/flows.md $(CALM_DIAGRAMS_OUT)/*.hbs
	npx --yes @finos/calm-cli@$(CALM_CLI_VERSION) template \
	  -a $(CALM_ARCH) \
	  -d $(CALM_TEMPLATES) \
	  -o $(CALM_DIAGRAMS_OUT)
	@for f in $(CALM_DIAGRAMS_OUT)/*.hbs; do \
	  [ -e "$$f" ] || continue; \
	  mv "$$f" "$${f%.hbs}"; \
	done
	@echo "✓ CALM diagrams written to $(CALM_DIAGRAMS_OUT)/"

# ----- Documentation (MkDocs Material) -----------------------------------------

docs: ## Build the MkDocs site into site/ (CALM diagrams are committed; see calm-diagrams)
	@command -v poetry >/dev/null 2>&1 || { echo "Error: Poetry not found. Install: curl -sSL https://install.python-poetry.org | python3 -"; exit 1; }
	@echo "Ensuring documentation dependencies are installed..."
	@poetry install --no-interaction --quiet
	@echo "Building MkDocs site..."
	@poetry run mkdocs build --strict
	@echo "✓ Documentation built at site/index.html"

docs-serve: ## Serve docs locally with live reload at http://127.0.0.1:8000
	@command -v poetry >/dev/null 2>&1 || { echo "Error: Poetry not found. Install: curl -sSL https://install.python-poetry.org | python3 -"; exit 1; }
	@poetry install --no-interaction --quiet
	@echo "Starting MkDocs server at http://127.0.0.1:8000 (live reload)..."
	@poetry run mkdocs serve --livereload

docs-clean: ## Remove docs build artefacts and venv
	@rm -rf site/ .venv/
	@echo "✓ Documentation artefacts cleaned"

clean: ## Remove build artifacts
	cargo clean
	rm -rf dist
