# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# All CI logic lives here (rules/github-workflows.md): workflows install tools
# and call these targets, and every target runs identically locally.

.PHONY: all help fmt fmt-check lint test deny audit check sbom dist dist-e2e image guest-image guest-image-check crds e2e live-admission-test \
        kind-install kind-create kind-delete kind-down kind-spire kind-deploy kind-up \
        kind-images kind-postgres kind-dex kind-openbao kind-broker kind-banlieue-crds kind-e2e-entries kind-e2e-mtls kind-e2e-watcher kind-e2e-sandbox \
        kind-e2e-store kind-e2e-dex kind-e2e kind-e2e-ci kind-e2e-logs \
        kind-spire-render kind-vtpm kind-e2e-tpm calm-validate calm-diagrams docs docs-serve docs-clean clean manifests dist-tpm-plugin

# kind: a throwaway cluster with SPIRE for the live tests (docs/guides/testing.md).
KIND_VERSION       ?= 0.33.0
# Same Kubernetes minor as the measured homelab cluster (ADR-0005 appendix); digest-pinned.
KIND_NODE_IMAGE    ?= kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
# The node image's Kubernetes version, what `kind-spire-render` tells the chart engine.
KIND_K8S_VERSION   ?= 1.36.4
KIND_CLUSTER_NAME  ?= mediatore
KIND_BIN_DIR       ?= /usr/local/bin
KIND_DIR           := .kind
KIND_KUBECONFIG    := $(KIND_DIR)/kubeconfig
KIND_SA_KUBECONFIG := $(KIND_DIR)/mediatore-sa.yaml
# The vTPM behind the node (make kind-vtpm): swtpm's state, device path and EK material.
KIND_VTPM_DIR      := $(KIND_DIR)/vtpm
# What kind-e2e-ci runs; the TPM tier is run by hand where the host has the vtpm proxy module.
KIND_E2E_SUITES    ?= kind-e2e
KIND_KUBECTL       := kubectl --kubeconfig $(KIND_KUBECONFIG)
# SPIRE in kind comes from manifests rendered once (`make kind-spire-render`, the only
# target that runs helm) from the same distribution and versions as the homelab, into
# dev/kind/spire, applied with kustomize together with the TPM attestor component
# (ADR-0018). Release name `spire` in namespace `spire-server` gives the controller
# manager the className `spire-server-spire`. Bump a version here, re-render, read the
# diff. SPIRE_TRUST_DOMAIN must agree with dev/kind/spire/values.yaml.
SPIRE_CHART_REPO    ?= https://spiffe.github.io/helm-charts-hardened/
SPIRE_CHART_VERSION ?= 0.30.2
SPIRE_CRDS_VERSION  ?= 0.6.1
SPIRE_KUSTOMIZATION := dev/kind/spire
SPIRE_TRUST_DOMAIN  ?= sandbox.test
SPIRE_NAMESPACE     := spire-server
SPIRE_CLASS_NAME    := spire-server-spire
# Images: `docker` or `podman` (kind follows KIND_EXPERIMENTAL_PROVIDER). The kind tags
# are loaded into the cluster with `kind load`, never pulled, never pushed.
CONTAINER_CLI      ?= docker
MUSL_TARGET        := x86_64-unknown-linux-musl
KIND_IMAGE         := ghcr.io/firestoned/mediatore:kind
# Test-only: the binary plus the testkit's dex-driver, for the Dex tier's user-side pod.
KIND_E2E_IMAGE     := localhost/mediatore-e2e:kind

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

dist: ## The one static musl binary into dist/ (ADR-0014): what the server image copies with BINARY_FROM=host and what the VM image bakes in
	cargo build --release --target $(MUSL_TARGET) -p mediatore
	@mkdir -p dist
	cp target/$(MUSL_TARGET)/release/mediatore dist/

dist-e2e: ## The testkit's dex-driver (musl) into dist/, for the test-only e2e image
	cargo build --release --target $(MUSL_TARGET) -p mediatore-testkit --bin dex-driver
	@mkdir -p dist
	cp target/$(MUSL_TARGET)/release/dex-driver dist/

image: ## Build the server container image locally (the binary is compiled inside the image)
	$(CONTAINER_CLI) build -t ghcr.io/firestoned/mediatore:dev .

# The sandbox VM image (ADR-0023): a Kairos derivative with the guest software in the
# immutable rootfs. The base, the SPIRE agent and the plugin are pinned by digest in
# image/Dockerfile; BINARY_FROM=host reuses dist/mediatore (make dist) as the kind tier does.
GUEST_IMAGE ?= ghcr.io/firestoned/mediatore-guest:dev
BINARY_FROM ?= container
guest-image: ## Build the sandbox VM image, a Kairos derivative (ADR-0023); BINARY_FROM=host copies dist/mediatore
	$(CONTAINER_CLI) build -f image/Dockerfile --build-arg BINARY_FROM=$(BINARY_FROM) -t $(GUEST_IMAGE) .

guest-image-check: ## Check the built VM image carries what ADR-0023 says, and no listener
	CONTAINER_CLI=$(CONTAINER_CLI) ./image/check.sh $(GUEST_IMAGE)

crds: ## Render mediatore's CRDs from their Rust types into deploy/base/crds/ (ADR-0008; never hand-edited, a unit test fails on a stale file)
	cargo run -q -p mediatore-claims --bin crdgen -- --out-dir deploy/base/crds

# ----- End to end --------------------------------------------------------------

e2e: ## Front-to-back dev-mode loop with the real binary (fake IdP; mediatore serve, guest and token as separate processes)
	./dev/demo.sh

# The TPM attestor plugin (ADR-0018): the release deploy/spire-tpm runs on the server and
# the VM image runs on the agent, pinned by image digest and by the checksum of the static
# binary inside. deploy/spire-tpm and image/spire/agent.conf carry the same checksums.
TPM_PLUGIN_VERSION     := v1.11.3
TPM_PLUGIN_SERVER_IMG  := ghcr.io/spiffe/spire-tpm-plugin-tpm-attestor-server:$(TPM_PLUGIN_VERSION)@sha256:2fec80b2db3171af5bb54312c4ad75187e430b635df6adc7ea4116a863ce0084
TPM_PLUGIN_AGENT_IMG   := ghcr.io/spiffe/spire-tpm-plugin-tpm-attestor-agent:$(TPM_PLUGIN_VERSION)@sha256:4dba6dc77fcec06b66962b632b6453636d49d51a38946efb0bc6fed29e4b75b1
TPM_PLUGIN_SERVER_SHA  := 5f32c3e8cc6c81fa1060a9155eea0a455935d199278406384567ffa125127d83
TPM_PLUGIN_AGENT_SHA   := ffb7e266c7a10a7b1bdb349409d6c2ded8090715770287813055431cb692575c

dist-tpm-plugin: ## Extract the pinned tpm attestor binaries (server and agent) from their images into dist/ and verify their checksums (ADR-0018)
	@mkdir -p dist
	@for pair in server:$(TPM_PLUGIN_SERVER_IMG):$(TPM_PLUGIN_SERVER_SHA) agent:$(TPM_PLUGIN_AGENT_IMG):$(TPM_PLUGIN_AGENT_SHA); do \
	  role=$${pair%%:*}; rest=$${pair#*:}; img=$${rest%:*}; sha=$${rest##*:}; bin=tpm_attestor_$$role; \
	  $(CONTAINER_CLI) pull -q "$$img" >/dev/null; id=$$($(CONTAINER_CLI) create "$$img"); \
	  $(CONTAINER_CLI) cp "$$id:/app/$$bin" dist/$$bin; $(CONTAINER_CLI) rm "$$id" >/dev/null; \
	  echo "$$sha  dist/$$bin" | sha256sum -c - >/dev/null || { echo "dist/$$bin: checksum mismatch"; exit 1; }; \
	  echo "✓ dist/$$bin ($$sha)"; \
	done

manifests: ## Render deploy/base and the example overlay with kustomize, as a check that both still build
	@command -v kubectl >/dev/null 2>&1 || { echo "Error: kubectl not found"; exit 1; }
	kubectl kustomize deploy/base > /dev/null
	kubectl kustomize deploy/overlays/homelab-example > /dev/null
	@echo "✓ deploy/base and deploy/overlays/homelab-example render"

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

kind-create: kind-install ## Create the kind cluster (no-op if it exists) and write $(KIND_KUBECONFIG)
	@mkdir -p $(KIND_DIR)
	@cp dev/kind/cluster.yaml $(KIND_DIR)/cluster.yaml
	@# With a vTPM up (make kind-vtpm), its device goes into the node as /dev/tpmrm0.
	@if [ -r $(KIND_VTPM_DIR)/device ]; then \
		printf '    extraMounts:\n      - hostPath: %s\n        containerPath: /dev/tpmrm0\n' "$$(cat $(KIND_VTPM_DIR)/device)" >> $(KIND_DIR)/cluster.yaml; \
	fi
	@if kind get clusters 2>/dev/null | grep -qx $(KIND_CLUSTER_NAME); then \
		echo "✓ kind cluster '$(KIND_CLUSTER_NAME)' already exists"; \
	else \
		kind create cluster --name $(KIND_CLUSTER_NAME) --image $(KIND_NODE_IMAGE) --config $(KIND_DIR)/cluster.yaml --wait 120s --kubeconfig $(KIND_KUBECONFIG); \
	fi
	@kind get kubeconfig --name $(KIND_CLUSTER_NAME) > $(KIND_KUBECONFIG)
	@$(KIND_KUBECTL) cluster-info

kind-delete: ## Delete the kind cluster, the vTPM behind it if any, and its kubeconfigs
	@if kind get clusters 2>/dev/null | grep -qx $(KIND_CLUSTER_NAME); then \
		kind delete cluster --name $(KIND_CLUSTER_NAME); \
	else \
		echo "✓ no kind cluster named '$(KIND_CLUSTER_NAME)'"; \
	fi
	@./dev/kind/vtpm.sh down $(KIND_VTPM_DIR)
	@rm -rf $(KIND_DIR)

kind-vtpm: ## A swtpm behind the kernel's vtpm proxy as a device for the kind node (sudo, swtpm, swtpm_setup); before the cluster exists
	@./dev/kind/vtpm.sh up $(KIND_VTPM_DIR)
	@# The device goes in at creation: a node without it is recreated, not patched.
	@if kind get clusters 2>/dev/null | grep -qx $(KIND_CLUSTER_NAME); then \
		$(CONTAINER_CLI) exec $(KIND_CLUSTER_NAME)-control-plane test -c /dev/tpmrm0 2>/dev/null \
		  || { echo "ERROR: kind cluster '$(KIND_CLUSTER_NAME)' has no /dev/tpmrm0; run make kind-delete first"; exit 1; }; \
	fi

kind-down: kind-delete ## Alias for kind-delete

kind-spire-render: ## Render SPIRE's distribution (hardened charts, pinned versions) into $(SPIRE_KUSTOMIZATION); needs helm and jq; after a version bump, read the diff
	@command -v helm >/dev/null 2>&1 || { echo "ERROR: helm not found on PATH"; exit 1; }
	@command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found on PATH"; exit 1; }
	helm template spire-crds spire-crds --repo $(SPIRE_CHART_REPO) --version $(SPIRE_CRDS_VERSION) \
	  -n $(SPIRE_NAMESPACE) --kube-version $(KIND_K8S_VERSION) > $(SPIRE_KUSTOMIZATION)/crds.yaml
	helm template spire spire --repo $(SPIRE_CHART_REPO) --version $(SPIRE_CHART_VERSION) \
	  -n $(SPIRE_NAMESPACE) --kube-version $(KIND_K8S_VERSION) --no-hooks --skip-tests \
	  -f $(SPIRE_KUSTOMIZATION)/values.yaml > $(SPIRE_KUSTOMIZATION)/spire.yaml
	./$(SPIRE_KUSTOMIZATION)/render-server-conf-patch.sh $(SPIRE_KUSTOMIZATION)/spire.yaml deploy/spire-tpm/server.conf.fragment.hcl \
	  > $(SPIRE_KUSTOMIZATION)/server-conf-patch.yaml
	@kubectl kustomize $(SPIRE_KUSTOMIZATION) >/dev/null
	@echo "✓ rendered spire-crds $(SPIRE_CRDS_VERSION) and spire $(SPIRE_CHART_VERSION) into $(SPIRE_KUSTOMIZATION)"

kind-spire: kind-create ## Apply SPIRE (server, controller manager, agent, CSI driver) and the TPM attestor component from the rendered manifests
	@$(KIND_KUBECTL) get ns $(SPIRE_NAMESPACE) >/dev/null 2>&1 || $(KIND_KUBECTL) create ns $(SPIRE_NAMESPACE)
	@$(KIND_KUBECTL) get ns spire-system >/dev/null 2>&1 || $(KIND_KUBECTL) create ns spire-system
	$(KIND_KUBECTL) apply -f $(SPIRE_KUSTOMIZATION)/crds.yaml
	@$(KIND_KUBECTL) wait --for=condition=established --timeout=60s -f $(SPIRE_KUSTOMIZATION)/crds.yaml >/dev/null
	$(KIND_KUBECTL) apply -k $(SPIRE_KUSTOMIZATION)
	@$(KIND_KUBECTL) -n $(SPIRE_NAMESPACE) rollout status statefulset/spire-server --timeout=600s
	@$(KIND_KUBECTL) -n spire-system rollout status daemonset/spire-agent --timeout=300s
	@# What the chart's post-install hook did: the webhook is applied lenient so the chart's own
	@# ClusterSPIFFEIDs go in before the controller manager answers, then fails closed.
	@$(KIND_KUBECTL) patch validatingwebhookconfiguration $(SPIRE_CLASS_NAME)-controller-manager-webhook --type=strategic \
	  -p '{"webhooks":[{"name":"vclusterfederatedtrustdomain.kb.io","failurePolicy":"Fail"},{"name":"vclusterspiffeid.kb.io","failurePolicy":"Fail"}]}' >/dev/null
	@$(KIND_KUBECTL) -n $(SPIRE_NAMESPACE) logs statefulset/spire-server -c spire-server | grep -Eq 'Plugin loaded.*plugin_name=tpm' \
	  || { echo "ERROR: the tpm node attestor (deploy/spire-tpm) did not load"; $(KIND_KUBECTL) -n $(SPIRE_NAMESPACE) logs statefulset/spire-server -c spire-server --tail=60; exit 1; }
	@echo "✓ SPIRE $(SPIRE_CHART_VERSION) up from $(SPIRE_KUSTOMIZATION); controller manager className $(SPIRE_CLASS_NAME); tpm node attestor loaded"

kind-deploy: kind-create ## Apply the broker's CRD, ServiceAccount, RBAC and admission policies; mint its kubeconfig
	@$(KIND_KUBECTL) get ns banlieue-system >/dev/null 2>&1 || $(KIND_KUBECTL) create ns banlieue-system
	$(KIND_KUBECTL) apply -n banlieue-system -f deploy/base/crds -f deploy/base/serviceaccount.yaml -f deploy/base/rbac.yaml -f deploy/base/admission/clusterstaticentry-mediatore.yaml -f deploy/base/admission/agentsandbox-subject.yaml
	@./dev/kind/sa-kubeconfig.sh $(KIND_KUBECONFIG) $(KIND_SA_KUBECONFIG)
	@./dev/kind/admission-settled.sh $(KIND_SA_KUBECONFIG) $(SPIRE_TRUST_DOMAIN)

kind-up: kind-create kind-spire kind-deploy ## Cluster + SPIRE + the broker's identity, ready for the live tests

kind-images: kind-create dist dist-e2e ## The server image (the shipped Dockerfile's runtime stage over dist/) and the test-only e2e image, loaded into the cluster; the node and workload pods run the server image too (ADR-0014)
	$(CONTAINER_CLI) build --build-arg BINARY_FROM=host -t $(KIND_IMAGE) .
	$(CONTAINER_CLI) build -f dev/kind/Dockerfile.e2e -t $(KIND_E2E_IMAGE) .
	@# One image per call: under the podman provider a multi-image load ends up with one manifest.
	kind load docker-image --name $(KIND_CLUSTER_NAME) $(KIND_IMAGE)
	kind load docker-image --name $(KIND_CLUSTER_NAME) $(KIND_E2E_IMAGE)

kind-postgres: kind-create ## PostgreSQL in kind with a certificate this target mints (ADR-0012); the broker's store
	@$(KIND_KUBECTL) get ns banlieue-system >/dev/null 2>&1 || $(KIND_KUBECTL) create ns banlieue-system
	cargo run -q -p mediatore-testkit --bin tls-fixture -- --out-dir $(KIND_DIR)/pg --dns mediatore-postgres.banlieue-system.svc --dns localhost
	$(KIND_KUBECTL) -n banlieue-system create secret generic mediatore-postgres-tls --from-file=$(KIND_DIR)/pg/server.pem --from-file=$(KIND_DIR)/pg/server-key.pem --dry-run=client -o yaml | $(KIND_KUBECTL) apply -f -
	$(KIND_KUBECTL) -n banlieue-system create configmap mediatore-pg-ca --from-file=$(KIND_DIR)/pg/ca.pem --dry-run=client -o yaml | $(KIND_KUBECTL) apply -f -
	$(KIND_KUBECTL) apply -f dev/kind/postgres/postgres.yaml
	@# A new certificate needs a new pod.
	$(KIND_KUBECTL) -n banlieue-system rollout restart deploy/mediatore-postgres
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore-postgres --timeout=300s

kind-dex: kind-create ## Dex over TLS with a glauth directory behind it (ADR-0013), and the broker's STS signing key, minted by this target
	@$(KIND_KUBECTL) get ns banlieue-system >/dev/null 2>&1 || $(KIND_KUBECTL) create ns banlieue-system
	cargo run -q -p mediatore-testkit --bin tls-fixture -- --out-dir $(KIND_DIR)/dex --dns mediatore-dex.banlieue-system.svc
	$(KIND_KUBECTL) -n banlieue-system create secret generic mediatore-dex-tls --from-file=$(KIND_DIR)/dex/server.pem --from-file=$(KIND_DIR)/dex/server-key.pem --dry-run=client -o yaml | $(KIND_KUBECTL) apply -f -
	$(KIND_KUBECTL) -n banlieue-system create configmap mediatore-dex-ca --from-file=$(KIND_DIR)/dex/ca.pem --dry-run=client -o yaml | $(KIND_KUBECTL) apply -f -
	$(KIND_KUBECTL) -n banlieue-system create configmap mediatore-glauth-config --from-file=dev/kind/dex/glauth.cfg --dry-run=client -o yaml | $(KIND_KUBECTL) apply -f -
	@[ -f $(KIND_DIR)/sts.pem ] || openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out $(KIND_DIR)/sts.pem
	$(KIND_KUBECTL) -n banlieue-system create secret generic mediatore-sts --from-file=sts.pem=$(KIND_DIR)/sts.pem --dry-run=client -o yaml | $(KIND_KUBECTL) apply -f -
	$(KIND_KUBECTL) apply -f dev/kind/dex/glauth.yaml -f dev/kind/dex/dex.yaml
	@# A new certificate needs a new pod.
	$(KIND_KUBECTL) -n banlieue-system rollout restart deploy/mediatore-dex
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore-glauth --timeout=300s
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore-dex --timeout=300s

kind-openbao: kind-create ## OpenBao over TLS (ADR-0015): minted certificate, initialised and unsealed, transit with a derived key, Kubernetes auth role for the broker
	@$(KIND_KUBECTL) get ns banlieue-system >/dev/null 2>&1 || $(KIND_KUBECTL) create ns banlieue-system
	cargo run -q -p mediatore-testkit --bin tls-fixture -- --out-dir $(KIND_DIR)/openbao --dns mediatore-openbao.banlieue-system.svc --dns localhost
	$(KIND_KUBECTL) -n banlieue-system create secret generic mediatore-openbao-tls --from-file=$(KIND_DIR)/openbao/server.pem --from-file=$(KIND_DIR)/openbao/server-key.pem --dry-run=client -o yaml | $(KIND_KUBECTL) apply -f -
	$(KIND_KUBECTL) -n banlieue-system create configmap mediatore-openbao-ca --from-file=$(KIND_DIR)/openbao/ca.pem --dry-run=client -o yaml | $(KIND_KUBECTL) apply -f -
	$(KIND_KUBECTL) apply -f dev/kind/openbao/openbao.yaml
	@# A new certificate needs a new pod; in-memory storage starts over, the setup redoes it.
	$(KIND_KUBECTL) -n banlieue-system rollout restart deploy/mediatore-openbao
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore-openbao --timeout=300s
	@rm -f $(KIND_DIR)/openbao/init.json
	./dev/kind/openbao-setup.sh $(KIND_KUBECONFIG) $(KIND_DIR)/openbao

kind-broker: kind-up kind-images kind-postgres kind-dex kind-openbao ## deploy/base in kind on the CSI driver's socket, the kind PostgreSQL, Dex and OpenBao (dev/kind/broker overlay), rolled out
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

kind-e2e-store: kind-broker ## ADR-0012 live: the broker on PostgreSQL over verify-full, the store conformance suite against that database
	./dev/kind/store-e2e.sh $(KIND_KUBECONFIG) $(KIND_DIR)/pg/ca.pem

kind-e2e-dex: kind-banlieue-crds kind-broker ## ADR-0013 live: the real CLI logs in at a real Dex and delegates the session, every token issue refreshes it, a group removal and a revocation at Dex release the claim
	$(KIND_KUBECTL) -n banlieue-system rollout restart deploy/mediatore
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore --timeout=300s
	./dev/kind/dex-e2e.sh $(KIND_KUBECONFIG) $(SPIRE_TRUST_DOMAIN) $(KIND_DIR)/ek.pem $(KIND_DIR)/ek.hash

kind-e2e-tpm: kind-vtpm kind-banlieue-crds kind-broker ## ADR-0018 live: an agent attesting with the vTPM behind the node on the image's agent.conf, the EK CA fail-closed, the node entry under that agent, re-attestation
	$(KIND_KUBECTL) -n banlieue-system rollout restart deploy/mediatore
	$(KIND_KUBECTL) -n banlieue-system rollout status deploy/mediatore --timeout=300s
	TPM_PLUGIN_AGENT_IMG=$(TPM_PLUGIN_AGENT_IMG) ./dev/kind/tpm-e2e.sh $(KIND_KUBECONFIG) $(SPIRE_TRUST_DOMAIN) $(KIND_VTPM_DIR)

kind-e2e: kind-e2e-entries kind-e2e-mtls kind-e2e-watcher kind-e2e-sandbox kind-e2e-store kind-e2e-dex ## Every live suite against kind that needs nothing of the host (grows with the roadmap); kind-e2e-tpm needs a vTPM

kind-e2e-ci: ## CI shape: $(KIND_E2E_SUITES), cluster state on failure, cluster deleted after
	@$(MAKE) $(KIND_E2E_SUITES) || { $(MAKE) kind-e2e-logs; $(MAKE) kind-delete; exit 1; }
	@$(MAKE) kind-delete

kind-e2e-logs: ## What a failing live suite needs: entries, policy, broker and client pods, controller-manager and server logs
	-$(KIND_KUBECTL) get clusterstaticentries -o yaml
	-$(KIND_KUBECTL) get clusterspiffeids -o yaml
	-$(KIND_KUBECTL) -n banlieue-system get pods -o wide
	-$(KIND_KUBECTL) -n banlieue-system logs deploy/mediatore --tail=200
	-$(KIND_KUBECTL) -n banlieue-system logs deploy/mediatore-postgres --tail=50
	-$(KIND_KUBECTL) -n banlieue-system logs deploy/mediatore-dex --tail=80
	-$(KIND_KUBECTL) -n banlieue-system logs deploy/mediatore-openbao --tail=60
	-$(KIND_KUBECTL) -n banlieue-system logs deploy/mediatore-glauth --tail=30
	-$(KIND_KUBECTL) -n banlieue-system get refreshtokens.dex.coreos.com
	-$(KIND_KUBECTL) -n mediatore-e2e-sandbox logs pod/cli-1 --tail=60
	-$(KIND_KUBECTL) -n mediatore-e2e get pods -o wide
	-$(KIND_KUBECTL) -n banlieue-system get lease mediatore-watcher -o yaml
	-$(KIND_KUBECTL) -n mediatore-e2e-watcher get virtualmachines,virtualmachineclaims -o yaml
	-$(KIND_KUBECTL) -n mediatore-e2e-sandbox get agentsandboxes,virtualmachineclaims,pods -o yaml
	-$(KIND_KUBECTL) -n mediatore-e2e-sandbox logs pod/node --tail=50
	-$(KIND_KUBECTL) -n mediatore-e2e-tpm get pods -o wide
	-$(KIND_KUBECTL) -n mediatore-e2e-tpm logs deploy/member -c spire-agent --tail=80
	-$(KIND_KUBECTL) -n mediatore-e2e-tpm logs deploy/member -c guest --tail=40
	-$(KIND_KUBECTL) -n $(SPIRE_NAMESPACE) exec spire-server-0 -c spire-server -- spire-server agent list
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
