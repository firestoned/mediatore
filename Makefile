# Copyright (c) 2026 Erick Bourgeois, mediatore
# SPDX-License-Identifier: Apache-2.0
#
# All CI logic lives here (rules/github-workflows.md): workflows install tools
# and call these targets, and every target runs identically locally.

.PHONY: all help fmt fmt-check lint test deny audit check sbom guest image e2e \
        calm-validate calm-diagrams clean

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

image: ## Build the server container image locally
	docker build -t ghcr.io/firestoned/mediatore:dev .

# ----- End to end --------------------------------------------------------------

e2e: ## Front-to-back dev-mode loop with real binaries (fake IdP, server, guest, sandbox-token)
	./dev/demo.sh

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

clean: ## Remove build artifacts
	cargo clean
