.PHONY: all help fmt clippy build test docs-check ci validate-deployment generate-crd clean

all: ci

help:
	@echo "Workspace targets:"
	@echo "  ci                  Run all CI checks (fmt, clippy, test, build, docs-check) [default]"
	@echo "  fmt                 Format all crates"
	@echo "  clippy              Lint all crates"
	@echo "  build               Build all crates"
	@echo "  test                Run unit tests for all crates"
	@echo "  docs-check          Verify _quarto.yml chapters exist on disk"
	@echo "  validate-deployment Dry-run kubectl apply on deployment/ manifests"
	@echo "  generate-crd        Regenerate deployment/crd/bistouriconfig.yaml from Rust types"
	@echo "  clean               Clean workspace build artifacts"

fmt:
	cargo +nightly fmt --all

clippy:
	cargo +nightly clippy --workspace --all-targets --all-features -- -D warnings

build:
	cargo +nightly build --workspace --all-targets --all-features

test:
	cargo +nightly test --workspace --all-targets --all-features -- --skip bistouri_e2e

docs-check:
	python3 scripts/check_docs.py

ci: fmt clippy test build docs-check

# Regenerate deployment/crd/bistouriconfig.yaml from the Rust type definitions in
# api/src/bin/crd-gen.rs. Commit the result — CI validates the committed YAML via dry-run.
generate-crd:
	cargo run -q -p bistouri-api --bin crd-gen --features kube > deployment/crd/bistouriconfig.yaml

# Mirror of the CI validate_deployment job — run locally before pushing.
# Requires kubectl to be installed and configured (any cluster or just the binary).
validate-deployment:
	@echo "==> Validating all deployment manifests"
	@find deployment -name '*.yaml' | sort | while read -r f; do \
		echo "    $$f"; \
		out=$$(kubectl apply --dry-run=client -f "$$f" 2>&1); rc=$$?; echo "$$out"; \
		if [ $$rc -ne 0 ] && ! echo "$$out" | grep -q 'no matches for kind'; then exit 1; fi; \
	done
	@echo "==> All manifests valid"

clean:
	cargo clean
