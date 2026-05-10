.PHONY: all help fmt clippy build test docs-check ci clean

all: ci

help:
	@echo "Workspace targets:"
	@echo "  ci          Run all CI checks (fmt, clippy, test, build, docs-check) [default]"
	@echo "  fmt         Format all crates"
	@echo "  clippy      Lint all crates"
	@echo "  build       Build all crates"
	@echo "  test        Run unit tests for all crates"
	@echo "  docs-check  Verify _quarto.yml chapters exist on disk"
	@echo "  clean       Clean workspace build artifacts"

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

clean:
	cargo clean
