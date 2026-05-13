.PHONY: docker-build docker-build-debuginfod e2e fixtures help

help:
	@echo "Symbolizer targets:"
	@echo "  docker-build           Build the symbolizer Docker image"
	@echo "  docker-build-debuginfod Build the debuginfod sidecar Docker image"
	@echo "  fixtures               Rebuild fixture binaries + manifest.json"
	@echo "  e2e                    Run symbolizer E2E tests (requires k3s + Docker)"

# Build the symbolizer Docker image.
docker-build:
	DOCKER_BUILDKIT=1 docker build -t bistouri-symbolizer:local -f Dockerfile ..

# Build the debuginfod fixtures Docker image.
docker-build-debuginfod:
	docker build \
		-t debuginfod-fixtures:local \
		-f tests/e2e/images/Dockerfile.debuginfod \
		tests/e2e/

# Rebuild fixture binaries and manifest (only needed when adding new test functions).
fixtures:
	python3 tests/e2e/fixtures/build_fixtures.py

# Run symbolizer E2E tests (requires k3s + Docker).
e2e:
	RUST_LOG=debug ./tests/e2e/run-e2e-wrapper.sh
