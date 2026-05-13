.PHONY: help docker-build e2e e2e-debug

help:
	@echo "Agent targets:"
	@echo "  docker-build       Build the agent Docker image"
	@echo "  e2e				Run E2E integration tests in k3s (includes validate-deployment)"
	@echo "  e2e-debug			Run E2E tests with DEBUG logging, skip image rebuild"

# Build from repo root context so workspace Cargo.toml + api/ crate are available.
# The Dockerfile lives here but the build context is the parent directory.
docker-build:
	DOCKER_BUILDKIT=1 docker build -t bistouri-agent -f Dockerfile ..

# Run E2E integration tests in a k3s cluster
e2e:
	./tests/e2e/run-e2e-wrapper.sh

# Run E2E tests with DEBUG logging and keep the cluster alive for inspection.
e2e-debug:
	SKIP_CLEANUP=true RUST_LOG=debug ./tests/e2e/run-e2e-wrapper.sh
