.PHONY: all help fmt clippy build test ci clean docker-build docker-run integration-tests integration-tests-debug

# The default target when you just run `make`
all: ci

# Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@echo "  help                    Show this help message"
	@echo "  ci                      Run all CI checks locally (fmt, clippy, test, build) [default]"
	@echo "  fmt                     Format the code"
	@echo "  clippy                  Run the linter"
	@echo "  build                   Build the project"
	@echo "  test                    Run the tests"
	@echo "  clean                   Clean the project"
	@echo "  docker-build            Build the Docker image"
	@echo "  docker-run              Run the Docker image locally"
	@echo "  integration-tests       Run E2E integration tests in a k3s cluster"
	@echo "  integration-tests-debug Run E2E tests, skip image rebuild"

# Format the code
fmt:
	cargo +nightly fmt --all

# Run the linter
clippy:
	cargo +nightly clippy --all-targets --all-features -- -D warnings

# Build the project
build:
	cargo +nightly build --all-targets --all-features

# Run the tests
test:
	cargo +nightly test --all-targets --all-features -- --skip bistouri_e2e

# Run all CI checks locally
ci:
	cargo +nightly fmt --all
	cargo +nightly clippy --fix --allow-dirty --all-targets --all-features -- -D warnings
	cargo +nightly test --all-targets --all-features -- --skip bistouri_e2e
	cargo +nightly build --all-targets --all-features

# Clean the project
clean:
	cargo clean

# Build the Docker image
docker-build:
	DOCKER_BUILDKIT=1 docker build -t bistouri-agent .

# Run the Docker image locally with granular permissions.
# Each flag is documented — no privileged mode, no CAP_SYS_ADMIN.
docker-run:
	docker run --rm -it \
		--cap-add=BPF           `# Load BPF programs and create BPF maps (kernel >= 5.8)` \
		--cap-add=PERFMON       `# perf_event_open() for stack sampling (kernel >= 5.8)` \
		--cap-add=SYS_RESOURCE  `# Create PSI trigger FDs with sub-2s windows` \
		--security-opt seccomp=unconfined `# Allow bpf() and perf_event_open() syscalls` \
		--pid=host              `# Access /proc for all host processes` \
		-v /proc:/host/proc:ro            `# Host procfs for cgroup namespace resolution` \
		-v /sys/kernel/tracing:/sys/kernel/tracing:ro `# BPF tracepoint attachment` \
		-v /sys/fs/bpf:/sys/fs/bpf                    `# BPF map pinning` \
		-v /sys/fs/cgroup:/sys/fs/cgroup               `# Cgroup info + PSI trigger FD writes` \
		bistouri-agent:latest --proc-path /host/proc

# Run E2E integration tests in a k3s cluster
integration-tests:
	./tests/e2e/run-e2e-wrapper.sh

# Run E2E tests, skip image rebuild (reuse existing images)
integration-tests-debug:
	SKIP_BUILD=true ./tests/e2e/run-e2e-wrapper.sh

