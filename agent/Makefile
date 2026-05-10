.PHONY: help docker-build docker-run integration-tests integration-tests-debug clean

help:
	@echo "Agent targets:"
	@echo "  docker-build            Build the agent Docker image"
	@echo "  docker-run              Run the agent Docker image locally"
	@echo "  integration-tests       Run E2E integration tests in k3s"
	@echo "  integration-tests-debug Run E2E tests, skip image rebuild"
	@echo "  clean                   Clean agent build artifacts"

# Build from repo root context so workspace Cargo.toml + api/ crate are available.
# The Dockerfile lives here but the build context is the parent directory.
docker-build:
	DOCKER_BUILDKIT=1 docker build -t bistouri-agent -f Dockerfile ..

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
	SKIP_CLEANUP=true ./tests/e2e/run-e2e-wrapper.sh

clean:
	cargo clean -p bistouri-agent
