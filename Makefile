.PHONY: all help fmt clippy build test ci clean docker-build docker-run

# The default target when you just run `make`
all: ci

# Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@echo "  help         Show this help message"
	@echo "  ci           Run all CI checks locally (fmt, clippy, test, build) [default]"
	@echo "  fmt          Format the code"
	@echo "  clippy       Run the linter"
	@echo "  build        Build the project"
	@echo "  test         Run the tests"
	@echo "  clean        Clean the project"
	@echo "  docker-build Build the Docker image"
	@echo "  docker-run   Run the Docker image locally"

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
	cargo +nightly test --all-targets --all-features

# Run all CI checks locally
ci:
	cargo +nightly fmt --all
	cargo +nightly clippy --fix --allow-dirty --all-targets --all-features -- -D warnings
	cargo +nightly test --all-targets --all-features
	cargo +nightly build --all-targets --all-features

# Clean the project
clean:
	cargo clean

# Build the Docker image
docker-build:
	DOCKER_BUILDKIT=1 docker build -t bistouri-agent .

# Run the Docker image locally with granular permissions
docker-run:
	docker run --rm -it \
		--cap-add=BPF \
		--cap-add=PERFMON \
		--security-opt seccomp=unconfined \
		--pid=host \
		-v /sys/kernel/tracing:/sys/kernel/tracing:ro \
		-v /sys/fs/bpf:/sys/fs/bpf \
		bistouri-agent:latest
