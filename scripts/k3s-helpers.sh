#!/usr/bin/env bash
# k3s-helpers.sh — Shared k3s lifecycle functions for E2E tests.
#
# Source this from your E2E wrapper script:
#   source "$(dirname "$0")/../../../scripts/k3s-helpers.sh"
#
# Provides:
#   - Colored logging: e2e_info(), e2e_warn(), e2e_error()
#   - k3s lifecycle: start_fresh_k3s(), nuke_k3s(), setup_kubeconfig()
#   - Image management: import_k3s_images()
#
# Both agent and symbolizer E2E scripts use the same deterministic
# strategy: nuke → start fresh → run tests → nuke on exit.
# No "reuse if running" — E2E tests demand a clean slate.

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── Logging ──────────────────────────────────────────────────────────
# Callers set E2E_LOG_PREFIX before sourcing this file.

E2E_LOG_PREFIX="${E2E_LOG_PREFIX:-e2e}"

e2e_info() { echo -e "${GREEN}[${E2E_LOG_PREFIX}]${NC} $*"; }
e2e_warn() { echo -e "${YELLOW}[${E2E_LOG_PREFIX}]${NC} $*"; }
e2e_error() { echo -e "${RED}[${E2E_LOG_PREFIX}]${NC} $*" >&2; }

# ── k3s lifecycle ────────────────────────────────────────────────────

# Kill all k3s processes, wipe state. Safe to call even if k3s isn't running.
nuke_k3s() {
	e2e_info "Nuking k3s state..."
	sudo k3s kubectl delete pods --all -n default 2>/dev/null || true
	sudo k3s-killall.sh 2>/dev/null || true
	sudo pkill -9 "k3s" 2>/dev/null || true
	sudo rm -fr /var/lib/rancher/k3s/server/db || true
	if systemctl is-active --quiet k3s 2>/dev/null; then
		sudo systemctl stop k3s
	fi
	stty sane 2>/dev/null || true
}

# Start a fresh k3s cluster from scratch and wait for readiness.
# Always nukes first — E2E tests demand a clean slate.
start_fresh_k3s() {
	nuke_k3s

	e2e_info "Starting k3s fresh..."
	sudo nohup k3s server \
		--disable=traefik \
		--disable=servicelb \
		--disable=metrics-server \
		--write-kubeconfig-mode=644 \
		>/tmp/k3s.log 2>&1 &

	e2e_info "Waiting for k3s API server..."
	local retries=30
	while ! k3s kubectl cluster-info &>/dev/null; do
		retries=$((retries - 1))
		if [ "$retries" -le 0 ]; then
			e2e_error "k3s failed to start within 60 seconds"
			exit 1
		fi
		sleep 2
	done

	# API server is up, but the node may not have registered yet.
	e2e_info "Waiting for node to register..."
	until sudo k3s kubectl get nodes --no-headers 2>/dev/null | grep -q .; do
		sleep 2
	done

	e2e_info "Waiting for node to be Ready..."
	sudo k3s kubectl wait --for=condition=Ready node --all --timeout=60s
	e2e_info "k3s ready"
}

# Configure KUBECONFIG so cargo test / kubectl can reach the cluster.
# Uses a temp copy so non-root processes can read it.
setup_kubeconfig() {
	e2e_info "Configuring KUBECONFIG..."
	sudo cp /etc/rancher/k3s/k3s.yaml /tmp/bistouri-e2e-kubeconfig
	sudo chown "$(id -u):$(id -g)" /tmp/bistouri-e2e-kubeconfig
	export KUBECONFIG=/tmp/bistouri-e2e-kubeconfig
}

# Import one or more Docker images into k3s containerd.
# Usage: import_k3s_images image1:tag image2:tag ...
import_k3s_images() {
	e2e_info "Importing images into k3s containerd..."
	for img in "$@"; do
		docker save "$img" | sudo k3s ctr images import -
	done
}

# Register the cleanup trap. Call this after start_fresh_k3s().
# Respects SKIP_CLEANUP=true for debugging failed runs.
register_cleanup_trap() {
	trap _e2e_cleanup EXIT
}

_e2e_cleanup() {
	if [[ "${SKIP_CLEANUP:-false}" != "true" ]]; then
		nuke_k3s
	else
		e2e_warn "SKIP_CLEANUP=true — k3s left running for debugging"
	fi
}
