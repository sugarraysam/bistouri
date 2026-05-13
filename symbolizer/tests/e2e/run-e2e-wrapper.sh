#!/usr/bin/env bash
# run-e2e-wrapper.sh — Orchestrate symbolizer E2E test lifecycle.
#
# 1. Ensure k3s is running (start if needed)
# 2. Build symbolizer + debuginfod-fixtures Docker images
# 3. Import images into k3s containerd
# 4. Run cargo test --test e2e
# 5. Cleanup on exit
#
# This mirrors the agent's E2E wrapper pattern but runs its own
# k3s lifecycle (separate CI jobs).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SYMBOLIZER_DIR="${REPO_ROOT}/symbolizer"

# ── Colors ───────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[symbolizer-e2e]${NC} $*"; }
warn()  { echo -e "${YELLOW}[symbolizer-e2e]${NC} $*"; }
error() { echo -e "${RED}[symbolizer-e2e]${NC} $*" >&2; }

# ── k3s lifecycle ────────────────────────────────────────────────────

K3S_STARTED_BY_US=false

ensure_k3s() {
    if k3s kubectl cluster-info &>/dev/null; then
        info "k3s already running"
        return
    fi

    info "Starting k3s..."
    sudo k3s server \
        --disable traefik \
        --disable metrics-server \
        --write-kubeconfig-mode 644 \
        &>/dev/null &

    K3S_STARTED_BY_US=true

    # Wait for k3s to be ready.
    local retries=30
    while ! k3s kubectl cluster-info &>/dev/null; do
        retries=$((retries - 1))
        if [ "$retries" -le 0 ]; then
            error "k3s failed to start within 60 seconds"
            exit 1
        fi
        sleep 2
    done
    info "k3s ready"
}

cleanup() {
    info "Cleaning up..."
    # Delete the symbolizer pod (ignore errors if it doesn't exist).
    k3s kubectl delete -f "${SCRIPT_DIR}/k8s/symbolizer-pod.yaml" --ignore-not-found 2>/dev/null || true

    if [ "$K3S_STARTED_BY_US" = true ]; then
        info "Stopping k3s..."
        sudo k3s-killall.sh 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Kernel debug symbols ─────────────────────────────────────────────

VMLINUX_DBG="/usr/lib/debug/boot/vmlinux-$(uname -r)"

ensure_kernel_dbgsym() {
    if [ -f "$VMLINUX_DBG" ]; then
        info "Kernel debug symbols found: $VMLINUX_DBG"
        return
    fi

    local pkg="linux-image-$(uname -r)-dbgsym"
    info "Kernel debug symbols not found — installing $pkg..."

    # Ubuntu dbgsym packages live in a dedicated repo.
    if ! grep -q ddebs /etc/apt/sources.list.d/*.list 2>/dev/null; then
        warn "Adding Ubuntu ddebs repository..."
        sudo apt-get install -y ubuntu-dbgsym-keyring 2>/dev/null || true
        echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" \
            | sudo tee /etc/apt/sources.list.d/ddebs.list >/dev/null
        sudo apt-get update -qq
    fi

    if sudo apt-get install -y --no-install-recommends "$pkg" 2>/dev/null; then
        info "Installed $pkg"
    else
        warn "Could not install $pkg — Phase 2 (kernel resolution) will be skipped"
    fi
}

# ── Docker builds ────────────────────────────────────────────────────

build_images() {
    info "Building symbolizer Docker image..."
    make -C "$SYMBOLIZER_DIR" docker-build

    info "Building debuginfod-fixtures Docker image..."
    make -C "$SYMBOLIZER_DIR" docker-build-debuginfod
}

import_images() {
    info "Importing images into k3s containerd..."
    docker save bistouri-symbolizer:local | sudo k3s ctr images import -
    docker save debuginfod-fixtures:local | sudo k3s ctr images import -
}

# ── Main ─────────────────────────────────────────────────────────────

ensure_kernel_dbgsym
ensure_k3s
build_images
import_images

info "Setting KUBECONFIG for cargo test..."
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

info "Running symbolizer E2E tests..."
# sudo is required so /proc/kallsyms exposes real addresses (kptr_restrict).
# --preserve-env forwards KUBECONFIG, RUST_LOG, and cargo toolchain paths.
sudo --preserve-env=KUBECONFIG,RUST_LOG,HOME,PATH \
    cargo +nightly test -p bistouri-symbolizer --test e2e -- --nocapture

info "All symbolizer E2E tests passed!"
