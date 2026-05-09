#!/usr/bin/env bash
# Outer safety net for Bistouri E2E tests.
#
# Exists because three things cannot be done from Rust:
#   1. sudo (k3s server, ctr import, k3s-killall.sh)
#   2. docker build
#   3. trap EXIT (catches SIGKILL/abort that Drop misses)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Start k3s if not already running.
K3S_STARTED=false
if ! sudo k3s kubectl get node >/dev/null 2>&1; then
    sudo nohup k3s server --disable=traefik --disable=servicelb \
        --write-kubeconfig-mode=644 \
        --kubelet-arg=--sync-frequency=3s \
        >/tmp/k3s.log 2>&1 &
    K3S_STARTED=true
    until sudo k3s kubectl get nodes --no-headers 2>/dev/null | grep -q .; do sleep 2; done
    sudo k3s kubectl wait --for=condition=Ready node --all --timeout=60s
fi
cleanup() { $K3S_STARTED && sudo k3s-killall.sh 2>/dev/null || true; }
trap cleanup EXIT

# Make kubeconfig user-readable (k3s writes it as root:root 600).
sudo cp /etc/rancher/k3s/k3s.yaml /tmp/bistouri-e2e-kubeconfig
sudo chown "$(id -u):$(id -g)" /tmp/bistouri-e2e-kubeconfig
export KUBECONFIG=/tmp/bistouri-e2e-kubeconfig

# Build + load images (skip with SKIP_BUILD=true).
if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
    DOCKER_BUILDKIT=1 docker build -t bistouri-agent:local "$REPO_ROOT"
    docker build -t bistouri-stress:local \
        -f "${SCRIPT_DIR}/images/Dockerfile.stress" "${SCRIPT_DIR}/images/"
fi
docker save bistouri-agent:local | sudo k3s ctr images import -
docker save bistouri-stress:local | sudo k3s ctr images import -

# Run the Rust E2E test.
cargo +nightly test --test e2e -- --nocapture "$@"
