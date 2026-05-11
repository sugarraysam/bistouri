#!/usr/bin/env bash
# Outer safety net for Bistouri E2E tests.

set -euxo pipefail

SKIP_CLEANUP="${SKIP_CLEANUP:-false}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# 1. Clean slate: Kill any stale k3s processes
function cleanup() {
    sudo k3s kubectl delete all --all -n default || true
    sudo k3s-killall.sh || true
    sudo pkill -9 "k3s" 2>/dev/null || true
    sudo rm -fr /var/lib/rancher/k3s/server/db || true

    # fix terminal output
    stty sane || true
}

cleanup
if systemctl is-active --quiet k3s 2>/dev/null; then
    sudo systemctl stop k3s
fi

# 2. Start k3s fresh with standard defaults (Watch strategy is already native and fast)
sudo nohup k3s server --disable=traefik \
    --disable=servicelb \
    --write-kubeconfig-mode=644 \
    --kubelet-arg="sync-frequency=3s" \
    >/tmp/k3s.log 2>&1 &

until sudo k3s kubectl get nodes --no-headers 2>/dev/null | grep -q .; do sleep 2; done
sudo k3s kubectl wait --for=condition=Ready node --all --timeout=60s

trap_cleanup() {
    if [[ "${SKIP_CLEANUP}" != "true" ]]; then
        cleanup
    fi
}
trap trap_cleanup EXIT

# 3. Kubeconfig setup
sudo cp /etc/rancher/k3s/k3s.yaml /tmp/bistouri-e2e-kubeconfig
sudo chown "$(id -u):$(id -g)" /tmp/bistouri-e2e-kubeconfig
export KUBECONFIG=/tmp/bistouri-e2e-kubeconfig

# 4. Validate deployment manifests against the live cluster (dry-run client-side).
# The cluster is up and kubectl is configured — CRD kinds are registered by the
# E2E Rust test itself, but --dry-run=client doesn't require server-side schema
# awareness and the Makefile target tolerates 'no matches for kind' gracefully.
make -C "$REPO_ROOT" validate-deployment

# 5. Build + load images
if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
    DOCKER_BUILDKIT=1 docker build -t bistouri-agent:local -f "${REPO_ROOT}/agent/Dockerfile" "$REPO_ROOT"
    docker build -t bistouri-stress:local \
        -f "${SCRIPT_DIR}/images/Dockerfile.stress" "${SCRIPT_DIR}/images/"
fi
docker save bistouri-agent:local | sudo k3s ctr images import -
docker pull busybox:latest
docker save busybox:latest | sudo k3s ctr images import -
docker save bistouri-stress:local | sudo k3s ctr images import -

# 6. Run the Rust E2E test
cargo +nightly test --test e2e -- --nocapture "$@"
