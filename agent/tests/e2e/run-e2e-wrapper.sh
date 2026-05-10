#!/usr/bin/env bash
# Outer safety net for Bistouri E2E tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# 1. Clean slate: Kill any stale k3s processes
sudo k3s-killall.sh 2>/dev/null || true
if systemctl is-active --quiet k3s 2>/dev/null; then
	sudo systemctl stop k3s
fi

# 2. Start k3s fresh with standard defaults (Watch strategy is already native and fast)
sudo nohup k3s server --disable=traefik --disable=servicelb \
	--write-kubeconfig-mode=644 \
	--kubelet-arg="sync-frequency=3s" \
	>/tmp/k3s.log 2>&1 &

until sudo k3s kubectl get nodes --no-headers 2>/dev/null | grep -q .; do sleep 2; done
sudo k3s kubectl wait --for=condition=Ready node --all --timeout=60s

cleanup() { sudo k3s-killall.sh 2>/dev/null || true; }
trap cleanup EXIT

# 3. Kubeconfig setup
sudo cp /etc/rancher/k3s/k3s.yaml /tmp/bistouri-e2e-kubeconfig
sudo chown "$(id -u):$(id -g)" /tmp/bistouri-e2e-kubeconfig
export KUBECONFIG=/tmp/bistouri-e2e-kubeconfig

# 4. Build + load images
if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
	DOCKER_BUILDKIT=1 docker build -t bistouri-agent:local -f "${REPO_ROOT}/agent/Dockerfile" "$REPO_ROOT"
	docker build -t bistouri-stress:local \
		-f "${SCRIPT_DIR}/images/Dockerfile.stress" "${SCRIPT_DIR}/images/"
fi
docker save bistouri-agent:local | sudo k3s ctr images import -
docker pull busybox:latest
docker save busybox:latest | sudo k3s ctr images import -
docker save bistouri-stress:local | sudo k3s ctr images import -

# 5. Run the Rust E2E test
cargo +nightly test --test e2e -- --nocapture "$@"
