#!/usr/bin/env bash
# run-e2e-wrapper.sh — Orchestrate agent E2E test lifecycle.
#
# Lifecycle: nuke k3s → start fresh → build/import → test → nuke on exit.
# All k3s lifecycle is handled by scripts/k3s-helpers.sh.

SKIP_CLEANUP="${SKIP_CLEANUP:-false}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

E2E_LOG_PREFIX="agent-e2e"
# shellcheck source=../../../scripts/k3s-helpers.sh
source "${REPO_ROOT}/scripts/k3s-helpers.sh"

# ── k3s ──────────────────────────────────────────────────────────────

start_fresh_k3s
register_cleanup_trap
setup_kubeconfig

# ── Validate ─────────────────────────────────────────────────────────
# Dry-run manifests. CRD kinds are registered by the Rust test itself.

e2e_info "Validating deployment manifests..."
make -C "$REPO_ROOT" validate-deployment

# ── Build + load images ──────────────────────────────────────────────

if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
    e2e_info "Building agent Docker image..."
    DOCKER_BUILDKIT=1 docker build -t bistouri-agent:local \
        -f "${REPO_ROOT}/agent/Dockerfile" "$REPO_ROOT"
    e2e_info "Building stress workload Docker image..."
    docker build -t bistouri-stress:local \
        -f "${SCRIPT_DIR}/images/Dockerfile.stress" "${SCRIPT_DIR}/images/"
else
    e2e_info "Skipping Docker builds (SKIP_BUILD=true)"
fi

import_k3s_images bistouri-agent:local bistouri-stress:local

# ── Run tests ────────────────────────────────────────────────────────

e2e_info "Running agent E2E tests..."
cargo test --test e2e -- --nocapture "$@"

e2e_info "All agent E2E tests passed!"
