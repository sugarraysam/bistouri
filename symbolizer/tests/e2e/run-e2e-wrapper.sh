#!/usr/bin/env bash
# run-e2e-wrapper.sh — Orchestrate symbolizer E2E test lifecycle.
#
# Lifecycle: nuke k3s → start fresh → build/import → test → nuke on exit.
# All k3s lifecycle is handled by scripts/k3s-helpers.sh.

SKIP_CLEANUP="${SKIP_CLEANUP:-false}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SYMBOLIZER_DIR="${REPO_ROOT}/symbolizer"

E2E_LOG_PREFIX="symbolizer-e2e"
# shellcheck source=../../../scripts/k3s-helpers.sh
source "${REPO_ROOT}/scripts/k3s-helpers.sh"

# ── Kernel debug symbols ─────────────────────────────────────────────

VMLINUX_DBG="/usr/lib/debug/boot/vmlinux-$(uname -r)"

ensure_kernel_dbgsym() {
	if [ -f "$VMLINUX_DBG" ]; then
		e2e_info "Kernel debug symbols found: $VMLINUX_DBG"
		return
	fi

	e2e_info "Kernel debug symbols not found, installing..."

	# Ubuntu dbgsym packages live in a dedicated repo.
	if ! grep -q ddebs /etc/apt/sources.list.d/*.list 2>/dev/null; then
		e2e_warn "Adding Ubuntu ddebs repository..."
		sudo apt-get install -y ubuntu-dbgsym-keyring 2>/dev/null || true

		# ADD -updates AND -security REPOS HERE
		cat <<EOF | sudo tee /etc/apt/sources.list.d/ddebs.list >/dev/null
deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
EOF

		sudo apt-get update -qq
	fi

	local version="$(uname -r)"
	local pkg

	pkg=$(apt-cache search "linux-image.*${version}.*dbgsym" | awk '{print $1}' | head -n 1)

	if [ -z "$pkg" ]; then
		e2e_warn "Could not find any dbgsym packages for $version."
		e2e_warn "Could not install debug symbols — Phase 2 skipped."
		return
	fi

	e2e_info "Found matching debug package: $pkg"
	if sudo apt-get install -y --no-install-recommends "$pkg"; then
		e2e_info "Installed $pkg"
	else
		e2e_warn "Could not install $pkg — Phase 2 (kernel resolution) skipped."
	fi
}

# ── k3s ──────────────────────────────────────────────────────────────

ensure_kernel_dbgsym
start_fre sh_k3s
register_cleanup_trap
setup_kubeconfig

# ── Build + load images ──────────────────────────────────────────────

if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
	e2e_info "Building symbolizer Docker image..."
	make -C "$SYMBOLIZER_DIR" docker-build

	e2e_info "Building debuginfod-fixtures Docker image..."
	make -C "$SYMBOLIZER_DIR" docker-build-debuginfod
else
	e2e_info "Skipping Docker builds (SKIP_BUILD=true)"
fi
import_k3s_images bistouri-symbolizer:local debuginfod-fixtures:local

# ── Run tests ────────────────────────────────────────────────────────

e2e_info "Running symbolizer E2E tests..."

# sudo is required so /proc/kallsyms exposes real addresses (kptr_restrict).
sudo --preserve-env=KUBECONFIG,RUST_LOG,HOME \
	"$(which cargo)" +nightly test -p bistouri-symbolizer --test e2e -- --nocapture

e2e_info "All symbolizer E2E tests passed!"
