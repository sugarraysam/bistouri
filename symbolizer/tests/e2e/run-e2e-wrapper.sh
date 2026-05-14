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

VMLINUX_DBG=""
HOST_DEBUG_STAGING="/tmp/bistouri-host-debug"

find_vmlinux_dbg() {
	find /usr/lib/debug/boot -maxdepth 1 -name "vmlinux-$(uname -r)*" 2>/dev/null | head -n 1 || true
}

ensure_kernel_dbgsym() {
	VMLINUX_DBG=$(find_vmlinux_dbg)

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

	local version
	version="$(uname -r)"

	local exact_version
	exact_version=$(dpkg-query -W -f='${Version}' "linux-image-${version}" 2>/dev/null)

	if [ -z "$exact_version" ]; then
		e2e_warn "Could not determine exact Debian version of the running kernel."
		return
	fi

	# STRICT search: Enforce end-of-string bounds to prevent -fde leakage
	# This ensures we match linux-image-6.17.0-1010-azure-dbgsym and NOT -azure-fde-dbgsym
	local pkg

	# DEBUG
	apt-cache search "^linux-image-${version}*"

	pkg=$(apt-cache search "^linux-image-${version}-dbgsym$" | awk '{print $1}' | head -n 1)

	# Some cloud images use an unsigned dbgsym variant. Fallback if the strict match fails.
	if [ -z "$pkg" ]; then
		pkg=$(apt-cache search "^linux-image-unsigned-${version}-dbgsym$" | awk '{print $1}' | head -n 1)
	fi

	if [ -z "$pkg" ]; then
		e2e_warn "Could not find any exact dbgsym packages for $version."
		return
	fi

	e2e_info "Found matching debug package: $pkg"
	e2e_info "Enforcing exact version match: ${exact_version}"

	# 3. Install the specific version mapped to the running kernel
	if sudo apt-get install -y --allow-downgrades --no-install-recommends "${pkg}=${exact_version}"; then
		e2e_info "Installed ${pkg}=${exact_version}"
		VMLINUX_DBG=$(find_vmlinux_dbg)
	else
		e2e_warn "Could not install exact version ${exact_version} of $pkg."
	fi
}

stage_kernel_dbgsym() {
	e2e_info "Staging targeted kernel debug symbols into $HOST_DEBUG_STAGING..."

	# Clean up previous runs to ensure no stale files from older kernels exist
	sudo rm -rf "$HOST_DEBUG_STAGING"
	mkdir -p "$HOST_DEBUG_STAGING"

	if [ -n "$VMLINUX_DBG" ] && [ -f "$VMLINUX_DBG" ]; then
		# Copy the file so it resolves correctly inside the container mount
		cp "$VMLINUX_DBG" "$HOST_DEBUG_STAGING/"
		e2e_info "Successfully copied $VMLINUX_DBG to staging directory."

		local staged_file=$(ls "$HOST_DEBUG_STAGING/"vmlinux* | head -n 1)
		if command -v readelf >/dev/null 2>&1; then
			local actual_build_id=$(readelf -n "$staged_file" 2>/dev/null | grep "Build ID" || echo "UNKNOWN")
			e2e_info "Staged vmlinux Build ID: $actual_build_id"
		fi
	else
		e2e_warn "No kernel debug symbols found to stage."
	fi
}

# ── k3s ──────────────────────────────────────────────────────────────

ensure_kernel_dbgsym
stage_kernel_dbgsym
start_fresh_k3s
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
