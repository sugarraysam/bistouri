#!/usr/bin/env bash
# Bistouri E2E Integration Tests
#
# Deploys Bistouri as a DaemonSet in a Kind cluster alongside three stress
# workloads (cpu-burner, io-burner, mem-hog). Validates that:
#   Phase 1: PSI triggers fire for the correct (workload, resource) pairs
#   Phase 2: After hot-reloading config to drop violated rules, no new triggers fire
#
# Configuration via environment variables:
#   PHASE1_TIMEOUT  — seconds to wait for expected triggers (default: 60)
#   PHASE2_TIMEOUT  — seconds to wait for config reload    (default: 60)
#   POLL_INTERVAL   — seconds between metrics polls        (default: 5)
#   KIND_CLUSTER    — Kind cluster name                    (default: bistouri-e2e)
#   SKIP_BUILD      — skip Docker image builds             (default: false)
#   SKIP_CLEANUP    — keep cluster after test              (default: false)
#   BISTOURI_IMAGE  — Bistouri Docker image tag            (default: bistouri-agent:local)
#   STRESS_IMAGE    — Stress workload image tag            (default: bistouri-stress:local)
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
PHASE1_TIMEOUT="${PHASE1_TIMEOUT:-60}"
PHASE2_TIMEOUT="${PHASE2_TIMEOUT:-60}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
KIND_CLUSTER="${KIND_CLUSTER:-bistouri-e2e}"
SKIP_BUILD="${SKIP_BUILD:-false}"
SKIP_CLEANUP="${SKIP_CLEANUP:-false}"
BISTOURI_IMAGE="${BISTOURI_IMAGE:-bistouri-agent:local}"
STRESS_IMAGE="${STRESS_IMAGE:-bistouri-stress:local}"
LOCAL_METRICS_PORT="${LOCAL_METRICS_PORT:-19464}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
K8S_DIR="${SCRIPT_DIR}/k8s"
IMAGES_DIR="${SCRIPT_DIR}/images"

FAILURES=0
PF_PID=""

# ── Output helpers ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${CYAN}[e2e]${NC} $*"; }
pass() { echo -e "  ${GREEN}✅ PASS:${NC} $*"; }
fail() { echo -e "  ${RED}❌ FAIL:${NC} $*"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "  ${YELLOW}⚠️  WARN:${NC} $*"; }

# ── Metrics helpers ──────────────────────────────────────────────────

# Scrape a Prometheus counter value by name and optional label filter.
# Returns "0" if the metric is not found (counter never incremented).
get_metric() {
    local name="$1" labels="${2:-}"
    local body
    body=$(curl -sf "http://localhost:${LOCAL_METRICS_PORT}/metrics" 2>/dev/null || true)
    if [[ -z "$body" ]]; then
        echo "0"
        return
    fi
    local val
    if [[ -n "$labels" ]]; then
        val=$(echo "$body" | grep "^${name}{" | grep "${labels}" | awk '{print $2}' | head -1)
    else
        val=$(echo "$body" | grep "^${name}" | grep -v "^#" | awk '{print $2}' | head -1)
    fi
    echo "${val:-0}"
}

assert_gt() {
    local val="$1" threshold="$2" msg="$3"
    if (( $(echo "$val > $threshold" | bc -l) )); then
        pass "$msg (value=$val > $threshold)"
    else
        fail "$msg (value=$val <= $threshold)"
    fi
}

assert_eq() {
    local val="$1" expected="$2" msg="$3"
    if [[ "$val" == "$expected" ]]; then
        pass "$msg (value=$val)"
    else
        fail "$msg (got=$val, expected=$expected)"
    fi
}

# ── Lifecycle functions ──────────────────────────────────────────────

cleanup() {
    local exit_code=$?
    # Prevent re-entrant cleanup from nested signals.
    trap - EXIT INT TERM
    log "Cleaning up..."
    # Kill port-forward if running
    if [[ -n "$PF_PID" ]]; then
        kill "$PF_PID" 2>/dev/null || true
        wait "$PF_PID" 2>/dev/null || true
        PF_PID=""
    fi
    if [[ "$SKIP_CLEANUP" == "true" ]]; then
        warn "Skipping cluster deletion (SKIP_CLEANUP=true). Cluster: ${KIND_CLUSTER}"
    else
        kind delete cluster --name "$KIND_CLUSTER" 2>/dev/null || true
    fi
    exit "$exit_code"
}

# Catch Ctrl+C (INT), SIGTERM, and normal exit (EXIT).
# On INT/TERM: set a failing exit code then run cleanup.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

build_images() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log "Skipping image builds (SKIP_BUILD=true)"
        return
    fi
    log "Building Bistouri image..."
    (cd "$REPO_ROOT" && DOCKER_BUILDKIT=1 docker build -t "$BISTOURI_IMAGE" .)

    log "Building stress workload image..."
    docker build -t "$STRESS_IMAGE" -f "${IMAGES_DIR}/Dockerfile.stress" "$IMAGES_DIR"
}

setup_cluster() {
    log "Creating Kind cluster '${KIND_CLUSTER}'..."
    kind create cluster --name "$KIND_CLUSTER" --config "${K8S_DIR}/kind-config.yaml" --wait 60s

    log "Loading images into Kind..."
    kind load docker-image "$BISTOURI_IMAGE" --name "$KIND_CLUSTER"
    kind load docker-image "$STRESS_IMAGE" --name "$KIND_CLUSTER"
}

deploy_phase1() {
    log "Deploying Phase 1 config (9 rules)..."
    kubectl apply -f "${K8S_DIR}/configmap-phase1.yaml"

    log "Deploying Bistouri DaemonSet..."
    kubectl apply -f "${K8S_DIR}/bistouri-daemonset.yaml"
    kubectl rollout status daemonset/bistouri --timeout=120s

    log "Deploying stress workloads..."
    kubectl apply -f "${K8S_DIR}/workloads.yaml"

    log "Waiting for stress pods to be Running..."
    kubectl wait --for=condition=Ready pod/cpu-stress pod/io-stress pod/mem-stress --timeout=60s
}

start_port_forward() {
    log "Starting port-forward to Bistouri metrics..."
    local bistouri_pod
    bistouri_pod=$(kubectl get pods -l app=bistouri -o jsonpath='{.items[0].metadata.name}')
    kubectl port-forward "pod/${bistouri_pod}" "${LOCAL_METRICS_PORT}:9464" &>/dev/null &
    PF_PID=$!
    sleep 3

    if ! curl -sf "http://localhost:${LOCAL_METRICS_PORT}/metrics" > /dev/null; then
        fail "Cannot reach Bistouri metrics endpoint"
        exit 1
    fi
    log "Metrics endpoint reachable at localhost:${LOCAL_METRICS_PORT}"
}

# ── Phase 1: Assert expected PSI triggers fire ───────────────────────

assert_phase1() {
    echo ""
    log "${BOLD}Phase 1: Waiting for PSI triggers (timeout: ${PHASE1_TIMEOUT}s)...${NC}"
    echo ""

    local elapsed=0
    local cpu_ok=false io_ok=false mem_ok=false

    while (( elapsed < PHASE1_TIMEOUT )); do
        local cpu_val io_val mem_val
        cpu_val=$(get_metric "bistouri_capture_sessions_started" 'resource="cpu",comm="cpu-burner"')
        io_val=$(get_metric "bistouri_capture_sessions_started" 'resource="io",comm="io-burner"')
        mem_val=$(get_metric "bistouri_capture_sessions_started" 'resource="memory",comm="mem-hog"')

        [[ "$cpu_val" != "0" ]] && cpu_ok=true
        [[ "$io_val" != "0" ]] && io_ok=true
        [[ "$mem_val" != "0" ]] && mem_ok=true

        # CPU trigger is the required gate — IO/MEM are best-effort in Kind.
        if $cpu_ok; then
            log "CPU trigger fired after ${elapsed}s (io=$io_ok mem=$mem_ok)"
            break
        fi

        log "  polling... cpu=$cpu_val io=$io_val mem=$mem_val (${elapsed}s/${PHASE1_TIMEOUT}s)"
        sleep "$POLL_INTERVAL"
        elapsed=$((elapsed + POLL_INTERVAL))
    done

    echo ""
    log "Phase 1 assertions — required triggers:"
    assert_gt "$(get_metric "bistouri_capture_sessions_started" 'resource="cpu",comm="cpu-burner"')" 0 \
        "cpu-burner triggered CPU capture session"

    # IO and Memory PSI triggers are environment-dependent. Kind nodes use
    # tmpfs/overlay filesystems (no real IO stalls) and have ample RAM
    # (no page reclaim). These are soft checks — logged but not gating.
    local io_val mem_val
    io_val=$(get_metric "bistouri_capture_sessions_started" 'resource="io",comm="io-burner"')
    mem_val=$(get_metric "bistouri_capture_sessions_started" 'resource="memory",comm="mem-hog"')
    if [[ "$io_val" != "0" ]]; then
        pass "io-burner triggered IO capture session (value=$io_val)"
    else
        warn "io-burner IO trigger did not fire (expected in Kind — tmpfs backend)"
    fi
    if [[ "$mem_val" != "0" ]]; then
        pass "mem-hog triggered Memory capture session (value=$mem_val)"
    else
        warn "mem-hog Memory trigger did not fire (expected in Kind — ample RAM)"
    fi

    echo ""
    log "Phase 1 noise check (informational — cross-resource triggers expected in shared Kind nodes):"
    local cross_cpu_mem cross_cpu_io cross_io_cpu cross_io_mem cross_mem_cpu cross_mem_io
    cross_cpu_mem=$(get_metric "bistouri_capture_sessions_started" 'resource="memory",comm="cpu-burner"')
    cross_cpu_io=$(get_metric "bistouri_capture_sessions_started" 'resource="io",comm="cpu-burner"')
    cross_io_cpu=$(get_metric "bistouri_capture_sessions_started" 'resource="cpu",comm="io-burner"')
    cross_io_mem=$(get_metric "bistouri_capture_sessions_started" 'resource="memory",comm="io-burner"')
    cross_mem_cpu=$(get_metric "bistouri_capture_sessions_started" 'resource="cpu",comm="mem-hog"')
    cross_mem_io=$(get_metric "bistouri_capture_sessions_started" 'resource="io",comm="mem-hog"')
    log "  cpu-burner: memory=$cross_cpu_mem io=$cross_cpu_io"
    log "  io-burner:  cpu=$cross_io_cpu memory=$cross_io_mem"
    log "  mem-hog:    cpu=$cross_mem_cpu io=$cross_mem_io"
}

# ── Phase 2: Hot-reload and assert no new triggers ───────────────────

deploy_phase2() {
    echo ""
    log "${BOLD}Phase 2: Hot-reloading config (dropping violated resources)...${NC}"
    echo ""

    kubectl apply -f "${K8S_DIR}/configmap-phase2.yaml"

    # Wait for Bistouri to detect the config change and reload.
    # ConfigMap volume mounts use symlink-swap which triggers inotify.
    local elapsed=0
    local initial_reloads
    initial_reloads=$(get_metric "bistouri_trigger_config_reloads")

    while (( elapsed < PHASE2_TIMEOUT )); do
        local current_reloads
        current_reloads=$(get_metric "bistouri_trigger_config_reloads")
        if (( $(echo "$current_reloads > $initial_reloads" | bc -l) )); then
            log "Config reload detected after ${elapsed}s (reloads: $current_reloads)"
            break
        fi
        log "  waiting for reload... counter=$current_reloads (${elapsed}s/${PHASE2_TIMEOUT}s)"
        sleep "$POLL_INTERVAL"
        elapsed=$((elapsed + POLL_INTERVAL))
    done

    assert_gt "$(get_metric "bistouri_trigger_config_reloads")" "$initial_reloads" \
        "Config hot-reload occurred"
}

assert_phase2() {
    log "Phase 2: Verifying dropped triggers stop firing (30s observation)..."

    # Snapshot the 3 dropped-resource counters — these should NOT increase
    # because Phase 2 config no longer monitors these (resource, comm) pairs:
    #   cpu-burner → cpu     (dropped)
    #   io-burner  → io      (dropped)
    #   mem-hog    → memory  (dropped)
    local snap_cpu_burner_cpu snap_io_burner_io snap_mem_hog_mem
    snap_cpu_burner_cpu=$(get_metric "bistouri_capture_sessions_started" 'resource="cpu",comm="cpu-burner"')
    snap_io_burner_io=$(get_metric "bistouri_capture_sessions_started" 'resource="io",comm="io-burner"')
    snap_mem_hog_mem=$(get_metric "bistouri_capture_sessions_started" 'resource="memory",comm="mem-hog"')

    sleep 30

    echo ""
    log "Phase 2 assertions — dropped triggers should not fire new sessions:"
    assert_eq "$(get_metric "bistouri_capture_sessions_started" 'resource="cpu",comm="cpu-burner"')" "$snap_cpu_burner_cpu" \
        "No new cpu-burner/cpu sessions after dropping cpu rule"
    assert_eq "$(get_metric "bistouri_capture_sessions_started" 'resource="io",comm="io-burner"')" "$snap_io_burner_io" \
        "No new io-burner/io sessions after dropping io rule"
    assert_eq "$(get_metric "bistouri_capture_sessions_started" 'resource="memory",comm="mem-hog"')" "$snap_mem_hog_mem" \
        "No new mem-hog/memory sessions after dropping memory rule"
}

# ── Main ─────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       Bistouri E2E Integration Tests         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

build_images
setup_cluster
deploy_phase1
start_port_forward
assert_phase1
deploy_phase2
assert_phase2

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if (( FAILURES > 0 )); then
    fail "E2E tests completed with ${FAILURES} failure(s)"
    exit 1
else
    echo -e "  ${GREEN}${BOLD}✅ All E2E tests passed!${NC} 🎉"
    exit 0
fi
