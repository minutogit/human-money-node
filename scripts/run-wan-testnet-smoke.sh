#!/usr/bin/env bash
# HuMoCo Layer-2 Multi-Process Daemon Cluster & WAN Testnet Smoke Test (Milestone M5.1 / NODE-002)
#
# Validates real multi-process OS daemon execution over loopback QUIC and HTTP RPC,
# testing cluster peering, quorum persistence, idempotent replays, conflict handling,
# graceful shutdown, and offline database compaction.
#
# Optional WAN Emulation:
# Simulates WAN conditions (latency 60ms ± 15ms, 1% packet loss) on loopback using Linux netem:
#   sudo tc qdisc add dev lo root netem delay 60ms 15ms loss 1%
# Or run without root using an unprivileged network namespace via unshare:
#   ./scripts/run-wan-testnet-smoke.sh --netem
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${WORKSPACE_ROOT}"

echo "=================================================================="
echo " HuMoCo M5.1 Multi-Process Cluster & WAN Testnet Smoke Test"
echo "=================================================================="

# Check if WAN emulation mode is requested
USE_NETEM=0
if [[ "${1:-}" == "--netem" || "${1:-}" == "--wan" || "${WAN_NETEM:-0}" == "1" ]]; then
    USE_NETEM=1
fi

# Step 1: Ensure humoco daemon binary is compiled
echo "==> Building humoco daemon binary..."
cargo build -p humoco-node --bin humoco

# Step 2: Run test with or without netem network namespace
if [[ "${USE_NETEM}" -eq 1 ]]; then
    echo "==> WAN netem emulation requested (delay 60ms 15ms loss 1%)..."
    if command -v unshare >/dev/null 2>&1 && command -v tc >/dev/null 2>&1; then
        echo "==> Launching in isolated network namespace via 'unshare -rn'..."
        exec unshare -rn bash -c '
            set -euo pipefail
            ip link set dev lo up
            tc qdisc add dev lo root netem delay 60ms 15ms loss 1%
            echo "==> Netem active on loopback interface inside isolated namespace:"
            tc qdisc show dev lo
            cargo test -p humoco-node --test multiprocess_cluster_wan_tests -- --nocapture
        '
    else
        echo "WARNING: 'unshare' or 'tc' utility not available or unprivileged namespaces not supported."
        echo "Falling back to standard localhost execution without netem..."
        exec cargo test -p humoco-node --test multiprocess_cluster_wan_tests -- --nocapture
    fi
else
    echo "==> Running multi-process cluster test (standard localhost mode)..."
    echo "    (Tip: Pass --netem or set WAN_NETEM=1 to emulate 60ms±15ms WAN latency and 1% loss)"
    exec cargo test -p humoco-node --test multiprocess_cluster_wan_tests -- --nocapture
fi
