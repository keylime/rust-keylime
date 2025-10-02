#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025 Keylime Authors
#
# Script to run Mockoon-based registrar integration tests
# This script starts a Mockoon server on port 3001 with the registrar configuration
# and runs the integration tests that require a mock registrar server

source ./tests/common_tests.sh || source ./common_tests.sh

echo "-------- Testing Registrar with Mockoon"
start_swtpm

# Check that tpm2-openssl provider is available
if openssl list -provider tpm2 -providers > /dev/null; then
    # If any IAK/IDevID related certificate is missing, re-generate them
    if [[ ( ! -f "${IAK_IDEVID_CERTS}/iak.cert.pem" ) ||
        ( ! -f "${IAK_IDEVID_CERTS}/iak.cert.der" ) ||
        ( ! -f "${IAK_IDEVID_CERTS}/idevid.cert.pem" ) ||
        ( ! -f "${IAK_IDEVID_CERTS}/idevid.cert.der" ) ||
        ( ! -f "${IAK_IDEVID_CERTS}/ca-cert-chain.pem" ) ]]
    then
        # Remove any leftover from old certificates
        rm -rf "${IAK_IDEVID_CERTS}"
        mkdir -p "${IAK_IDEVID_CERTS}"
        echo "-------- Create IAK/IDevID certificates"
        "${GIT_ROOT}/tests/generate-iak-idevid-certs.sh" -o "${IAK_IDEVID_CERTS}"
    fi
fi

mkdir -p /var/lib/keylime

# Function to log detailed information about port 3001 usage
log_port_3001_info() {
    echo "======== DETAILED PORT 3001 ANALYSIS ========"
    echo "Timestamp: $(date)"
    echo "Environment: CI=${CI:-false}, GITHUB_ACTIONS=${GITHUB_ACTIONS:-false}"
    echo ""

    echo "--- lsof output for port 3001 ---"
    if command -v lsof >/dev/null 2>&1; then
        lsof -i :3001 2>/dev/null || echo "No lsof results for port 3001"
        echo ""
        echo "--- lsof with process details ---"
        lsof -i :3001 -P -n 2>/dev/null || echo "No detailed lsof results"
    else
        echo "lsof command not available"
    fi
    echo ""

    echo "--- netstat output ---"
    if command -v netstat >/dev/null 2>&1; then
        netstat -tulpn 2>/dev/null | grep ':3001' || echo "No netstat results for port 3001"
    else
        echo "netstat command not available"
    fi
    echo ""

    echo "--- ss (socket statistics) output ---"
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn 2>/dev/null | grep ':3001' || echo "No ss results for port 3001"
    else
        echo "ss command not available"
    fi
    echo ""

    echo "--- Process tree and details ---"
    if lsof -i :3001 >/dev/null 2>&1; then
        echo "Processes using port 3001:"
        for pid in $(lsof -ti :3001 2>/dev/null); do
            echo "  PID: $pid"
            if [ -d "/proc/$pid" ]; then
                echo "    Command: $(cat "/proc/$pid/comm" 2>/dev/null || echo 'N/A')"
                echo "    Cmdline: $(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo 'N/A')"
                echo "    User: $(stat -c '%U' "/proc/$pid" 2>/dev/null || echo 'N/A')"
                echo "    Parent PID: $(awk '{print $4}' < "/proc/$pid/stat" 2>/dev/null || echo 'N/A')"
                echo "    Start time: $(stat -c '%Y' "/proc/$pid" 2>/dev/null | xargs -I {} date -d @{} 2>/dev/null || echo 'N/A')"
                echo "    Working directory: $(readlink "/proc/$pid/cwd" 2>/dev/null || echo 'N/A')"
                echo "    Environment (filtered):"
                grep -E "(MOCKOON|NODE|NPM|PATH|USER|HOME)" "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | sed 's/^/      /' || echo "      N/A"
            else
                echo "    Process details not available (proc not mounted or process gone)"
            fi
            echo ""
        done
    fi

    echo "--- Process list (mockoon related) ---"
    pgrep -f -l mockoon 2>/dev/null || echo "No mockoon processes found"
    echo ""

    echo "--- Process list (node related on port 3001) ---"
    { pgrep -f -l node 2>/dev/null; pgrep -f -l npm 2>/dev/null; } | sort -u || echo "No node/npm processes found"
    echo ""

    echo "--- Docker containers (if running in container) ---"
    if command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then
        docker ps | grep -E "(mockoon|3001)" || echo "No docker containers with mockoon or port 3001"
    else
        echo "Docker not available or not accessible"
    fi
    echo ""

    echo "--- Systemd services (if available) ---"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service | grep -i mockoon || echo "No systemd mockoon services"
    else
        echo "systemctl not available"
    fi
    echo ""

    echo "--- HTTP response test ---"
    if curl -s --connect-timeout 2 http://localhost:3001 2>/dev/null; then
        echo "HTTP response received from port 3001"
        echo "Response headers:"
        curl -sI --connect-timeout 2 http://localhost:3001 2>/dev/null || echo "Failed to get headers"
    else
        echo "No HTTP response from port 3001"
    fi
    echo ""

    echo "======== END PORT 3001 ANALYSIS ========"
}

# Check if Mockoon is already running on port 3001 (e.g., in CI)
# Try multiple methods to detect if port 3001 is in use
PORT_IN_USE=false
if lsof -i :3001 > /dev/null 2>&1; then
    PORT_IN_USE=true
elif netstat -ln 2>/dev/null | grep -q ':3001 '; then
    PORT_IN_USE=true
elif ss -ln 2>/dev/null | grep -q ':3001 '; then
    PORT_IN_USE=true
elif curl -s --connect-timeout 2 http://localhost:3001 > /dev/null 2>&1; then
    PORT_IN_USE=true
fi

if $PORT_IN_USE; then
    echo "-------- Mockoon already running on port 3001 (likely in CI)"
    log_port_3001_info
    MOCKOON_PID=""
else
    # Check if Mockoon is installed for local runs
    if ! command -v mockoon-cli &> /dev/null; then
        echo "Error: mockoon-cli is not installed"
        echo "Install it with: npm install -g @mockoon/cli"
        exit 1
    fi

    # Start Mockoon server with registrar configuration on port 3001
    echo "-------- Starting Mockoon server on port 3001 with registrar configuration"
    REGISTRAR_JSON="${GIT_ROOT}/keylime-push-model-agent/test-data/registrar.json"

    if [ ! -f "$REGISTRAR_JSON" ]; then
        echo "Error: Registrar configuration file not found at $REGISTRAR_JSON"
        exit 1
    fi

    # Start Mockoon in the background
    mockoon-cli start --data "$REGISTRAR_JSON" --port 3001 &
    MOCKOON_PID=$!

    # Wait for Mockoon to start
    echo "Waiting for Mockoon server to start..."
    sleep 3

    # Check if Mockoon is running
    if ! kill -0 $MOCKOON_PID 2>/dev/null; then
        echo "Error: Mockoon failed to start"
        exit 1
    fi

    echo "Mockoon server started with PID $MOCKOON_PID"
fi

# Run tests with MOCKOON_REGISTRAR environment variable set
echo "-------- Running registrar tests with Mockoon"
RUST_BACKTRACE=1 RUST_LOG=info \
KEYLIME_CONFIG=$PWD/keylime-agent.conf \
MOCKOON_REGISTRAR=1 cargo test --features testing test_mockoon_registrar -- --nocapture

# Capture test exit code
TEST_EXIT_CODE=$?

# Stop Mockoon server only if we started it locally
if [ -n "$MOCKOON_PID" ]; then
    echo "-------- Stopping Mockoon server"
    kill $MOCKOON_PID 2>/dev/null || true
    wait $MOCKOON_PID 2>/dev/null || true

    # Check if port 3001 is still in use and force cleanup if needed
    PORT_STILL_IN_USE=false
    if lsof -i :3001 > /dev/null 2>&1; then
        PORT_STILL_IN_USE=true
    elif netstat -ln 2>/dev/null | grep -q ':3001 '; then
        PORT_STILL_IN_USE=true
    elif ss -ln 2>/dev/null | grep -q ':3001 '; then
        PORT_STILL_IN_USE=true
    fi

    if $PORT_STILL_IN_USE; then
        echo "Warning: Port 3001 still in use after stopping Mockoon, forcing cleanup"
        echo "---- Port 3001 status before cleanup ----"
        log_port_3001_info

        echo "---- Performing cleanup ----"
        lsof -ti :3001 | xargs kill -9 2>/dev/null || true
        # Additional cleanup methods
        pkill -f "mockoon-cli.*3001" 2>/dev/null || true
        pkill -f "node.*mockoon.*3001" 2>/dev/null || true

        # Wait a moment and check again
        sleep 2
        echo "---- Port 3001 status after cleanup ----"
        if lsof -i :3001 >/dev/null 2>&1 || netstat -ln 2>/dev/null | grep -q ':3001 ' || ss -ln 2>/dev/null | grep -q ':3001 '; then
            echo "WARNING: Port 3001 still in use after cleanup attempts"
            log_port_3001_info
        else
            echo "Port 3001 successfully cleaned up"
        fi
    fi
else
    echo "-------- Mockoon was already running (CI), not stopping it"
fi

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "-------- Registrar Mockoon tests PASSED"
else
    echo "-------- Registrar Mockoon tests FAILED with exit code $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
