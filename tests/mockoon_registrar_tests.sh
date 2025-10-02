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

# Check if Mockoon is already running on port 3001 (e.g., in CI)
if lsof -i :3001 > /dev/null 2>&1; then
    echo "-------- Mockoon already running on port 3001 (likely in CI)"
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
    if lsof -i :3001 > /dev/null 2>&1; then
        echo "Warning: Port 3001 still in use, forcing cleanup"
        lsof -ti :3001 | xargs kill -9 2>/dev/null || true
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
