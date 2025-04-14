#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Keylime Authors

source ./tests/common_tests.sh || source ./common_tests.sh

echo "-------- Testing"
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
RUST_BACKTRACE=1 RUST_LOG=info \
KEYLIME_CONFIG=$PWD/keylime-agent.conf \
MOCKOON=1 cargo test --features testing -- --nocapture
