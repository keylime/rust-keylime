#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Keylime Authors

set -euf -o pipefail

echo "-------- Setting up Virtual TPM"
mkdir /tmp/tpmdir
swtpm_setup --tpm2 \
    --tpmstate /tmp/tpmdir \
    --createek --decryption --create-ek-cert \
    --create-platform-cert \
    --display
swtpm socket --tpm2 \
    --tpmstate dir=/tmp/tpmdir \
    --flags startup-clear \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --daemon
tpm2-abrmd \
    --logger=stdout \
    --tcti=swtpm: \
    --allow-root \
    --session \
    --flush-all &

echo "-------- Running clippy"
# The cargo denies are currently disabled, because that will require a bunch of dep cleanup
cargo clippy --all-targets --all-features -- -D clippy::all  # -D clippy::cargo

echo "-------- Building"
RUST_BACKTRACE=1 cargo build

echo "-------- Testing"
mkdir -p /var/lib/keylime
TCTI=tabrmd:bus_type=session RUST_BACKTRACE=1 RUST_LOG=info \
KEYLIME_CONFIG=$PWD/keylime-agent.conf \
cargo test --features testing -- --nocapture

echo "-------- Testing with coverage"
TCTI=tabrmd:bus_type=session RUST_BACKTRACE=1 RUST_LOG=info \
KEYLIME_CONFIG=$PWD/keylime-agent.conf \
cargo tarpaulin --verbose \
      --target-dir target/tarpaulin \
      --workspace \
      --exclude-files 'target/*' \
      --ignore-panics --ignore-tests \
      --out Html --out Json \
      --all-features \
      --engine llvm \
      -- --test-threads=1
