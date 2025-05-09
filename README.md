# Keylime

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202-blue)](https://www.apache.org/licenses/LICENSE-2.0)

## Overview

This is a Rust implementation of
[keylime](https://github.com/keylime/keylime) agent. Keylime is system
integrity monitoring system that has the following features:

* Exposes TPM trust chain for higher-level use
* Provides an end-to-end solution for bootstrapping node cryptographic
  identities
* Securely monitors system integrity

For more information, visit the [keylime website](https://keylime.dev)

For now, this project is focusing on the keylime agent component, which is a
HTTP server running on the machine that executes keylime operations.
Most keylime operations rely on TPM co-processor; therefore, the server needs
a physical TPM chip (or a TPM emulator) to perform keylime operations.  The
TPM emulator is a program that runs in the daemon to mimic TPM commands.

The rust-keylime agent is the official agent (starting with version 0.1.0) and
replaces the Python implementation.

## Prerequisites

### Required Packages

#### Fedora

The following packages are required for building:

* `clang`
* `openssl-devel`
* `tpm2-tss-devel`
* (optional for the `with-zmq` feature): `zeromq-devel`

To install, use the following command:
```
$ dnf install clang openssl-devel tpm2-tss-devel zeromq-devel
```

For runtime, the following packages are required:

* `openssl`
* `tpm2-tss`
* `systemd` (to run as systemd service)
* `util-linux-core` (for the `mount` command)
* (optional for the `with-zmq` feature): `zeromq`

#### Debian and Ubuntu

For Debian and Ubuntu, use the following packages are required:

* `libclang-dev`
* `libssl-dev`
* `libtss2-dev`
* `pkg-config`
* (optional for the `with-zmq` feature): `libzmq3-dev`

To install, use the following command:

```
$ apt-get install libclang-dev libssl-dev libtss2-dev libzmq3-dev pkg-config
```

For runtime, the following packages are required:

* `coreutils` (for the `mount` command)
* `libssl`
* `libtss2-esys-3.0.2-0`
* (optional for the `with-zmq` feature): `libzmq3`
* `systemd` (to run as systemd service)

### Rust

Make sure Rust is installed before running Keylime. Installation
instructions can be found [here](https://www.rust-lang.org/en-US/install.html).

## Logging env

To run with `pretty-env-logger` trace logging active, set cargo run
within `RUST_LOG`, as follows:

    $ RUST_LOG=keylime_agent=trace cargo run --bin keylime_agent

## Testing

Unit tests are gating in CI for new code submission.  To run them:

```
$ cargo test
```
In case you want to execute [Mockoon](https://mockoon.com/) based tests, you need to follow two steps:

1. Start Mockoon with [appropriate configuration file](https://github.com/keylime/rust-keylime/blob/master/keylime-push-model-agent/test-data/verifier.json) on port 3000
2. Execute tests through MOCKOON environment variable:

```
$ MOCKOON=1 cargo test
```

## Running agent as a systemd-managed service

To make deployment and management of the service easier, this crate
comes with a Makefile and systemd unit file.

To install the executables and the unit file, do:

```console
$ make
$ sudo make install
```

Then you should be able to start the service with:

```console
$ sudo systemctl start keylime_agent
```

## Building Debian package with cargo-deb

Cargo deb requires Rust 1.60, so on Debian you need to install it first from rustup.rs.

```shell
# Install cargo-deb
rustup update
cargo install cargo-deb

# Build Debian package
cargo deb -p keylime_agent
```
