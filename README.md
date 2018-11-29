# Keylime

[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

## Overview

This is a Rust implementation of
[python-keylime](https://github.com/mit-ll/python-keylime) from MIT Lincoln
Lab.  Keylime is system integrity monitoring system that has the following
features:

* Exposes TPM trust chain for higher-level use
* Provides an end-to-end solution for bootstrapping node cryptographic
  identities
* Securely monitors system integrity

For more information, see the original python implementation repo and paper in
the References section.

For now, this project is focusing on the keylime node component, which is a
HTTP server running on the server machine that executes keylime operations.
Most keylime operations reply on TPM co-processor; therefore, the server needs
a physical TPM chip (or a TPM emulator) to perform keylime operations.  The
TPM emulator is a program that runs in the deamon to mimic TPM commands.

## Prerequisite

**Rust** Make sure Rust is installed before running Keylime. Installation
instructions can be found [here]
(https://www.rust-lang.org/en-US/install.html).

**TPM** The `TPM4720` package is required to use Keylime.  It can be found at
[mit-ll/tpm4720-keylime]((https://github.com/mit-ll/tpm4720-keylime). `TPM4720`
supports systems that have physical TPM chips, and can also provide a TPM
emulator.

## Installation

**TPM4720 Emulator on Fedora-28** To install TPM4720, run the following script
to install TPM4720 in mit-ll/tpm4720-keylime
[repo](https://github.com/mit-ll/tpm4720-keylime) root directory as root to
install tpm emulator into you system.  We have tested it with Fedora 28; it
may or may not work with other environments.

```
$ cd scripts/
$ sudo bash install-fedora-28.sh
```

## Testing

Unit tests are gating in CI for new code submission.  To run them:

```
$ cargo test
```

## References
1. Keylime Paper: [here]
(https://github.com/mit-ll/python-keylime/blob/master/doc/tci-acm.pdf)
2. python-keylime: [here](https://github.com/mit-ll/python-keylime)
3. TPM4720: [here](https://github.com/mit-ll/tpm4720-keylime)
