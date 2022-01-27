# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Keylime Authors

RELEASE ?= 0
TARGETDIR ?= target

ifeq ($(RELEASE),1)
        PROFILE ?= release
        CARGO_ARGS = --release
else
        PROFILE ?= debug
        CARGO_ARGS =
endif

systemdsystemunitdir := $(shell pkg-config systemd --variable=systemdsystemunitdir)

.PHONY: all

.PHONY: build
build:
	cargo build --target-dir="${TARGETDIR}" ${CARGO_ARGS}

.PHONY: install
install: build
	install -D -t ${DESTDIR}/usr/bin "${TARGETDIR}/${PROFILE}/keylime_agent"
	install -D -t ${DESTDIR}/usr/bin "${TARGETDIR}/${PROFILE}/keylime_ima_emulator"
	install -D -m 644 -t ${DESTDIR}$(systemdsystemunitdir) dist/systemd/system/keylime_agent.service

# This only runs tests without TPM access. See tests/run.sh for
# running full testsuite with swtpm.
.PHONY: check
check: build
	cargo test --target-dir="${TARGETDIR}"
