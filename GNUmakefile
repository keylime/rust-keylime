# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Keylime Authors

RELEASE ?= 0
TARGETDIR ?= target
CONFFILE ?= ./keylime-agent.conf

ifeq ($(RELEASE),1)
        PROFILE ?= release
        CARGO_ARGS = --release
else
        PROFILE ?= debug
        CARGO_ARGS =
endif

systemdsystemunitdir := $(shell pkg-config systemd --variable=systemdsystemunitdir)

programs = \
	${TARGETDIR}/${PROFILE}/keylime_agent \
	${TARGETDIR}/${PROFILE}/keylime_ima_emulator

.PHONY: all
all: $(programs)

$(programs):
	cargo build --target-dir="${TARGETDIR}" ${CARGO_ARGS}

.PHONY: clean
clean::
	${RM} -rf target

.PHONY: install
install: all
	mkdir -p ${DESTDIR}/etc/keylime/
	mkdir -p ${DESTDIR}/etc/keylime/agent.conf.d
	cp ${CONFFILE} ${DESTDIR}/etc/keylime/agent.conf
	for f in $(programs); do \
		install -D -t ${DESTDIR}/usr/bin "$$f"; \
	done
	install -D -m 644 -t ${DESTDIR}$(systemdsystemunitdir) dist/systemd/system/keylime_agent.service
	install -D -m 644 -t ${DESTDIR}$(systemdsystemunitdir) dist/systemd/system/var-lib-keylime-secure.mount
	# Remove when https://github.com/keylime/rust-keylime/issues/325 is fixed
	install -D -t ${DESTDIR}/usr/libexec/keylime keylime-agent/tests/actions/shim.py

# This only runs tests without TPM access. See tests/run.sh for
# running full testsuite with swtpm.
.PHONY: check
check: all
	cargo test --target-dir="${TARGETDIR}"
