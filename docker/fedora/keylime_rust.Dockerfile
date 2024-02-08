##############################################################################
# keylime TPM 2.0 Rust Dockerfile
#
# This file is for automatic test running of Keylime and rust-keylime.
# It is not recommended for use beyond testing scenarios.
##############################################################################

FROM fedora:latest
LABEL version="2.0.1" description="Keylime - Bootstrapping and Maintaining Trust in the Cloud"

# environment variables
ARG BRANCH=master
ENV RUST_KEYLIME_HOME ${HOME}/rust-keylime
ENV container docker
COPY dbus-policy.conf /etc/dbus-1/system.d/

# Install dev tools and libraries (includes openssl-devel)
RUN dnf groupinstall -y \
    "Development Tools" \
    "Development Libraries"

# Packaged dependencies
ENV PKGS_DEPS="automake \
cargo \
clang-devel \
dbus \
dbus-daemon \
dbus-devel \
dnf-plugins-core \
efivar-devel \
gcc \
git \
glib2-devel \
glib2-static \
gnulib \
kmod \
llvm llvm-devel \
libselinux-python3 \
libtool \
libtpms \
make \
openssl-devel \
redhat-rpm-config \
rust clippy cargo \
pkg-config \
swtpm \
swtpm-tools \
tpm2-abrmd \
tpm2-tools \
tpm2-tss \
tpm2-tss-devel \
uthash-devel \
czmq-devel"

RUN dnf makecache && \
  dnf -y install $PKGS_DEPS && \
  dnf clean all && \
  rm -rf /var/cache/dnf/*

# clone and build rust-keylime
WORKDIR ${RUST_KEYLIME_HOME}
RUN git clone https://github.com/keylime/rust-keylime.git && \
cd rust-keylime && \
make && \
make install && \
cargo clean
