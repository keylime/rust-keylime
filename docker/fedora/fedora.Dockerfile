FROM fedora:32

# Install dev tools and libraries (includes openssl-devel)
RUN dnf groupinstall -y \
    "Development Tools" \
    "Development Libraries"

# Install additional packages
RUN dnf install -y \
    clang-devel \
    kmod \
    libtpms \
    swtpm \
    swtpm-tools \
    tpm2-tss-devel

# Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
