# keylime-agent-rust.spec

%bcond_without check

%global crate keylime_agent

# Centos: Use bundled deps as it doesn't ship Rust libraries
%global bundled_rust_deps 1
%global __brp_mangle_shebangs_exclude_from ^/usr/src/debug/.*$

Name:           keylime-agent-rust
Version:        0.2.5
Release:        %{?autorelease}%{!?autorelease:1%{?dist}}
Summary:        Rust agent for Keylime

# Upstream license specification: Apache-2.0
#
# The build dependencies have the following licenses:
#
#   0BSD or MIT or ASL 2.0
#   ASL 2.0
#   ASL 2.0 or Boost
#   ASL 2.0 or MIT
#   ASL 2.0 with exceptions
#   BSD
#   MIT
#   MIT or ASL 2.0
#   MIT or ASL 2.0 or zlib
#   MIT or zlib or ASL 2.0
#   Unlicense or MIT
#   zlib or ASL 2.0 or MIT
#
License:        ASL 2.0 and BSD and MIT
URL:            https://github.com/keylime/rust-keylime/
Source0:        rust-keylime-v%{version}.tar.gz
# The vendor tarball is created using cargo-vendor-filterer to remove Windows
# related files (https://github.com/cgwalters/cargo-vendor-filterer)
#   tar xf rust-keylime-%%{version}.tar.gz
#   cd rust-keylime-%%{version}
#   cargo vendor-filterer --platform x86_64-unknown-linux-gnu \
#       --platform powerpc64le-unknown-linux-gnu \
#       --platform aarch64-unknown-linux-gnu \
#       --platform i686-unknown-linux-gnu \
#       --platform s390x-unknown-linux-gnu \
#       --exclude-crate-path "libloading#tests"
#   tar jcf rust-keylime-%%{version}-vendor.tar.xz vendor
Source1:        rust-keylime-vendor.tar.xz

ExclusiveArch:  %{rust_arches}

Requires: tpm2-tss
Requires: util-linux-core

# The keylime-base package provides the keylime user creation. It is available
# from Fedora 36
%if 0%{?fedora} >= 36 || 0%{?rhel} >= 9
Requires: keylime-base
%endif

BuildRequires:  systemd
BuildRequires:  openssl-devel
BuildRequires:  tpm2-tss-devel
BuildRequires:  clang
BuildRequires:  rust-toolset

# Virtual Provides to support swapping between Python and Rust implementation
Provides:       keylime-agent
Conflicts:      keylime-agent

%description
Rust agent for Keylime

%prep
%autosetup -n rust-keylime-%{version} -N
%autopatch -m 100 -p1
# Source1 is vendored dependencies
%cargo_prep -V 1

%build
%if 0%{?rhel} >= 10
%cargo_build -ftesting
%else
%cargo_build --features=testing
%endif

%install

mkdir -p %{buildroot}/%{_sharedstatedir}/keylime
mkdir -p --mode=0700 %{buildroot}/%{_rundir}/keylime
mkdir -p --mode=0700 %{buildroot}/%{_libexecdir}/keylime
mkdir -p --mode=0700  %{buildroot}/%{_sysconfdir}/keylime
mkdir -p --mode=0700  %{buildroot}/%{_sysconfdir}/keylime/agent.conf.d

install -Dpm 400 keylime-agent.conf \
    %{buildroot}%{_sysconfdir}/keylime/agent.conf

install -Dpm 644 ./dist/systemd/system/keylime_agent.service \
    %{buildroot}%{_unitdir}/keylime_agent.service

install -Dpm 644 ./dist/systemd/system/var-lib-keylime-secure.mount \
    %{buildroot}%{_unitdir}/var-lib-keylime-secure.mount

# Setting up the agent to use keylime:keylime user/group after dropping privileges.
cat > %{buildroot}/%{_sysconfdir}/keylime/agent.conf.d/001-run_as.conf << EOF
[agent]
run_as = "keylime:keylime"
EOF

install -Dpm 0755 \
    -t %{buildroot}%{_bindir} \
    ./target/release/keylime_agent
install -Dpm 0755 \
    -t %{buildroot}%{_bindir} \
    ./target/release/keylime_ima_emulator

%posttrans
chmod 500 %{_sysconfdir}/keylime/agent.conf.d
chmod 400 %{_sysconfdir}/keylime/agent.conf.d/*.conf
chmod 500 %{_sysconfdir}/keylime
chown -R keylime:keylime %{_sysconfdir}/keylime

%preun
%systemd_preun keylime_agent.service
%systemd_preun var-lib-keylime-secure.mount

%postun
%systemd_postun_with_restart keylime_agent.service
%systemd_postun_with_restart var-lib-keylime-secure.mount

%files
%license LICENSE
%doc README.md
%attr(500,keylime,keylime) %dir %{_sysconfdir}/keylime
%attr(500,keylime,keylime) %dir %{_sysconfdir}/keylime/agent.conf.d
%config(noreplace) %attr(400,keylime,keylime) %{_sysconfdir}/keylime/agent.conf.d/001-run_as.conf
%config(noreplace) %attr(400,keylime,keylime) %{_sysconfdir}/keylime/agent.conf
%{_unitdir}/keylime_agent.service
%{_unitdir}/var-lib-keylime-secure.mount
%attr(700,keylime,keylime) %dir %{_rundir}/keylime
%attr(700,keylime,keylime) %{_sharedstatedir}/keylime
%attr(700,keylime,keylime) %{_libexecdir}/keylime
%{_bindir}/keylime_agent
%{_bindir}/keylime_ima_emulator

%if %{with check}
%check
%cargo_test
%endif

%changelog
%autochangelog
