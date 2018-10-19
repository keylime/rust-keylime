%define name python-keylime
%define version 1.2 
%define unmangled_version 1.2 
%define release 1

Summary: TPM-based key bootstrapping and system integrity measurement system
for cloud
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}.tar
License: BSD-2-Clause
BuildArch: noarch
Group: Development/Libraries
Vendor: MIT Lincoln Laboratory <nabil@ll.mit.edu>
Url: https://github.com/mit-ll/python-keylime
AutoReq: no
Requires: epel-release, git, wget, python-setuptools >= 0.7, python-devel,
gcc, automake, gcc-c++, openssl, openssl-devel, libtool

#%define PipRequires m2crypto pycryptodomex tornado zmq

%description
This library provides a cloud verifier infrastructure to derive keys
from TPMs in the cloud.

%prep
#%setup -q -n %{name}

%install
mkdir -p %{buildroot}%{_bindir}
cp %{SOURCE0} %{buildroot}%{_bindir}
cd %{buildroot}%{_bindir}
tar -xf %{name}.tar
rm %{name}.tar

%post
#pip2.7 install %{PipRequires} --user
cd %{_bindir}/%{name}
sudo sh installer.sh -co

%files
%{_bindir}/%{name}/*

%changelog
* Wed Jul 18 2018 Huzefa Mandviwala <huzefam@bu.edu> 1.2-1
– Initial Packaging
