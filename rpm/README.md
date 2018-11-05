# Keylime RPM distribution

The Python version of the Keylime project (original repo by MIT Lincoln Labs
[here](https://github.com/mit-ll/python-keylime)) is available as a packaged
RPM. Installation instructions and related materials are available in this
directory.

## Installing Keylime using the RPM

The Keylime RPM is designed for use on CentOS 7 systems, and these
installation instructions will assume you're using that system. Either a
proper installation or a virtual machine should suffice.

### Cloning the repository

In a directory of your choice, use `git` to clone the `keylimeRPM` repo found 
[here](https://github.com/HuzefaMandvi/keylimeRPM). Once complete, change into
the new `keylimeRPM` directory.

### Upgrading Python 2.7

CentOS 7 currently uses an older version of Python 2.7 than Keylime
requires. Running the `python2714.sh` shell script will install a newer
version that will allow Keylime to work. To run the script, run 
`chmod +x python2714.sh` from within the `keylimeRPM` directory, and then run
`sudo ./python2714.sh`. Press `y` to accept any prompts if they come up.

### Install the RPM

Use `sudo rpm -ivh python-keylime-1.2-1.noarch.rpm` to install the RPM. Use
`y` to accept any prompts if they come up.

*Troubleshooting:* If the installation errors out saying that the
`python-devel` package is required by `keylime`, you will need to install that
package using `yum install python-devel`. Once finished, the RPM should
install with no issues.

### Install Keylime

The RPM installs Keylime to the `usr/bin/python-keylime` directory. Everything
needed to run Keylime can be found there. Execute Keylime installer to install
`Keylime` and `tmp4720` to your system.

```
$ cd /usr/bin/python-keylime
$ sudo ./install.sh
```

While installing keylime with tpm emulator, use `-s` flag for socket mode
installation. Typically, virtual machine needs to use tpm emulator.

```
$ cd /usr/bin/python-keylime
$ sudo ./install.sh -s
```

#### Reference

mit keylime tpm470 [repository](https://github.com/mit-ll/tpm4720-keylime)

mit python-keylime [repository](https://github.com/mit-ll/python-keylime)

python-keylime rpm install 
[repository](https://github.com/HuzefaMandvi/keylimeRPM)
