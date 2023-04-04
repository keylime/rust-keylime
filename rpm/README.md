# Keylime testing RPM

The specfiles in this directory are used to build RPM packages on Copr using
packit for testing purposes.  Do not use the RPM built using these files in a
production environment.

The goal is to avoid recompiling the project multiple times during testing.

The binaries in the test RPM are build with the `testing` feature enabled.
