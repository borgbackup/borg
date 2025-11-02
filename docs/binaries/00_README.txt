Binary BorgBackup builds
========================

General notes
-------------

The binaries are supposed to work on the specified platform without installing anything else.

There are some limitations, though:
- for Linux, your system must have the same or newer glibc version as the one used for building
- for macOS, you need to have the same or newer macOS version as the one used for building
- for other OSes, there are likely similar limitations

If you don't find something working on your system, check the older borg releases.

*.asc are GnuPG signatures - only provided for locally built binaries.
*.exe (or no extension) is the single-file fat binary.
*.tgz is the single-directory fat binary (extract it once with tar -xzf).

Using the single-directory build is faster and does not require as much space
in the temporary directory as the self-extracting single-file build.

macOS: to avoid issues, download the file via the command line OR remove the
       "quarantine" attribute after downloading:
       $ xattr -dr com.apple.quarantine borg-macos1012.tgz


Download the correct files
--------------------------

Binaries built on GitHub servers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

borg-linux-glibc235-x86_64-gh Linux AMD/Intel (built on Ubuntu 22.04 LTS with glibc 2.35)
borg-linux-glibc235-arm64-gh  Linux ARM (built on Ubuntu 22.04 LTS with glibc 2.35)

borg-macos-14-arm64-gh        macOS Apple Silicon (built on macOS 14 w/o FUSE support)
borg-macos-13-x86_64-gh       macOS Intel (built on macOS 13 w/o FUSE support)


Binaries built locally
~~~~~~~~~~~~~~~~~~~~~~

borg-linux-glibc241-x86_64 Linux (built on Debian 13 "Trixie" with glibc 2.41)
borg-linux-glibc236-x86_64 Linux (built on Debian 12 "Bookworm" with glibc 2.36)
borg-linux-glibc231-x86_64 Linux (built on Debian 11 "Bullseye" with glibc 2.31)

borg-freebsd-14-x86_64     FreeBSD (built on FreeBSD 14)

Note: if you don't find a specific binary here, check release 1.4.1 or 1.2.9.

Verifying your download
-----------------------

I provide GPG signatures for files which I have built locally on my machines.

To check the GPG signature, download both the file and the corresponding
signature (*.asc file) and then (on the shell) type, for example:

    gpg --recv-keys 9F88FB52FAF7B393
    gpg --verify borgbackup.tar.gz.asc borgbackup.tar.gz

The files are signed by:

Thomas Waldmann <tw@waldmann-edv.de>
GPG key fingerprint: 6D5B EF9A DD20 7580 5747 B70F 9F88 FB52 FAF7 B393

My fingerprint is also in the footer of all my BorgBackup mailing list posts.


Provenance attestations for GitHub-built binaries
-------------------------------------------------

For binaries built on GitHub (files with a "-gh" suffix in the name), we publish
an artifact provenance attestation that proves the binary was built by our
GitHub Actions workflow from a specific commit or tag. You can verify this using
the GitHub CLI (gh). Install it from https://cli.github.com/ and make sure you
use a recent version that supports "gh attestation".

Practical example (Linux, 2.0.0b20 tag):

    curl -LO https://github.com/borgbackup/borg/releases/download/2.0.0b20/borg-linux-glibc235-x86_64-gh
    gh attestation verify --repo borgbackup/borg --ref 2.0.0b20 ./borg-linux-glibc235-x86_64-gh

If verification succeeds, gh prints a summary stating the subject (your file),
that it was attested by GitHub Actions, and the job/workflow reference.


Installing
----------

It is suggested that you rename or symlink the binary to just "borg".
If you need "borgfs", just also symlink it to the same binary; it will
detect internally under which name it was invoked.

On UNIX-like platforms, /usr/local/bin/ or ~/bin/ is a nice place for it,
but you can invoke it from anywhere by providing the full path to it.

Make sure the file is readable and executable (chmod +rx borg on UNIX-like
platforms).


Reporting issues
----------------

Please first check the FAQ and whether a GitHub issue already exists.

If you find a NEW issue, please open a ticket on our issue tracker:

https://github.com/borgbackup/borg/issues/

There, please give:
- the version number (it is displayed if you invoke borg -V)
- the sha256sum of the binary
- a good description of what the issue is
- a good description of how to reproduce your issue
- a traceback with system info (if you have one)
- your precise platform (CPU, 32/64-bit?), OS, distribution, release
- your Python and (g)libc versions

