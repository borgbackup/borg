Binary BorgBackup builds
========================

The binaries are supposed to work on the specified platform without installing
any dependencies.


Download the correct files
--------------------------

x86 / x86_64 architecture
~~~~~~~~~~~~~~~~~~~~~~~~~
borg-linuxnewer64   Linux 64bit (built on Debian 12 "Bookworm" with glibc 2.36)
                    Note: you can also try them on other older Linuxes - as
                    long as the glibc is compatible, they will work.
borg-linuxnew64     Linux 64bit (built on Debian 11 "Bullseye" with glibc 2.31)
                    Note: you can also try them on other older Linuxes - as
                    long as the glibc is compatible, they will work.
borg-linux64        Linux 64bit (built on Debian 10 "Buster" with glibc 2.28)
                    Note: you can also try them on other older Linuxes - as
                    long as the glibc is compatible, they will work.
borg-linuxold64     Linux 64bit (built on Debian 9 "Stretch" with glibc 2.24)
                    Note: you can also try them on other older Linuxes - as
                    long as the glibc is compatible, they will work.
borg-macos64        macOS (Darwin) 64bit (built on macOS Sierra 10.12
                    with latest macFUSE from brew, requires >= 10.12)
borg-freebsd64      FreeBSD 64bit (built on FreeBSD 13.1)
*.tgz               similar to above, but built as a directory with files,
                    not as a single self-extracting binary.
*.asc               GnuPG signatures for *


Verifying your download
-----------------------

Please check the GPG signature to make sure you received the binary as I have
built it.

To check the GPG signature, download both the binary and the corresponding
*.asc file and then (on the shell) type, e.g.:

    gpg --recv-keys 9F88FB52FAF7B393
    gpg --verify borg-linux64.asc borg-linux64

The files are signed by:

Thomas Waldmann <tw@waldmann-edv.de>
GPG key fingerprint: 6D5B EF9A DD20 7580 5747 B70F 9F88 FB52 FAF7 B393

My fingerprint is also in the footer of all my borgbackup mailing list posts.


Installing
----------

It is suggested that you rename or symlink the binary to just "borg".

On UNIX-like platforms, /usr/local/bin/ or ~/bin/ is a nice place for it,
but you can invoke it from every place by giving a full path to it.

Make sure the file is readable and executable (chmod +rx borg on UNIX-like
platforms).


Reporting issues
----------------
If you find issues, please open a ticket on our issue tracker:

https://github.com/borgbackup/borg/issues/

There, please give:
- the version number (it is displayed if you invoke borg -V)
- the sha256sum of the binary
- a good description of what the issue is
- a good description of how to reproduce your issue
- a traceback with system info (if you have one)
- your precise platform (CPU, 32/64bit?), OS, distribution, release
- your python and (g)libc version

