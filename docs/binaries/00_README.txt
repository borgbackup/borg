Binary BorgBackup builds
========================

The binaries are supposed to work on the specified platform without installing
any dependencies.


Download the correct files
--------------------------

AMD64/x86_64 architecture
~~~~~~~~~~~~~~~~~~~~~~~~~~~

borg-linux-glibc236 Linux (built on Debian 12 "Bookworm" with glibc 2.36)
borg-linux-glibc231 Linux (built on Debian 11 "Bullseye" with glibc 2.31)
borg-linux-glibc228 Linux (built on Debian 10 "Buster" with glibc 2.28)
                    Note: You can also try them on other Linux distributions with different glibc
                    versions - as long as glibc is compatible, they will work.
                    If it doesn't work, try a Borg 1.2.x binary.

borg-macos1012      macOS (built on macOS Sierra 10.12 with the latest macFUSE from Homebrew)
                    To avoid signing issues, download the file via the command line OR
                    remove the "quarantine" attribute after downloading:
                    $ xattr -dr com.apple.quarantine borg-macos1012.tgz

borg-freebsd13      FreeBSD (built on FreeBSD 13)
borg-freebsd14      FreeBSD (built on FreeBSD 14)

*.tgz               Similar to the above, but built as a directory with files,
                    not as a single self-extracting binary. Using the directory
                    build is faster and does not require as much space in the temporary
                    directory as the one-file build.
*.asc               GnuPG signatures for *


Verifying your download
-----------------------

Please check the GPG signature to make sure you received the binary as I have
built it.

To check the GPG signature, download both the binary and the corresponding
*.asc file and then (on the shell) type, for example:

    gpg --recv-keys 9F88FB52FAF7B393
    gpg --verify borg-freebsd.asc borg-freebsd

The files are signed by:

Thomas Waldmann <tw@waldmann-edv.de>
GPG key fingerprint: 6D5B EF9A DD20 7580 5747 B70F 9F88 FB52 FAF7 B393

My fingerprint is also in the footer of all my BorgBackup mailing list posts.


Installing
----------

It is suggested that you rename or symlink the binary to just "borg".
If you need "borgfs", just also symlink it to the same binary, it will
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

