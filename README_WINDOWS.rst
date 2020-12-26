Borg Native on Windows
======================

Running borg natively on windows is in a early alpha stage. Expect many things to fail.
Do not use the native windows build on any data which you do not want to lose!

Build Requirements
------------------

- VC 14.0 Compiler
- OpenSSL Library v1.1.1c, 64bit (available at https://github.com/python/cpython-bin-deps)
  Please use the `win-download-openssl.ps1` script to download and extract the library to
  the correct location. See also the OpenSSL section below.
- Patience and a lot of coffee / beer

What's working
--------------

.. note::
   The following examples assume that the `BORG_REPO` and `BORG_PASSPHRASE` environment variables are set
   if the repo or passphrase is not explicitly given.

- Borg does not crash if called with ``borg``
- ``borg init --encryption repokey-blake2 ./demoRepo`` runs without an error/warning.
  Note that absolute paths only work if the protocol is explicitly set to file://
- ``borg create ::backup-{now} D:\DemoData`` works as expected.
- ``borg list`` works as expected.
- ``borg extract --strip-components 1 ::backup-XXXX`` works. 
  If absolute paths are extracted, it's important to pass ``--strip-components 1`` as
  otherwise the data is restored to the original location!

What's NOT working
------------------

- Extracting a backup which was created on windows machine on a non windows machine will fail.
- And many things more.


OpenSSL, Windows and Python
---------------------------
Windows does not ship OpenSSL by default, so we need to get the library from somewhere else.
However, a default python installation does include `libcrypto` which is required by borg.
The only things which are missing to build borg are the header and `*.lib` files.
Luckily the python developers provide all required files in a separate repository.
The `win-download-openssl.ps1` script can be used to download the package from
https://github.com/python/cpython-bin-deps and extract the files to the correct location.
For Anaconda, the required libraries can be installed with `conda install -c anaconda openssl`.

