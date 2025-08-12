Borg native on Windows
======================

Running Borg natively on Windows is in an early alpha stage. Expect many things to fail.
Do not use the native Windows build on any data that you do not want to lose!

Build Requirements
------------------

- VC 14.0 Compiler
- OpenSSL Library v1.1.1c, 64-bit (available at https://github.com/python/cpython-bin-deps)
  Use the `win-download-openssl.ps1` script to download and extract the library to
  the correct location. See also the OpenSSL section below.
- Patience and a lot of coffee/beer

What's working
--------------

.. note::
   The following examples assume that the `BORG_REPO` and `BORG_PASSPHRASE` environment variables are set
   when the repository or passphrase is not explicitly provided.

- Borg does not crash if called with ``borg``
- ``borg init --encryption repokey-blake2 ./demoRepo`` runs without errors or warnings.
  Note that absolute paths only work if the protocol is explicitly set to ``file://``
- ``borg create ::backup-{now} D:\DemoData`` works as expected.
- ``borg list`` works as expected.
- ``borg extract --strip-components 1 ::backup-XXXX`` works.
  If absolute paths are extracted, it is important to pass ``--strip-components 1``,
  otherwise the data is restored to the original location!

What's NOT working
------------------

- Extracting a backup created on a Windows machine on a non-Windows machine will fail.
- Many other things.


OpenSSL, Windows and Python
---------------------------
Windows does not ship OpenSSL by default, so we need to get the library from somewhere else.
However, a default Python installation does include `libcrypto`, which is required by Borg.
The only things missing to build Borg are the header and `*.lib` files.
Luckily, the Python developers provide all required files in a separate repository.
The `win-download-openssl.ps1` script can be used to download the package from
https://github.com/python/cpython-bin-deps and extract the files to the correct location.
For Anaconda, the required libraries can be installed with ``conda install -c anaconda openssl``.

