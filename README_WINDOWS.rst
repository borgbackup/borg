Borg Native on Windows
======================

Running borg natively on windows is in a early alpha stage. Expect many things to fail.
Do not use the native windows build on any data which you do not want to lose!

Build Requirements
------------------

- VC 14.0 Compiler
- OpenSSL Library v1.1.1c, 64bit (available at https://slproweb.com/products/Win32OpenSSL.html)
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
  otherwise the data is resotred to the original location!

What's NOT working
------------------

- Extracting a backup which was created on windows machine on a non windows machine will fail.
- And many things more.
