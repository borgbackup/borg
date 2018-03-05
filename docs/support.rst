.. _support:

Support
=======

Support and Services
--------------------

Please see https://www.borgbackup.org/ for free and paid support and service options.


.. _security-contact:

Security
--------

In case you discover a security issue, please use this contact for reporting it privately
and please, if possible, use encrypted E-Mail:

Thomas Waldmann <tw@waldmann-edv.de>

GPG Key Fingerprint: 6D5B EF9A DD20 7580 5747  B70F 9F88 FB52 FAF7 B393

The public key can be fetched from any GPG keyserver, but be careful: you must
use the **full fingerprint** to check that you got the correct key.

Verifying signed releases
-------------------------

`Releases <https://github.com/borgbackup/borg/releases>`_ are signed with the same GPG key and a .asc file is provided for each binary.

To verify a signature, the public key needs to be known to GPG. It can be imported into the local keystore from a keyserver with the fingerprint::

      gpg --recv-keys "6D5B EF9A DD20 7580 5747 B70F 9F88 FB52 FAF7 B393"

If GPG successfully imported the key, the output should be (among other things): 'Total number processed: 1'.

To verify for example the signature of the borg-linux64 binary::

      gpg --verify borg-linux64.asc

GPG outputs if it finds a good signature. The output should look similar to this::

      gpg: Signature made Sat 30 Dec 2017 01:07:36 PM CET using RSA key ID 51F78E01
      gpg: Good signature from "Thomas Waldmann <email>"
      gpg: aka "Thomas Waldmann <email>"
      gpg: aka "Thomas Waldmann <email>"
      gpg: aka "Thomas Waldmann <email>"
      gpg: WARNING: This key is not certified with a trusted signature!
      gpg: There is no indication that the signature belongs to the owner.
      Primary key fingerprint: 6D5B EF9A DD20 7580 5747 B70F 9F88 FB52 FAF7 B393
      Subkey fingerprint: 2F81 AFFB AB04 E11F E8EE 65D4 243A CFA9 51F7 8E01

If you want to make absolutely sure that you have the right key, you need to verify it via another channel and assign a trust-level to it.
