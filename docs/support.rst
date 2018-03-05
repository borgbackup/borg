.. include:: global.rst.inc
.. _support:

Support
=======

Please first read the docs, the existing issue tracker issues and mailing
list posts -- a lot of stuff is already documented / explained / discussed /
filed there.

Issue Tracker
-------------

If you've found a bug or have a concrete feature request, please create a new
ticket on the project's `issue tracker`_.

For more general questions or discussions, IRC or mailing list are preferred.

Chat (IRC)
----------
Join us on channel #borgbackup on chat.freenode.net.

As usual on IRC, just ask or tell directly and then patiently wait for replies.
Stay connected.

You could use the following link (after connecting, you can change the random
nickname you get by typing "/nick mydesirednickname"):

http://webchat.freenode.net/?randomnick=1&channels=%23borgbackup&uio=MTY9dHJ1ZSY5PXRydWUa8

.. _mailing_list:

Mailing list
------------

To find out about the mailing list, its topic, how to subscribe, how to
unsubscribe and where you can find the archives of the list, see the
`mailing list homepage
<https://mail.python.org/mailman/listinfo/borgbackup>`_.

Twitter
-------

Follow @borgbackup for announcements. You can also add @borgbackup if you
would like to get retweeted for a borg related tweet.

Please understand that Twitter is not suitable for longer / more complex
discussions - use one of the other channels for that.

Bounties and Fundraisers
------------------------

We use `BountySource <https://www.bountysource.com/teams/borgbackup>`_ to allow
monetary contributions to the project and the developers, who push it forward.

There, you can give general funds to the borgbackup members (the developers will
then spend the funds as they deem fit). If you do not have some specific bounty
(see below), you can use this as a general way to say "Thank You!" and support
the software / project you like.

If you want to encourage developers to fix some specific issue or implement some
specific feature suggestion, you can post a new bounty or back an existing one
(they always refer to an issue in our `issue tracker`_).

As a developer, you can become a Bounty Hunter and win bounties (earn money) by
contributing to |project_name|, a free and open source software project.

We might also use BountySource to fund raise for some bigger goals.

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
