.. include:: transfer.rst.inc

Examples
~~~~~~~~
::

    # 0. Have borg 2.0 installed on client AND server, have a b12 repo copy for testing.

    # 1. Create a new "related" repository:
    # here, the existing borg 1.2 repo used repokey-blake2 (and aes-ctr mode),
    # thus we use repokey-blake2-aes-ocb for the new borg 2.0 repo.
    # staying with the same chunk id algorithm (blake2) and with the same
    # key material (via --other-repo <oldrepo>) will make deduplication work
    # between old archives (copied with borg transfer) and future ones.
    # the AEAD cipher does not matter (everything must be re-encrypted and
    # re-authenticated anyway), you could also choose repokey-blake2-chacha20-poly1305.
    # in case your old borg repo did not use blake2, just remove the "-blake2".
    $ borg --repo       ssh://borg2@borgbackup/./tests/b20 rcreate \
           --other-repo ssh://borg2@borgbackup/./tests/b12 -e repokey-blake2-aes-ocb

    # 2. Check what and how much it would transfer:
    $ borg --repo       ssh://borg2@borgbackup/./tests/b20 transfer --upgrader=From12To20 \
           --other-repo ssh://borg2@borgbackup/./tests/b12 --dry-run

    # 3. Transfer (copy) archives from old repo into new repo (takes time and space!):
    $ borg --repo       ssh://borg2@borgbackup/./tests/b20 transfer --upgrader=From12To20 \
           --other-repo ssh://borg2@borgbackup/./tests/b12

    # 4. Check if we have everything (same as 2.):
    $ borg --repo       ssh://borg2@borgbackup/./tests/b20 transfer --upgrader=From12To20 \
           --other-repo ssh://borg2@borgbackup/./tests/b12 --dry-run

