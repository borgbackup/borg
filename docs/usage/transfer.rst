.. include:: transfer.rst.inc

Examples
~~~~~~~~
::

    # 0. Have Borg 2.0 installed on the client AND server; have a b12 repository copy for testing.

    # 1. Create a new "related" repository:
    # Here, the existing Borg 1.2 repository used repokey-blake2 (and AES-CTR mode),
    # thus we use repokey-blake2-aes-ocb for the new Borg 2.0 repository.
    # Staying with the same chunk ID algorithm (BLAKE2) and with the same
    # key material (via --other-repo <oldrepo>) will make deduplication work
    # between old archives (copied with borg transfer) and future ones.
    # The AEAD cipher does not matter (everything must be re-encrypted and
    # re-authenticated anyway); you could also choose repokey-blake2-chacha20-poly1305.
    # In case your old Borg repository did not use BLAKE2, just remove the "-blake2".
    $ borg --repo       ssh://borg2@borgbackup/./tests/b20 repo-create \
           --other-repo ssh://borg2@borgbackup/./tests/b12 -e repokey-blake2-aes-ocb

    # 2. Check what and how much it would transfer:
    $ borg --repo       ssh://borg2@borgbackup/./tests/b20 transfer --upgrader=From12To20 \
           --other-repo ssh://borg2@borgbackup/./tests/b12 --dry-run

    # 3. Transfer (copy) archives from the old repository into the new repository (takes time and space!):
    $ borg --repo       ssh://borg2@borgbackup/./tests/b20 transfer --upgrader=From12To20 \
           --other-repo ssh://borg2@borgbackup/./tests/b12

    # 4. Check whether we have everything (same as step 2):
    $ borg --repo       ssh://borg2@borgbackup/./tests/b20 transfer --upgrader=From12To20 \
           --other-repo ssh://borg2@borgbackup/./tests/b12 --dry-run

