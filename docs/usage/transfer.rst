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

Keyfile considerations when upgrading from borg 1.x
++++++++++++++++++++++++++++++++++++++++++++++++++++

If you are using a ``keyfile`` encryption mode (not ``repokey``), borg 2
may not automatically find your borg 1.x key file, because the default
key file directory has changed on some platforms due to the switch to
the `platformdirs <https://pypi.org/project/platformdirs/>`_ library.

On **Linux**, there is typically no change -- both borg 1.x and borg 2
use ``~/.config/borg/keys/``.

On **macOS**, borg 1.x stored key files in ``~/.config/borg/keys/``,
but borg 2 defaults to ``~/Library/Application Support/borg/keys/``.

On **Windows**, borg 1.x used XDG-style paths (e.g. ``~/.config/borg/keys/``),
while borg 2 defaults to ``C:\Users\<user>\AppData\Roaming\borg\keys\``.

If borg 2 cannot find your key file, you have several options:

1. **Copy the key file** from the old location to the new one.
2. **Set BORG_KEYS_DIR** to point to the old key file directory::

       export BORG_KEYS_DIR=~/.config/borg/keys

3. **Set BORG_KEY_FILE** to point directly to the specific key file::

       export BORG_KEY_FILE=~/.config/borg/keys/your_key_file

4. **Set BORG_BASE_DIR** to force borg 2 to use the same base directory
   as borg 1.x::

       export BORG_BASE_DIR=$HOME

   This makes borg 2 use ``$HOME/.config/borg``, ``$HOME/.cache/borg``,
   etc., matching borg 1.x behaviour on all platforms.

See :ref:`env_vars` for more details on directory environment variables.

