from ._common import with_repository, with_other_repository, Highlander
from ..cache import Cache
from ..constants import *  # NOQA
from ..crypto.key import key_creator, encryption_argument_names, id_hash_argument_names
from ..helpers import CancelledByUser
from ..helpers import location_validator, Location
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class RepoCreateMixIn:
    @with_repository(create=True, exclusive=True, manifest=False)
    @with_other_repository(manifest=True, compatibility=(Manifest.Operation.READ,))
    def do_repo_create(self, args, repository, *, other_repository=None, other_manifest=None):
        """Creates a new, empty repository."""
        other_key = other_manifest.key if other_manifest is not None else None
        path = args.location.canonical_path()
        logger.info('Initializing repository at "%s"' % path)
        if other_key is not None:
            other_key.copy_crypt_key = args.copy_crypt_key
        try:
            key = key_creator(repository, args, other_key=other_key)
        except (EOFError, KeyboardInterrupt):
            repository.destroy()
            raise CancelledByUser()
        manifest = Manifest(key, repository)
        manifest.key = key
        manifest.write()
        with Cache(repository, manifest, warn_if_unencrypted=False):
            pass
        if key.ENC_NAME != "none":  # any key-bearing suite (everything except plaintext "none")
            logger.warning(
                "\n"
                "IMPORTANT: you will need both KEY AND PASSPHRASE to access this repository!\n"
                "\n"
                "Key storage location depends on the mode:\n"
                "- repokey modes: key is stored in the repository directory.\n"
                "- keyfile modes: key is stored in the home directory of this user.\n"
                "\n"
                "For any mode, you should:\n"
                "1. Export the Borg key and store the result in a safe place:\n"
                "   borg key export -r REPOSITORY           encrypted-key-backup\n"
                "   borg key export -r REPOSITORY --paper   encrypted-key-backup.txt\n"
                "   borg key export -r REPOSITORY --qr-html encrypted-key-backup.html\n"
                "2. Write down the Borg key passphrase and store it in a safe place."
            )
        logger.warning(
            "\n"
            "Reserve some repository storage space now for emergencies like 'disk full'\n"
            "by running:\n"
            "    borg repo-space --reserve 1G"
        )

    def build_parser_repo_create(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        repo_create_epilog = process_epilog(
            """
        This command creates a new, empty repository. A repository is a ``borgstore`` store
        containing the deduplicated data from zero or more archives.

        Repository creation can be quite slow for some kinds of stores (e.g. for ``sftp:``) -
        this is due to borgstore pre-creating all directories needed, making usage of the
        store faster.

        Encryption mode TL;DR
        +++++++++++++++++++++

        The encryption mode can only be configured when creating a new repository - you can
        neither configure it on a per-archive basis nor change the mode of an existing repository.
        This example will likely NOT give optimum performance on your machine (performance
        tips will come below):

        ::

            borg repo-create --encryption aes256-ocb --key-location repokey

        Borg will:

        1. Ask you to come up with a passphrase.
        2. Create a borg key (which contains some random secrets. See :ref:`key_files`).
        3. Derive a "key encryption key" from your passphrase
        4. Encrypt and sign the key with the key encryption key
        5. Store the encrypted borg key inside the repository directory (in the repo config).
           This is why it is essential to use a secure passphrase.
        6. Encrypt and sign your backups to prevent anyone from reading or forging them unless they
           have the key and know the passphrase. Make sure to keep a backup of
           your key **outside** the repository - do not lock yourself out by
           "leaving your keys inside your car" (see :ref:`borg_key_export`).
           The encryption is done locally - if you use a remote repository, the remote machine
           never sees your passphrase, your unencrypted key or your unencrypted files.
           Chunking and ID generation are also based on your key to improve
           your privacy.
        7. Use the key when extracting files to decrypt them and to verify that the contents of
           the backups have not been accidentally or maliciously altered.

        Picking a passphrase
        ++++++++++++++++++++

        Make sure you use a good passphrase. Not too short, not too simple. The real
        encryption / decryption key is encrypted with / locked by your passphrase.
        If an attacker gets your key, they cannot unlock and use it without knowing the
        passphrase.

        Be careful with special or non-ASCII characters in your passphrase:

        - Borg processes the passphrase as Unicode (and encodes it as UTF-8),
          so it does not have problems dealing with even the strangest characters.
        - BUT: that does not necessarily apply to your OS/VM/keyboard configuration.

        So better use a long passphrase made from simple ASCII characters than one that
        includes non-ASCII stuff or characters that are hard or impossible to enter on
        a different keyboard layout.

        You can change your passphrase for existing repositories at any time; it will not affect
        the encryption/decryption key or other secrets.

        Choosing a crypto suite
        +++++++++++++++++++++++

        Depending on your hardware, hashing and crypto performance may vary widely.
        The easiest way to find out what is fastest is to run ``borg benchmark cpu``.

        A crypto suite is selected by three orthogonal options:

        ``--encryption`` (**required**) selects the cipher / authenticated-encryption algorithm:

        - ``aes256-ocb``: AES256 in OCB mode (encryption + authentication).
        - ``chacha20-poly1305``: ChaCha20 + Poly1305 (encryption + authentication).
        - ``authenticated``: no encryption, but still authenticates your data (tamper detection).
        - ``none``: no encryption and no authentication (see the warning below).

        ``--id-hash`` selects the id hash function (used for chunk ids and authentication):

        - ``sha256`` (default): HMAC-SHA-256 (or plain SHA-256 for the ``none`` encryption).
        - ``blake3``: BLAKE3. Often faster on CPUs without SHA hardware acceleration.

        The ``none`` encryption has no key, so it only supports the ``sha256`` id hash.

        ``--key-location`` selects where the key is stored (orthogonal to the crypto suite):

        - ``repokey`` (default): the key is stored in the repository (under ``keys/``). Pick this
          if you want ease-of-use and "passphrase" security is good enough.
        - ``keyfile``: the key is stored in your home directory (in ``~/.config/borg/keys``). Pick
          this if you want "passphrase and having-the-key" security.

        You can move the key between these locations later with ``borg key change-location``.
        This also applies to the ``authenticated`` encryption: it does not encrypt your data, but it
        still has a key (used for the id hash and authentication), so ``--key-location`` selects
        where that key is stored, just like for the encrypted suites.
        ``--key-location`` is only ignored for the ``none`` encryption, which has no key at all.

        `none` encryption uses no encryption and no authentication. You are advised NOT to use this
        as it would expose you to a Denial-of-Service risk (due to how the :ref:`internals_hashindex`
        works) and other issues (confidentiality, tampering, ...) in case of malicious activity
        in the repository.

        If you do **not** want to encrypt the contents of your backups, but still want to detect
        malicious tampering, use ``--encryption authenticated``. It is like an encrypted suite
        minus the data encryption.
        To normally work with ``authenticated`` repositories, you will need the passphrase, but
        there is an emergency workaround; see ``BORG_WORKAROUNDS=authenticated_no_key`` docs.

        Creating a related repository
        +++++++++++++++++++++++++++++

        You can use ``borg repo-create --other-repo ORIG_REPO ...`` to create a related repository
        that uses the same secret key material as the given other/original repository.

        By default, only the ID key and chunker secret will be the same (these are important
        for deduplication) and the AE crypto keys will be newly generated random keys.

        Optionally, if you use ``--copy-crypt-key`` you can also keep the same crypt_key
        (used for authenticated encryption). This might be desired, for example, if you want to have fewer
        keys to manage.

        Creating related repositories is useful, for example, if you want to use ``borg transfer`` later.

        Creating a related repository for data migration from Borg 1.2 or 1.4
        +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        You can use ``borg repo-create --other-repo ORIG_REPO --from-borg1 ...`` to create a related
        repository that uses the same secret key material as the given other/original repository.

        Then use ``borg transfer --other-repo ORIG_REPO --from-borg1 ...`` to transfer the archives.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_repo_create.__doc__, epilog=repo_create_epilog
        )
        subparsers.add_subcommand("repo-create", subparser, help="create a new, empty repository")
        subparser.add_argument(
            "--other-repo",
            metavar="SRC_REPOSITORY",
            dest="other_location",
            type=location_validator(other=True),
            default=Location(other=True),
            action=Highlander,
            help="reuse the key material from the other repository",
        )
        subparser.add_argument(
            "--from-borg1", dest="v1_legacy", action="store_true", help="other repository is Borg 1.x"
        )
        subparser.add_argument(
            "-e",
            "--encryption",
            metavar="ENCRYPTION",
            dest="encryption",
            required=True,
            choices=encryption_argument_names(),
            action=Highlander,
            help="select cipher / AE algorithm: 'none', 'authenticated', 'aes256-ocb' or "
            "'chacha20-poly1305' **(required)**",
        )
        subparser.add_argument(
            "-i",
            "--id-hash",
            metavar="HASH",
            dest="id_hash",
            choices=id_hash_argument_names(),
            default="sha256",
            action=Highlander,
            help="select the id hash function: 'sha256' (default) or 'blake3'. "
            "The 'none' encryption only supports 'sha256'.",
        )
        subparser.add_argument(
            "--key-location",
            metavar="LOCATION",
            dest="key_location",
            choices=("repokey", "keyfile"),
            default="repokey",
            action=Highlander,
            help="where to store the key: 'repokey' (in the repository, default) or 'keyfile' "
            "(in the local keys directory). Ignored for the 'none' mode (which has no key).",
        )
        subparser.add_argument(
            "--copy-crypt-key",
            dest="copy_crypt_key",
            action="store_true",
            help="copy the crypt_key (used for authenticated encryption) from the key of the other repository "
            "(default: new random key).",
        )
