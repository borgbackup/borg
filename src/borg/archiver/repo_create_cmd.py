import argparse

from ._common import with_repository, with_other_repository, Highlander
from ..cache import Cache
from ..constants import *  # NOQA
from ..crypto.key import key_creator, key_argument_names
from ..helpers import CancelledByUser
from ..helpers import location_validator, Location
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class RepoCreateMixIn:
    @with_repository(create=True, exclusive=True, manifest=False)
    @with_other_repository(manifest=True, compatibility=(Manifest.Operation.READ,))
    def do_repo_create(self, args, repository, *, other_repository=None, other_manifest=None):
        """Create a new, empty repository"""
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
        if key.NAME != "plaintext":
            logger.warning(
                "\n"
                "IMPORTANT: you will need both KEY AND PASSPHRASE to access this repo!\n"
                "\n"
                "Key storage location depends on the mode:\n"
                "- repokey modes: key is stored in the repository directory.\n"
                "- keyfile modes: key is stored in the home directory of this user.\n"
                "\n"
                "For any mode, you should:\n"
                "1. Export the borg key and store the result at a safe place:\n"
                "   borg key export -r REPOSITORY           encrypted-key-backup\n"
                "   borg key export -r REPOSITORY --paper   encrypted-key-backup.txt\n"
                "   borg key export -r REPOSITORY --qr-html encrypted-key-backup.html\n"
                "2. Write down the borg key passphrase and store it at safe place."
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

        Encryption mode TLDR
        ++++++++++++++++++++

        The encryption mode can only be configured when creating a new repository - you can
        neither configure it on a per-archive basis nor change the mode of an existing repository.
        This example will likely NOT give optimum performance on your machine (performance
        tips will come below):

        ::

            borg repo-create --encryption repokey-aes-ocb

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
           Chunking and id generation are also based on your key to improve
           your privacy.
        7. Use the key when extracting files to decrypt them and to verify that the contents of
           the backups have not been accidentally or maliciously altered.

        Picking a passphrase
        ++++++++++++++++++++

        Make sure you use a good passphrase. Not too short, not too simple. The real
        encryption / decryption key is encrypted with / locked by your passphrase.
        If an attacker gets your key, he can't unlock and use it without knowing the
        passphrase.

        Be careful with special or non-ascii characters in your passphrase:

        - Borg processes the passphrase as unicode (and encodes it as utf-8),
          so it does not have problems dealing with even the strangest characters.
        - BUT: that does not necessarily apply to your OS / VM / keyboard configuration.

        So better use a long passphrase made from simple ascii chars than one that
        includes non-ascii stuff or characters that are hard/impossible to enter on
        a different keyboard layout.

        You can change your passphrase for existing repos at any time, it won't affect
        the encryption/decryption key or other secrets.

        Choosing an encryption mode
        +++++++++++++++++++++++++++

        Depending on your hardware, hashing and crypto performance may vary widely.
        The easiest way to find out about what's fastest is to run ``borg benchmark cpu``.

        `repokey` modes: if you want ease-of-use and "passphrase" security is good enough -
        the key will be stored in the repository (in ``repo_dir/config``).

        `keyfile` modes: if you want "passphrase and having-the-key" security -
        the key will be stored in your home directory (in ``~/.config/borg/keys``).

        The following table is roughly sorted in order of preference, the better ones are
        in the upper part of the table, in the lower part is the old and/or unsafe(r) stuff:

        .. nanorst: inline-fill

        +-----------------------------------+--------------+----------------+--------------------+
        | Mode (K = keyfile or repokey)     | ID-Hash      | Encryption     | Authentication     |
        +-----------------------------------+--------------+----------------+--------------------+
        | K-blake2-chacha20-poly1305        | BLAKE2b      | CHACHA20       | POLY1305           |
        +-----------------------------------+--------------+----------------+--------------------+
        | K-chacha20-poly1305               | HMAC-SHA-256 | CHACHA20       | POLY1305           |
        +-----------------------------------+--------------+----------------+--------------------+
        | K-blake2-aes-ocb                  | BLAKE2b      | AES256-OCB     | AES256-OCB         |
        +-----------------------------------+--------------+----------------+--------------------+
        | K-aes-ocb                         | HMAC-SHA-256 | AES256-OCB     | AES256-OCB         |
        +-----------------------------------+--------------+----------------+--------------------+
        | authenticated-blake2              | BLAKE2b      | none           | BLAKE2b            |
        +-----------------------------------+--------------+----------------+--------------------+
        | authenticated                     | HMAC-SHA-256 | none           | HMAC-SHA256        |
        +-----------------------------------+--------------+----------------+--------------------+
        | none                              | SHA-256      | none           | none               |
        +-----------------------------------+--------------+----------------+--------------------+

        .. nanorst: inline-replace

        `none` mode uses no encryption and no authentication. You're advised NOT to use this mode
        as it would expose you to all sorts of issues (DoS, confidentiality, tampering, ...) in
        case of malicious activity in the repository.

        If you do **not** want to encrypt the contents of your backups, but still want to detect
        malicious tampering use an `authenticated` mode. It's like `repokey` minus encryption.
        To normally work with ``authenticated`` repos, you will need the passphrase, but
        there is an emergency workaround, see ``BORG_WORKAROUNDS=authenticated_no_key`` docs.

        Creating a related repository
        +++++++++++++++++++++++++++++

        You can use ``borg repo-create --other-repo ORIG_REPO ...`` to create a related repository
        that uses the same secret key material as the given other/original repository.

        By default, only the ID key and chunker secret will be the same (these are important
        for deduplication) and the AE crypto keys will be newly generated random keys.

        Optionally, if you use ``--copy-crypt-key`` you can also keep the same crypt_key
        (used for authenticated encryption). Might be desired e.g. if you want to have less
        keys to manage.

        Creating related repositories is useful e.g. if you want to use ``borg transfer`` later.

        Creating a related repository for data migration from borg 1.2 or 1.4
        +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        You can use ``borg repo-create --other-repo ORIG_REPO --from-borg1 ...`` to create a related
        repository that uses the same secret key material as the given other/original repository.

        Then use ``borg transfer --other-repo ORIG_REPO --from-borg1 ...`` to transfer the archives.
        """
        )
        subparser = subparsers.add_parser(
            "repo-create",
            parents=[common_parser],
            add_help=False,
            description=self.do_repo_create.__doc__,
            epilog=repo_create_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="create a new, empty repository",
        )
        subparser.set_defaults(func=self.do_repo_create)
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
            "--from-borg1", dest="v1_or_v2", action="store_true", help="other repository is borg 1.x"
        )
        subparser.add_argument(
            "-e",
            "--encryption",
            metavar="MODE",
            dest="encryption",
            required=True,
            choices=key_argument_names(),
            action=Highlander,
            help="select encryption key mode **(required)**",
        )
        subparser.add_argument(
            "--copy-crypt-key",
            dest="copy_crypt_key",
            action="store_true",
            help="copy the crypt_key (used for authenticated encryption) from the key of the other repo "
            "(default: new random key).",
        )
