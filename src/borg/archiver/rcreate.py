import argparse

from .common import with_repository, with_other_repository
from ..cache import Cache
from ..constants import *  # NOQA
from ..crypto.key import key_creator, key_argument_names, tam_required_file
from ..helpers import EXIT_WARNING
from ..helpers import location_validator, Location
from ..helpers import parse_storage_quota
from ..helpers import Manifest

from ..logger import create_logger

logger = create_logger()


class RCreateMixIn:
    @with_repository(create=True, exclusive=True, manifest=False)
    @with_other_repository(key=True, compatibility=(Manifest.Operation.READ,))
    def do_rcreate(self, args, repository, *, other_repository=None, other_key=None):
        """Create a new, empty repository"""
        path = args.location.canonical_path()
        logger.info('Initializing repository at "%s"' % path)
        if other_key is not None:
            other_key.copy_crypt_key = args.copy_crypt_key
        try:
            key = key_creator(repository, args, other_key=other_key)
        except (EOFError, KeyboardInterrupt):
            repository.destroy()
            return EXIT_WARNING
        manifest = Manifest(key, repository)
        manifest.key = key
        manifest.write()
        repository.commit(compact=False)
        with Cache(repository, key, manifest, warn_if_unencrypted=False):
            pass
        if key.tam_required:
            tam_file = tam_required_file(repository)
            open(tam_file, "w").close()

        if key.NAME != "plaintext":
            logger.warning(
                "\n"
                "IMPORTANT: you will need both KEY AND PASSPHRASE to access this repo!\n"
                "If you used a repokey mode, the key is stored in the repo, but you should back it up separately.\n"
                'Use "borg key export" to export the key, optionally in printable format.\n'
                "Write down the passphrase. Store both at safe place(s).\n"
            )
        return self.exit_code

    def build_parser_rcreate(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog

        rcreate_epilog = process_epilog(
            """
        This command creates a new, empty repository. A repository is a filesystem
        directory containing the deduplicated data from zero or more archives.

        Encryption mode TLDR
        ++++++++++++++++++++

        The encryption mode can only be configured when creating a new repository - you can
        neither configure it on a per-archive basis nor change the mode of an existing repository.
        This example will likely NOT give optimum performance on your machine (performance
        tips will come below):

        ::

            borg rcreate --encryption repokey-aes-ocb

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

        `keyfile` modes: if you rather want "passphrase and having-the-key" security -
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

        `none` mode uses no encryption and no authentication. You're advised to NOT use this mode
        as it would expose you to all sorts of issues (DoS, confidentiality, tampering, ...) in
        case of malicious activity in the repository.

        If you do **not** want to encrypt the contents of your backups, but still want to detect
        malicious tampering use an `authenticated` mode. It's like `repokey` minus encryption.

        Creating a related repository
        +++++++++++++++++++++++++++++

        A related repository uses same secret key material as the other/original repository.

        By default, only the ID key and chunker secret will be the same (these are important
        for deduplication) and the AE crypto keys will be newly generated random keys.

        Optionally, if you use ``--copy-crypt-key`` you can also keep the same crypt_key
        (used for authenticated encryption). Might be desired e.g. if you want to have less
        keys to manage.

        Creating related repositories is useful e.g. if you want to use ``borg transfer`` later.
        """
        )
        subparser = subparsers.add_parser(
            "rcreate",
            parents=[common_parser],
            add_help=False,
            description=self.do_rcreate.__doc__,
            epilog=rcreate_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="create a new, empty repository",
        )
        subparser.set_defaults(func=self.do_rcreate)
        subparser.add_argument(
            "--other-repo",
            metavar="SRC_REPOSITORY",
            dest="other_location",
            type=location_validator(other=True),
            default=Location(other=True),
            help="reuse the key material from the other repository",
        )
        subparser.add_argument(
            "-e",
            "--encryption",
            metavar="MODE",
            dest="encryption",
            required=True,
            choices=key_argument_names(),
            help="select encryption key mode **(required)**",
        )
        subparser.add_argument(
            "--append-only",
            dest="append_only",
            action="store_true",
            help="create an append-only mode repository. Note that this only affects "
            "the low level structure of the repository, and running `delete` "
            "or `prune` will still be allowed. See :ref:`append_only_mode` in "
            "Additional Notes for more details.",
        )
        subparser.add_argument(
            "--storage-quota",
            metavar="QUOTA",
            dest="storage_quota",
            default=None,
            type=parse_storage_quota,
            help="Set storage quota of the new repository (e.g. 5G, 1.5T). Default: no quota.",
        )
        subparser.add_argument(
            "--make-parent-dirs",
            dest="make_parent_dirs",
            action="store_true",
            help="create the parent directories of the repository directory, if they are missing.",
        )
        subparser.add_argument(
            "--copy-crypt-key",
            dest="copy_crypt_key",
            action="store_true",
            help="copy the crypt_key (used for authenticated encryption) from the key of the other repo "
            "(default: new random key).",
        )
