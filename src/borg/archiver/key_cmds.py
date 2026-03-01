import os

from ..constants import *  # NOQA
from ..crypto.key import AESOCBRepoKey, CHPORepoKey, Blake2AESOCBRepoKey, Blake2CHPORepoKey
from ..crypto.key import AESOCBKeyfileKey, CHPOKeyfileKey, Blake2AESOCBKeyfileKey, Blake2CHPOKeyfileKey
from ..crypto.keymanager import KeyManager
from ..helpers import PathSpec, CommandError
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest

from ._common import with_repository

from ..logger import create_logger

logger = create_logger(__name__)


class KeysMixIn:
    @with_repository(compatibility=(Manifest.Operation.CHECK,))
    def do_key_change_passphrase(self, args, repository, manifest):
        """Changes the repository key file passphrase."""
        key = manifest.key
        if not hasattr(key, "change_passphrase"):
            raise CommandError("This repository is not encrypted, cannot change the passphrase.")
        key.change_passphrase()
        logger.info("Key updated")
        if hasattr(key, "find_key"):
            # print key location to make backing it up easier
            logger.info("Key location: %s", key.find_key())

    @with_repository(exclusive=True, manifest=True, cache=True, compatibility=(Manifest.Operation.CHECK,))
    def do_key_change_location(self, args, repository, manifest, cache):
        """Changes the repository key location."""
        key = manifest.key
        if not hasattr(key, "change_passphrase"):
            raise CommandError("This repository is not encrypted, cannot change the key location.")

        if args.key_mode == "keyfile":
            if isinstance(key, AESOCBRepoKey):
                key_new = AESOCBKeyfileKey(repository)
            elif isinstance(key, CHPORepoKey):
                key_new = CHPOKeyfileKey(repository)
            elif isinstance(key, Blake2AESOCBRepoKey):
                key_new = Blake2AESOCBKeyfileKey(repository)
            elif isinstance(key, Blake2CHPORepoKey):
                key_new = Blake2CHPOKeyfileKey(repository)
            else:
                print("Change not needed or not supported.")
                return
        if args.key_mode == "repokey":
            if isinstance(key, AESOCBKeyfileKey):
                key_new = AESOCBRepoKey(repository)
            elif isinstance(key, CHPOKeyfileKey):
                key_new = CHPORepoKey(repository)
            elif isinstance(key, Blake2AESOCBKeyfileKey):
                key_new = Blake2AESOCBRepoKey(repository)
            elif isinstance(key, Blake2CHPOKeyfileKey):
                key_new = Blake2CHPORepoKey(repository)
            else:
                print("Change not needed or not supported.")
                return

        for name in ("repository_id", "crypt_key", "id_key", "chunk_seed", "sessionid", "cipher"):
            value = getattr(key, name)
            setattr(key_new, name, value)

        key_new.target = key_new.get_new_target(args)
        # save with same passphrase and algorithm
        key_new.save(key_new.target, key._passphrase, create=True, algorithm=key._encrypted_key_algorithm)

        # rewrite the manifest with the new key, so that the key-type byte of the manifest changes
        manifest.key = key_new
        manifest.repo_objs.key = key_new
        manifest.write()

        cache.key = key_new

        loc = key_new.find_key() if hasattr(key_new, "find_key") else None
        if args.keep:
            logger.info(f"Key copied to {loc}")
        else:
            key.remove(key.target)  # remove key from current location
            logger.info(f"Key moved to {loc}")

    @with_repository(lock=False, manifest=False, cache=False)
    def do_key_export(self, args, repository):
        """Exports the repository key for backup."""
        manager = KeyManager(repository)
        manager.load_keyblob()
        try:
            if args.path is not None and os.path.isdir(args.path):
                # on Windows, Python raises PermissionError instead of IsADirectoryError
                # (like on Unix) if the file to open is actually a directory.
                raise IsADirectoryError
            if args.paper:
                manager.export_paperkey(args.path)
            elif args.qr:
                manager.export_qr(args.path)
            else:
                manager.export(args.path)
        except IsADirectoryError:
            raise CommandError(f"'{args.path}' must be a file, not a directory")

    @with_repository(lock=False, manifest=False, cache=False)
    def do_key_import(self, args, repository):
        """Imports the repository key from backup."""
        manager = KeyManager(repository)
        if args.paper:
            if args.path:
                raise CommandError("with --paper, import from file is not supported")
            manager.import_paperkey(args)
        else:
            if not args.path:
                raise CommandError("expected input file to import the key from")
            if args.path != "-" and not os.path.exists(args.path):
                raise CommandError(f"input file does not exist: {args.path}")
            manager.import_keyfile(args)

    def build_parser_keys(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        subparser = ArgumentParser(
            parents=[mid_common_parser], description="Manage the keyfile or repokey of a repository", epilog=""
        )
        subparsers.add_subcommand("key", subparser, help="manage the repository key")

        key_parsers = subparser.add_subcommands(required=False, title="required arguments", metavar="<command>")

        key_export_epilog = process_epilog(
            """
        This command backs up the borg key.

        If repository encryption is used, the repository is inaccessible
        without the borg key (and the passphrase that protects the borg key).
        If a repository is not encrypted, but authenticated, the borg key is
        still needed to access the repository normally.

        For repositories using **keyfile** encryption the key is kept locally
        on the system that is capable of doing backups. To guard against loss
        or corruption of this key, the key needs to be backed up independently
        of the main data backup.

        For repositories using **repokey** encryption or **authenticated** mode
        the key is kept in the repository. A backup is thus not strictly needed,
        but guards against the repository becoming inaccessible if the key is
        corrupted or lost.

        Note that the backup produced does not include the passphrase itself
        (i.e. the exported key stays encrypted). In order to regain access to a
        repository, one needs both the exported key and the original passphrase.
        Keep the exported key and the passphrase at safe places.

        There are three backup formats. The normal backup format is suitable for
        digital storage as a file. The ``--paper`` backup format is optimized
        for printing and typing in while importing, with per line checks to
        reduce problems with manual input. The ``--qr-html`` creates a printable
        HTML template with a QR code and a copy of the ``--paper``-formatted key.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_key_export.__doc__, epilog=key_export_epilog
        )
        key_parsers.add_subcommand("export", subparser, help="export the repository key for backup")
        subparser.add_argument("path", metavar="PATH", nargs="?", type=PathSpec, help="where to store the backup")
        subparser.add_argument(
            "--paper",
            dest="paper",
            action="store_true",
            help="Create an export suitable for printing and later type-in",
        )
        subparser.add_argument(
            "--qr-html",
            dest="qr",
            action="store_true",
            help="Create an HTML file suitable for printing and later type-in or QR scan",
        )

        key_import_epilog = process_epilog(
            """
        This command restores a key previously backed up with the export command.

        If the ``--paper`` option is given, the import will be an interactive
        process in which each line is checked for plausibility before
        proceeding to the next line. For this format PATH must not be given.

        For repositories using keyfile encryption, the key file which ``borg key
        import`` writes to depends on several factors. If the ``BORG_KEY_FILE``
        environment variable is set and non-empty, ``borg key import`` creates
        or overwrites that file named by ``$BORG_KEY_FILE``. Otherwise, ``borg
        key import`` searches in the ``$BORG_KEYS_DIR`` directory for a key file
        associated with the repository. If a key file is found in
        ``$BORG_KEYS_DIR``, ``borg key import`` overwrites it; otherwise, ``borg
        key import`` creates a new key file in ``$BORG_KEYS_DIR``.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_key_import.__doc__, epilog=key_import_epilog
        )
        key_parsers.add_subcommand("import", subparser, help="import the repository key from backup")
        subparser.add_argument(
            "path", metavar="PATH", nargs="?", type=PathSpec, help="path to the backup ('-' to read from stdin)"
        )
        subparser.add_argument(
            "--paper",
            dest="paper",
            action="store_true",
            help="interactively import from a backup done with ``--paper``",
        )

        change_passphrase_epilog = process_epilog(
            """
        The key files used for repository encryption are optionally passphrase
        protected. This command can be used to change this passphrase.

        Please note that this command only changes the passphrase, but not any
        secret protected by it (like e.g. encryption/MAC keys or chunker seed).
        Thus, changing the passphrase after passphrase and borg key got compromised
        does not protect future (nor past) backups to the same repository.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_key_change_passphrase.__doc__, epilog=change_passphrase_epilog
        )
        key_parsers.add_subcommand("change-passphrase", subparser, help="change the repository passphrase")

        change_location_epilog = process_epilog(
            """
        Change the location of a Borg key. The key can be stored at different locations:

        - keyfile: locally, usually in the home directory
        - repokey: inside the repository (in the repository config)

        Please note:

        This command does NOT change the crypto algorithms, just the key location,
        thus you must ONLY give the key location (keyfile or repokey).
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_key_change_location.__doc__, epilog=change_location_epilog
        )
        key_parsers.add_subcommand("change-location", subparser, help="change the key location")
        subparser.add_argument(
            "key_mode", metavar="KEY_LOCATION", choices=("repokey", "keyfile"), help="select key location"
        )
        subparser.add_argument(
            "--keep",
            dest="keep",
            action="store_true",
            help="keep the key also at the current location (default: remove it)",
        )
