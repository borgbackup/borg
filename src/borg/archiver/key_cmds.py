import os

from ..constants import *  # NOQA
from ..crypto.key import KEY_LOCATIONS
from ..crypto.keymanager import KeyManager
from ..helpers import FilesystemPathSpec, CommandError
from ..helpers.argparsing import ArgumentParser

from ._common import with_repository

from ..logger import create_logger

logger = create_logger(__name__)


class KeysMixIn:
    @with_repository()
    def do_key_change_passphrase(self, args, repository, manifest):
        """Changes the repository key file passphrase."""
        key = manifest.key
        key.change_passphrase()
        logger.info("Key updated")
        # print key location to make backing it up easier
        logger.info("Key location: %s", key.find_key())

    @with_repository(manifest=True)
    def do_key_add(self, args, repository, manifest):
        """Add a new borg key (protected by an independent passphrase or a FIDO2 token) to the repository."""
        if args.fido2_touch == "no" and args.fido2_device is None:
            raise CommandError("--fido2-touch=no only makes sense together with --fido2-device.")
        key = manifest.key
        key.add_key(label=args.label, fido2_device=args.fido2_device, fido2_touch=args.fido2_touch == "yes")
        if args.fido2_device is not None:
            logger.info("FIDO2-protected borg key with label %r added.", args.label)
        else:
            logger.info("Borg key with label %r added.", args.label)
        logger.info("Key location: %s", key.find_key())

    @with_repository(manifest=True)
    def do_key_remove(self, args, repository, manifest):
        """Remove a borg key from the repository."""
        key = manifest.key
        victim = key.remove_key(label=args.label, key_id=args.key, current=args.by_passphrase)
        logger.info("Borg key %s (label %r) removed.", victim["id"][:12], victim["label"])

    @with_repository(manifest=True)
    def do_key_list(self, args, repository, manifest):
        """List the borg keys of the repository."""
        key = manifest.key
        fmt = "%-1s %-12s %-8s %-24s %s"
        print(fmt % ("", "KEY ID", "MODE", "LABEL", "ALGORITHM"))
        for bk in key.list_keys():
            marker = "*" if bk["current"] else ""
            print(fmt % (marker, bk["id"][:12], bk["mode"], bk["label"] or "-", bk["algorithm"] or "-"))

    @with_repository(exclusive=True, manifest=True, cache=True)
    def do_key_change_location(self, args, repository, manifest, cache):
        """Changes the location of the borg key used to unlock this repository."""
        key = manifest.key
        new_storage = KEY_LOCATIONS[args.key_mode]
        if key.storage == new_storage:
            print(f"The borg key is already stored as {args.key_mode}, nothing to do.")
            return

        if key._encrypted_key_algorithm == KEY_ALGORITHMS["fido2"]:
            # a FIDO2-protected borg key blob is moved verbatim: re-encrypting (like the
            # passphrase path below does) would silently mint a new credential on the token.
            key.change_blob_location(args, new_storage, keep=args.keep)
            loc = key.find_key()
            logger.info(f"Key {'copied' if args.keep else 'moved'} to {loc}")
            return

        # the crypto class / manifest key-type byte does not change - only the storage location does.
        # build a same-class key with the same key material and store it at the new location.
        key_new = type(key)(repository)
        # sessionid/cipher only exist for the AEAD modes; authenticated keys do not have them.
        for name in ("repository_id", "crypt_key", "id_key", "chunk_seed", "sessionid", "cipher"):
            if hasattr(key, name):
                setattr(key_new, name, getattr(key, name))
        key_new.storage = new_storage
        key_new.target = key_new.get_new_target(args)
        # save with same passphrase, algorithm and label (keep the unlocked borg key's label)
        key_new.save(
            key_new.target,
            key._passphrase,
            create=True,
            algorithm=key._encrypted_key_algorithm,
            label=key._loaded_label,
        )

        # the new key (same crypto material, new storage) is the canonical key going forward
        manifest.key = key_new
        manifest.repo_objs.key = key_new
        cache.key = key_new

        loc = key_new.find_key()
        if args.keep:
            logger.info(f"Key copied to {loc}")
        else:
            key.remove(key.target)  # remove the borg key from its previous location only
            logger.info(f"Key moved to {loc}")

    @with_repository(lock=False, manifest=False, cache=False)
    def do_key_export(self, args, repository):
        """Exports a borg key of the repository for backup."""
        manager = KeyManager(repository)
        manager.load_keyblob(label=args.label, key_id=args.key)
        if manager.loaded_algorithm == KEY_ALGORITHMS["fido2"]:
            logger.warning(
                "This is a FIDO2-protected borg key: the exported backup is useless without "
                "the FIDO2 token it was enrolled with."
            )
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
        logger.info("Exported borg key %s (label %r).", manager.loaded_key_id[:12], manager.loaded_label)

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

        A repository may have more than one borg key (each protected by its own
        passphrase, see ``borg key add``). Select which borg key to export with
        ``--label`` or ``--key`` (its key id or a unique prefix, see
        ``borg key list``). If the repository has only a single borg key, no
        selector is required.

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
        key_parsers.add_subcommand("export", subparser, help="export a borg key for backup")
        subparser.add_argument(
            "path", metavar="PATH", nargs="?", type=FilesystemPathSpec, help="where to store the backup"
        )
        export_select = subparser.add_mutually_exclusive_group()
        export_select.add_argument("--label", metavar="LABEL", dest="label", help="export the borg key with this label")
        export_select.add_argument(
            "--key", metavar="ID", dest="key", help="export the borg key with this id (or unique id prefix)"
        )
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

        Where the imported key is stored is decided by ``--key-location``:

        - ``repokey`` (the default): the key is stored **in the repository**, no local
          key file is written.
        - ``keyfile``: the key is stored in a local key file.

        The key file that ``--key-location=keyfile`` writes to depends on several
        factors. If the ``BORG_KEY_FILE`` environment variable is set and non-empty,
        ``borg key import`` creates or overwrites the file named by ``$BORG_KEY_FILE``.
        Otherwise, ``borg key import`` searches the ``$BORG_KEYS_DIR`` directory for a
        key file associated with the repository. If one is found there, ``borg key
        import`` overwrites it; otherwise it creates a new key file in
        ``$BORG_KEYS_DIR``.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_key_import.__doc__, epilog=key_import_epilog
        )
        key_parsers.add_subcommand("import", subparser, help="import the repository key from backup")
        subparser.add_argument(
            "path",
            metavar="PATH",
            nargs="?",
            type=FilesystemPathSpec,
            help="path to the backup ('-' to read from stdin)",
        )
        subparser.add_argument(
            "--paper",
            dest="paper",
            action="store_true",
            help="interactively import from a backup done with ``--paper``",
        )
        subparser.add_argument(
            "--key-location",
            metavar="LOCATION",
            dest="key_location",
            choices=("repokey", "keyfile"),
            default="repokey",
            help="where to store the imported key: 'repokey' (in the repository, default) or "
            "'keyfile' (in the local keys directory)",
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

        add_epilog = process_epilog(
            """
        A repository can be protected by more than one borg key. Each borg key contains the
        same secret key material, but is protected independently - by its own passphrase, or
        by a FIDO2 hardware token - and any of them can be used to unlock the same repository.
        This is useful e.g. to give individual users their own passphrase while keeping a
        separate admin/recovery passphrase.

        This command adds an additional borg key. It does not re-encrypt any repository data
        and does not change the existing borg keys. The new passphrase is read from
        ``BORG_NEW_PASSPHRASE`` or queried interactively.

        With ``--fido2-device``, the new borg key is protected by a FIDO2 token's hmac-secret
        instead of a passphrase: the token holds a device-bound secret that is needed to
        unlock this borg key, so the key blob is useless without the plugged-in token.
        Enrollment needs two touches on the token (create the credential, then derive the
        secret once). If the token has a PIN or built-in user verification configured, it is
        also required - both at enrollment and at every unlock. Without ``DEVICE``, the single
        plugged-in FIDO2 device is used; with several devices plugged in, one must be selected
        explicitly (``fido2-token -L`` lists devices). At unlock time, the matching token is
        found automatically among the plugged-in devices (``BORG_FIDO2_DEVICE`` pins one).

        ``--fido2-touch=no`` stores a borg key that unlocks without a touch on the token
        (useful for unattended backups; the key is then bound to the plugged-in device, but
        not presence-gated). Note that the CTAP specification requires tokens to refuse
        touchless hmac-secret derivation and most (e.g. YubiKeys) do - only tokens deviating
        from the spec on this point support it. That is verified at enrollment, which fails
        cleanly in that case.

        Note that a repository is only as secure as its *weakest* borg key: adding a FIDO2 key
        does not strengthen a weak or empty admin passphrase. The admin key is the recovery
        path if the token is lost - treat it like one.

        Each borg key has a label. The first borg key, created at repository creation time, has
        the reserved label ``admin`` and is protected from deletion. Additionally added borg
        keys require a unique, user-defined ``--label``.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_key_add.__doc__, epilog=add_epilog)
        key_parsers.add_subcommand("add", subparser, help="add a borg key (passphrase or FIDO2 token)")
        subparser.add_argument(
            "--label", metavar="LABEL", dest="label", required=True, help="label for the new borg key (must be unique)"
        )
        subparser.add_argument(
            "--fido2-device",
            metavar="DEVICE",
            dest="fido2_device",
            nargs="?",
            const=True,
            default=None,
            help="protect the new borg key with a FIDO2 token's hmac-secret instead of a passphrase. "
            "DEVICE is a platform device identifier (see ``fido2-token -L``); when omitted, the "
            "single plugged-in FIDO2 device is used.",
        )
        subparser.add_argument(
            "--fido2-touch",
            dest="fido2_touch",
            choices=("yes", "no"),
            default="yes",
            help="whether unlocking with the new FIDO2 borg key requires a touch (user presence) "
            "on the token (default: yes). 'no' requires a token that supports touchless hmac-secret "
            "derivation (the CTAP spec forbids it, so most tokens, e.g. YubiKeys, refuse); "
            "this is verified at enrollment.",
        )

        remove_epilog = process_epilog(
            """
        Remove a borg key from the repository.

        The borg key to remove is selected by exactly one of: ``--label`` (its label),
        ``--key`` (its key id or a unique prefix, see ``borg key list``), or
        ``--passphrase`` (remove the borg key that was used to unlock the repository now).

        The ``admin`` borg key is protected and cannot be removed, and the last remaining
        borg key of a repository cannot be removed either.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser], description=self.do_key_remove.__doc__, epilog=remove_epilog
        )
        key_parsers.add_subcommand("remove", subparser, help="remove a borg key")
        remove_group = subparser.add_mutually_exclusive_group(required=True)
        remove_group.add_argument("--label", metavar="LABEL", dest="label", help="remove the borg key with this label")
        remove_group.add_argument(
            "--key", metavar="ID", dest="key", help="remove the borg key with this id (or unique id prefix)"
        )
        remove_group.add_argument(
            "--passphrase",
            dest="by_passphrase",
            action="store_true",
            help="remove the borg key that was used to unlock the repository",
        )

        list_epilog = process_epilog(
            """
        List the borg keys of the repository, showing each borg key's id, mode (``repokey`` or
        ``keyfile``), label and key derivation/encryption algorithm. The borg key used to
        unlock the repository in this invocation is marked with ``*``.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_key_list.__doc__, epilog=list_epilog)
        key_parsers.add_subcommand("list", subparser, help="list the repository borg keys")

        change_location_epilog = process_epilog(
            """
        Change the location of a Borg key. The key can be stored at different locations:

        - keyfile: locally, usually in the home directory
        - repokey: inside the repository

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
