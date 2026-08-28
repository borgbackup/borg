import os

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import RTError
from ..helpers import PathSpec, FilesystemDirSpec
from ..helpers import location_validator
from ..helpers import umount
from ..helpers.argparsing import ArgumentParser
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class MountMixIn:
    def do_mount(self, args):
        """Mounts an archive or an entire repository as a FUSE filesystem."""
        # Perform these checks before opening the repository and asking for a passphrase.

        from ..fuse_impl import llfuse, has_mfusepy, BORG_FUSE_IMPL, fuse_import_errors

        if llfuse is None and not has_mfusepy:
            msg = "borg mount not available: no FUSE support, BORG_FUSE_IMPL=%s." % BORG_FUSE_IMPL
            msg += "".join(f"\nimport of {impl} failed: {err}" for impl, err in fuse_import_errors.items())
            raise RTError(msg)

        if not os.path.isdir(args.mountpoint):
            raise RTError(f"{args.mountpoint}: Mountpoint must be an **existing directory**")

        if not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            raise RTError(f"{args.mountpoint}: Mountpoint must be a **writable** directory")

        self._do_mount(args)

    @with_repository(compatibility=(Manifest.Operation.READ,))
    def _do_mount(self, args, repository, manifest):
        from ..fuse_impl import has_mfusepy

        if has_mfusepy:
            from ..hlfuse import borgfs as fuse_operations  # high-level FUSE API
        else:
            from ..fuse import FuseOperations as fuse_operations  # low-level FUSE API

        operations = fuse_operations(manifest, args, repository)
        logger.info("Mounting filesystem")
        try:
            operations.mount(args.mountpoint, args.options, args.foreground, args.show_rc)
        except RuntimeError:
            # Relevant error message already printed to stderr by FUSE
            raise RTError("FUSE mount failed")

    def do_umount(self, args):
        """Unmounts the FUSE filesystem."""
        umount(args.mountpoint)

    def build_parser_mount_umount(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        mount_epilog = process_epilog(
            """
        This command mounts a repository or an archive as a FUSE filesystem.
        This can be useful for browsing or restoring individual files.

        When restoring, take into account that the current FUSE implementation does
        not support special fs flags. On Linux, POSIX ACLs of the archived fs objects
        are exposed (read-only) via the ``system.posix_acl_access`` and
        ``system.posix_acl_default`` extended attributes, so tools like ``getfacl`` or
        ``rsync -A`` can read them from the mounted archive. Note that the mount does
        not enforce the ACLs for permission checks. On other platforms, ACLs are not
        supported.

        When mounting a repository, there is one top directory per archive and the
        directory structure below these will be loaded on-demand from the repository
        when entering these directories, so expect some delay.

        By default, these top directories are named like the archives; as the archives
        of a series all have the same name, ``-{id:.8}`` (the first 8 hex digits of the
        archive id) is appended whenever a name is not unique. To name them differently,
        set the ``BORG_MOUNT_ARCHIVE_DIR_FORMAT`` environment variable to a format string
        using the placeholders of ``borg repo-list --format``, e.g.
        ``{name}-{time:%Y-%m-%dT%H:%M:%S}`` or ``{hostname}-{name}``; names that are
        still not unique get ``-{id:.8}`` appended.

        .. note::

            Borg stores symbolic links as-is. Consequently, when an archive or
            repository is mounted, symbolic links may resolve to locations outside of
            the mountpoint, either because they are absolute or because relative links
            traverse outside of the mounted tree.

            Normal UNIX pathname resolution applies: most tools follow symbolic links
            by default and may therefore access files or directories that are not part
            of the mounted archive. Consequently, operations intended to inspect
            archived data may instead access "live" data from the host filesystem.

            On Linux, this can be prevented by remounting the mountpoint with the
            ``nosymfollow`` VFS mount option, for example:

                borg -r <repo path> mount <mountpoint>
                mount -o remount,nosymfollow <mountpoint>

            Alternatively, access the mounted archive from an appropriately isolated
            environment (for example, a container or ``chroot``).

        Unless the ``--foreground`` option is given, the command will run in the
        background until the filesystem is ``unmounted``.

        Performance tips:

        - When doing a "whole repository" mount:
          do not enter archive directories if not needed; this avoids on-demand loading.
        - Only mount a specific archive, not the whole repository.
        - Only mount specific paths in a specific archive, not the complete archive.

        The command ``borgfs`` provides a wrapper for ``borg mount``. It is invoked as
        ``borgfs [REPOSITORY] MOUNTPOINT [PATH...]``, taking the repository as its first
        positional argument (if it is not given, ``-r`` / ``BORG_REPO`` is used). This can
        also be used in fstab entries:
        ``/path/to/repo /mnt/point fuse.borgfs defaults,noauto 0 0``

        To allow a regular user to use fstab entries, add the ``user`` option:
        ``/path/to/repo /mnt/point fuse.borgfs defaults,noauto,user 0 0``

        For FUSE configuration and mount options, see the mount.fuse(8) manual page.

        Borg's default behavior is to use the archived user and group names of each
        file and map them to the system's respective user and group IDs.
        Alternatively, using ``numeric-ids`` will instead use the archived user and
        group IDs without any mapping.

        The ``uid`` and ``gid`` mount options (implemented by Borg) can be used to
        override the user and group IDs of all files (i.e., ``borg mount -o
        uid=1000,gid=1000``).

        The man page references ``user_id`` and ``group_id`` mount options
        (implemented by FUSE) which specify the user and group ID of the mount owner
        (also known as the user who does the mounting). It is set automatically by libfuse (or
        the filesystem if libfuse is not used). However, you should not specify these
        manually. Unlike the ``uid`` and ``gid`` mount options, which affect all files,
        ``user_id`` and ``group_id`` affect the user and group ID of the mounted
        (base) directory.

        Additional mount options supported by Borg:

        - ``versions``: when used with a repository mount, this gives a merged, versioned
          view of the files in the archives. EXPERIMENTAL; layout may change in the future.
        - ``allow_damaged_files``: by default, damaged files (where chunks are missing)
          will return EIO (I/O error) when trying to read the related parts of the file.
          Set this option to replace the missing parts with all-zero bytes.
        - ``ignore_permissions``: for security reasons the ``default_permissions`` mount
          option is internally enforced by Borg. ``ignore_permissions`` can be given to
          not enforce ``default_permissions``.

        The BORG_MOUNT_DATA_CACHE_ENTRIES environment variable is intended for advanced users
        to tweak performance. It sets the number of cached data chunks; additional
        memory usage can be up to ~8 MiB times this number. The default is the number
        of CPU cores.

        When the daemonized process receives a signal or crashes, it does not unmount.
        Unmounting in these cases could cause an active rsync or similar process
        to delete data unintentionally.

        When running in the foreground, ^C/SIGINT cleanly unmounts the filesystem,
        but other signals or crashes do not.

        Debugging:

        ``borg mount`` usually daemonizes and the daemon process sends stdout/stderr
        to /dev/null. Thus, you need to either use ``-f / --foreground`` to make it stay
        in the foreground and not daemonize, or use ``BORG_LOGGING_CONF`` to reconfigure
        the logger to output to a file.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_mount.__doc__, epilog=mount_epilog)
        subparsers.add_subcommand("mount", subparser, help="mount a repository")
        self._define_borg_mount(subparser)

        umount_epilog = process_epilog(
            """
        This command unmounts a FUSE filesystem that was mounted with ``borg mount``.

        This is a convenience wrapper that just calls the platform-specific shell
        command - usually this is either umount or fusermount -u.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_umount.__doc__, epilog=umount_epilog)
        subparsers.add_subcommand("umount", subparser, help="unmount a repository")
        subparser.add_argument(
            "mountpoint", metavar="MOUNTPOINT", type=FilesystemDirSpec, help="mountpoint of the filesystem to unmount"
        )

    def build_parser_borgfs(self, parser):
        assert parser.prog == "borgfs"
        parser.description = self.do_mount.__doc__
        parser.epilog = "For more information, see borg mount --help."
        parser.help = "mount a repository"
        # borgfs is a top-level parser, thus it reads the same default config file as borg does,
        # but it has no subcommands - just ignore the per-subcommand sections of that config file.
        parser.ignore_unknown_config_keys = True
        # borgfs *is* the mount command, so the "mount:" section applies to it: adopt its keys as
        # top-level keys (they win over same-named top-level keys of the config file).
        parser.adopt_config_sections = ("mount",)
        self._define_borg_mount(parser, borgfs=True)
        return parser

    def _define_borg_mount(self, parser, borgfs=False):
        from ._common import define_exclusion_group, define_archive_filters_group

        if borgfs:
            # mount(8) / mount.fuse(8) invoke "borgfs <spec> <mountpoint> -o <options>", so for an
            # /etc/fstab entry like "/path/to/repo /mnt/point fuse.borgfs defaults,noauto 0 0" to work,
            # borgfs must accept the repository as its first positional argument.
            # It is optional: if it is not given, -r/--repo or BORG_REPO is used, like for borg mount.
            # Archiver.parse_args() copies it to args.location, where -r/--repo would have put it.
            parser.add_argument(
                "repository",
                metavar="REPOSITORY",
                nargs="?",
                type=location_validator(other=False),
                default=None,
                help="repository to mount (default: as given by -r/--repo or BORG_REPO)",
            )
        parser.add_argument(
            "mountpoint", metavar="MOUNTPOINT", type=FilesystemDirSpec, help="where to mount the filesystem"
        )
        parser.add_argument(
            "-f", "--foreground", dest="foreground", action="store_true", help="stay in foreground, do not daemonize"
        )
        parser.add_argument("-o", dest="options", type=str, action=Highlander, help="extra mount options")
        parser.add_argument(
            "--numeric-ids",
            dest="numeric_ids",
            action="store_true",
            help="use numeric user and group identifiers from archives",
        )
        define_archive_filters_group(parser)
        parser.add_argument(
            "paths", metavar="PATH", nargs="*", type=PathSpec, help="paths to extract; patterns are supported"
        )
        define_exclusion_group(parser, strip_components=True)
