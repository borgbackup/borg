import os

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import RTError
from ..helpers import PathSpec
from ..helpers import umount
from ..helpers.argparsing import ArgumentParser, RawDescriptionHelpFormatter
from ..manifest import Manifest
from ..remote import cache_if_remote

from ..logger import create_logger

logger = create_logger()


class MountMixIn:
    def do_mount(self, args):
        """Mounts an archive or an entire repository as a FUSE filesystem."""
        # Perform these checks before opening the repository and asking for a passphrase.

        from ..fuse_impl import llfuse, has_mfusepy, BORG_FUSE_IMPL

        if llfuse is None and not has_mfusepy:
            raise RTError("borg mount not available: no FUSE support, BORG_FUSE_IMPL=%s." % BORG_FUSE_IMPL)

        if not os.path.isdir(args.mountpoint):
            raise RTError(f"{args.mountpoint}: Mountpoint must be an **existing directory**")

        if not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            raise RTError(f"{args.mountpoint}: Mountpoint must be a **writable** directory")

        self._do_mount(args)

    @with_repository(compatibility=(Manifest.Operation.READ,))
    def _do_mount(self, args, repository, manifest):
        from ..fuse_impl import has_mfusepy

        if has_mfusepy:
            # Use mfusepy implementation
            from ..hlfuse import borgfs

            operations = borgfs(manifest, args, repository)
            logger.info("Mounting filesystem")
            try:
                operations.mount(args.mountpoint, args.options, args.foreground, args.show_rc)
            except RuntimeError:
                # Relevant error message already printed to stderr by FUSE
                raise RTError("FUSE mount failed")
        else:
            # Use llfuse/pyfuse3 implementation
            from ..fuse import FuseOperations

            with cache_if_remote(repository, decrypted_cache=manifest.repo_objs) as cached_repo:
                operations = FuseOperations(manifest, args, cached_repo)
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
        not support special fs flags and ACLs.

        When mounting a repository, the top directories will be named like the
        archives and the directory structure below these will be loaded on-demand from
        the repository when entering these directories, so expect some delay.

        Care should be taken, as Borg backs up symlinks as-is. When an archive 
        or repository is mounted, it is possible to “jump” outside the mount point 
        by following a symlink. If this happens, files or directories (or versions of them)
        that are not part of the archive or repository may appear to be within the mount point.

        Unless the ``--foreground`` option is given, the command will run in the
        background until the filesystem is ``unmounted``.

        Performance tips:

        - When doing a "whole repository" mount:
          do not enter archive directories if not needed; this avoids on-demand loading.
        - Only mount a specific archive, not the whole repository.
        - Only mount specific paths in a specific archive, not the complete archive.

        The command ``borgfs`` provides a wrapper for ``borg mount``. This can also be
        used in fstab entries:
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
        subparser = ArgumentParser(
            parents=[common_parser],
            add_help=False,
            description=self.do_mount.__doc__,
            epilog=mount_epilog,
            formatter_class=RawDescriptionHelpFormatter,
        )
        subparsers.add_subcommand("mount", subparser, help="mount a repository")
        self._define_borg_mount(subparser)

        umount_epilog = process_epilog(
            """
        This command unmounts a FUSE filesystem that was mounted with ``borg mount``.

        This is a convenience wrapper that just calls the platform-specific shell
        command - usually this is either umount or fusermount -u.
        """
        )
        subparser = ArgumentParser(
            parents=[common_parser],
            add_help=False,
            description=self.do_umount.__doc__,
            epilog=umount_epilog,
            formatter_class=RawDescriptionHelpFormatter,
        )
        subparsers.add_subcommand("umount", subparser, help="unmount a repository")
        subparser.add_argument(
            "mountpoint", metavar="MOUNTPOINT", type=str, help="mountpoint of the filesystem to unmount"
        )

    def build_parser_borgfs(self, parser):
        assert parser.prog == "borgfs"
        parser.description = self.do_mount.__doc__
        parser.epilog = "For more information, see borg mount --help."
        parser.formatter_class = RawDescriptionHelpFormatter
        parser.help = "mount a repository"
        self._define_borg_mount(parser)
        return parser

    def _define_borg_mount(self, parser):
        from ._common import define_exclusion_group, define_archive_filters_group

        parser.add_argument("mountpoint", metavar="MOUNTPOINT", type=str, help="where to mount the filesystem")
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
