import argparse
import os

from .common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import EXIT_ERROR
from ..helpers import Manifest
from ..helpers import umount
from ..remote import cache_if_remote

from ..logger import create_logger

logger = create_logger()


class MountMixIn:
    def do_mount(self, args):
        """Mount archive or an entire repository as a FUSE filesystem"""
        # Perform these checks before opening the repository and asking for a passphrase.

        from ..fuse_impl import llfuse, BORG_FUSE_IMPL

        if llfuse is None:
            self.print_error("borg mount not available: no FUSE support, BORG_FUSE_IMPL=%s." % BORG_FUSE_IMPL)
            return self.exit_code

        if not os.path.isdir(args.mountpoint) or not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            self.print_error("%s: Mountpoint must be a writable directory" % args.mountpoint)
            return self.exit_code

        return self._do_mount(args)

    @with_repository(compatibility=(Manifest.Operation.READ,))
    def _do_mount(self, args, repository, manifest, key):
        from ..fuse import FuseOperations

        with cache_if_remote(repository, decrypted_cache=key) as cached_repo:
            operations = FuseOperations(key, repository, manifest, args, cached_repo)
            logger.info("Mounting filesystem")
            try:
                operations.mount(args.mountpoint, args.options, args.foreground)
            except RuntimeError:
                # Relevant error message already printed to stderr by FUSE
                self.exit_code = EXIT_ERROR
        return self.exit_code

    def do_umount(self, args):
        """un-mount the FUSE filesystem"""
        return umount(args.mountpoint)

    def build_parser_mount_umount(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog

        mount_epilog = process_epilog(
            """
        This command mounts an archive as a FUSE filesystem. This can be useful
        for browsing an archive or restoring individual files. When restoring,
        take into account that the current FUSE implementation does not support
        special fs flags and ACLs.

        Unless the ``--foreground`` option is given the command will run in the
        background until the filesystem is ``umounted``.

        The command ``borgfs`` provides a wrapper for ``borg mount``. This can also be
        used in fstab entries:
        ``/path/to/repo /mnt/point fuse.borgfs defaults,noauto 0 0``

        To allow a regular user to use fstab entries, add the ``user`` option:
        ``/path/to/repo /mnt/point fuse.borgfs defaults,noauto,user 0 0``

        For FUSE configuration and mount options, see the mount.fuse(8) manual page.

        Borg's default behavior is to use the archived user and group names of each
        file and map them to the system's respective user and group ids.
        Alternatively, using ``numeric-ids`` will instead use the archived user and
        group ids without any mapping.

        The ``uid`` and ``gid`` mount options (implemented by Borg) can be used to
        override the user and group ids of all files (i.e., ``borg mount -o
        uid=1000,gid=1000``).

        The man page references ``user_id`` and ``group_id`` mount options
        (implemented by fuse) which specify the user and group id of the mount owner
        (aka, the user who does the mounting). It is set automatically by libfuse (or
        the filesystem if libfuse is not used). However, you should not specify these
        manually. Unlike the ``uid`` and ``gid`` mount options which affect all files,
        ``user_id`` and ``group_id`` affect the user and group id of the mounted
        (base) directory.

        Additional mount options supported by borg:

        - versions: when used with a repository mount, this gives a merged, versioned
          view of the files in the archives. EXPERIMENTAL, layout may change in future.
        - allow_damaged_files: by default damaged files (where missing chunks were
          replaced with runs of zeros by borg check ``--repair``) are not readable and
          return EIO (I/O error). Set this option to read such files.
        - ignore_permissions: for security reasons the "default_permissions" mount
          option is internally enforced by borg. "ignore_permissions" can be given to
          not enforce "default_permissions".

        The BORG_MOUNT_DATA_CACHE_ENTRIES environment variable is meant for advanced users
        to tweak the performance. It sets the number of cached data chunks; additional
        memory usage can be up to ~8 MiB times this number. The default is the number
        of CPU cores.

        When the daemonized process receives a signal or crashes, it does not unmount.
        Unmounting in these cases could cause an active rsync or similar process
        to unintentionally delete data.

        When running in the foreground ^C/SIGINT unmounts cleanly, but other
        signals or crashes do not.
        """
        )
        subparser = subparsers.add_parser(
            "mount",
            parents=[common_parser],
            add_help=False,
            description=self.do_mount.__doc__,
            epilog=mount_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="mount repository",
        )
        self._define_borg_mount(subparser)

        umount_epilog = process_epilog(
            """
        This command un-mounts a FUSE filesystem that was mounted with ``borg mount``.

        This is a convenience wrapper that just calls the platform-specific shell
        command - usually this is either umount or fusermount -u.
        """
        )
        subparser = subparsers.add_parser(
            "umount",
            parents=[common_parser],
            add_help=False,
            description=self.do_umount.__doc__,
            epilog=umount_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="umount repository",
        )
        subparser.set_defaults(func=self.do_umount)
        subparser.add_argument(
            "mountpoint", metavar="MOUNTPOINT", type=str, help="mountpoint of the filesystem to umount"
        )

    def build_parser_borgfs(self, parser):
        assert parser.prog == "borgfs"
        parser.description = self.do_mount.__doc__
        parser.epilog = "For more information, see borg mount --help."
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.help = "mount repository"
        self._define_borg_mount(parser)
        return parser

    def _define_borg_mount(self, parser):
        from .common import define_exclusion_group, define_archive_filters_group

        parser.set_defaults(func=self.do_mount)
        parser.add_argument(
            "--consider-checkpoints",
            action="store_true",
            dest="consider_checkpoints",
            help="Show checkpoint archives in the repository contents list (default: hidden).",
        )
        parser.add_argument("mountpoint", metavar="MOUNTPOINT", type=str, help="where to mount filesystem")
        parser.add_argument(
            "-f", "--foreground", dest="foreground", action="store_true", help="stay in foreground, do not daemonize"
        )
        parser.add_argument("-o", dest="options", type=str, action=Highlander, help="Extra mount options")
        parser.add_argument(
            "--numeric-ids",
            dest="numeric_ids",
            action="store_true",
            help="use numeric user and group identifiers from archive(s)",
        )
        define_archive_filters_group(parser)
        parser.add_argument(
            "paths", metavar="PATH", nargs="*", type=str, help="paths to extract; patterns are supported"
        )
        define_exclusion_group(parser, strip_components=True)
