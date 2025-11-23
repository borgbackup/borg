import argparse
import os

from ._common import with_repository, Highlander
from ..constants import *  # NOQA
from ..helpers import RTError
from ..helpers import PathSpec
from ..helpers import umount
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class Mount2MixIn:
    def do_mount2(self, args):
        """Mounts an archive or an entire repository as a FUSE filesystem."""
        # Perform these checks before opening the repository and asking for a passphrase.

        try:
            from ..fuse2 import mfuse
        except ImportError:
            mfuse = None

        if mfuse is None:
            raise RTError("borg mount2 not available: mfuse not installed.")

        if not os.path.isdir(args.mountpoint):
            raise RTError(f"{args.mountpoint}: Mountpoint must be an **existing directory**")

        if not os.access(args.mountpoint, os.R_OK | os.W_OK | os.X_OK):
            raise RTError(f"{args.mountpoint}: Mountpoint must be a **writable** directory")

        self._do_mount2(args)

    @with_repository(compatibility=(Manifest.Operation.READ,))
    def _do_mount2(self, args, repository, manifest):
        from ..fuse2 import borgfs

        operations = borgfs(manifest, args, repository)
        logger.info("Mounting filesystem")
        try:
            operations.mount(args.mountpoint, args.options, args.foreground, args.show_rc)
        except RuntimeError:
            # Relevant error message already printed to stderr by FUSE
            raise RTError("FUSE mount failed")

    def do_umount2(self, args):
        """Unmounts the FUSE filesystem."""
        umount(args.mountpoint)

    def build_parser_mount2_umount2(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        mount_epilog = process_epilog(
            """
        This command mounts a repository or an archive as a FUSE filesystem.
        This can be useful for browsing or restoring individual files.

        This is an alternative implementation using mfusepy.
        """
        )
        subparser = subparsers.add_parser(
            "mount2",
            parents=[common_parser],
            add_help=False,
            description=self.do_mount2.__doc__,
            epilog=mount_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="mount a repository (new implementation)",
        )
        self._define_borg_mount2(subparser)

        umount_epilog = process_epilog(
            """
        This command unmounts a FUSE filesystem that was mounted with ``borg mount2``.

        This is a convenience wrapper that just calls the platform-specific shell
        command - usually this is either umount or fusermount -u.
        """
        )
        subparser = subparsers.add_parser(
            "umount2",
            parents=[common_parser],
            add_help=False,
            description=self.do_umount2.__doc__,
            epilog=umount_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="unmount a repository (new implementation)",
        )
        subparser.set_defaults(func=self.do_umount2)
        subparser.add_argument(
            "mountpoint", metavar="MOUNTPOINT", type=str, help="mountpoint of the filesystem to unmount"
        )

    def _define_borg_mount2(self, parser):
        from ._common import define_exclusion_group, define_archive_filters_group

        parser.set_defaults(func=self.do_mount2)
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
