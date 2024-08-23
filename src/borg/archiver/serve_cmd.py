import argparse

from ._common import Highlander
from ..constants import *  # NOQA
from ..helpers import parse_storage_quota
from ..remote import RepositoryServer

from ..logger import create_logger

logger = create_logger()


class ServeMixIn:
    def do_serve(self, args):
        """Start in server mode. This command is usually not used manually."""
        RepositoryServer(
            restrict_to_paths=args.restrict_to_paths,
            restrict_to_repositories=args.restrict_to_repositories,
            append_only=args.append_only,
            storage_quota=args.storage_quota,
            use_socket=args.use_socket,
        ).serve()

    def build_parser_serve(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        serve_epilog = process_epilog(
            """
        This command starts a repository server process.

        borg serve can currently support:

        - Getting automatically started via ssh when the borg client uses a ssh://...
          remote repository. In this mode, `borg serve` will live until that ssh connection
          gets terminated.

        - Getting started by some other means (not by the borg client) as a long-running socket
          server to be used for borg clients using a socket://... repository (see the `--socket`
          option if you do not want to use the default path for the socket and pid file).
        """
        )
        subparser = subparsers.add_parser(
            "serve",
            parents=[common_parser],
            add_help=False,
            description=self.do_serve.__doc__,
            epilog=serve_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="start repository server process",
        )
        subparser.set_defaults(func=self.do_serve)
        subparser.add_argument(
            "--restrict-to-path",
            metavar="PATH",
            dest="restrict_to_paths",
            action="append",
            help="restrict repository access to PATH. "
            "Can be specified multiple times to allow the client access to several directories. "
            "Access to all sub-directories is granted implicitly; PATH doesn't need to point directly to a repository.",
        )
        subparser.add_argument(
            "--restrict-to-repository",
            metavar="PATH",
            dest="restrict_to_repositories",
            action="append",
            help="restrict repository access. Only the repository located at PATH "
            "(no sub-directories are considered) is accessible. "
            "Can be specified multiple times to allow the client access to several repositories. "
            "Unlike ``--restrict-to-path`` sub-directories are not accessible; "
            "PATH needs to point directly at a repository location. "
            "PATH may be an empty directory or the last element of PATH may not exist, in which case "
            "the client may initialize a repository there.",
        )
        subparser.add_argument(
            "--append-only",
            dest="append_only",
            action="store_true",
            help="only allow appending to repository segment files. Note that this only "
            "affects the low level structure of the repository, and running `delete` "
            "or `prune` will still be allowed. See :ref:`append_only_mode` in Additional "
            "Notes for more details.",
        )
        subparser.add_argument(
            "--storage-quota",
            metavar="QUOTA",
            dest="storage_quota",
            type=parse_storage_quota,
            default=None,
            action=Highlander,
            help="Override storage quota of the repository (e.g. 5G, 1.5T). "
            "When a new repository is initialized, sets the storage quota on the new "
            "repository as well. Default: no quota.",
        )
