import argparse

from .. import __version__
from ..constants import *  # NOQA
from ..remote import RemoteRepository

from ..logger import create_logger

logger = create_logger()


class VersionMixIn:
    def do_version(self, args):
        """Display the borg client / borg server version"""
        from borg.version import parse_version, format_version

        client_version = parse_version(__version__)
        if args.location.proto in ("ssh", "socket"):
            with RemoteRepository(args.location, lock=False, args=args) as repository:
                server_version = repository.server_version
        else:
            server_version = client_version
        print(f"{format_version(client_version)} / {format_version(server_version)}")

    def build_parser_version(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        version_epilog = process_epilog(
            """
        This command displays the borg client version / borg server version.

        If a local repo is given, the client code directly accesses the repository,
        thus we show the client version also as the server version.

        If a remote repo is given (e.g. ssh:), the remote borg is queried and
        its version is displayed as the server version.

        Examples::

            # local repo (client uses 1.4.0 alpha version)
            $ borg version /mnt/backup
            1.4.0a / 1.4.0a

            # remote repo (client uses 1.4.0 alpha, server uses 1.2.7 release)
            $ borg version ssh://borg@borgbackup:repo
            1.4.0a / 1.2.7

        Due to the version tuple format used in borg client/server negotiation, only
        a simplified version is displayed (as provided by borg.version.format_version).

        There is also borg --version to display a potentially more precise client version.
        """
        )
        subparser = subparsers.add_parser(
            "version",
            parents=[common_parser],
            add_help=False,
            description=self.do_version.__doc__,
            epilog=version_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="display borg client version / borg server version",
        )
        subparser.set_defaults(func=self.do_version)
