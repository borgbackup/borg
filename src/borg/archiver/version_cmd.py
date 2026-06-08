from .. import __version__
from ..constants import *  # NOQA
from ..helpers.argparsing import ArgumentParser

from ..logger import create_logger

logger = create_logger()


class VersionMixIn:
    def do_version(self, args):
        """Displays the Borg client and server versions."""
        from borg.version import parse_version, format_version

        client_version = parse_version(__version__)
        if args.location.proto == "ssh" and getattr(args, "v1_legacy", False):
            from ..legacy.remote import LegacyRemoteRepository

            with LegacyRemoteRepository(args.location, lock=False, args=args) as repository:
                server_version = repository.server_version
        else:
            server_version = client_version
        print(f"{format_version(client_version)} / {format_version(server_version)}")

    def build_parser_version(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        version_epilog = process_epilog(
            """
        This command displays the Borg client and server versions.

        For current repositories the client code directly accesses the repository (also for
        rest:// repositories), so the client version is shown as the server version, too.

        If a legacy (borg 1.x / v1) repository is given via ssh: together with --from-borg1,
        the remote Borg is queried, and its version is displayed as the server version.

        Examples::

            # local repository (client uses 1.4.0 alpha version)
            $ borg version /mnt/backup
            1.4.0a / 1.4.0a

            # legacy remote repository (client uses 1.4.0 alpha, server uses 1.2.7 release)
            $ borg version --from-borg1 ssh://borg@borgbackup:repo
            1.4.0a / 1.2.7

        Due to the version tuple format used in Borg client/server negotiation, only
        a simplified version is displayed (as provided by borg.version.format_version).

        You can also use ``borg --version`` to display a potentially more precise client version.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_version.__doc__, epilog=version_epilog)
        subparsers.add_subcommand("version", subparser, help="display the Borg client and server versions")
