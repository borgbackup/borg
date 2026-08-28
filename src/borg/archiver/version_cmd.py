from .. import __version__
from ..constants import *  # NOQA
from ..helpers import json_print
from ..helpers.argparsing import ArgumentParser

from ..logger import create_logger

logger = create_logger()


class VersionMixIn:
    def do_version(self, args):
        """Displays the Borg client and server versions."""
        from borg.version import parse_version, format_version

        client_version = parse_version(__version__)
        if args.location.proto == "ssh" and args.v1_legacy:
            from ..legacy.remote import LegacyRemoteRepository

            with LegacyRemoteRepository(args.location, lock=False, args=args) as repository:
                server_version = repository.server_version
        else:
            server_version = client_version

        formatted_client_version = format_version(client_version)
        formatted_server_version = format_version(server_version)
        if args.json:
            version_info = {"client": formatted_client_version, "server": formatted_server_version}
            json_print(version_info)
        else:
            print(f"{formatted_client_version} / {formatted_server_version}")

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

            # local repository
            $ borg -r /mnt/backup version
            2.0.0 / 2.0.0

            # legacy remote repository (client uses 2.0.0, server uses 1.4.5 release)
            $ borg -r ssh://borg@borgbackup/repo version --from-borg1
            2.0.0 / 1.4.5

        Due to the version tuple format used in Borg client/server negotiation, only
        a simplified version is displayed (as provided by borg.version.format_version).

        You can also use ``borg --version`` to display a potentially more precise client version.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_version.__doc__, epilog=version_epilog)
        subparsers.add_subcommand("version", subparser, help="display the Borg client and server versions")
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
        subparser.add_argument("--from-borg1", dest="v1_legacy", action="store_true", help="repository is Borg 1.x")
