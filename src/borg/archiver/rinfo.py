import argparse
import textwrap

from .common import with_repository
from ..constants import *  # NOQA
from ..helpers import Manifest
from ..helpers import bin_to_hex, json_print, basic_json_data

from ..logger import create_logger

logger = create_logger()


class RInfoMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.READ,))
    def do_rinfo(self, args, repository, manifest, key, cache):
        """Show repository infos"""
        info = basic_json_data(manifest, cache=cache, extra={"security_dir": cache.security_manager.dir})

        if args.json:
            json_print(info)
        else:
            encryption = "Encrypted: "
            if key.NAME in ("plaintext", "authenticated"):
                encryption += "No"
            else:
                encryption += "Yes (%s)" % key.NAME
            if key.NAME.startswith("key file"):
                encryption += "\nKey file: %s" % key.find_key()
            info["encryption"] = encryption

            print(
                textwrap.dedent(
                    """
            Repository ID: {id}
            Location: {location}
            Repository version: {version}
            Append only: {append_only}
            {encryption}
            Cache: {cache.path}
            Security dir: {security_dir}
            """
                )
                .strip()
                .format(
                    id=bin_to_hex(repository.id),
                    location=repository._location.canonical_path(),
                    version=repository.version,
                    append_only=repository.append_only,
                    **info,
                )
            )
            print(str(cache))
        return self.exit_code

    def build_parser_rinfo(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog

        rinfo_epilog = process_epilog(
            """
        This command displays detailed information about the repository.

        Please note that the deduplicated sizes of the individual archives do not add
        up to the deduplicated size of the repository ("all archives"), because the two
        are meaning different things:

        This archive / deduplicated size = amount of data stored ONLY for this archive
        = unique chunks of this archive.
        All archives / deduplicated size = amount of data stored in the repo
        = all chunks in the repository.
        """
        )
        subparser = subparsers.add_parser(
            "rinfo",
            parents=[common_parser],
            add_help=False,
            description=self.do_rinfo.__doc__,
            epilog=rinfo_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="show repository information",
        )
        subparser.set_defaults(func=self.do_rinfo)
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
