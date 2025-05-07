import argparse
import textwrap

from ._common import with_repository
from ..constants import *  # NOQA
from ..helpers import bin_to_hex, json_print, basic_json_data
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class RepoInfoMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.READ,))
    def do_repo_info(self, args, repository, manifest, cache):
        """Show repository infos"""
        key = manifest.key
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

            output = (
                textwrap.dedent(
                    """
            Repository ID: {id}
            Location: {location}
            Repository version: {version}
            {encryption}
            Security dir: {security_dir}
            """
                )
                .strip()
                .format(
                    id=bin_to_hex(repository.id),
                    location=repository._location.canonical_path(),
                    version=repository.version,
                    encryption=info["encryption"],
                    security_dir=info["security_dir"],
                )
            )

            if hasattr(info["cache"], "path"):
                output += "\nCache: {cache.path}\n".format(**info)

            print(output)

    def build_parser_repo_info(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        repo_info_epilog = process_epilog(
            """
        This command displays detailed information about the repository.
        """
        )
        subparser = subparsers.add_parser(
            "repo-info",
            parents=[common_parser],
            add_help=False,
            description=self.do_repo_info.__doc__,
            epilog=repo_info_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="show repository information",
        )
        subparser.set_defaults(func=self.do_repo_info)
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
