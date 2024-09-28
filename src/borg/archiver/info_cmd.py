import argparse
import textwrap
from datetime import timedelta

from ._common import with_repository
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import format_timedelta, json_print, basic_json_data, archivename_validator
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class InfoMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.READ,))
    def do_info(self, args, repository, manifest, cache):
        """Show archive details such as disk space used"""

        if args.name:
            archive_infos = [manifest.archives.get_one([args.name])]
        else:
            archive_infos = manifest.archives.list_considering(args)

        output_data = []

        for i, archive_info in enumerate(archive_infos, 1):
            archive = Archive(manifest, archive_info.id, cache=cache, iec=args.iec)
            info = archive.info()
            if args.json:
                output_data.append(info)
            else:
                info["duration"] = format_timedelta(timedelta(seconds=info["duration"]))
                info["tags"] = ",".join(info["tags"])
                print(
                    textwrap.dedent(
                        """
                Archive name: {name}
                Archive fingerprint: {id}
                Comment: {comment}
                Hostname: {hostname}
                Username: {username}
                Tags: {tags}
                Time (start): {start}
                Time (end): {end}
                Duration: {duration}
                Command line: {command_line}
                Number of files: {stats[nfiles]}
                Original size: {stats[original_size]}
                """
                    )
                    .strip()
                    .format(**info)
                )
            if not args.json and len(archive_infos) - i:
                print()

        if args.json:
            json_print(basic_json_data(manifest, cache=cache, extra={"archives": output_data}))

    def build_parser_info(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog, define_archive_filters_group

        info_epilog = process_epilog(
            """
        This command displays detailed information about the specified archive.

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
            "info",
            parents=[common_parser],
            add_help=False,
            description=self.do_info.__doc__,
            epilog=info_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="show repository or archive information",
        )
        subparser.set_defaults(func=self.do_info)
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
        define_archive_filters_group(subparser)
        subparser.add_argument(
            "name", metavar="NAME", nargs="?", type=archivename_validator, help="specify the archive name"
        )
