import argparse
import shlex
import textwrap
from datetime import timedelta

from .common import with_repository
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import Manifest
from ..helpers import remove_surrogates, format_timedelta, json_print, basic_json_data

from ..logger import create_logger

logger = create_logger()


class InfoMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.READ,))
    def do_info(self, args, repository, manifest, key, cache):
        """Show archive details such as disk space used"""

        def format_cmdline(cmdline):
            return remove_surrogates(" ".join(shlex.quote(x) for x in cmdline))

        args.consider_checkpoints = True
        archive_names = tuple(x.name for x in manifest.archives.list_considering(args))

        output_data = []

        for i, archive_name in enumerate(archive_names, 1):
            archive = Archive(
                repository,
                key,
                manifest,
                archive_name,
                cache=cache,
                consider_part_files=args.consider_part_files,
                iec=args.iec,
            )
            info = archive.info()
            if args.json:
                output_data.append(info)
            else:
                info["duration"] = format_timedelta(timedelta(seconds=info["duration"]))
                info["command_line"] = format_cmdline(info["command_line"])
                print(
                    textwrap.dedent(
                        """
                Archive name: {name}
                Archive fingerprint: {id}
                Comment: {comment}
                Hostname: {hostname}
                Username: {username}
                Time (start): {start}
                Time (end): {end}
                Duration: {duration}
                Command line: {command_line}
                Number of files: {stats[nfiles]}
                Original size: {stats[original_size]}
                Deduplicated size: {stats[deduplicated_size]}
                """
                    )
                    .strip()
                    .format(**info)
                )
            if self.exit_code:
                break
            if not args.json and len(archive_names) - i:
                print()

        if args.json:
            json_print(basic_json_data(manifest, cache=cache, extra={"archives": output_data}))
        return self.exit_code

    def build_parser_info(self, subparsers, common_parser, mid_common_parser):
        from .common import process_epilog, define_archive_filters_group

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
