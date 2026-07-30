import textwrap
from datetime import timedelta

from ._common import with_repository
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import format_timedelta, json_print, basic_json_data, archivename_validator, use_iec_units
from ..helpers.argparsing import ArgumentParser
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
            archive = Archive(manifest, archive_info.id, cache=cache, iec=use_iec_units())
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
                Time (nominal): {time}
                Time (start): {start}
                Time (end): {end}
                Duration: {duration}
                Command line: {command_line}
                Working Directory: {cwd}
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

        The original size shown here is the total size of the archive's source data
        (uncompressed, counting duplicate content per occurrence).

        Deduplicated sizes are not shown here (computing them per archive is expensive).
        For the deduplicated size of a set of archives, use ``borg analyze``; for the
        repository-wide deduplicated size, use ``borg compact --stats``.
        """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_info.__doc__, epilog=info_epilog)
        subparsers.add_subcommand("info", subparser, help="show repository or archive information")
        subparser.add_argument("--json", action="store_true", help="format output as JSON")
        define_archive_filters_group(subparser)
        subparser.add_argument(
            "name", metavar="NAME", nargs="?", type=archivename_validator, help="specify the archive name"
        )
