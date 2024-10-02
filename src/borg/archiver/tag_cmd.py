import argparse

from ._common import with_repository, define_archive_filters_group
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import bin_to_hex, archivename_validator, tag_validator
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class TagMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.WRITE,))
    def do_tag(self, args, repository, manifest, cache):
        """Manage tags"""

        def tags_set(tags):
            """return a set of tags, removing empty tags"""
            return set(tag for tag in tags if tag)

        if args.name:
            archive_infos = [manifest.archives.get_one([args.name])]
        else:
            archive_infos = manifest.archives.list_considering(args)

        for archive_info in archive_infos:
            archive = Archive(manifest, archive_info.id, cache=cache)
            if args.set_tags:
                archive.tags = tags_set(args.set_tags)
            if args.add_tags:
                archive.tags |= tags_set(args.add_tags)
            if args.remove_tags:
                archive.tags -= tags_set(args.remove_tags)
            old_id = archive.id
            archive.set_meta("tags", list(sorted(archive.tags)))
            if old_id != archive.id:
                manifest.archives.delete_by_id(old_id)
            print(
                f"id: {bin_to_hex(old_id):.8} -> {bin_to_hex(archive.id):.8}, "
                f"tags: {','.join(sorted(archive.tags))}."
            )

    def build_parser_tag(self, subparsers, common_parser, mid_common_parser):
        from ._common import process_epilog

        tag_epilog = process_epilog(
            """
            Manage archive tags.

            Borg archives can have a set of tags which can be used for matching archives.

            You can set the tags to a specific set of tags or you can add or remove
            tags from the current set of tags.
            """
        )
        subparser = subparsers.add_parser(
            "tag",
            parents=[common_parser],
            add_help=False,
            description=self.do_tag.__doc__,
            epilog=tag_epilog,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            help="tag archives",
        )
        subparser.set_defaults(func=self.do_tag)
        subparser.add_argument(
            "--set",
            dest="set_tags",
            metavar="TAG",
            type=tag_validator,
            action="append",
            help="set tags (can be given multiple times)",
        )
        subparser.add_argument(
            "--add",
            dest="add_tags",
            metavar="TAG",
            type=tag_validator,
            action="append",
            help="add tags (can be given multiple times)",
        )
        subparser.add_argument(
            "--remove",
            dest="remove_tags",
            metavar="TAG",
            type=tag_validator,
            action="append",
            help="remove tags (can be given multiple times)",
        )
        define_archive_filters_group(subparser)
        subparser.add_argument(
            "name", metavar="NAME", nargs="?", type=archivename_validator, help="specify the archive name"
        )
