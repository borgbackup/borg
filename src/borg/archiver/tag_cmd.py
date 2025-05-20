import argparse

from ._common import with_repository, define_archive_filters_group
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import bin_to_hex, archivename_validator, tag_validator, Error
from ..manifest import Manifest

from ..logger import create_logger

logger = create_logger()


class TagMixIn:
    @with_repository(cache=True, compatibility=(Manifest.Operation.WRITE,))
    def do_tag(self, args, repository, manifest, cache):
        """Manage tags"""

        def tags_set(tags):
            """return a set of tags, removing empty tags"""
            return {tag for tag in tags if tag}

        if args.name:
            archive_infos = [manifest.archives.get_one([args.name])]
        else:
            archive_infos = manifest.archives.list_considering(args)

        def check_special(tags):
            if tags:
                special = {tag for tag in tags_set(tags) if tag.startswith("@")}
                if not special.issubset(SPECIAL_TAGS):
                    raise Error("unknown special tags given.")

        check_special(args.set_tags)
        check_special(args.add_tags)
        check_special(args.remove_tags)

        for archive_info in archive_infos:
            archive = Archive(manifest, archive_info.id, cache=cache)
            if args.set_tags:
                # avoid that --set (accidentally) erases existing special tags,
                # but allow --set if the existing special tags are also given.
                new_tags = tags_set(args.set_tags)
                existing_special = {tag for tag in archive.tags if tag.startswith("@")}
                clobber = not existing_special.issubset(new_tags)
                if not clobber:
                    archive.tags = new_tags
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

            User defined tags must not start with `@` because such tags are considered
            special and users are only allowed to use known special tags:

            ``@PROT``: protects archives against archive deletion or pruning.

            Pre-existing special tags can not be removed via ``--set``. You can still use
            ``--set``, but you must give pre-existing special tags also (so they won't be
            removed).
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
