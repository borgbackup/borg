from ._common import with_repository, define_archive_filters_group, archive_match_patterns
from ..archive import Archive
from ..constants import *  # NOQA
from ..helpers import bin_to_hex, archivename_validator, tag_validator
from ..helpers.argparsing import ArgumentParser

from ..logger import create_logger

logger = create_logger()


class TagMixIn:
    @with_repository(cache=True)
    def do_tag(self, args, repository, manifest, cache):
        """Manage tags."""

        if args.name:
            archive_infos = [manifest.archives.get_one(archive_match_patterns(args))]
        else:
            archive_infos = manifest.archives.list_considering(args)

        for archive_info in archive_infos:
            archive = Archive(manifest, archive_info, cache=cache)
            if args.set_tags is not None:
                # avoid that --set (accidentally) erases existing special tags,
                # but allow --set if the existing special tags are also given.
                new_tags = set(args.set_tags)
                existing_special = {tag for tag in archive.tags if tag.startswith("@")}
                clobber = not existing_special.issubset(new_tags)
                if not clobber:
                    archive.tags = new_tags
            archive.tags |= set(args.add_tags or [])
            archive.tags -= set(args.remove_tags or [])
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

            User-defined tags must not start with `@` because such tags are considered
            special and users are only allowed to use known special tags:

            ``@PROT``: protects archives against archive deletion or pruning.

            Pre-existing special tags cannot be removed via ``--set``. You can still use
            ``--set``, but you must also give pre-existing special tags (so they won't be
            removed).

            Each of ``--set``, ``--add`` and ``--remove`` takes exactly one tag. To give
            multiple tags, use the option multiple times.

            Examples::

                # add the tags "important" and "keep" to the archive with the given ID
                $ borg tag --add important --add keep aid:1ddaae55

                # remove the tag "keep" from all archives named "home"
                $ borg tag --remove keep --match-archives home

                # set the tags of the archive with the given ID to exactly "foo" and "bar"
                $ borg tag --set foo --set bar aid:1ddaae55

                # protect the archive with the given ID against deletion and pruning
                $ borg tag --add @PROT aid:1ddaae55
            """
        )
        subparser = ArgumentParser(parents=[common_parser], description=self.do_tag.__doc__, epilog=tag_epilog)
        subparsers.add_subcommand("tag", subparser, help="tag archives")
        # each option takes exactly one tag, so it can not swallow the NAME positional argument.
        # note: "extend" with nargs=1 (not "append") gives a flat list of tags that jsonargparse can validate.
        subparser.add_argument(
            "--set",
            dest="set_tags",
            metavar="TAG",
            type=tag_validator,
            action="extend",
            nargs=1,
            help="set tags (can be given multiple times)",
        )
        subparser.add_argument(
            "--add",
            dest="add_tags",
            metavar="TAG",
            type=tag_validator,
            action="extend",
            nargs=1,
            help="add tag (can be given multiple times)",
        )
        subparser.add_argument(
            "--remove",
            dest="remove_tags",
            metavar="TAG",
            type=tag_validator,
            action="extend",
            nargs=1,
            help="remove tag (can be given multiple times)",
        )
        define_archive_filters_group(subparser)
        subparser.add_argument(
            "name", metavar="NAME", nargs="?", type=archivename_validator, help="specify the archive name"
        )
